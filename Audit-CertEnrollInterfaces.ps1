<#
.SYNOPSIS
    Enumerates the COM coclasses and interfaces exposed by Microsoft's
    Certificate Enrollment (CertEnroll) API for X.509 certificates.

.DESCRIPTION
    Loads the certenroll.dll type library WITHOUT registering it
    (REGKIND_NONE) and walks its ITypeLib / ITypeInfo metadata to report:

      - Every coclass (CX509...) with its CLSID and ProgID
      - The interfaces each coclass implements (default interface marked)
      - Every interface / dispinterface with its declared methods and
        property accessors

    The type-library walk runs inside compiled C# so the ITypeLib / ITypeInfo
    calls are early-bound (vtable). Doing this walk directly from PowerShell
    fails, because a raw COM object is dispatched via IDispatch, which these
    OLE Automation interfaces do not implement.

    This is read-only reflection. It creates no CertEnroll objects, writes
    nothing to the registry, and requires no certificate access. It must run
    on Windows.

.PARAMETER DllPath
    Path to certenroll.dll. Defaults to %SystemRoot%\System32\certenroll.dll.

.PARAMETER IncludeInherited
    Include the IUnknown / IDispatch boilerplate members. Off by default.

.PARAMETER AsJson
    Emit structured JSON instead of the formatted text report.

.PARAMETER Path
    Optional file path to write the report to.

.EXAMPLE
    .\Audit-CertEnrollInterfaces.ps1

.EXAMPLE
    .\Audit-CertEnrollInterfaces.ps1 -AsJson -Path .\certenroll-audit.json
#>

[CmdletBinding()]
param(
    [string]$DllPath = (Join-Path $env:SystemRoot 'System32\certenroll.dll'),
    [switch]$IncludeInherited,
    [switch]$AsJson,
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This audit relies on Windows COM type libraries and must run on Windows.'
}
if (-not (Test-Path -LiteralPath $DllPath)) {
    throw ('CertEnroll library not found at: ' + $DllPath)
}

# ---------------------------------------------------------------------------
# Compiled type-library walker. All ITypeLib / ITypeInfo calls happen here so
# they bind through the vtable. Returns plain data objects to PowerShell.
# (No C# string interpolation is used.)
# ---------------------------------------------------------------------------
if (-not ([System.Management.Automation.PSTypeName]'CertAudit.Enumerator').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ITypeLib      = System.Runtime.InteropServices.ComTypes.ITypeLib;
using ITypeInfo     = System.Runtime.InteropServices.ComTypes.ITypeInfo;
using TYPEATTR      = System.Runtime.InteropServices.ComTypes.TYPEATTR;
using FUNCDESC      = System.Runtime.InteropServices.ComTypes.FUNCDESC;
using IMPLTYPEFLAGS = System.Runtime.InteropServices.ComTypes.IMPLTYPEFLAGS;

namespace CertAudit
{
    public class MethodRec
    {
        public string Name;
        public string Kind;
        public int ParamCount;
    }

    public class ImplRec
    {
        public string Interface;
        public bool Default;
        public bool Source;
    }

    public class InterfaceRec
    {
        public string Name;
        public string IID;
        public string Kind;
        public MethodRec[] Methods;
    }

    public class CoclassRec
    {
        public string Name;
        public string CLSID;
        public ImplRec[] Implements;
    }

    public class AuditResult
    {
        public CoclassRec[] Coclasses;
        public InterfaceRec[] Interfaces;
    }

    public static class Enumerator
    {
        [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void LoadTypeLibEx(
            string strTypeLibName,
            int regKind,
            [MarshalAs(UnmanagedType.Interface)] out ITypeLib typeLib);

        private const int MEMBERID_NIL   = -1;
        private const int TKIND_INTERFACE = 3;
        private const int TKIND_DISPATCH  = 4;
        private const int TKIND_COCLASS   = 5;

        private static readonly string[] Standard = new string[] {
            "QueryInterface", "AddRef", "Release",
            "GetTypeInfoCount", "GetTypeInfo", "GetIDsOfNames", "Invoke"
        };

        private static bool IsStandard(string n)
        {
            foreach (string s in Standard) { if (s == n) return true; }
            return false;
        }

        private static string NameOf(ITypeInfo ti)
        {
            string name, doc, help;
            int ctx;
            ti.GetDocumentation(MEMBERID_NIL, out name, out doc, out ctx, out help);
            return name;
        }

        private static MethodRec[] Methods(ITypeInfo ti, TYPEATTR attr, bool includeInherited)
        {
            List<MethodRec> list = new List<MethodRec>();
            for (int f = 0; f < attr.cFuncs; f++)
            {
                IntPtr p;
                ti.GetFuncDesc(f, out p);
                try
                {
                    FUNCDESC fd = (FUNCDESC)Marshal.PtrToStructure(p, typeof(FUNCDESC));
                    string[] names = new string[1];
                    int pc;
                    ti.GetNames(fd.memid, names, 1, out pc);
                    string nm = names[0];
                    if (!includeInherited && IsStandard(nm)) { continue; }

                    string kind;
                    switch ((int)fd.invkind)
                    {
                        case 1:  kind = "method"; break;
                        case 2:  kind = "get";    break;
                        case 4:  kind = "put";    break;
                        case 8:  kind = "putref"; break;
                        default: kind = "method"; break;
                    }

                    MethodRec m = new MethodRec();
                    m.Name = nm;
                    m.Kind = kind;
                    m.ParamCount = fd.cParams;
                    list.Add(m);
                }
                finally
                {
                    ti.ReleaseFuncDesc(p);
                }
            }
            return list.ToArray();
        }

        public static AuditResult Run(string dllPath, bool includeInherited)
        {
            ITypeLib tlb;
            LoadTypeLibEx(dllPath, 2, out tlb); // 2 = REGKIND_NONE
            int count = tlb.GetTypeInfoCount();

            List<CoclassRec> coclasses = new List<CoclassRec>();
            List<InterfaceRec> interfaces = new List<InterfaceRec>();

            for (int i = 0; i < count; i++)
            {
                ITypeInfo ti;
                tlb.GetTypeInfo(i, out ti);

                IntPtr pAttr;
                ti.GetTypeAttr(out pAttr);
                try
                {
                    TYPEATTR attr = (TYPEATTR)Marshal.PtrToStructure(pAttr, typeof(TYPEATTR));
                    string name = NameOf(ti);
                    string guid = "{" + attr.guid.ToString() + "}";
                    int kind = (int)attr.typekind;

                    if (kind == TKIND_INTERFACE || kind == TKIND_DISPATCH)
                    {
                        InterfaceRec ir = new InterfaceRec();
                        ir.Name = name;
                        ir.IID = guid;
                        ir.Kind = (kind == TKIND_DISPATCH) ? "dispinterface" : "interface";
                        ir.Methods = Methods(ti, attr, includeInherited);
                        interfaces.Add(ir);
                    }
                    else if (kind == TKIND_COCLASS)
                    {
                        List<ImplRec> impls = new List<ImplRec>();
                        for (int j = 0; j < attr.cImplTypes; j++)
                        {
                            int href;
                            ti.GetRefTypeOfImplType(j, out href);
                            ITypeInfo rti;
                            ti.GetRefTypeInfo(href, out rti);
                            IMPLTYPEFLAGS flags;
                            ti.GetImplTypeFlags(j, out flags);

                            ImplRec ip = new ImplRec();
                            ip.Interface = NameOf(rti);
                            ip.Default = (((int)flags) & 1) != 0; // IMPLTYPEFLAG_FDEFAULT
                            ip.Source  = (((int)flags) & 2) != 0; // IMPLTYPEFLAG_FSOURCE
                            impls.Add(ip);
                        }

                        CoclassRec cr = new CoclassRec();
                        cr.Name = name;
                        cr.CLSID = guid;
                        cr.Implements = impls.ToArray();
                        coclasses.Add(cr);
                    }
                }
                finally
                {
                    ti.ReleaseTypeAttr(pAttr);
                }
            }

            AuditResult res = new AuditResult();
            res.Coclasses = coclasses.ToArray();
            res.Interfaces = interfaces.ToArray();
            return res;
        }
    }
}
'@
}

# ---------------------------------------------------------------------------
# Run the walk, then enrich coclasses with registry data from PowerShell.
# ---------------------------------------------------------------------------
$result = [CertAudit.Enumerator]::Run($DllPath, [bool]$IncludeInherited)

function Get-RegDefault {
    param([string]$SubKey)
    $key = 'Registry::HKEY_CLASSES_ROOT\' + $SubKey
    if (Test-Path -LiteralPath $key) {
        return (Get-ItemProperty -LiteralPath $key).'(default)'
    }
    return $null
}

$coclasses = foreach ($c in $result.Coclasses) {
    $inprocKey = 'Registry::HKEY_CLASSES_ROOT\CLSID\' + $c.CLSID + '\InprocServer32'
    $server = $null; $threading = $null
    if (Test-Path -LiteralPath $inprocKey) {
        $ip = Get-ItemProperty -LiteralPath $inprocKey
        $server = $ip.'(default)'
        $threading = $ip.ThreadingModel
    }
    [pscustomobject]@{
        Name           = $c.Name
        CLSID          = $c.CLSID
        ProgID         = Get-RegDefault ('CLSID\' + $c.CLSID + '\ProgID')
        Server         = $server
        ThreadingModel = $threading
        Implements     = $c.Implements
    }
}

$interfaces = $result.Interfaces

$sortedCoclasses  = $coclasses  | Sort-Object Name
$sortedInterfaces = $interfaces | Sort-Object Name

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if ($AsJson) {
    $report = [pscustomobject]@{
        Source     = $DllPath
        Generated  = (Get-Date).ToString('s')
        Coclasses  = $sortedCoclasses
        Interfaces = $sortedInterfaces
    }
    $json = $report | ConvertTo-Json -Depth 8
    if ($Path) { $json | Set-Content -LiteralPath $Path -Encoding UTF8; Write-Host ('Report written to ' + $Path) }
    else       { $json }
    return
}

$sb = New-Object System.Text.StringBuilder
$null = $sb.AppendLine('CertEnroll COM Interface Audit')
$null = $sb.AppendLine('Source: ' + $DllPath)
$null = $sb.AppendLine('Generated: ' + (Get-Date).ToString('u'))
$null = $sb.AppendLine('Coclasses: ' + @($sortedCoclasses).Count + '   Interfaces: ' + @($sortedInterfaces).Count)
$null = $sb.AppendLine('')
$null = $sb.AppendLine('============================================================')
$null = $sb.AppendLine(' COCLASSES (instantiable objects)')
$null = $sb.AppendLine('============================================================')

foreach ($c in $sortedCoclasses) {
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine($c.Name)
    $null = $sb.AppendLine('  CLSID  : ' + $c.CLSID)
    if ($c.ProgID) { $null = $sb.AppendLine('  ProgID : ' + $c.ProgID) }
    if ($c.Server) { $null = $sb.AppendLine('  Server : ' + $c.Server + '  [' + $c.ThreadingModel + ']') }
    foreach ($impl in $c.Implements) {
        $marker = ''
        if ($impl.Default) { $marker = '  (default)' }
        if ($impl.Source)  { $marker = $marker + '  (source)' }
        $null = $sb.AppendLine('  -> ' + $impl.Interface + $marker)
    }
}

$null = $sb.AppendLine('')
$null = $sb.AppendLine('============================================================')
$null = $sb.AppendLine(' INTERFACES (members)')
$null = $sb.AppendLine('============================================================')

foreach ($iface in $sortedInterfaces) {
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine($iface.Name + '   [' + $iface.Kind + ']   ' + $iface.IID)
    foreach ($m in $iface.Methods) {
        $line = '    ' + $m.Kind.PadRight(7) + ' ' + $m.Name + ' (' + $m.ParamCount + ' param)'
        $null = $sb.AppendLine($line)
    }
}

$text = $sb.ToString()
if ($Path) {
    $text | Set-Content -LiteralPath $Path -Encoding UTF8
    Write-Host ('Report written to ' + $Path)
}
else {
    $text
}
