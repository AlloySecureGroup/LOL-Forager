<#
.SYNOPSIS
    Discovers known LOLBins and previously-unknown risky / dual-use applications
    to help improve Windows Defender Application Control (WDAC) policies.

.DESCRIPTION
    Extends the original Scan-InMemoryCompilePatterns.ps1 with four layers:

      A. Known LOLBin / dual-use executable catalog.
      B. Managed-code capability fingerprints.
      C. Native + managed string/capability heuristics for suspicious features
         such as scripting, download/network retrieval, proxy execution,
         installers, archive extraction, debugger/dump capability, DLL loading,
         child-process creation, and dynamic code execution.
      D. WDAC-oriented risk scoring based on capability combinations, signer,
         writable location, executable type, and catalog confidence.

    The script is intended for DEFENSIVE application-control discovery. A hit is
    not proof that a binary is malicious. Review business use and publisher/path
    trust before adding deny rules.

    For strongest results, run elevated and scan enterprise software locations.

.PARAMETER ScanPaths
    Directories to recursively scan.

.PARAMETER OutputCsv
    CSV report path.

.PARAMETER MaxFileSizeMB
    Maximum file size for string scanning. Known catalog hits are still reported
    even if larger.

.PARAMETER ExeOnly
    Scan EXEs only.

.PARAMETER CatalogOnly
    Only report known catalog entries.

.PARAMETER IncludeWinSxS
    Include C:\Windows\WinSxS.

.PARAMETER IncludeScripts
    Also inspect common script file types (.ps1, .cmd, .bat, .vbs, .js, .wsf).

.PARAMETER MinimumRiskScore
    Minimum risk score to emit. Default 20. Catalog entries always emit.

.PARAMETER DisableCriticalValidation
    Disables creation of capability-specific benign PoC validation harnesses for Critical findings.
    By default, each Critical finding receives a validation directory beside the CSV.

.EXAMPLE
    .\Scan-WdacRiskyApplications.ps1 -OutputCsv C:\Reports\WdacRisk.csv

.EXAMPLE
    .\Scan-WdacRiskyApplications.ps1 -CatalogOnly

.EXAMPLE
    .\Scan-WdacRiskyApplications.ps1 -IncludeScripts -MinimumRiskScore 35
#>

[CmdletBinding()]
param(
    [string[]]$ScanPaths = @(
        'C:\Windows\Microsoft.NET\Framework',
        'C:\Windows\Microsoft.NET\Framework64',
        'C:\Windows\Microsoft.NET\FrameworkArm64',
        'C:\Windows\Microsoft.NET\assembly',
        'C:\Windows\assembly',
        'C:\Windows\System32',
        'C:\Windows\SysWOW64',
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\Program Files\dotnet',
        'C:\ProgramData'
    ),
    [switch]$IncludeWinSxS,
    [switch]$IncludeScripts,
    [string]$OutputCsv = '.\WdacRiskDiscovery.csv',
    [int]$MaxFileSizeMB = 96,
    [int]$MinimumRiskScore = 20,
    [switch]$ExeOnly,
    [switch]$CatalogOnly,
    [switch]$DisableCriticalValidation
)

if ($IncludeWinSxS) {
    $ScanPaths += 'C:\Windows\WinSxS'
}

# -----------------------------------------------------------------------------
# Known dual-use / LOLBin catalog.
# Keep this catalog intentionally capability-focused. Presence is not malicious;
# it means the application deserves explicit WDAC consideration.
# -----------------------------------------------------------------------------
$KnownRisky = @{
    # Script / shell / interpreter hosts
    'powershell.exe' = @{ Category='ScriptHost'; Risk=90; Technique='PowerShell script and .NET execution host' }
    'pwsh.exe'       = @{ Category='ScriptHost'; Risk=90; Technique='PowerShell Core script and .NET execution host' }
    'cmd.exe'        = @{ Category='Shell'; Risk=65; Technique='Windows command shell' }
    'wscript.exe'    = @{ Category='ScriptHost'; Risk=85; Technique='Windows Script Host GUI interpreter' }
    'cscript.exe'    = @{ Category='ScriptHost'; Risk=85; Technique='Windows Script Host console interpreter' }
    'mshta.exe'      = @{ Category='ScriptHost'; Risk=95; Technique='HTML Application / script execution host' }
    'hh.exe'         = @{ Category='ScriptHost'; Risk=80; Technique='HTML Help executable with script/proxy-execution potential' }
    'wmic.exe'       = @{ Category='Management'; Risk=80; Technique='WMI command execution / process creation utility' }

    # Compilers / dynamic code
    'msbuild.exe'    = @{ Category='Compiler'; Risk=95; Technique='MSBuild inline task compilation/execution' }
    'csc.exe'        = @{ Category='Compiler'; Risk=90; Technique='C# compiler' }
    'vbc.exe'        = @{ Category='Compiler'; Risk=90; Technique='Visual Basic compiler' }
    'jsc.exe'        = @{ Category='Compiler'; Risk=90; Technique='JScript.NET compiler' }
    'ilasm.exe'      = @{ Category='Compiler'; Risk=85; Technique='Microsoft IL assembler' }
    'csi.exe'        = @{ Category='ScriptHost'; Risk=95; Technique='C# interactive scripting host' }
    'fsi.exe'        = @{ Category='ScriptHost'; Risk=95; Technique='F# interactive scripting host' }
    'fsianycpu.exe'  = @{ Category='ScriptHost'; Risk=95; Technique='F# interactive scripting host' }
    'dotnet.exe'     = @{ Category='RuntimeHost'; Risk=85; Technique='.NET host can execute arbitrary managed assemblies/tools' }
    'aspnet_compiler.exe' = @{ Category='Compiler'; Risk=85; Technique='ASP.NET compilation utility' }
    'microsoft.workflow.compiler.exe' = @{ Category='Compiler'; Risk=90; Technique='Workflow/XOML compilation utility' }

    # Trusted loaders / registration / proxy execution
    'installutil.exe' = @{ Category='ProxyExecution'; Risk=95; Technique='Installer class execution' }
    'regasm.exe'      = @{ Category='ProxyExecution'; Risk=90; Technique='COM registration hook execution' }
    'regsvcs.exe'     = @{ Category='ProxyExecution'; Risk=90; Technique='EnterpriseServices registration hook execution' }
    'rundll32.exe'    = @{ Category='ProxyExecution'; Risk=95; Technique='DLL export / control panel proxy execution' }
    'regsvr32.exe'    = @{ Category='ProxyExecution'; Risk=95; Technique='DLL registration / scriptlet proxy execution' }
    'control.exe'     = @{ Category='ProxyExecution'; Risk=75; Technique='Control Panel applet launcher' }
    'forfiles.exe'    = @{ Category='ProxyExecution'; Risk=70; Technique='Can spawn commands for matched files' }
    'pcalua.exe'      = @{ Category='ProxyExecution'; Risk=70; Technique='Program Compatibility Assistant launcher' }
    'explorer.exe'    = @{ Category='Shell'; Risk=45; Technique='Shell process capable of opening handlers/content' }
    'addinprocess.exe'   = @{ Category='ProxyExecution'; Risk=85; Technique='Managed add-in host' }
    'addinprocess32.exe' = @{ Category='ProxyExecution'; Risk=85; Technique='Managed add-in host (32-bit)' }

    # Download / transfer / remote content
    'certutil.exe'    = @{ Category='Download'; Risk=90; Technique='Certificate utility with URL retrieval/encoding features' }
    'bitsadmin.exe'   = @{ Category='Download'; Risk=90; Technique='BITS job administration / transfer utility' }
    'curl.exe'        = @{ Category='Download'; Risk=80; Technique='Command-line URL transfer utility' }
    'desktopimgdownldr.exe' = @{ Category='Download'; Risk=80; Technique='Desktop image downloader' }
    'esentutl.exe'    = @{ Category='FileTransfer'; Risk=70; Technique='Database utility with copy/recovery primitives' }
    'expand.exe'      = @{ Category='Archive'; Risk=55; Technique='CAB extraction utility' }
    'extrac32.exe'    = @{ Category='Archive'; Risk=55; Technique='CAB extraction utility' }

    # Installation / package engines
    'msiexec.exe'     = @{ Category='Installer'; Risk=85; Technique='Windows Installer package execution' }
    'winget.exe'      = @{ Category='Installer'; Risk=70; Technique='Windows Package Manager' }
    'appinstaller.exe'= @{ Category='Installer'; Risk=70; Technique='App Installer package handler' }
    'setup.exe'       = @{ Category='Installer'; Risk=45; Technique='Generic installer name; requires contextual review' }

    # Debug / dump / process manipulation
    'procdump.exe'    = @{ Category='ProcessDump'; Risk=90; Technique='Process dump utility' }
    'procdump64.exe'  = @{ Category='ProcessDump'; Risk=90; Technique='Process dump utility' }
    'createdump.exe'  = @{ Category='ProcessDump'; Risk=80; Technique='.NET process dump utility' }
    'vsjitdebugger.exe' = @{ Category='Debugger'; Risk=70; Technique='Visual Studio JIT debugger' }
    'ntsd.exe'        = @{ Category='Debugger'; Risk=80; Technique='Windows debugger' }
    'cdb.exe'         = @{ Category='Debugger'; Risk=80; Technique='Windows console debugger' }
    'windbg.exe'      = @{ Category='Debugger'; Risk=75; Technique='Windows debugger' }
    'tttracer.exe'    = @{ Category='Debugger'; Risk=80; Technique='Time Travel Debugging tracer' }

    # Office / developer / database utilities often worth WDAC review
    'devenv.exe'      = @{ Category='DeveloperTool'; Risk=55; Technique='Visual Studio IDE / extension and tool host' }
    'vswhere.exe'     = @{ Category='Discovery'; Risk=25; Technique='Visual Studio discovery utility' }
    'sqlcmd.exe'      = @{ Category='RemoteAdmin'; Risk=50; Technique='SQL command-line client' }
    'sqlps.exe'       = @{ Category='ScriptHost'; Risk=70; Technique='SQL Server PowerShell host' }
}

# -----------------------------------------------------------------------------
# Capability fingerprints. These apply to both managed and native PE files.
# Weight is deliberately modest for single generic strings; combinations raise
# the score materially.
# -----------------------------------------------------------------------------
$CapabilityRules = @(
    @{ Name='ManagedCompilation'; Weight=45; Patterns=@('CSharpCodeProvider','VBCodeProvider','CodeDomProvider','CompileAssemblyFromSource','CSharpCompilation','VisualBasicCompilation','RoslynCodeTaskFactory','CodeTaskFactory','Microsoft.CodeAnalysis') },
    @{ Name='DynamicIL'; Weight=40; Patterns=@('System.Reflection.Emit','AssemblyBuilder','ModuleBuilder','TypeBuilder','DynamicMethod','ILGenerator') },
    @{ Name='PowerShellHosting'; Weight=45; Patterns=@('System.Management.Automation','RunspaceFactory','InitialSessionState','PowerShell.Create') },
    @{ Name='ScriptEngineHosting'; Weight=40; Patterns=@('IActiveScript','MSScriptControl','Microsoft.Scripting','IronPython','FsiEvaluationSession','JScript') },
    @{ Name='AssemblyLoading'; Weight=30; Patterns=@('Assembly.Load','LoadFrom','LoadFile','UnsafeLoadFrom','AssemblyLoadContext','AssemblyDependencyResolver','ExecuteAssembly','CreateInstanceFromAndUnwrap') },
    @{ Name='PluginLoading'; Weight=25; Patterns=@('CompositionContainer','DirectoryCatalog','System.ComponentModel.Composition','LoadLibrary','LoadLibraryEx','GetProcAddress') },
    @{ Name='ChildProcess'; Weight=25; Patterns=@('CreateProcess','CreateProcessW','CreateProcessA','ShellExecute','ShellExecuteEx','Process.Start','System.Diagnostics.Process') },
    @{ Name='CommandShell'; Weight=25; Patterns=@('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe') },
    @{ Name='NetworkRetrieval'; Weight=30; Patterns=@('URLDownloadToFile','WinHttpOpen','WinHttpConnect','InternetOpen','InternetOpenUrl','HttpClient','WebClient','DownloadString','DownloadFile','Invoke-WebRequest') },
    @{ Name='RemoteProtocol'; Weight=25; Patterns=@('http://','https://','ftp://','\\\\','WebSocket','NamedPipeClientStream') },
    @{ Name='InstallerExecution'; Weight=30; Patterns=@('MsiInstallProduct','msiexec.exe','InstallHelper','ManagedInstallerClass','RunInstallerAttribute') },
    @{ Name='ComRegistration'; Weight=35; Patterns=@('ComRegisterFunctionAttribute','ComUnregisterFunctionAttribute','RegistrationServices','RegisterAssembly','UnregisterAssembly') },
    @{ Name='CredentialOrDumpAccess'; Weight=40; Patterns=@('MiniDumpWriteDump','DbgHelp','ReadProcessMemory','OpenProcessToken','LsaOpenPolicy','CredEnumerate','MiniDump') },
    @{ Name='ProcessInjectionPrimitives'; Weight=45; Patterns=@('VirtualAllocEx','WriteProcessMemory','CreateRemoteThread','NtCreateThreadEx','QueueUserAPC','SetThreadContext','MapViewOfFile') },
    @{ Name='AMSIOrETWInteraction'; Weight=30; Patterns=@('AmsiScanBuffer','AmsiInitialize','EtwEventWrite','EventWrite','amsi.dll') },
    @{ Name='ArchiveExtraction'; Weight=18; Patterns=@('cabinet.dll','Expand-Archive','System.IO.Compression','ZipFile','ExtractToDirectory') },
    @{ Name='TaskOrServiceCreation'; Weight=25; Patterns=@('CreateService','OpenSCManager','schtasks.exe','TaskScheduler','RegisterTaskDefinition') },
    @{ Name='WMIExecution'; Weight=25; Patterns=@('Win32_Process','ManagementClass','ManagementObjectSearcher','IWbemServices','wmic.exe') }
)

$ManagedFingerprints = @(
    'GenerateInMemory','CSharpCodeProvider','VBCodeProvider','JScriptCodeProvider',
    'CompilerParameters','CompileAssemblyFromSource','CompileAssemblyFromFile',
    'Microsoft.CodeAnalysis','CSharpCompilation','VisualBasicCompilation',
    'System.Reflection.Emit','AssemblyBuilder','DynamicMethod','ILGenerator',
    'System.Management.Automation','RunspaceFactory','AssemblyLoadContext',
    'ManagedInstallerClass','InstallHelper','RegistrationServices',
    'ComRegisterFunctionAttribute','ComUnregisterFunctionAttribute'
)

function Test-IsPeFile {
    param([string]$Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        try {
            if ($fs.Length -lt 2) { return $false }
            return ($fs.ReadByte() -eq 0x4D -and $fs.ReadByte() -eq 0x5A)
        } finally { $fs.Dispose() }
    } catch { return $false }
}

function Test-IsManagedAssembly {
    param([string]$Path)
    $stream=$null; $reader=$null
    try {
        $stream=[IO.File]::OpenRead($Path); $reader=[IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 0x100) { return $false }
        if ($reader.ReadUInt16() -ne 0x5A4D) { return $false }
        $stream.Seek(0x3C,[IO.SeekOrigin]::Begin)|Out-Null
        $peOffset=$reader.ReadUInt32()
        if ($peOffset -eq 0 -or $peOffset+0x100 -gt $stream.Length) { return $false }
        $stream.Seek($peOffset,[IO.SeekOrigin]::Begin)|Out-Null
        if ($reader.ReadUInt32() -ne 0x00004550) { return $false }
        $optional=$peOffset+24
        $stream.Seek($optional,[IO.SeekOrigin]::Begin)|Out-Null
        $magic=$reader.ReadUInt16()
        $dd=if($magic -eq 0x20B){$optional+112}else{$optional+96}
        $clr=$dd+(14*8)
        if ($clr+8 -gt $stream.Length) { return $false }
        $stream.Seek($clr,[IO.SeekOrigin]::Begin)|Out-Null
        return (($reader.ReadUInt32() -ne 0) -and ($reader.ReadUInt32() -ne 0))
    } catch { return $false }
    finally { if($reader){$reader.Dispose()}; if($stream){$stream.Dispose()} }
}

function Get-FileTextView {
    param([string]$Path)
    try {
        $bytes=[IO.File]::ReadAllBytes($Path)
        # ASCII catches PE import/metadata strings; Unicode catches many Win32 strings.
        $ascii=[Text.Encoding]::ASCII.GetString($bytes)
        $unicode=[Text.Encoding]::Unicode.GetString($bytes)
        return $ascii + "`n" + $unicode
    } catch { return '' }
}

function Get-SignatureInfo {
    param([string]$Path)
    try {
        $s=Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        [pscustomobject]@{
            Status=[string]$s.Status
            Signer=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}
            Issuer=if($s.SignerCertificate){$s.SignerCertificate.Issuer}else{''}
        }
    } catch {
        [pscustomobject]@{Status='Unknown';Signer='';Issuer=''}
    }
}

function Get-VersionInfoSafe {
    param([string]$Path)
    try {
        $v=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        [pscustomobject]@{
            Company=$v.CompanyName
            Product=$v.ProductName
            Description=$v.FileDescription
            OriginalName=$v.OriginalFilename
            Version=$v.FileVersion
        }
    } catch {
        [pscustomobject]@{Company='';Product='';Description='';OriginalName='';Version=''}
    }
}

function Test-UserWritableLocation {
    param([string]$Path)
    $p=$Path.ToLowerInvariant()
    return (
        $p -like "$($env:USERPROFILE.ToLowerInvariant())*" -or
        $p -like '*\\users\\public\\*' -or
        $p -like '*\\programdata\\*' -or
        $p -like '*\\windows\\temp\\*' -or
        $p -like '*\\temp\\*' -or
        $p -like '*\\downloads\\*' -or
        $p -like '*\\appdata\\*'
    )
}

function Get-CapabilityAnalysis {
    param([string]$Text)
    $hits=[Collections.Generic.List[string]]::new()
    $patterns=[Collections.Generic.List[string]]::new()
    $score=0

    foreach($rule in $CapabilityRules){
        $ruleHit=$false
        foreach($pattern in $rule.Patterns){
            if($Text.IndexOf($pattern,[StringComparison]::OrdinalIgnoreCase) -ge 0){
                $patterns.Add("$($rule.Name):$pattern")
                $ruleHit=$true
            }
        }
        if($ruleHit){
            $hits.Add($rule.Name)
            $score += [int]$rule.Weight
        }
    }

    # Synergy matters more than one generic API string.
    if($hits.Contains('NetworkRetrieval') -and $hits.Contains('ChildProcess')) { $score += 20 }
    if($hits.Contains('AssemblyLoading') -and $hits.Contains('NetworkRetrieval')) { $score += 20 }
    if($hits.Contains('CommandShell') -and $hits.Contains('ChildProcess')) { $score += 15 }
    if($hits.Contains('ProcessInjectionPrimitives')) { $score += 20 }
    if($hits.Contains('ManagedCompilation') -and $hits.Contains('AssemblyLoading')) { $score += 20 }

    [pscustomobject]@{Capabilities=$hits; Patterns=$patterns; Score=$score}
}

function Get-RiskLevel {
    param([int]$Score)
    if($Score -ge 100){'Critical'}
    elseif($Score -ge 75){'High'}
    elseif($Score -ge 45){'Medium'}
    elseif($Score -ge 20){'Low'}
    else{'Informational'}
}



function Get-SafeFileComponent {
    param([string]$Value)
    if([string]::IsNullOrWhiteSpace($Value)){ return 'unknown' }
    $safe = $Value -replace '[^A-Za-z0-9._-]','_'
    if($safe.Length -gt 80){ $safe = $safe.Substring(0,80) }
    return $safe
}

function Get-StringHash8 {
    param([string]$Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes($Value)
        $hash=$sha.ComputeHash($bytes)
        return (([BitConverter]::ToString($hash)).Replace('-','').Substring(0,8))
    } finally { $sha.Dispose() }
}

function New-CriticalValidationHarness {
    param(
        [Parameter(Mandatory=$true)][IO.FileInfo]$FindingFile,
        [Parameter(Mandatory=$true)][string]$RootDirectory,
        [string]$Category,
        [string]$Technique,
        [string[]]$Capabilities
    )

    $name = Get-SafeFileComponent -Value $FindingFile.Name
    $id = Get-StringHash8 -Value $FindingFile.FullName
    $dir = Join-Path $RootDirectory ("{0}_{1}" -f $name,$id)
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $binary = $FindingFile.FullName
    $fileName = $FindingFile.Name.ToLowerInvariant()
    $validationCommand = ''
    $validationType = 'ManualInterfaceValidationRequired'
    $validationInterface = ''
    $expectedResult = ''
    $notes = 'No safe, deterministic callable interface is known for this finding. Review the matched indicators and application documentation before attempting validation.'
    $artifacts = [Collections.Generic.List[string]]::new()

    function Write-ValidationArtifact {
        param([string]$Name,[string]$Content,[string]$Encoding='UTF8')
        $path = Join-Path $dir $Name
        Set-Content -LiteralPath $path -Value $Content -Encoding $Encoding
        $artifacts.Add($path)
        return $path
    }

    # Generic source files are only helpers. A finding is not marked validated by
    # their presence; the command below must exercise the discovered application.
    $ps1 = Write-ValidationArtifact 'HelloWorld.ps1' 'Write-Host "Hello World - executed by discovered PowerShell host"'
    $vbs = Write-ValidationArtifact 'HelloWorld.vbs' 'WScript.Echo "Hello World - executed by discovered Windows Script Host"' 'ASCII'
    $cs = Write-ValidationArtifact 'HelloWorld.cs' @'
using System;
public static class HelloWorld
{
    public static void Main()
    {
        Console.WriteLine("Hello World - compiled by discovered compiler");
    }
}
'@

    switch($fileName){
        'powershell.exe' {
            $validationType='PowerShellHost'
            $validationInterface='PowerShell script-file execution (-File)'
            $validationCommand='& "{0}" -NoProfile -File "{1}"' -f $binary,$ps1
            $expectedResult='Console displays: Hello World - executed by discovered PowerShell host'
            $notes='Exercises the discovered powershell.exe as a script interpreter. No execution-policy bypass flag is used.'
        }
        'pwsh.exe' {
            $validationType='PowerShellHost'
            $validationInterface='PowerShell script-file execution (-File)'
            $validationCommand='& "{0}" -NoProfile -File "{1}"' -f $binary,$ps1
            $expectedResult='Console displays: Hello World - executed by discovered PowerShell host'
            $notes='Exercises the discovered pwsh.exe as a script interpreter.'
        }
        'wscript.exe' {
            $validationType='VBScriptHost'
            $validationInterface='Windows Script Host VBScript execution'
            $validationCommand='& "{0}" //nologo "{1}"' -f $binary,$vbs
            $expectedResult='A Windows Script Host message displays the Hello World text.'
            $notes='Exercises the discovered wscript.exe by interpreting the generated VBScript.'
        }
        'cscript.exe' {
            $validationType='VBScriptHost'
            $validationInterface='Windows Script Host console VBScript execution'
            $validationCommand='& "{0}" //nologo "{1}"' -f $binary,$vbs
            $expectedResult='Console displays: Hello World - executed by discovered Windows Script Host'
            $notes='Exercises the discovered cscript.exe by interpreting the generated VBScript.'
        }
        'csc.exe' {
            $validationType='CSharpCompiler'
            $validationInterface='C# source-to-PE compilation'
            $exe=Join-Path $dir 'HelloWorld.exe'
            $validationCommand='& "{0}" /nologo /out:"{1}" "{2}"; if($LASTEXITCODE -eq 0){{ & "{1}" }}' -f $binary,$exe,$cs
            $expectedResult='The discovered compiler creates HelloWorld.exe and that program prints its Hello World message.'
            $notes='Exercises the discovered csc.exe compiler directly against generated benign C# source.'
        }
        'vbc.exe' {
            $vb = Write-ValidationArtifact 'HelloWorld.vb' @'
Imports System
Public Module HelloWorld
    Public Sub Main()
        Console.WriteLine("Hello World - compiled by discovered VB compiler")
    End Sub
End Module
'@
            $validationType='VisualBasicCompiler'
            $validationInterface='Visual Basic source-to-PE compilation'
            $exe=Join-Path $dir 'HelloWorldVB.exe'
            $validationCommand='& "{0}" /nologo /out:"{1}" "{2}"; if($LASTEXITCODE -eq 0){{ & "{1}" }}' -f $binary,$exe,$vb
            $expectedResult='The discovered compiler creates HelloWorldVB.exe and the program prints its Hello World message.'
            $notes='Exercises the discovered vbc.exe compiler directly.'
        }
        'csi.exe' {
            $csx = Write-ValidationArtifact 'HelloWorld.csx' 'System.Console.WriteLine("Hello World - executed by discovered C# interactive host");'
            $validationType='CSharpInteractive'
            $validationInterface='C# script execution'
            $validationCommand='& "{0}" "{1}"' -f $binary,$csx
            $expectedResult='Console displays: Hello World - executed by discovered C# interactive host'
            $notes='Exercises the discovered csi.exe scripting interface.'
        }
        'dotnet.exe' {
            $projDir=Join-Path $dir 'DotNetHelloWorld'
            New-Item -ItemType Directory -Path $projDir -Force | Out-Null
            $proj=Join-Path $projDir 'DotNetHelloWorld.csproj'
            $program=Join-Path $projDir 'Program.cs'
            @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
'@ | Set-Content -LiteralPath $proj -Encoding UTF8
            'Console.WriteLine("Hello World - built and executed by discovered dotnet host");' | Set-Content -LiteralPath $program -Encoding UTF8
            $artifacts.Add($proj); $artifacts.Add($program)
            $validationType='DotNetRuntimeHost'
            $validationInterface='.NET SDK project build + managed application execution'
            $validationCommand='& "{0}" run --project "{1}" --nologo' -f $binary,$proj
            $expectedResult='The discovered dotnet host builds the project and prints its Hello World message.'
            $notes='Exercises the discovered dotnet.exe as the managed build/runtime host. Requires a compatible SDK to be installed beside/for that host.'
        }
        'msbuild.exe' {
            $proj = Write-ValidationArtifact 'HelloWorld.proj' @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <UsingTask TaskName="HelloWorldTask" TaskFactory="CodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <ParameterGroup />
    <Task>
      <Using Namespace="System" />
      <Code Type="Fragment" Language="cs"><![CDATA[
        Console.WriteLine("Hello World - executed by discovered MSBuild inline task interface");
      ]]></Code>
    </Task>
  </UsingTask>
  <Target Name="Hello">
    <HelloWorldTask />
  </Target>
</Project>
'@
            $validationType='MSBuildInlineTask'
            $validationInterface='MSBuild inline CodeTaskFactory task execution'
            $validationCommand='& "{0}" "{1}" /nologo /target:Hello' -f $binary,$proj
            $expectedResult='MSBuild invokes the inline task and prints the Hello World message.'
            $notes='Exercises the specific inline-task capability that makes MSBuild relevant to WDAC review. Compatibility depends on the MSBuild version and available task factory.'
        }
        'mshta.exe' {
            $hta = Write-ValidationArtifact 'HelloWorld.hta' @'
<html>
<head>
<title>WDAC Validation</title>
<hta:application id="wdacValidation" border="thin" caption="yes" showintaskbar="yes" />
<script language="VBScript">
Sub Window_OnLoad
  document.getElementById("message").innerText = "Hello World - rendered by discovered mshta.exe"
End Sub
</script>
</head>
<body><div id="message">Loading...</div></body>
</html>
'@
            $validationType='MshtaHost'
            $validationInterface='Local HTA application execution'
            $validationCommand='& "{0}" "{1}"' -f $binary,$hta
            $expectedResult='A local HTA window displays the Hello World validation message.'
            $notes='Exercises the discovered mshta.exe against a local benign HTA; it does not retrieve remote content.'
        }
        'rundll32.exe' {
            $dllsrc = Write-ValidationArtifact 'HelloWorldRundll32.cs' @'
using System;
using System.Runtime.InteropServices;
public static class NativeExports
{
    // Source retained as documentation for a benign DLL export validation build.
    // Build this as a native-export-capable DLL using your approved lab toolchain.
    public static void HelloWorld()
    {
        Console.WriteLine("Hello World - invoked through rundll32 DLL export interface");
    }
}
'@
            $validationType='Rundll32DllExport'
            $validationInterface='rundll32 DLL-export invocation'
            $validationCommand=''
            $expectedResult='When an approved benign DLL exposing a rundll32-compatible HelloWorld export is supplied, rundll32 invokes that export.'
            $notes='The scanner intentionally does not fabricate a native exported DLL because csc.exe alone does not create rundll32-compatible exports. README documents the exact interface defenders should validate with an approved lab-built DLL.'
        }
        'regsvr32.exe' {
            $validationType='Regsvr32DllRegistration'
            $validationInterface='DLL registration export invocation (DllRegisterServer)'
            $validationCommand=''
            $expectedResult='An approved benign COM DLL writes/displays a Hello World marker from DllRegisterServer when invoked by the discovered regsvr32.exe.'
            $notes='Requires an approved benign COM test DLL exporting DllRegisterServer. No remote scriptlet or network-based validation is generated.'
        }
        'installutil.exe' {
            $installer = Write-ValidationArtifact 'HelloWorldInstaller.cs' @'
using System;
using System.Collections;
using System.ComponentModel;
using System.Configuration.Install;

[RunInstaller(true)]
public sealed class HelloWorldInstaller : Installer
{
    public override void Install(IDictionary stateSaver)
    {
        Console.WriteLine("Hello World - invoked through discovered InstallUtil installer interface");
        base.Install(stateSaver);
    }
}

public static class Program
{
    public static void Main() { }
}
'@
            $validationType='InstallUtilInstallerClass'
            $validationInterface='System.Configuration.Install Installer class execution'
            $validationCommand=''
            $expectedResult='After compiling HelloWorldInstaller.cs with the matching .NET Framework compiler/reference set, the discovered InstallUtil.exe invokes the installer class and prints the marker.'
            $notes='Exercises the specific RunInstaller/Installer interface, but compilation is left explicit/manual because the correct framework references vary by host.'
        }
        'regasm.exe' {
            $regsrc = Write-ValidationArtifact 'HelloWorldRegAsm.cs' @'
using System;
using System.Runtime.InteropServices;

[ComVisible(true)]
public class HelloWorldCom
{
    [ComRegisterFunction]
    public static void Register(Type t)
    {
        Console.WriteLine("Hello World - invoked through discovered RegAsm registration hook");
    }
}
'@
            $validationType='RegAsmRegistrationHook'
            $validationInterface='ComRegisterFunction registration hook'
            $validationCommand=''
            $expectedResult='After compiling the source with a matching .NET Framework compiler, the discovered RegAsm.exe invokes the ComRegisterFunction hook.'
            $notes='Demonstrates the exact registration-hook interface. Compilation and registration are manual to avoid modifying registry state automatically.'
        }
        'regsvcs.exe' {
            $validationType='RegSvcsRegistrationHook'
            $validationInterface='EnterpriseServices registration hook'
            $validationCommand=''
            $expectedResult='An approved benign EnterpriseServices test assembly invokes its registration hook through the discovered RegSvcs.exe.'
            $notes='No automatic registration recipe is generated because validation can alter COM+/registry state. The README identifies the interface defenders should reproduce in an isolated lab.'
        }
        'certutil.exe' {
            $source = Write-ValidationArtifact 'HelloWorld.txt' 'Hello World - local certutil copy/encode capability validation'
            $encoded = Join-Path $dir 'HelloWorld.b64.txt'
            $validationType='CertUtilEncode'
            $validationInterface='certutil local encode operation'
            $validationCommand='& "{0}" -encode "{1}" "{2}"' -f $binary,$source,$encoded
            $expectedResult='The discovered certutil.exe creates a Base64-encoded copy of the benign local HelloWorld.txt file.'
            $notes='Uses certutil itself and demonstrates a dual-use file transformation interface without network retrieval.'
        }
        'curl.exe' {
            $validationType='CurlLocalFile'
            $validationInterface='curl URL/file retrieval interface'
            $source = Write-ValidationArtifact 'HelloWorldCurl.txt' 'Hello World - retrieved through discovered curl interface'
            $dest = Join-Path $dir 'CurlRetrieved.txt'
            $uri = ([Uri]$source).AbsoluteUri
            $validationCommand='& "{0}" --fail --silent --show-error --output "{1}" "{2}"; Get-Content -LiteralPath "{1}"' -f $binary,$dest,$uri
            $expectedResult='The discovered curl.exe retrieves the local file URI and the resulting file contains the Hello World marker.'
            $notes='Exercises curl URL retrieval without external network access.'
        }
        'expand.exe' {
            $validationType='ArchiveExtraction'
            $validationInterface='CAB archive extraction'
            $expectedResult='The discovered expand.exe extracts a benign Hello World file from an approved test CAB.'
            $notes='A CAB is not automatically generated because makecab.exe may not be present. Use an approved benign CAB containing only HelloWorld.txt.'
        }
        default {
            if($Category -eq 'Compiler' -and $fileName -like '*csc*.exe'){
                $validationType='CSharpCompiler'
                $validationInterface='C# source-to-PE compilation'
                $exe=Join-Path $dir 'HelloWorld.exe'
                $validationCommand='& "{0}" /nologo /out:"{1}" "{2}"; if($LASTEXITCODE -eq 0){{ & "{1}" }}' -f $binary,$exe,$cs
                $expectedResult='The discovered compiler creates and runs the benign Hello World program.'
                $notes='Exercises the discovered compiler directly.'
            }
            elseif($Capabilities -contains 'PowerShellHosting'){
                $validationType='EmbeddedPowerShellHostManual'
                $validationInterface='Embedded System.Management.Automation / runspace hosting'
                $expectedResult='Application-specific invocation should cause the product to execute a benign PowerShell command that returns Hello World.'
                $notes='The risky interface is embedded PowerShell hosting, but the scanner cannot infer the product-specific entry point from raw strings alone. Manual validation is required.'
            }
            elseif($Capabilities -contains 'ManagedCompilation'){
                $validationType='EmbeddedCompilerManual'
                $validationInterface='Embedded CodeDom/Roslyn compilation'
                $expectedResult='Application-specific invocation should compile and execute/produce a benign Hello World program through its embedded compiler interface.'
                $notes='ManagedCompilation was detected, but a safe product-specific caller cannot be inferred automatically.'
            }
            elseif($Capabilities -contains 'PluginLoading' -or $Capabilities -contains 'AssemblyLoading'){
                # Capability PoC: compile a benign plugin DLL and a separate loader that
                # dynamically loads it with Assembly.LoadFrom. This demonstrates the
                # exact dynamic plugin/assembly-loading primitive detected by the scan.
                $plugin = Write-ValidationArtifact 'BenignPlugin.cs' @'
using System;
public static class BenignPlugin
{
    public static string Run()
    {
        return "Hello World - dynamically loaded plugin executed";
    }
}
'@
                $loader = Write-ValidationArtifact 'PluginLoaderPoC.cs' @'
using System;
using System.IO;
using System.Reflection;

public static class PluginLoaderPoC
{
    public static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: PluginLoaderPoC.exe <plugin.dll>");
            return 2;
        }

        string pluginPath = Path.GetFullPath(args[0]);
        Assembly assembly = Assembly.LoadFrom(pluginPath);
        Type type = assembly.GetType("BenignPlugin", throwOnError: true);
        MethodInfo method = type.GetMethod("Run", BindingFlags.Public | BindingFlags.Static);
        object result = method.Invoke(null, null);
        Console.WriteLine(result);
        return 0;
    }
}
'@
                $runner = Write-ValidationArtifact 'Run-PluginLoadingPoC.ps1' @'
param(
    [string]$CscPath
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $CscPath) {
    $CscPath = (Get-Command csc.exe -ErrorAction SilentlyContinue).Source
}
if (-not $CscPath) { throw 'csc.exe was not found. Supply -CscPath pointing to an approved C# compiler.' }
& $CscPath /nologo /target:library /out:"$here\BenignPlugin.dll" "$here\BenignPlugin.cs"
if ($LASTEXITCODE -ne 0) { throw 'Plugin compilation failed.' }
& $CscPath /nologo /out:"$here\PluginLoaderPoC.exe" "$here\PluginLoaderPoC.cs"
if ($LASTEXITCODE -ne 0) { throw 'Loader compilation failed.' }
& "$here\PluginLoaderPoC.exe" "$here\BenignPlugin.dll"
'@
                $validationType='PluginLoadingCapabilityPoC'
                $validationInterface='Dynamic managed assembly/plugin loading via Assembly.LoadFrom + reflection'
                $validationCommand='& "{0}"' -f $runner
                $expectedResult='The PoC loader dynamically loads BenignPlugin.dll, resolves BenignPlugin.Run by reflection, invokes it, and prints: Hello World - dynamically loaded plugin executed.'
                $notes='This reproduces the exact loader primitive detected in the finding. Because string analysis cannot infer an unknown product-specific entry point, the discovered binary is not claimed to be invoked unless a catalog-specific handler exists. Use this PoC to show defenders what the detected dynamic loading interface permits.'
            }
            elseif($Capabilities -contains 'RemoteProtocol'){
                $remote = Write-ValidationArtifact 'RemoteProtocolPoC.ps1' @'
$ErrorActionPreference = 'Stop'
$port = 8765
$prefix = "http://127.0.0.1:$port/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
$listener.Start()
try {
    $job = Start-Job -ScriptBlock {
        param($Uri)
        Start-Sleep -Milliseconds 250
        $client = [System.Net.WebClient]::new()
        try { $client.DownloadString($Uri) } finally { $client.Dispose() }
    } -ArgumentList $prefix

    $ctx = $listener.GetContext()
    $bytes = [Text.Encoding]::UTF8.GetBytes('Hello World - transferred over localhost HTTP capability PoC')
    $ctx.Response.ContentLength64 = $bytes.Length
    $ctx.Response.OutputStream.Write($bytes,0,$bytes.Length)
    $ctx.Response.OutputStream.Close()
    Receive-Job $job -Wait -AutoRemoveJob
}
finally {
    $listener.Stop()
    $listener.Close()
}
'@
                $validationType='RemoteProtocolCapabilityPoC'
                $validationInterface='Localhost HTTP client/server protocol exchange'
                $validationCommand='& "{0}"' -f $remote
                $expectedResult='A loopback-only HTTP request transfers and prints the Hello World marker, demonstrating a real remote-protocol interface without contacting an external host.'
                $notes='This independently reproduces the RemoteProtocol primitive using localhost only. It does not assert that an unknown application exposes a callable URL option; determining that product-specific path requires documentation or deeper code analysis.'
            }
            elseif($Capabilities -contains 'AMSIOrETWInteraction'){
                $amsi = Write-ValidationArtifact 'AmsiEtwCapabilityPoC.ps1' @'
$ErrorActionPreference = 'Stop'
$src = @"
using System;
using System.Diagnostics.Tracing;
using System.Runtime.InteropServices;

public static class AmsiEtwCapabilityPoC
{
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    static extern int AmsiInitialize(string appName, out IntPtr context);
    [DllImport("amsi.dll")]
    static extern void AmsiUninitialize(IntPtr context);
    [DllImport("amsi.dll", CharSet=CharSet.Unicode)]
    static extern int AmsiScanString(IntPtr context, string value, string contentName, IntPtr session, out int result);

    sealed class ValidationEventSource : EventSource
    {
        public static readonly ValidationEventSource Log = new ValidationEventSource();
        [Event(1, Level=EventLevel.Informational)]
        public void Validation(string message) { WriteEvent(1, message); }
    }

    public static void Run()
    {
        IntPtr ctx;
        int hr = AmsiInitialize("WDAC-Validation-PoC", out ctx);
        if (hr != 0) throw new InvalidOperationException("AmsiInitialize failed: 0x" + hr.ToString("X8"));
        try
        {
            int result;
            hr = AmsiScanString(ctx, "Hello World", "WDAC benign validation", IntPtr.Zero, out result);
            if (hr != 0) throw new InvalidOperationException("AmsiScanString failed: 0x" + hr.ToString("X8"));
            Console.WriteLine("AMSI scanned benign content; AMSI_RESULT=" + result);
            ValidationEventSource.Log.Validation("Hello World - ETW/EventSource validation event");
            Console.WriteLine("Hello World - AMSI and ETW interfaces invoked");
        }
        finally { AmsiUninitialize(ctx); }
    }
}
"@
Add-Type -TypeDefinition $src -Language CSharp
[AmsiEtwCapabilityPoC]::Run()
'@
                $validationType='AMSIOrETWCapabilityPoC'
                $validationInterface='AMSI initialization/scanning plus ETW EventSource emission'
                $validationCommand='& "{0}"' -f $amsi
                $expectedResult='The PoC submits the benign string Hello World through AMSI, reports the AMSI result code, emits an informational ETW/EventSource event, and confirms both interfaces were invoked.'
                $notes='This calls AMSI and ETW-related interfaces in their normal defensive direction. It does not disable, patch, bypass, or tamper with AMSI/ETW.'
            }
            elseif($Capabilities -contains 'WMIExecution'){
                $wmi = Write-ValidationArtifact 'WMIExecutionPoC.ps1' @'
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$marker = Join-Path $here 'WMI-HelloWorld.txt'
if (Test-Path $marker) { Remove-Item -LiteralPath $marker -Force }

# Exercise the same WMI process-creation surface commonly represented by
# Win32_Process.Create. The child process performs only a local file write.
$escaped = $marker.Replace('"','""')
$command = 'cmd.exe /d /c echo Hello World - created through Win32_Process.Create>"' + $escaped + '"'

if (Get-Command Invoke-CimMethod -ErrorAction SilentlyContinue) {
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $command }
    if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue)" }
} else {
    $proc = [wmiclass]'Win32_Process'
    $r = $proc.Create($command)
    if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue)" }
}

$deadline = (Get-Date).AddSeconds(5)
do {
    Start-Sleep -Milliseconds 100
} until ((Test-Path $marker) -or ((Get-Date) -gt $deadline))
if (-not (Test-Path $marker)) { throw 'Marker file was not created.' }
Get-Content -LiteralPath $marker
'@
                $validationType='WMIExecutionCapabilityPoC'
                $validationInterface='WMI/CIM Win32_Process.Create child-process execution'
                $validationCommand='& "{0}"' -f $wmi
                $expectedResult='Win32_Process.Create launches cmd.exe locally, which writes a Hello World marker file in the harness directory; the script reads the marker back.'
                $notes='This is a local, benign demonstration of the WMI process-creation capability. It does not use remote WMI, credentials, persistence, or elevated commands.'
            }
            elseif($Capabilities -contains 'ChildProcess'){
                $validationType='ChildProcessManual'
                $validationInterface='Child-process creation'
                $expectedResult='Application-specific functionality should start an approved benign HelloWorld executable and return its marker.'
                $notes='The process-creation primitive was detected, but no product-specific invocation path is inferred from strings alone.'
            }
            elseif($Capabilities -contains 'NetworkRetrieval'){
                $validationType='NetworkRetrievalManual'
                $validationInterface='Network/URL retrieval'
                $expectedResult='Application-specific functionality should retrieve a benign Hello World file from an isolated/local test endpoint.'
                $notes='No external network recipe is generated automatically. Validate only against a controlled local endpoint.'
            }
        }
    }

    $readme = Join-Path $dir 'README.txt'
    @(
        'WDAC Critical Finding - Capability-Specific Validation Harness',
        '=============================================================',
        '',
        "Finding: $($FindingFile.FullName)",
        "Category: $Category",
        "Technique: $Technique",
        "Capabilities: $($Capabilities -join ', ')",
        "Validation type: $validationType",
        "Risky interface demonstrated: $validationInterface",
        '',
        'Why this is different from a generic Hello World:',
        '  The proof is only considered meaningful when the discovered application,',
        '  DLL interface, interpreter, compiler, loader, or other risky surface is',
        '  actually involved in producing the benign Hello World result.',
        '',
        'Expected result:',
        "  $expectedResult",
        '',
        'Suggested validation command:',
        $(if($validationCommand){"  $validationCommand"}else{'  No automatic command generated. Follow the interface-specific notes below.'}),
        '',
        'Notes:',
        "  $notes",
        '',
        'Safety / interpretation:',
        '  - Nothing in this directory is executed automatically.',
        '  - Generated tests are local and benign; protocol tests use loopback only.',
        '  - A successful test confirms the specific callable capability, not maliciousness.',
        '  - A failed test does not automatically clear the finding; versions and invocation requirements differ.',
        '  - For state-changing interfaces (registration, COM+, services, etc.), validation is intentionally manual.',
        '',
        'Generated artifacts:'
    ) + @($artifacts | ForEach-Object { "  $_" }) | Set-Content -LiteralPath $readme -Encoding UTF8

    [pscustomobject]@{
        Directory=$dir
        ValidationType=$validationType
        ValidationInterface=$validationInterface
        ValidationCommand=$validationCommand
        ValidationExpectedResult=$expectedResult
        Readme=$readme
    }
}

function Get-WdacRecommendation {
    param(
        [bool]$CatalogHit,
        [int]$Score,
        [string]$SigStatus,
        [bool]$Writable,
        [string[]]$Capabilities
    )

    if($CatalogHit -and $Score -ge 85){ return 'Explicitly evaluate for deny/exception rule; validate operational dependency first' }
    if($Writable -and $SigStatus -ne 'Valid' -and $Score -ge 60){ return 'Strong deny candidate; unsigned risky executable in writable location' }
    if($Score -ge 100){ return 'High-priority WDAC review; consider explicit deny unless business-required' }
    if($Score -ge 75){ return 'Review for signer/file-name scoped deny or managed-installer restrictions' }
    if($Score -ge 45){ return 'Inventory and validate business need; tighten publisher/path trust where practical' }
    return 'Monitor/inventory; weak standalone signal'
}

$extensions=@('*.exe','*.dll')
if($ExeOnly){$extensions=@('*.exe')}
if($IncludeScripts -and -not $ExeOnly){$extensions += @('*.ps1','*.cmd','*.bat','*.vbs','*.js','*.jse','*.wsf')}

$maxBytes=$MaxFileSizeMB*1MB
$results=[Collections.Generic.List[object]]::new()

if(Test-Path $OutputCsv){Remove-Item -LiteralPath $OutputCsv -Force}

$validationRoot = ''
if(-not $DisableCriticalValidation){
    $outFull=[IO.Path]::GetFullPath($OutputCsv)
    $outDir=Split-Path -Parent $outFull
    $outStem=[IO.Path]::GetFileNameWithoutExtension($outFull)
    $validationRoot=Join-Path $outDir ($outStem + '-CriticalValidation')
}

Write-Host 'Enumerating files...' -ForegroundColor Cyan
$candidates = foreach($root in ($ScanPaths | Select-Object -Unique)){
    if(Test-Path $root){
        Get-ChildItem -LiteralPath $root -Recurse -File -Include $extensions -ErrorAction SilentlyContinue
    } else { Write-Warning "Path not found: $root" }
}

$candidates=$candidates | Sort-Object FullName -Unique
$total=($candidates|Measure-Object).Count
Write-Host "Found $total candidate files." -ForegroundColor Cyan

$i=0
foreach($file in $candidates){
    $i++
    if(($i % 200) -eq 0){
        Write-Progress -Activity 'WDAC risky application discovery' -Status $file.FullName -PercentComplete (($i/[math]::Max($total,1))*100)
    }

    $catalog=$KnownRisky[$file.Name.ToLowerInvariant()]
    if($CatalogOnly -and -not $catalog){continue}

    $isPe=Test-IsPeFile -Path $file.FullName
    $isManaged=if($isPe){Test-IsManagedAssembly -Path $file.FullName}else{$false}
    $canScan=($file.Length -le $maxBytes)

    $text=''
    $cap=[pscustomobject]@{Capabilities=@();Patterns=@();Score=0}
    if(-not $CatalogOnly -and $canScan){
        $text=Get-FileTextView -Path $file.FullName
        $cap=Get-CapabilityAnalysis -Text $text
    }

    # Additional managed-only confirmation strings.
    $managedHits=@()
    if($isManaged -and $text){
        $managedHits=@($ManagedFingerprints | Where-Object { $text.IndexOf($_,[StringComparison]::OrdinalIgnoreCase) -ge 0 })
    }

    $sig=if($isPe){Get-SignatureInfo -Path $file.FullName}else{[pscustomobject]@{Status='NotApplicable';Signer='';Issuer=''}}
    $ver=if($isPe){Get-VersionInfoSafe -Path $file.FullName}else{[pscustomobject]@{Company='';Product='';Description='';OriginalName='';Version=''}}
    $writable=Test-UserWritableLocation -Path $file.FullName

    $score=[int]$cap.Score
    if($catalog){ $score=[math]::Max($score,[int]$catalog.Risk) }
    if($writable){ $score += 15 }
    if($isPe -and $sig.Status -ne 'Valid'){ $score += 15 }
    if($isPe -and [string]::IsNullOrWhiteSpace($ver.Company)){ $score += 5 }
    if($managedHits.Count -ge 2){ $score += 10 }

    # Common enterprise trust reductions: do not erase dangerous capabilities,
    # just reduce low-signal noise from signed system binaries.
    $isMicrosoft=($sig.Signer -match 'Microsoft') -or ($ver.Company -match 'Microsoft')
    if($isMicrosoft -and -not $catalog -and $score -lt 75){ $score=[math]::Max(0,$score-10) }

    if(-not $catalog -and $score -lt $MinimumRiskScore){continue}

    $level=Get-RiskLevel -Score $score
    $recommendation=Get-WdacRecommendation -CatalogHit:([bool]$catalog) -Score $score -SigStatus $sig.Status -Writable:$writable -Capabilities @($cap.Capabilities)

    $validation=[pscustomobject]@{Directory='';ValidationType='';ValidationInterface='';ValidationCommand='';ValidationExpectedResult='';Readme=''}
    if($level -eq 'Critical' -and -not $DisableCriticalValidation){
        try {
            if(-not (Test-Path $validationRoot)){ New-Item -ItemType Directory -Path $validationRoot -Force | Out-Null }
            $validation=New-CriticalValidationHarness -FindingFile $file -RootDirectory $validationRoot -Category $(if($catalog){$catalog.Category}else{''}) -Technique $(if($catalog){$catalog.Technique}else{''}) -Capabilities @($cap.Capabilities)
        } catch {
            Write-Warning "Failed to create validation harness for $($file.FullName): $($_.Exception.Message)"
        }
    }

    $row=[pscustomobject]@{
        RiskScore=$score
        RiskLevel=$level
        Path=$file.FullName
        FileName=$file.Name
        Extension=$file.Extension
        SizeKB=[math]::Round($file.Length/1KB,1)
        IsPE=$isPe
        IsManaged=$isManaged
        UserWritableLocation=$writable
        CatalogMatch=[bool]$catalog
        CatalogCategory=if($catalog){$catalog.Category}else{''}
        CatalogTechnique=if($catalog){$catalog.Technique}else{''}
        SignatureStatus=$sig.Status
        Signer=$sig.Signer
        Company=$ver.Company
        Product=$ver.Product
        Description=$ver.Description
        OriginalFileName=$ver.OriginalName
        FileVersion=$ver.Version
        Capabilities=(ConvertTo-Json @($cap.Capabilities) -Compress)
        MatchedIndicators=(ConvertTo-Json @($cap.Patterns) -Compress)
        ManagedIndicators=(ConvertTo-Json @($managedHits) -Compress)
        ValidationDirectory=$validation.Directory
        ValidationType=$validation.ValidationType
        ValidationInterface=$validation.ValidationInterface
        ValidationCommand=$validation.ValidationCommand
        ValidationExpectedResult=$validation.ValidationExpectedResult
        ValidationReadme=$validation.Readme
        WdacRecommendation=$recommendation
    }

    $results.Add($row)
    try{$row|Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Append -Encoding UTF8}catch{}
}
Write-Progress -Activity 'WDAC risky application discovery' -Completed

$results |
    Sort-Object @{Expression='RiskScore';Descending=$true}, @{Expression='CatalogMatch';Descending=$true}, Path |
    Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "`nScan complete: $($results.Count) findings" -ForegroundColor Green
Write-Host "Report: $((Resolve-Path $OutputCsv).Path)" -ForegroundColor Green

$results |
    Sort-Object RiskScore -Descending |
    Select-Object -First 50 RiskScore,RiskLevel,FileName,CatalogCategory,SignatureStatus,Company,Capabilities,Path |
    Format-Table -AutoSize -Wrap

Write-Host "`nRisk-level counts:" -ForegroundColor Cyan
$results | Group-Object RiskLevel | Sort-Object Count -Descending | Select-Object Name,Count | Format-Table -AutoSize

if(-not $DisableCriticalValidation -and (Test-Path $validationRoot)){
    Write-Host "Critical validation harnesses: $validationRoot" -ForegroundColor Green
}

Write-Host "`nSuggested workflow: review Critical/High first, run benign validation only in an approved test environment, validate business need, then translate approved decisions into WDAC supplemental deny/allow policy rules." -ForegroundColor Yellow
