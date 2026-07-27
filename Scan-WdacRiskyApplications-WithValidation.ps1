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
    Disables creation of benign Hello World validation harnesses for Critical findings.
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

    $ps1 = Join-Path $dir 'HelloWorld.ps1'
    $vbs = Join-Path $dir 'HelloWorld.vbs'
    $cs  = Join-Path $dir 'HelloWorld.cs'

    @'
Write-Host "Hello World"
'@ | Set-Content -LiteralPath $ps1 -Encoding UTF8

    @'
WScript.Echo "Hello World"
'@ | Set-Content -LiteralPath $vbs -Encoding ASCII

    @'
using System;
public static class HelloWorld
{
    public static void Main()
    {
        Console.WriteLine("Hello World");
    }
}
'@ | Set-Content -LiteralPath $cs -Encoding UTF8

    $binary = $FindingFile.FullName
    $fileName = $FindingFile.Name.ToLowerInvariant()
    $validationCommand = ''
    $validationType = 'ArtifactOnly'
    $notes = 'No automatic execution recipe was generated for this binary. The artifacts are supplied for controlled manual validation only.'

    switch($fileName){
        'powershell.exe' {
            $validationType='PowerShellHost'
            $validationCommand='& "{0}" -NoProfile -ExecutionPolicy Bypass -File "{1}"' -f $binary,$ps1
            $notes='Invokes the discovered PowerShell host with the generated benign script.'
        }
        'pwsh.exe' {
            $validationType='PowerShellHost'
            $validationCommand='& "{0}" -NoProfile -File "{1}"' -f $binary,$ps1
            $notes='Invokes the discovered PowerShell Core host with the generated benign script.'
        }
        'wscript.exe' {
            $validationType='VBScriptHost'
            $validationCommand='& "{0}" //nologo "{1}"' -f $binary,$vbs
            $notes='Invokes the discovered Windows Script Host binary with the generated benign VBScript.'
        }
        'cscript.exe' {
            $validationType='VBScriptHost'
            $validationCommand='& "{0}" //nologo "{1}"' -f $binary,$vbs
            $notes='Invokes the discovered Windows Script Host console binary with the generated benign VBScript.'
        }
        'csc.exe' {
            $validationType='CSharpCompiler'
            $exe=Join-Path $dir 'HelloWorld.exe'
            $validationCommand='& "{0}" /nologo /out:"{1}" "{2}"; if($LASTEXITCODE -eq 0){{ & "{1}" }}' -f $binary,$exe,$cs
            $notes='Compiles the generated benign C# source with the discovered compiler, then runs the resulting Hello World program.'
        }
        default {
            if($Category -eq 'Compiler' -and $fileName -like '*csc*.exe'){
                $validationType='CSharpCompiler'
                $exe=Join-Path $dir 'HelloWorld.exe'
                $validationCommand='& "{0}" /nologo /out:"{1}" "{2}"; if($LASTEXITCODE -eq 0){{ & "{1}" }}' -f $binary,$exe,$cs
                $notes='Compiles the generated benign C# source with the discovered compiler, then runs the resulting Hello World program.'
            }
        }
    }

    $readme = Join-Path $dir 'README.txt'
    @(
        'WDAC Critical Finding Validation Harness',
        '========================================',
        '',
        "Finding: $($FindingFile.FullName)",
        "Category: $Category",
        "Technique: $Technique",
        "Capabilities: $($Capabilities -join ', ')",
        "Validation type: $validationType",
        '',
        'Purpose:',
        '  These files are intentionally benign and only print "Hello World".',
        '  They are intended to help confirm whether a Critical finding can perform',
        '  the specific interpreter/compiler behavior identified by the scanner.',
        '',
        'Important:',
        '  A successful Hello World test confirms capability, not maliciousness.',
        '  A failed test does not automatically make the original finding a false positive.',
        '  Run validation only in an approved test environment.',
        '',
        'Generated artifacts:',
        "  $ps1",
        "  $vbs",
        "  $cs",
        '',
        'Suggested benign validation command:',
        $(if($validationCommand){"  $validationCommand"}else{'  Not generated for this binary/category.'}),
        '',
        "Notes: $notes"
    ) | Set-Content -LiteralPath $readme -Encoding UTF8

    [pscustomobject]@{
        Directory=$dir
        ValidationType=$validationType
        ValidationCommand=$validationCommand
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

    $validation=[pscustomobject]@{Directory='';ValidationType='';ValidationCommand='';Readme=''}
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
        ValidationCommand=$validation.ValidationCommand
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
