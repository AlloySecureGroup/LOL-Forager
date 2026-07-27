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
    Disables creation of target-observation and capability-specific validation harnesses for Critical findings.
    By default, each Critical finding receives a validation directory beside the CSV.

.PARAMETER EnableUnmanagedDllExportTest
    Opt-in unmanaged DLL export validation. Alias: -EnableUnmanagedExportTest.
    Generates a benign IL DLL with a real unmanaged export and automatically
    discovers candidate product-specific DLL/plugin loading surfaces from the
    scanned binary and adjacent configuration/manifest files.

.EXAMPLE
    .\LOL-Forager.ps1 -OutputCsv C:\Reports\WdacRisk.csv

.EXAMPLE
    .\LOL-Forager.ps1 -CatalogOnly

.EXAMPLE
    .\LOL-Forager.ps1 -IncludeScripts -MinimumRiskScore 35
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
    [switch]$DisableCriticalValidation,
    [Alias('EnableUnmanagedExportTest')]
    [switch]$EnableUnmanagedDllExportTest
)
$LOLForagerVersion = '2026.07.27-claim-validation-v7'
Write-Verbose "LOL-Forager version: $LOLForagerVersion"

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
    $confidenceRows=[Collections.Generic.List[object]]::new()
    $score=0

    foreach($rule in $CapabilityRules){
        $matched = @(
            foreach($pattern in $rule.Patterns){
                if($Text.IndexOf($pattern,[StringComparison]::OrdinalIgnoreCase) -ge 0){
                    $patterns.Add("$($rule.Name):$pattern")
                    $pattern
                }
            }
        )

        if($matched.Count -eq 0){ continue }

        $hits.Add($rule.Name)

        $effectiveWeight = [int]$rule.Weight
        $confidence = 'Strong'
        $reason = 'Capability-specific indicator present.'

        switch($rule.Name){
            'PluginLoading' {
                $strong = @($matched | Where-Object { $_ -match 'CompositionContainer|DirectoryCatalog|System\.ComponentModel\.Composition' })
                if($strong.Count -eq 0){
                    $effectiveWeight = 5
                    $confidence = 'PrimitiveOnly'
                    $reason = 'LoadLibrary/GetProcAddress are common native primitives and do not prove a controllable plugin interface.'
                }
            }
            'NetworkRetrieval' {
                $strong = @($matched | Where-Object { $_ -match 'URLDownloadToFile|DownloadString|DownloadFile|Invoke-WebRequest' })
                if($strong.Count -eq 0){
                    $effectiveWeight = 8
                    $confidence = 'PrimitiveOnly'
                    $reason = 'WinHTTP/WinINet presence proves networking APIs, not a download/retrieval interface.'
                }
            }
            'RemoteProtocol' {
                $effectiveWeight = 5
                $confidence = 'PrimitiveOnly'
                $reason = 'Protocol strings alone do not prove caller-controlled remote endpoints.'
            }
            'CredentialOrDumpAccess' {
                if($matched -contains 'MiniDumpWriteDump'){
                    $effectiveWeight = 30
                    $confidence = 'Strong'
                    $reason = 'MiniDumpWriteDump is a specific dump primitive.'
                } else {
                    $effectiveWeight = [math]::Min(15, 5 * $matched.Count)
                    $confidence = 'PrimitiveOnly'
                    $reason = 'Process/token inspection APIs are common in legitimate diagnostics and do not prove credential dumping.'
                }
            }
            'ProcessInjectionPrimitives' {
                $specific = @($matched | Where-Object { $_ -match 'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext' })
                if($specific.Count -ge 3){
                    $effectiveWeight = 35
                    $confidence = 'StrongPrimitiveCluster'
                    $reason = 'Multiple cross-process primitives occur together, but attacker-controlled injection is still not proven.'
                } elseif($specific.Count -ge 1){
                    $effectiveWeight = 10
                    $confidence = 'PrimitiveOnly'
                    $reason = 'A single cross-process primitive is insufficient to assert process injection.'
                } else {
                    $effectiveWeight = 3
                    $confidence = 'PrimitiveOnly'
                    $reason = 'MapViewOfFile alone is not an injection claim.'
                }
            }
            'AMSIOrETWInteraction' {
                $strong = @($matched | Where-Object { $_ -match 'AmsiScanBuffer|AmsiInitialize|EtwEventWrite' })
                if($strong.Count -eq 0){
                    $effectiveWeight = 3
                    $confidence = 'PrimitiveOnly'
                    $reason = 'EventWrite is a common telemetry API and does not by itself justify an AMSI/ETW-risk claim.'
                }
            }
            'TaskOrServiceCreation' {
                $strong = @($matched | Where-Object { $_ -match 'CreateService|RegisterTaskDefinition|TaskScheduler' })
                if($strong.Count -eq 0){
                    $effectiveWeight = 5
                    $confidence = 'PrimitiveOnly'
                    $reason = 'OpenSCManager alone does not prove service creation.'
                }
            }
        }

        $score += $effectiveWeight
        $confidenceRows.Add([pscustomobject]@{
            Capability=$rule.Name
            Confidence=$confidence
            EffectiveWeight=$effectiveWeight
            Reason=$reason
            MatchedPatterns=($matched -join ';')
        })
    }

    if($hits.Contains('NetworkRetrieval') -and $hits.Contains('ChildProcess')) { $score += 10 }
    if($hits.Contains('AssemblyLoading') -and $hits.Contains('NetworkRetrieval')) { $score += 10 }
    if($hits.Contains('CommandShell') -and $hits.Contains('ChildProcess')) { $score += 10 }
    if($hits.Contains('ManagedCompilation') -and $hits.Contains('AssemblyLoading')) { $score += 20 }

    [pscustomobject]@{
        Capabilities=$hits
        Patterns=$patterns
        Confidence=$confidenceRows
        Score=$score
    }
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


function Get-LoadingSurfaceCandidates {
    param(
        [Parameter(Mandatory=$true)][IO.FileInfo]$FindingFile,
        [string]$StaticText
    )

    $rows = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    function Add-SurfaceCandidate {
        param(
            [string]$SurfaceType,
            [string]$Candidate,
            [string]$ArgumentTemplate,
            [int]$Confidence,
            [string]$Source,
            [string]$Evidence,
            [bool]$AutoUsable
        )
        $key = "$SurfaceType|$Candidate|$ArgumentTemplate|$Source"
        if($seen.Add($key)){
            $rows.Add([pscustomobject]@{
                SurfaceType=$SurfaceType
                Candidate=$Candidate
                ArgumentTemplate=$ArgumentTemplate
                Confidence=$Confidence
                Source=$Source
                Evidence=$Evidence
                AutoUsable=$AutoUsable
            })
        }
    }

    $name = $FindingFile.Name.ToLowerInvariant()

    # Known deterministic application interfaces.
    switch($name){
        'rundll32.exe' {
            Add-SurfaceCandidate -SurfaceType 'DllExport' `
                -Candidate 'rundll32 DLL,Export syntax' `
                -ArgumentTemplate '"{DLL}",TestMethod' `
                -Confidence 100 `
                -Source 'KnownInterfaceCatalog' `
                -Evidence 'rundll32.exe accepts a DLL path plus exported function name' `
                -AutoUsable $true
        }
    }

    if($StaticText){
        # High-confidence switches that conventionally take a DLL/library path.
        # Keep this list intentionally narrow so a generic string such as
        # "LoadLibrary" is never converted into a fake command-line interface.
        $dllSwitchPatterns = @(
            '(?im)(?<switch>--(?:load-)?dll(?:-path)?)(?:[ =:])',
            '(?im)(?<switch>--(?:load-)?library(?:-path)?)(?:[ =:])',
            '(?im)(?<switch>--(?:load-)?plugin(?:-dll|-library|-path)?)(?:[ =:])',
            '(?im)(?<switch>/(?:dll|dllpath|library|librarypath|plugin|pluginpath))(?=[ =:])',
            '(?im)(?<switch>-(?:dll|dllpath|library|librarypath|plugin|pluginpath))(?=[ =:])'
        )

        foreach($pattern in $dllSwitchPatterns){
            foreach($m in [regex]::Matches($StaticText,$pattern)){
                $sw = $m.Groups['switch'].Value
                if([string]::IsNullOrWhiteSpace($sw)){ continue }

                # Exclude obvious negative/diagnostic switches.
                if($sw -match '(?i)disable|block|deny|verify|log|trace'){ continue }

                Add-SurfaceCandidate -SurfaceType 'DllPathArgument' `
                    -Candidate $sw `
                    -ArgumentTemplate "$sw {DLL}" `
                    -Confidence 90 `
                    -Source 'EmbeddedCommandLineString' `
                    -Evidence ("Embedded option token appears to accept a DLL/library/plugin path: {0}" -f $sw) `
                    -AutoUsable $true
            }
        }

        # Medium-confidence plugin/extension switches are recorded but are not
        # automatically used with an unmanaged DLL unless the token itself
        # clearly denotes a DLL/library path.
        $otherSwitchPattern = '(?im)(?<switch>--[a-z0-9][a-z0-9_.-]{1,60}|/[a-z0-9][a-z0-9_.-]{1,40}|-[a-z][a-z0-9_.-]{1,40})'
        foreach($m in [regex]::Matches($StaticText,$otherSwitchPattern)){
            $sw = $m.Groups['switch'].Value
            if($sw -notmatch '(?i)plugin|extension|addin|module|component'){ continue }

            $surface = if($sw -match '(?i)extension'){ 'ExtensionOrPluginPath' } else { 'PluginOrModulePath' }
            Add-SurfaceCandidate -SurfaceType $surface `
                -Candidate $sw `
                -ArgumentTemplate "$sw {ARTIFACT}" `
                -Confidence 55 `
                -Source 'EmbeddedCommandLineString' `
                -Evidence ("Potential product loading option found: {0}" -f $sw) `
                -AutoUsable $false
        }

        # Embedded usage/help fragments containing a DLL-oriented option.
        foreach($m in [regex]::Matches(
            $StaticText,
            '(?im).{0,80}(?<switch>--[a-z0-9_.-]*(?:dll|library|plugin)[a-z0-9_.-]*).{0,120}'
        )){
            $fragment = ($m.Value -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]',' ').Trim()
            if($fragment.Length -gt 220){ $fragment=$fragment.Substring(0,220) }
            Add-SurfaceCandidate -SurfaceType 'UsageStringCandidate' `
                -Candidate $m.Groups['switch'].Value `
                -ArgumentTemplate '' `
                -Confidence 65 `
                -Source 'EmbeddedUsageContext' `
                -Evidence $fragment `
                -AutoUsable $false
        }
    }

    # Search only nearby small text configuration/manifest files. These can
    # reveal product-specific plugin or DLL path keys without executing target.
    $baseDir = $FindingFile.Directory.FullName
    $adjacent = @()
    try {
        $adjacent = @(
            Get-ChildItem -LiteralPath $baseDir -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.Length -le 2MB -and
                    $_.Extension.ToLowerInvariant() -in @('.json','.config','.xml','.manifest','.ini','.yaml','.yml','.toml')
                } |
                Select-Object -First 80
        )
    } catch {}

    foreach($cfg in $adjacent){
        try {
            $cfgText = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop
        } catch { continue }

        foreach($m in [regex]::Matches(
            $cfgText,
            '(?im)["'']?(?<key>[a-z0-9_.-]*(?:dll|library|plugin|addin|module|extension)[a-z0-9_.-]*(?:path|file|name|directory|dir)?)["'']?\s*[:=]'
        )){
            $key = $m.Groups['key'].Value
            $type = if($key -match '(?i)dll|library'){ 'ConfigDllPathKey' } else { 'ConfigPluginPathKey' }
            Add-SurfaceCandidate -SurfaceType $type `
                -Candidate $key `
                -ArgumentTemplate '' `
                -Confidence 70 `
                -Source $cfg.FullName `
                -Evidence ("Adjacent configuration key suggests a loading surface: {0}" -f $key) `
                -AutoUsable $false
        }
    }

    return @($rows | Sort-Object @{Expression='Confidence';Descending=$true},SurfaceType,Candidate)
}

function New-CriticalValidationHarness {
    param(
        [Parameter(Mandatory=$true)][IO.FileInfo]$FindingFile,
        [Parameter(Mandatory=$true)][string]$RootDirectory,
        [string]$Category,
        [string]$Technique,
        [string[]]$Capabilities,
        [string]$StaticText
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
    $loadingSurfaces = @(Get-LoadingSurfaceCandidates -FindingFile $FindingFile -StaticText $StaticText)
    $loadingSurfaceCsv = Join-Path $dir 'DiscoveredLoadingSurfaces.csv'
    if($loadingSurfaces.Count -gt 0){
        $loadingSurfaces | Export-Csv -NoTypeInformation -LiteralPath $loadingSurfaceCsv -Encoding UTF8
    } else {
        [pscustomobject]@{
            SurfaceType='NoneDetermined'
            Candidate=''
            ArgumentTemplate=''
            Confidence=0
            Source=''
            Evidence='No product-specific DLL/plugin loading surface could be inferred from static strings or adjacent configuration files.'
            AutoUsable=$false
        } | Export-Csv -NoTypeInformation -LiteralPath $loadingSurfaceCsv -Encoding UTF8
    }
    $artifacts.Add($loadingSurfaceCsv)

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

    function New-UnmanagedExportValidationArtifacts {
        if(-not $EnableUnmanagedDllExportTest){ return $null }

        $markerFile = Join-Path $dir 'UnmanagedExportExecuted.txt'
        $escapedMarker = $markerFile.Replace('\','\\').Replace('"','\"')

        $il = Write-ValidationArtifact 'UnmanagedExportTest.il' @"
.assembly extern mscorlib
{
}
.assembly UnmanagedExportTest
{
}
.module UnmanagedExportTest.dll

// x86 CLR image for the Framework\v4.0.30319 toolchain.
.corflags 0x00000002

// Real unmanaged export thunk.
.vtfixup [1] int32 fromunmanaged at VT_01
.data VT_01 = int32(0)

.class public auto ansi beforefieldinit Test.TestClass
       extends [mscorlib]System.Object
{
  .method public hidebysig static void
          modopt([mscorlib]System.Runtime.CompilerServices.CallConvStdcall)
          TestMethod(native int hwnd, native int hinst, native int cmdLine, int32 nCmdShow) cil managed
  {
    .vtentry 1:1
    .export [1] as TestMethod
    .maxstack 8

    ldstr "$escapedMarker"
    ldstr "Unmanaged export executed by discovered target"
    call void [mscorlib]System.IO.File::WriteAllText(string, string)
    ret
  }
}
"@

        $build = Write-ValidationArtifact 'Build-UnmanagedExportTest.ps1' @'
param(
    [string]$IlasmPath = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$il = Join-Path $here 'UnmanagedExportTest.il'
$dll = Join-Path $here 'UnmanagedExportTest.dll'

if(-not (Test-Path -LiteralPath $IlasmPath -PathType Leaf)){
    throw "Expected IL assembler was not found at: $IlasmPath"
}

Remove-Item -LiteralPath $dll -Force -ErrorAction SilentlyContinue

& $IlasmPath /nologo /dll "/output=$dll" $il
if($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dll)){
    throw "ILASM failed to create $dll"
}

Write-Host "Built unmanaged-export test DLL: $dll"
Write-Host "Export: TestMethod"
'@

        $targetRunner = Write-ValidationArtifact 'Run-TargetUnmanagedDllLoadTest.ps1' @"
param(
    [ValidateRange(2,120)]
    [int]`$ObservationSeconds = 15,

    [switch]`$StopTarget
)

`$ErrorActionPreference = 'Stop'
`$here = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$target = '$($binary.Replace("'","''"))'
`$build = Join-Path `$here 'Build-UnmanagedExportTest.ps1'
`$dll = Join-Path `$here 'UnmanagedExportTest.dll'
`$marker = Join-Path `$here 'UnmanagedExportExecuted.txt'
`$surfaceCsv = Join-Path `$here 'DiscoveredLoadingSurfaces.csv'
`$result = Join-Path `$here 'TargetUnmanagedDllLoadResult.csv'

if(-not (Test-Path -LiteralPath `$target -PathType Leaf)){
    throw "Discovered target not found: `$target"
}
if(-not (Test-Path -LiteralPath `$surfaceCsv -PathType Leaf)){
    throw "Loading-surface discovery results not found: `$surfaceCsv"
}

`$candidates = @(Import-Csv -LiteralPath `$surfaceCsv)
`$selected = `$candidates |
    Where-Object {
        `$_.AutoUsable -eq 'True' -and
        `$_.ArgumentTemplate -like '*{DLL}*' -and
        [int]`$_.Confidence -ge 85
    } |
    Sort-Object @{Expression={[int]`$_.Confidence};Descending=`$true} |
    Select-Object -First 1

if(-not `$selected){
    [pscustomobject]@{
        TestType='ExactDiscoveredTargetUnmanagedDllLoad'
        TargetPath=`$target
        LoadingSurfaceDetermined=`$false
        SelectedSurface=''
        SelectedTemplate=''
        ExactDiscoveredTargetUsed=`$false
        GeneratedDllObservedLoadedByTargetTree=`$false
        ExportMarkerCreated=`$false
        DirectValidationPassed=`$false
        Status='NotDirectlyTestable'
        Reason='Forager did not discover a high-confidence DLL-path argument/interface. Static LoadLibrary/GetProcAddress evidence is not enough to invent one.'
    } | Export-Csv -NoTypeInformation -LiteralPath `$result

    Write-Warning "No high-confidence DLL loading surface was discovered for the exact target."
    Write-Warning "See: `$surfaceCsv"
    Write-Warning "Result: NotDirectlyTestable"
    return
}

& `$build
if(-not (Test-Path -LiteralPath `$dll -PathType Leaf)){
    throw "Generated DLL not found: `$dll"
}

Remove-Item -LiteralPath `$marker -Force -ErrorAction SilentlyContinue

`$escapedDll = '"' + `$dll + '"'
`$arguments = `$selected.ArgumentTemplate.Replace('{DLL}', `$escapedDll)

Write-Host "Forager-selected loading surface:"
Write-Host "  Type:       `$(`$selected.SurfaceType)"
Write-Host "  Candidate:  `$(`$selected.Candidate)"
Write-Host "  Confidence: `$(`$selected.Confidence)"
Write-Host "Launching exact discovered binary:"
Write-Host "  `$target"
Write-Host "Arguments:"
Write-Host "  `$arguments"

`$p = Start-Process -FilePath `$target -ArgumentList `$arguments -PassThru
`$rootPid = [int]`$p.Id
`$deadline = (Get-Date).AddSeconds(`$ObservationSeconds)

`$loadedByTargetTree = `$false
`$observedProcessIds = New-Object System.Collections.Generic.HashSet[int]
[void]`$observedProcessIds.Add(`$rootPid)

function Get-DescendantPids {
    param([int]`$RootPid)
    try {
        `$all = @(Get-CimInstance Win32_Process -ErrorAction Stop)
        `$seen = New-Object System.Collections.Generic.HashSet[int]
        `$queue = New-Object 'System.Collections.Generic.Queue[int]'
        [void]`$seen.Add(`$RootPid)
        `$queue.Enqueue(`$RootPid)
        while(`$queue.Count -gt 0){
            `$parent = `$queue.Dequeue()
            foreach(`$proc in @(`$all | Where-Object { [int]`$_.ParentProcessId -eq `$parent })){
                `$id = [int]`$proc.ProcessId
                if(`$seen.Add(`$id)){
                    `$queue.Enqueue(`$id)
                }
            }
        }
        return @(`$seen)
    } catch {
        return @(`$RootPid)
    }
}

do {
    Start-Sleep -Milliseconds 300

    foreach(`$pidValue in @(Get-DescendantPids -RootPid `$rootPid)){
        [void]`$observedProcessIds.Add([int]`$pidValue)

        `$gp = Get-Process -Id `$pidValue -ErrorAction SilentlyContinue
        if(-not `$gp){ continue }

        try {
            foreach(`$m in @(`$gp.Modules)){
                if([string]::Equals([IO.Path]::GetFullPath(`$m.FileName), [IO.Path]::GetFullPath(`$dll), [StringComparison]::OrdinalIgnoreCase)){
                    `$loadedByTargetTree = `$true
                }
            }
        } catch {}
    }

    if(Test-Path -LiteralPath `$marker){ break }
}
while((Get-Date) -lt `$deadline -and (Get-Process -Id `$rootPid -ErrorAction SilentlyContinue))

`$markerCreated = Test-Path -LiteralPath `$marker
`$passed = [bool](`$loadedByTargetTree -and `$markerCreated)

[pscustomobject]@{
    TestType='ExactDiscoveredTargetUnmanagedDllLoad'
    TargetPath=`$target
    LoadingSurfaceDetermined=`$true
    SelectedSurface=`$selected.SurfaceType
    SelectedCandidate=`$selected.Candidate
    SelectedTemplate=`$selected.ArgumentTemplate
    SurfaceConfidence=[int]`$selected.Confidence
    SurfaceSource=`$selected.Source
    RootProcessId=`$rootPid
    ExpandedArguments=`$arguments
    DllPath=`$dll
    ExportName='TestMethod'
    ExactDiscoveredTargetUsed=`$true
    GeneratedDllObservedLoadedByTargetTree=[bool]`$loadedByTargetTree
    ExportMarkerCreated=[bool]`$markerCreated
    DirectValidationPassed=`$passed
    Status=$(if(`$passed){'DirectlyValidated'}elseif(`$loadedByTargetTree){'LoadedButExportNotInvoked'}else{'NotValidated'})
} | Export-Csv -NoTypeInformation -LiteralPath `$result

if(`$StopTarget){
    foreach(`$pidValue in @(`$observedProcessIds | Sort-Object -Descending)){
        Stop-Process -Id `$pidValue -Force -ErrorAction SilentlyContinue
    }
}

if(-not `$loadedByTargetTree){
    throw "FAIL: Forager selected a loading surface, but the exact target process tree did not load the generated DLL."
}
if(-not `$markerCreated){
    throw "PARTIAL: the exact target loaded the generated DLL, but TestMethod was not invoked."
}

Write-Host "PASS: exact discovered target loaded the generated DLL and invoked TestMethod."
"@

        return [pscustomobject]@{
            IlSource=$il
            BuildScript=$build
            TargetRunner=$targetRunner
            SurfaceDiscovery=$loadingSurfaceCsv
            DllPath=(Join-Path $dir 'UnmanagedExportTest.dll')
            MarkerPath=$markerFile
        }
    }

    # Every executable/script Critical finding receives the same exact-target
    # observation harness. Direct capability PoCs are additional evidence; they
    # do not replace target observation.
    $targetObserver = ''
    $targetExtension = [IO.Path]::GetExtension($binary).ToLowerInvariant()
    if($targetExtension -in @('.exe','.com','.bat','.cmd','.ps1','.vbs','.js','.wsf')) {
        $targetObserver = Write-ValidationArtifact 'Run-TargetBehaviorObservation.ps1' @'
param(
    [string]$TargetPath = '__TARGET_PATH__',

    [string[]]$ArgumentList = @(),

    [ValidateRange(2,120)]
    [int]$ObservationSeconds = 12,

    [switch]$StopTarget
)

$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$evidence = Join-Path $here 'TargetEvidence'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null

if (-not (Test-Path -LiteralPath $TargetPath -PathType Leaf)) {
    throw "Target not found: $TargetPath"
}

$targetExt = [IO.Path]::GetExtension($TargetPath)
if ($targetExt -notin @('.exe','.com','.bat','.cmd','.ps1','.vbs','.js','.wsf')) {
    throw "TargetBehaviorObservation requires an executable or script target. '$TargetPath' has extension '$targetExt'."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$summaryPath = Join-Path $evidence "Summary-$stamp.txt"
$modulePath  = Join-Path $evidence "LoadedModules-$stamp.csv"
$childPath   = Join-Path $evidence "ChildProcesses-$stamp.csv"
$netPath     = Join-Path $evidence "NetworkConnections-$stamp.csv"
$procPath    = Join-Path $evidence "Process-$stamp.csv"

function Get-ChildProcessEvidence {
    param([int[]]$ParentPids)

    if (-not $ParentPids -or $ParentPids.Count -eq 0) {
        return @()
    }

    try {
        $all = @(Get-CimInstance Win32_Process -ErrorAction Stop)

        $seen = [System.Collections.Generic.HashSet[int]]::new()
        $frontier = [System.Collections.Generic.Queue[int]]::new()
        $results = New-Object System.Collections.ArrayList

        foreach ($id in $ParentPids) {
            [void]$seen.Add([int]$id)
            $frontier.Enqueue([int]$id)
        }

        while ($frontier.Count -gt 0) {
            $parent = $frontier.Dequeue()

            foreach ($p in @($all | Where-Object { [int]$_.ParentProcessId -eq $parent })) {
                $childId = [int]$p.ProcessId

                if ($seen.Add($childId)) {
                    [void]$results.Add([pscustomobject]@{
                        ProcessId       = $childId
                        ParentProcessId = [int]$p.ParentProcessId
                        Name            = [string]$p.Name
                        ExecutablePath  = [string]$p.ExecutablePath
                        CommandLine     = [string]$p.CommandLine
                    })

                    $frontier.Enqueue($childId)
                }
            }
        }

        return @($results)
    }
    catch {
        Write-Verbose "Child-process enumeration failed: $($_.Exception.Message)"
        return @()
    }
}

function Get-NetworkEvidence {
    param([int[]]$ProcessIds)

    if (-not $ProcessIds -or $ProcessIds.Count -eq 0) {
        return @()
    }

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        return @()
    }

    try {
        return @(
            Get-NetTCPConnection -ErrorAction Stop |
                Where-Object { $ProcessIds -contains [int]$_.OwningProcess } |
                ForEach-Object {
                    [pscustomobject]@{
                        OwningProcess = [int]$_.OwningProcess
                        State         = [string]$_.State
                        LocalAddress  = [string]$_.LocalAddress
                        LocalPort     = [int]$_.LocalPort
                        RemoteAddress = [string]$_.RemoteAddress
                        RemotePort    = [int]$_.RemotePort
                    }
                }
        )
    }
    catch {
        Write-Verbose "TCP enumeration failed: $($_.Exception.Message)"
        return @()
    }
}

$startParams = @{
    FilePath    = $TargetPath
    PassThru    = $true
    ErrorAction = 'Stop'
}

if ($ArgumentList.Count -gt 0) {
    $startParams.ArgumentList = $ArgumentList
}

Write-Host "Launching exact target:"
Write-Host "  $TargetPath"

$started = Start-Process @startParams
$rootPid = [int]$started.Id
$deadline = (Get-Date).AddSeconds($ObservationSeconds)

# Use ArrayList rather than generic List[T].
# Windows PowerShell 5.1 has edge cases when generic collections are passed
# through the pipeline and then sorted/exported.
$moduleRows = New-Object System.Collections.ArrayList
$moduleSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$childRows = New-Object System.Collections.ArrayList
$childSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$networkRows = New-Object System.Collections.ArrayList
$networkSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

do {
    Start-Sleep -Milliseconds 500

    $children = @(Get-ChildProcessEvidence -ParentPids @($rootPid))
    $processIds = @(
        @($rootPid)
        @($children | ForEach-Object { [int]$_.ProcessId })
    ) | Select-Object -Unique

    foreach($child in $children){
        $childKey = '{0}|{1}' -f $child.ProcessId,$child.ParentProcessId
        if($childSeen.Add($childKey)){
            [void]$childRows.Add([pscustomobject]@{
                ProcessId       = [int]$child.ProcessId
                ParentProcessId = [int]$child.ParentProcessId
                Name            = [string]$child.Name
                ExecutablePath  = [string]$child.ExecutablePath
                CommandLine     = [string]$child.CommandLine
            })
        }
    }

    foreach($conn in @(Get-NetworkEvidence -ProcessIds $processIds)){
        $netKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f $conn.OwningProcess,$conn.State,$conn.LocalAddress,$conn.LocalPort,$conn.RemoteAddress,$conn.RemotePort
        if($networkSeen.Add($netKey)){
            [void]$networkRows.Add([pscustomobject]@{
                OwningProcess = [int]$conn.OwningProcess
                State         = [string]$conn.State
                LocalAddress  = [string]$conn.LocalAddress
                LocalPort     = [int]$conn.LocalPort
                RemoteAddress = [string]$conn.RemoteAddress
                RemotePort    = [int]$conn.RemotePort
            })
        }
    }

    foreach ($procId in $processIds) {
        $gp = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $gp) {
            continue
        }

        try {
            foreach ($m in @($gp.Modules)) {
                $moduleFile = [string]$m.FileName
                $key = '{0}|{1}' -f $procId, $moduleFile

                if ($moduleSeen.Add($key)) {
                    $baseAddress = ''
                    try {
                        $baseAddress = '0x{0:X}' -f $m.BaseAddress.ToInt64()
                    } catch {}

                    [void]$moduleRows.Add([pscustomobject]@{
                        ProcessId   = [int]$procId
                        ProcessName = [string]$gp.ProcessName
                        ModuleName  = [string]$m.ModuleName
                        FileName    = $moduleFile
                        BaseAddress = $baseAddress
                        ModuleSize  = [int64]$m.ModuleMemorySize
                    })
                }
            }
        }
        catch {
            # Module enumeration can fail for protected or cross-bitness processes.
        }
    }
}
while (
    (Get-Date) -lt $deadline -and
    (Get-Process -Id $rootPid -ErrorAction SilentlyContinue)
)

$childrenFinal = @(Get-ChildProcessEvidence -ParentPids @($rootPid))
foreach($child in $childrenFinal){
    $childKey = '{0}|{1}' -f $child.ProcessId,$child.ParentProcessId
    if($childSeen.Add($childKey)){
        [void]$childRows.Add([pscustomobject]@{
            ProcessId       = [int]$child.ProcessId
            ParentProcessId = [int]$child.ParentProcessId
            Name            = [string]$child.Name
            ExecutablePath  = [string]$child.ExecutablePath
            CommandLine     = [string]$child.CommandLine
        })
    }
}

$allFinalPids = @(
    @($rootPid)
    @($childRows | ForEach-Object { [int]$_.ProcessId })
) | Select-Object -Unique

foreach($conn in @(Get-NetworkEvidence -ProcessIds $allFinalPids)){
    $netKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f $conn.OwningProcess,$conn.State,$conn.LocalAddress,$conn.LocalPort,$conn.RemoteAddress,$conn.RemotePort
    if($networkSeen.Add($netKey)){
        [void]$networkRows.Add([pscustomobject]@{
            OwningProcess = [int]$conn.OwningProcess
            State         = [string]$conn.State
            LocalAddress  = [string]$conn.LocalAddress
            LocalPort     = [int]$conn.LocalPort
            RemoteAddress = [string]$conn.RemoteAddress
            RemotePort    = [int]$conn.RemotePort
        })
    }
}

# IMPORTANT:
# Materialize the ArrayList as a normal PowerShell array before Sort-Object.
# This avoids "Argument types do not match" in Windows PowerShell 5.1.
$moduleExport = @(
    foreach ($row in $moduleRows) {
        [pscustomobject]@{
            ProcessId   = [int]$row.ProcessId
            ProcessName = [string]$row.ProcessName
            ModuleName  = [string]$row.ModuleName
            FileName    = [string]$row.FileName
            BaseAddress = [string]$row.BaseAddress
            ModuleSize  = [int64]$row.ModuleSize
        }
    }
)

$childExport = @(
    foreach ($row in $childRows) {
        [pscustomobject]@{
            ProcessId       = [int]$row.ProcessId
            ParentProcessId = [int]$row.ParentProcessId
            Name            = [string]$row.Name
            ExecutablePath  = [string]$row.ExecutablePath
            CommandLine     = [string]$row.CommandLine
        }
    }
)

$networkExport = @(
    foreach ($row in $networkRows) {
        [pscustomobject]@{
            OwningProcess = [int]$row.OwningProcess
            State         = [string]$row.State
            LocalAddress  = [string]$row.LocalAddress
            LocalPort     = [int]$row.LocalPort
            RemoteAddress = [string]$row.RemoteAddress
            RemotePort    = [int]$row.RemotePort
        }
    }
)

if ($moduleExport.Count -gt 0) {
    $moduleExport |
        Sort-Object -Property ProcessId, FileName -Unique |
        Export-Csv -NoTypeInformation -LiteralPath $modulePath
}
else {
    'ProcessId,ProcessName,ModuleName,FileName,BaseAddress,ModuleSize' |
        Set-Content -LiteralPath $modulePath -Encoding UTF8
}

if ($childExport.Count -gt 0) {
    $childExport |
        Export-Csv -NoTypeInformation -LiteralPath $childPath
}
else {
    'ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine' |
        Set-Content -LiteralPath $childPath -Encoding UTF8
}

if ($networkExport.Count -gt 0) {
    $networkExport |
        Export-Csv -NoTypeInformation -LiteralPath $netPath
}
else {
    'OwningProcess,State,LocalAddress,LocalPort,RemoteAddress,RemotePort' |
        Set-Content -LiteralPath $netPath -Encoding UTF8
}

$stillRunning = [bool](Get-Process -Id $rootPid -ErrorAction SilentlyContinue)

[pscustomobject]@{
    TargetPath      = $TargetPath
    RootProcessId   = $rootPid
    StartedAt       = $started.StartTime
    StillRunning    = $stillRunning
    ObservationSecs = $ObservationSeconds
    Arguments       = ($ArgumentList -join ' ')
} |
    Export-Csv -NoTypeInformation -LiteralPath $procPath

$moduleCount = @($moduleExport).Count
$childCount = @($childExport).Count
$netCount = @($networkExport).Count

@(
    'WDAC target-behavior observation'
    '================================'
    ''
    "Target: $TargetPath"
    "PID: $rootPid"
    "Observation seconds: $ObservationSeconds"
    "Loaded modules observed: $moduleCount"
    "Descendant processes observed: $childCount"
    "TCP connections observed: $netCount"
    ''
    'Evidence files:'
    "  $modulePath"
    "  $childPath"
    "  $netPath"
    "  $procPath"
    ''
    'Interpretation:'
    '  Static capability indicators and observed target behavior are separate.'
    '  A module appearing here proves it was observed loaded in the target tree.'
    '  It does not prove arbitrary or attacker-controlled module loading.'
    '  A child process proves descendant execution, not which API created it.'
    '  A TCP connection proves observed network activity, not endpoint control.'
) | Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host ''
Write-Host "Executed discovered target: $TargetPath"
Write-Host "PID: $rootPid"
Write-Host "Loaded modules observed: $moduleCount"
Write-Host "Child processes observed: $childCount"
Write-Host "TCP connections observed: $netCount"
Write-Host "Evidence directory: $evidence"

if ($StopTarget) {
    foreach ($procId in ($allFinalPids | Sort-Object -Descending -Unique)) {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
    }
}
'@
        (Get-Content -LiteralPath $targetObserver -Raw).Replace('__TARGET_PATH__', $binary.Replace("'","''")) |
            Set-Content -LiteralPath $targetObserver -Encoding UTF8
    }

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
            if($EnableUnmanagedDllExportTest){
                $unmanaged = New-UnmanagedExportValidationArtifacts
                $rundllRunner = Write-ValidationArtifact 'Run-Rundll32UnmanagedExportTest.ps1' @"
`$ErrorActionPreference = 'Stop'
`$here = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$runner = Join-Path `$here 'Run-TargetUnmanagedDllLoadTest.ps1'

# rundll32 syntax is a known direct loading surface:
#   rundll32.exe "<dll>",<export>
& `$runner
"@
                $validationType='Rundll32UnmanagedExportTest'
                $validationInterface='Exact discovered rundll32.exe loading and invoking the generated TestMethod export'
                $validationCommand='& "{0}"' -f $rundllRunner
                $expectedResult='The exact discovered rundll32.exe must load UnmanagedExportTest.dll and invoke TestMethod. The validation only passes when the target process tree is observed loading the generated DLL and the export creates UnmanagedExportExecuted.txt.'
                $notes='This is direct target-specific validation because rundll32 has a known DLL/export invocation syntax.'
            }
            else {
                $validationType='Rundll32DllExport'
                $validationInterface='rundll32 DLL-export invocation'
                $validationCommand='& "{0}"' -f $targetObserver
                $expectedResult='The exact discovered rundll32.exe is launched and observed. Enable -EnableUnmanagedDllExportTest for direct exported-DLL validation.'
                $notes='Unmanaged export validation is disabled by default.'
            }
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
        'msinfo32.exe' {
            $msinfo = Write-ValidationArtifact 'Run-Msinfo32DocumentedInterfaceTest.ps1' @"
`$ErrorActionPreference = 'Stop'
`$here = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$target = '$($binary.Replace("'","''"))'
`$report = Join-Path `$here 'msinfo32-validation-report.txt'
`$nfo = Join-Path `$here 'msinfo32-validation.nfo'
`$result = Join-Path `$here 'Msinfo32ValidationResult.csv'

Remove-Item -LiteralPath `$report,`$nfo -Force -ErrorAction SilentlyContinue

`$p1 = Start-Process -FilePath `$target -ArgumentList @('/report',`$report) -PassThru -Wait
`$reportOk = (Test-Path -LiteralPath `$report) -and ((Get-Item -LiteralPath `$report).Length -gt 0)

`$p2 = Start-Process -FilePath `$target -ArgumentList @('/nfo',`$nfo) -PassThru -Wait
`$nfoOk = (Test-Path -LiteralPath `$nfo) -and ((Get-Item -LiteralPath `$nfo).Length -gt 0)

[pscustomobject]@{
    TestType='Msinfo32DocumentedInterface'
    TargetPath=`$target
    ExactDiscoveredTargetUsed=`$true
    ReportInterfaceValidated=[bool]`$reportOk
    NfoInterfaceValidated=[bool]`$nfoOk
    ReportPath=`$report
    NfoPath=`$nfo
    DirectValidationPassed=[bool](`$reportOk -and `$nfoOk)
} | Export-Csv -NoTypeInformation -LiteralPath `$result

if(-not (`$reportOk -and `$nfoOk)){
    throw "msinfo32 direct validation failed: /report and/or /nfo did not produce output."
}

Write-Host "PASS: exact discovered msinfo32.exe produced both /report and /nfo output."
"@
            $validationType='Msinfo32DocumentedInterface'
            $validationInterface='Documented msinfo32 /report and /nfo export interfaces'
            $validationCommand='& "{0}"' -f $msinfo
            $expectedResult='The exact discovered msinfo32.exe creates non-empty report and NFO files using its documented command-line interface.'
            $notes='This validates what msinfo32 actually exposes. It does not validate PluginLoading, process injection, credential dumping, or service creation merely because those API names occur in the binary.'
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
    [string]$CscPath = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path -LiteralPath $CscPath -PathType Leaf)) {
    throw "Expected C# compiler was not found at: $CscPath"
}
& $CscPath /nologo /target:library /out:"$here\BenignPlugin.dll" "$here\BenignPlugin.cs"
if ($LASTEXITCODE -ne 0) { throw 'Plugin compilation failed.' }
& $CscPath /nologo /out:"$here\PluginLoaderPoC.exe" "$here\PluginLoaderPoC.cs"
if ($LASTEXITCODE -ne 0) { throw 'Loader compilation failed.' }
& "$here\PluginLoaderPoC.exe" "$here\BenignPlugin.dll"
'@
                $unmanaged = $null
                if($EnableUnmanagedDllExportTest){
                    $unmanaged = New-UnmanagedExportValidationArtifacts
                }
                $validationType='TargetObservedPluginLoading'
                $validationInterface=$(if($EnableUnmanagedDllExportTest){
                    'Forager automatically discovers candidate DLL/plugin loading surfaces. The exact discovered executable is launched only when a high-confidence DLL-path interface is found; validation passes only if that target process tree loads the generated DLL and invokes TestMethod.'
                } else {
                    'Discovered executable is launched; loaded DLL/modules are captured from that process and descendants.'
                })
                $validationCommand='& "{0}"' -f $targetObserver
                $expectedResult=$(if($EnableUnmanagedDllExportTest){
                    'Run-TargetUnmanagedDllLoadTest.ps1 reads DiscoveredLoadingSurfaces.csv and automatically selects only a high-confidence DLL-path interface. PASS requires both: (1) the generated DLL is observed in the exact target process tree and (2) TestMethod creates UnmanagedExportExecuted.txt. If no such interface is discovered, the result is NotDirectlyTestable.'
                } else {
                    'The exact discovered executable is started. TargetEvidence\LoadedModules-*.csv records modules actually observed in that process or its descendants.'
                })
                $notes=$(if($EnableUnmanagedDllExportTest){
                    'No generic helper loader is used and no defender-supplied template is required. Forager searches embedded command-line/usage strings plus adjacent configuration and manifest files. It auto-tests only a high-confidence DLL-path surface; otherwise PluginLoading remains unvalidated and DiscoveredLoadingSurfaces.csv explains what was or was not found.'
                } else {
                    'Static LoadLibrary/GetProcAddress strings remain potential capability until corroborated by observed behavior or a documented product-specific plugin interface.'
                })
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
                $validationType='TargetObservedRemoteProtocol'
                $validationInterface='Discovered executable is launched and its TCP connections are captured; a separate localhost HTTP PoC reproduces the protocol primitive.'
                $validationCommand='& "{0}"' -f $targetObserver
                $expectedResult='The exact discovered executable is started. TargetEvidence\NetworkConnections-*.csv records TCP connections actually observed for it or its descendants. RemoteProtocolPoC.ps1 is supplemental and demonstrates a localhost protocol exchange only.'
                $notes='Direct validation executes the target and records its network behavior. A static http/https string alone is not proof that an attacker can control a URL. The localhost protocol PoC is educational evidence of the primitive, not target-specific proof.'
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
                $validationType='TargetExecutedAMSIOrETWReview'
                $validationInterface='Discovered executable is launched for target-specific observation; a supplemental PoC invokes AMSI scanning and ETW/EventSource emission independently.'
                $validationCommand='& "{0}"' -f $targetObserver
                $expectedResult='The exact discovered executable is started and basic process/module/network evidence is captured. AmsiEtwCapabilityPoC.ps1 separately proves normal AMSI and ETW interfaces are callable; it is not proof that the target exercised those APIs.'
                $notes='Built-in PowerShell observation cannot reliably attribute individual AMSI/ETW API calls inside an arbitrary process. Treat EventWrite/AMSI strings as unconfirmed until corroborated with ETW tracing, debugger/API telemetry, vendor documentation, or deeper code analysis. The supplemental PoC does not bypass or tamper with AMSI/ETW.'
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
                $validationType='TargetExecutedWMIReview'
                $validationInterface='Discovered executable is launched and descendant processes are captured; a supplemental PoC independently exercises WMI/CIM Win32_Process.Create.'
                $validationCommand='& "{0}"' -f $targetObserver
                $expectedResult='The exact discovered executable is started. TargetEvidence\ChildProcesses-*.csv records descendants actually observed. WMIExecutionPoC.ps1 separately demonstrates benign Win32_Process.Create behavior but is not proof that the target invoked WMI.'
                $notes='Process descendants can corroborate execution behavior but do not by themselves prove WMI was the creation mechanism. Confirm WMI attribution with WMI Activity logs/ETW or deeper instrumentation. The supplemental WMI PoC remains local and benign.'
            }
            elseif($Capabilities -contains 'ChildProcess'){
                $validationType='TargetObservedChildProcess'
                $validationInterface='Exact discovered executable is launched and descendant processes are captured.'
                $validationCommand=$(if($targetObserver){'& "{0}"' -f $targetObserver}else{''})
                $expectedResult='TargetEvidence\ChildProcesses-*.csv records any descendant processes actually observed beneath the discovered target.'
                $notes='Observed descendants corroborate child-process behavior but do not identify the exact creation API or prove attacker control of process arguments.'
            }
            elseif($Capabilities -contains 'NetworkRetrieval'){
                $validationType='TargetObservedNetworkActivity'
                $validationInterface='Exact discovered executable is launched and TCP connections from its process tree are captured.'
                $validationCommand=$(if($targetObserver){'& "{0}"' -f $targetObserver}else{''})
                $expectedResult='TargetEvidence\NetworkConnections-*.csv records TCP connections actually observed for the discovered target or its descendants.'
                $notes='Observed TCP activity corroborates networking behavior but does not prove a download occurred or that an untrusted caller controls the endpoint.'
            }
        }
    }


    # Preserve any capability-specific direct command. Run-Validation.ps1 will
    # always execute target observation first, then this direct command when it
    # is distinct from the observer.
    $directValidationCommand = $validationCommand

    if(-not $validationCommand -and $targetObserver){
        $validationType='TargetBehaviorObservation'
        $validationInterface='Exact discovered executable launch with module, child-process, and TCP observation'
        $validationCommand='& "{0}"' -f $targetObserver
        $expectedResult='The discovered executable is launched and TargetEvidence contains process, loaded-module, child-process, and TCP evidence.'
        $notes='This is target-specific observation. It does not convert static API strings into validated attacker-controllable capabilities.'
        $directValidationCommand=''
    }

    $capabilityLiteral = '@(' + (($Capabilities | ForEach-Object { "'" + $_.Replace("'","''") + "'" }) -join ',') + ')'
    $assertScript = Write-ValidationArtifact 'Assert-ForagerClaims.ps1' @'
param(
    [string]$EvidenceDirectory = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'TargetEvidence')
)

$ErrorActionPreference = 'Stop'
$Capabilities = __CAPABILITY_ARRAY__

function Import-NewestCsv {
    param([string]$Prefix)
    $f = Get-ChildItem -LiteralPath $EvidenceDirectory -Filter "$Prefix-*.csv" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if(-not $f){ return @() }
    try { return @(Import-Csv -LiteralPath $f.FullName) } catch { return @() }
}

$modules  = @(Import-NewestCsv 'LoadedModules')
$children = @(Import-NewestCsv 'ChildProcesses')
$network  = @(Import-NewestCsv 'NetworkConnections')
$targetDllResultPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'TargetUnmanagedDllLoadResult.csv'
$targetDllResult = $null
if(Test-Path -LiteralPath $targetDllResultPath){
    try { $targetDllResult = Import-Csv -LiteralPath $targetDllResultPath | Select-Object -First 1 } catch {}
}

$rows = foreach($capability in $Capabilities){
    $status = 'StaticOnly'
    $assertion = 'Static fingerprint only; not validated by the generic observer.'
    $evidence = ''

    switch($capability){
        'ChildProcess' {
            if($children.Count -gt 0){
                $status = 'ObservedCorroboration'
                $assertion = 'At least one descendant process was observed beneath the target.'
                $evidence = "$($children.Count) descendant process record(s)"
            } else {
                $status = 'NotObserved'
                $assertion = 'No descendant process was observed during this observation window.'
            }
        }
        'NetworkRetrieval' {
            if($network.Count -gt 0){
                $status = 'ObservedCorroboration'
                $assertion = 'TCP activity was observed for the target process tree. This does not prove retrieval/download behavior.'
                $evidence = "$($network.Count) TCP connection record(s)"
            } else {
                $status = 'NotObserved'
                $assertion = 'No TCP connection was observed during this observation window.'
            }
        }
        'RemoteProtocol' {
            if($network.Count -gt 0){
                $status = 'ObservedCorroboration'
                $assertion = 'TCP activity was observed. The observer cannot identify protocol semantics or endpoint controllability.'
                $evidence = "$($network.Count) TCP connection record(s)"
            } else {
                $status = 'NotObserved'
                $assertion = 'No TCP connection was observed during this observation window.'
            }
        }
        'PluginLoading' {
            if($targetDllResult -and $targetDllResult.DirectValidationPassed -eq 'True'){
                $status = 'DirectlyValidated'
                $assertion = 'The exact discovered target process tree loaded the generated unmanaged-export DLL through a Forager-discovered loading surface and invoked TestMethod.'
                $evidence = "Surface=$($targetDllResult.SelectedCandidate); Confidence=$($targetDllResult.SurfaceConfidence); DLL=$($targetDllResult.DllPath)"
            }
            elseif($targetDllResult -and $targetDllResult.Status -eq 'LoadedButExportNotInvoked'){
                $status = 'ObservedCorroboration'
                $assertion = 'The exact discovered target process tree loaded the generated DLL, but the TestMethod export was not invoked.'
                $evidence = "Surface=$($targetDllResult.SelectedCandidate); DLL=$($targetDllResult.DllPath)"
            }
            elseif($targetDllResult -and $targetDllResult.Status -eq 'NotDirectlyTestable'){
                $status = 'StaticOnly'
                $assertion = 'Forager did not discover a high-confidence DLL-path loading surface. PluginLoading remains a static capability candidate.'
                $evidence = 'See DiscoveredLoadingSurfaces.csv'
            }
            elseif($modules.Count -gt 0){
                $status = 'TargetModulesObserved'
                $assertion = 'Modules were observed loaded in the target process tree. This does not validate arbitrary or attacker-controlled plugin loading.'
                $evidence = "$($modules.Count) loaded-module record(s)"
            }
        }
        'AssemblyLoading' {
            if($modules.Count -gt 0){
                $status = 'TargetModulesObserved'
                $assertion = 'Modules were observed, but the observer cannot prove managed Assembly.Load/LoadFrom was used or attacker-controlled.'
                $evidence = "$($modules.Count) loaded-module record(s)"
            }
        }
        'WMIExecution' {
            $status = 'NotAssertableByObserver'
            $assertion = 'Process-tree observation cannot attribute process creation to WMI. Requires WMI Activity/ETW, debugger/API telemetry, or a documented direct interface.'
        }
        'AMSIOrETWInteraction' {
            $status = 'NotAssertableByObserver'
            $assertion = 'Generic observation cannot attribute AMSI or ETW API calls. Requires ETW/API telemetry or code-level validation.'
        }
        'CredentialOrDumpAccess' {
            $status = 'NotAssertableByObserver'
            $assertion = 'The scanner does not perform credential access or memory dumping. Requires safe code review or dedicated telemetry.'
        }
        'ProcessInjectionPrimitives' {
            $status = 'NotAssertableByObserver'
            $assertion = 'The scanner does not perform process injection. Requires debugger/API/ETW telemetry or code review.'
        }
        'TaskOrServiceCreation' {
            $status = 'NotAssertableByObserver'
            $assertion = 'Generic observation does not create or attribute services/tasks. Requires SCM/Task Scheduler telemetry or a documented direct interface.'
        }
    }

    [pscustomobject]@{
        Capability = $capability
        ClaimStatus = $status
        Assertion = $assertion
        Evidence = $evidence
    }
}

$out = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'CapabilityAssertions.csv'
@($rows) | Export-Csv -NoTypeInformation -LiteralPath $out -Encoding UTF8
@($rows) | Format-Table -AutoSize
Write-Host "Capability assertion report: $out"
'@
    (Get-Content -LiteralPath $assertScript -Raw).Replace('__CAPABILITY_ARRAY__',$capabilityLiteral) |
        Set-Content -LiteralPath $assertScript -Encoding UTF8

    $runnerLines = New-Object System.Collections.Generic.List[string]
    $runnerLines.Add('$ErrorActionPreference = ''Stop''')
    $runnerLines.Add('$here = Split-Path -Parent $MyInvocation.MyCommand.Path')
    if($targetObserver){
        $runnerLines.Add('Write-Host ''=== Exact target behavior observation ===''')
        $runnerLines.Add('& (Join-Path $here ''Run-TargetBehaviorObservation.ps1'')')
    }
    if($directValidationCommand -and $directValidationCommand -notmatch 'Run-TargetBehaviorObservation\.ps1'){
        $runnerLines.Add('')
        $runnerLines.Add('Write-Host ''=== Direct capability-specific validation ===''')
        $runnerLines.Add($directValidationCommand)
    }
    if($EnableUnmanagedDllExportTest -and
       (Test-Path -LiteralPath (Join-Path $dir 'Run-TargetUnmanagedDllLoadTest.ps1')) -and
       -not (Test-Path -LiteralPath (Join-Path $dir 'Run-Rundll32UnmanagedExportTest.ps1'))){
        $runnerLines.Add('')
        $runnerLines.Add('Write-Host ''=== Forager-discovered target DLL-loading validation ===''')
        $runnerLines.Add('& (Join-Path $here ''Run-TargetUnmanagedDllLoadTest.ps1'')')
    }
    $runnerLines.Add('')
    $runnerLines.Add('Write-Host ''=== Forager claim assertions ===''')
    $runnerLines.Add('& (Join-Path $here ''Assert-ForagerClaims.ps1'')')

    $runValidation = Write-ValidationArtifact 'Run-Validation.ps1' ($runnerLines -join "`r`n")
    $validationCommand='& "{0}"' -f $runValidation

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
        'Validation rule:',
        '  Direct validation must execute the exact discovered application whenever',
        '  the scanner does not have a catalog-specific deterministic interface.',
        '  Static capability strings are kept separate from observed target behavior.',
        '  Supplemental primitive PoCs are educational and are never represented as',
        '  proof that an unknown target exposes that primitive to untrusted input.',
        '',
        'Expected result:',
        "  $expectedResult",
        '',
        'Primary validation command:',
        $(if($validationCommand){"  $validationCommand"}else{'  No automatic command generated. Follow the interface-specific notes below.'}),
        '',
        'Validation sequence:',
        '  1. Run-TargetBehaviorObservation.ps1 executes the exact discovered target when executable.',
        '  2. Forager-discovered loading surfaces are tested automatically when unmanaged DLL testing is enabled.',
        '  3. A safe direct capability-specific test runs when one is known.',
        '  4. Assert-ForagerClaims.ps1 classifies each capability claim against observed evidence.',
        '  5. PluginLoading is DirectlyValidated only when the exact target loads the generated DLL and invokes TestMethod.',
        '  6. CapabilityAssertions.csv records DirectlyValidated, StaticOnly, ObservedCorroboration,',
        '     TargetModulesObserved, NotObserved, or NotAssertableByObserver.',
        '',
        'Notes:',
        "  $notes",
        '',
        'Unmanaged export testing:',
        $(if($EnableUnmanagedDllExportTest){
            '  ENABLED: generated only where relevant. Uses Framework\v4.0.30319\ilasm.exe to build an x86 managed DLL with a real unmanaged PE export.'
        }else{
            '  DISABLED: use -EnableUnmanagedDllExportTest to generate the optional unmanaged-export DLL validation artifacts.'
        }),
        '  No standalone helper loader is used for target validation.',
        '  DiscoveredLoadingSurfaces.csv records product-specific loading interfaces inferred from this scan.',
        '  Run-TargetUnmanagedDllLoadTest.ps1 automatically selects only high-confidence DLL-path surfaces.',
        '  No defender-supplied argument template is required.',
        '  If no usable DLL-path interface is discovered, the test reports NotDirectlyTestable.',
        '  PASS requires the generated DLL to be observed in the exact target process tree and the TestMethod marker to be created.',
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
        DirectValidationCommand=$directValidationCommand
        ObservationScript=$targetObserver
        AssertionScript=$assertScript
        LoadingSurfaceDiscovery=$loadingSurfaceCsv
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

    # Static native primitives alone should not promote a signed Microsoft,
    # non-catalog application to Critical. Critical requires a known risky
    # catalog entry, a stronger managed/execution capability, or a discovered
    # high-confidence product-specific DLL loading surface.
    $loadingSurfacePreview=@()
    if(-not $catalog -and $isPe -and -not $isManaged -and ($cap.Capabilities -contains 'PluginLoading')){
        try { $loadingSurfacePreview=@(Get-LoadingSurfaceCandidates -FindingFile $file -StaticText $text) } catch {}
    }

    $hasAutoDllSurface = @($loadingSurfacePreview | Where-Object {
        $_.AutoUsable -eq $true -and [int]$_.Confidence -ge 85 -and $_.ArgumentTemplate -like '*{DLL}*'
    }).Count -gt 0

    $strongExecutionCapability = (
        $cap.Capabilities -contains 'ManagedCompilation' -or
        $cap.Capabilities -contains 'DynamicIL' -or
        $cap.Capabilities -contains 'PowerShellHosting' -or
        $cap.Capabilities -contains 'ScriptEngineHosting' -or
        $cap.Capabilities -contains 'ComRegistration' -or
        $cap.Capabilities -contains 'InstallerExecution'
    )

    if($isMicrosoft -and -not $catalog -and -not $isManaged -and
       -not $hasAutoDllSurface -and -not $strongExecutionCapability -and
       $score -ge 100){
        $score = 74
    }

    if(-not $catalog -and $score -lt $MinimumRiskScore){continue}

    $level=Get-RiskLevel -Score $score
    $recommendation=Get-WdacRecommendation -CatalogHit:([bool]$catalog) -Score $score -SigStatus $sig.Status -Writable:$writable -Capabilities @($cap.Capabilities)

    $validation=[pscustomobject]@{Directory='';ValidationType='';ValidationInterface='';ValidationCommand='';DirectValidationCommand='';ObservationScript='';AssertionScript='';LoadingSurfaceDiscovery='';ValidationExpectedResult='';Readme=''}
    if($level -eq 'Critical' -and -not $DisableCriticalValidation){
        try {
            if(-not (Test-Path $validationRoot)){ New-Item -ItemType Directory -Path $validationRoot -Force | Out-Null }
            $validation=New-CriticalValidationHarness -FindingFile $file -RootDirectory $validationRoot -Category $(if($catalog){$catalog.Category}else{''}) -Technique $(if($catalog){$catalog.Technique}else{''}) -Capabilities @($cap.Capabilities) -StaticText $text
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
        CapabilityConfidence=(ConvertTo-Json @($cap.Confidence) -Compress -Depth 4)
        MatchedIndicators=(ConvertTo-Json @($cap.Patterns) -Compress)
        ManagedIndicators=(ConvertTo-Json @($managedHits) -Compress)
        ValidationDirectory=$validation.Directory
        ValidationType=$validation.ValidationType
        ValidationInterface=$validation.ValidationInterface
        ValidationCommand=$validation.ValidationCommand
        DirectValidationCommand=$validation.DirectValidationCommand
        RunBehaviorObservation=$validation.ObservationScript
        AssertionScript=$validation.AssertionScript
        LoadingSurfaceDiscovery=$validation.LoadingSurfaceDiscovery
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
