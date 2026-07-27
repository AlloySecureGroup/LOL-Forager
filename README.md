# LOL-Forager

# WDAC / AppLocker Risky Application & LOLBin Capability Scanner

`LOL-Forager.ps1` inventories trusted, signed, unsigned, native, managed, and script-based applications present on a Windows host that may provide capabilities useful for executing unapproved code or weakening application-control boundaries.

The goal is to help defenders, detection engineers, and WDAC/AppLocker policy authors discover both:

1. **Known LOLBins / dual-use applications**, and
2. **Previously unknown or third-party applications with similar risky capabilities.**

The scanner does **not** exploit findings. It inventories capability and assigns a WDAC-oriented risk score so you can decide what should be explicitly denied, allowed with tighter rules, monitored, or investigated further.

For findings rated **Critical**, the scanner creates a validation harness that prioritizes execution of the **exact discovered application**.

Static capability indicators and observed target behavior are recorded separately.

A Critical result may contain static evidence such as `LoadLibrary`, `CreateProcess`, `WinHttpOpen`, `MiniDumpWriteDump`, `VirtualAllocEx`, `EventWrite`, or `OpenSCManager`. These indicators show that the capability may be present in the binary. They do not by themselves prove that the interface is reachable, attacker-controlled, or exercised during normal execution.

For known applications with a documented callable interface, the harness directly invokes that interface using the discovered binary.

For unknown or heuristic-only findings, the primary validation harness launches the exact discovered executable and records behavior that can be observed safely from outside the process, including loaded modules, descendant processes, and TCP connections. Supplemental primitive PoCs may also be generated, but they are not treated as proof that the discovered application exposes that primitive.

> Run this only on systems you are authorised to assess. A finding means that a binary is known to provide, or appears to contain, a capability that deserves application-control review. It does **not** prove maliciousness, successful WDAC bypass, or exploitability under your specific policy.

---

## What changed

The scanner has been expanded beyond the original managed in-memory compilation checks.

Major additions include:

- Broader known LOLBin and dual-use application catalog.
- Native **and** managed binary inspection.
- Discovery of unknown or third-party applications by capability fingerprints.
- Risk scoring based on combinations of capabilities rather than filename alone.
- Authenticode signer and publisher context.
- User-writable path detection.
- Script-file inspection with `-IncludeScripts`.
- Optional WinSxS coverage.
- WDAC-specific recommendation text for every emitted finding.
- Critical-finding target-validation directories.
- Direct invocation of supported discovered interpreters, compilers, runtime hosts, and other known applications.
- Exact-target execution for heuristic-only Critical findings.
- Loaded-module evidence from the discovered process and its descendants.
- Child-process evidence from the discovered process tree.
- TCP connection evidence from the discovered process tree.
- Supplemental PoCs for dynamic plugin loading, localhost remote-protocol use, AMSI/ETW interaction, and WMI process creation.
- Explicit separation between **static capability indicators**, **observed target behavior**, and **supplemental primitive reproduction**.
- CSV fields identifying the validation directory, type, risky interface, command, expected result, and README.

---

# How detection works

The scanner uses multiple independent layers. A known catalog match can be reported on its own, while unknown applications can be surfaced through capability analysis and risk scoring.

## Layer A: known LOLBin / dual-use application catalog

A curated catalog identifies Windows, .NET, developer, administrative, installer, debugger, transfer, and scripting utilities that deserve explicit WDAC review.

Unlike the earlier version, the catalog is intentionally broader than only .NET compilation and trusted-loader techniques.

Examples include:

| Category | Examples | Capability |
|---|---|---|
| Script hosts | `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `csi.exe`, `fsi.exe` | Script, managed-code, HTML application, or interactive-code execution |
| Shells | `cmd.exe`, `explorer.exe` | Command or shell-mediated execution |
| Compilers | `MSBuild.exe`, `csc.exe`, `vbc.exe`, `jsc.exe`, `ilasm.exe`, `aspnet_compiler.exe` | Source, IL, workflow, or build-task compilation |
| Runtime hosts | `dotnet.exe` | Managed assembly and .NET tool execution |
| Proxy execution | `InstallUtil.exe`, `RegAsm.exe`, `RegSvcs.exe`, `rundll32.exe`, `regsvr32.exe`, `control.exe`, `forfiles.exe`, `pcalua.exe` | Trusted or indirect execution paths |
| Download / transfer | `certutil.exe`, `bitsadmin.exe`, `curl.exe`, `desktopimgdownldr.exe`, `esentutl.exe` | Remote-content retrieval or file-transfer primitives |
| Installers | `msiexec.exe`, `winget.exe`, `appinstaller.exe`, `setup.exe` | Package installation or application deployment |
| Archive tools | `expand.exe`, `extrac32.exe` | Archive or CAB extraction |
| Debug / dump tools | `procdump.exe`, `createdump.exe`, `ntsd.exe`, `cdb.exe`, `windbg.exe`, `tttracer.exe` | Process dumping, debugging, or process inspection |
| Management / remote administration | `wmic.exe`, `sqlcmd.exe`, `sqlps.exe` | Process creation, remote administration, SQL, or management functionality |
| Developer tooling | `devenv.exe`, `vswhere.exe` | IDE, extension-hosting, or environment discovery capabilities |

Catalog presence is **not** an assertion that the binary is malicious or that it bypasses your policy. It means the application has capabilities that may require explicit treatment in a WDAC design.

The catalog is inspired by publicly documented living-off-the-land research such as the LOLBAS project, but it also contains broader dual-use applications that may not be classified as LOLBins.

---

## Layer B: managed-code capability fingerprints

Managed PE files are inspected for type names, APIs, and metadata associated with dynamic execution.

Examples include:

- CodeDom compilation.
- Roslyn compilation.
- `System.Reflection.Emit`.
- Dynamic methods and IL generation.
- PowerShell runspace hosting.
- .NET scripting engines.
- `Assembly.Load`, `LoadFrom`, and related assembly-loading APIs.
- `AssemblyLoadContext`.
- Managed installer execution.
- COM registration hooks.
- MEF / plugin-loading functionality.

This allows the scanner to identify applications that carry the same capability as a known LOLBin even when their filename is not in the catalog.

---

## Layer C: native + managed capability heuristics

The scanner also creates ASCII and UTF-16 text views of files and searches for capability indicators in both native and managed binaries.

Current capability groups include:

| Capability | Examples of indicators |
|---|---|
| Managed compilation | CodeDom, Roslyn, CodeTaskFactory |
| Dynamic IL | `AssemblyBuilder`, `DynamicMethod`, `ILGenerator` |
| PowerShell hosting | `System.Management.Automation`, runspaces |
| Script-engine hosting | ActiveScript, IronPython, F# interactive |
| Assembly loading | `Assembly.Load`, `AssemblyLoadContext`, `ExecuteAssembly` |
| Plugin / DLL loading | MEF, `LoadLibrary`, `GetProcAddress` |
| Child-process creation | `CreateProcess`, `ShellExecute`, `Process.Start` |
| Command-shell references | PowerShell, CMD, WSH, MSHTA |
| Network retrieval | WinHTTP, WinINet, `HttpClient`, `WebClient`, URL download APIs |
| Remote protocols | HTTP, HTTPS, FTP, UNC paths, WebSockets, named pipes |
| Installer execution | MSI and managed installer APIs |
| COM registration | Registration hooks and registration services |
| Credential / dump access | `MiniDumpWriteDump`, `ReadProcessMemory`, token APIs |
| Process-injection primitives | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, APCs |
| AMSI / ETW interaction | AMSI and event-writing APIs |
| Archive extraction | CAB, ZIP, and compression APIs |
| Task / service creation | SCM and Task Scheduler APIs |
| WMI execution | `Win32_Process`, WMI service interfaces |

A single generic string is deliberately given limited weight. Combinations of related capabilities increase the score more aggressively.

For example:

- network retrieval + child-process creation,
- assembly loading + network retrieval,
- command-shell references + child-process creation,
- managed compilation + assembly loading,
- process-injection primitives.

This helps surface previously unknown risky applications without treating every API reference as equally important.

---

## Layer D: WDAC-oriented risk scoring

Every finding receives a numeric `RiskScore` and corresponding `RiskLevel`.

Current severity thresholds are:

| Score | Risk level |
|---:|---|
| 100+ | **Critical** |
| 75-99 | **High** |
| 45-74 | **Medium** |
| 20-44 | **Low** |
| Below 20 | Informational |

The score can include:

- Known-catalog risk.
- Detected capability weights.
- Capability-combination bonuses.
- User-writable location.
- Missing or invalid Authenticode signature.
- Missing publisher/company metadata.
- Multiple managed-code indicators.

Microsoft-signed non-catalog files can receive a small noise reduction when the overall signal is still low. Dangerous capabilities are not removed simply because the binary is signed.

`-MinimumRiskScore` controls which non-catalog findings are emitted. Known catalog entries are still reported even if their score falls below that threshold.

---

# Optional unmanaged DLL export validation

Use:

```powershell
.\LOL-Forager.ps1 `
    -EnableUnmanagedDllExportTest `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

The switch is **off by default**.

For relevant `PluginLoading` / `AssemblyLoading` findings and `rundll32.exe`, the Critical validation directory can contain:

```text
UnmanagedExportTest.il
UnmanagedExportLoader.cs
Run-UnmanagedDllExportTest.ps1
```

The generated IL produces an x86 managed DLL with a real unmanaged PE export:

```text
TestMethod
```

The IL uses:

```text
.corflags 0x00000002
.vtfixup
.vtentry
.export [1] as TestMethod
```

and is assembled with:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe
```

The test loader is compiled with:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
```

using `/platform:x86`.

`Run-UnmanagedDllExportTest.ps1`:

```text
1. Assembles UnmanagedExportTest.il into UnmanagedExportTest.dll.
2. Compiles an x86 validation loader.
3. Calls LoadLibraryW on the generated DLL.
4. Calls GetProcAddress for TestMethod.
5. Invokes the unmanaged export.
6. Verifies that the export created UnmanagedExportExecuted.txt.
```

A successful test asserts:

```text
Generated DLL loaded successfully:
    YES

TestMethod present in PE export table / resolvable through GetProcAddress:
    YES

Export invocation executed managed IL:
    YES
```

When the Critical finding itself is `rundll32.exe`, the harness also generates:

```text
Run-Rundll32UnmanagedExportTest.ps1
```

That test:

```text
1. Builds UnmanagedExportTest.dll.
2. Uses the full path of the exact discovered rundll32.exe.
3. Invokes TestMethod from the generated DLL.
4. Verifies UnmanagedExportExecuted.txt.
5. Writes Rundll32UnmanagedExportResult.csv.
```

For `rundll32.exe`, successful marker creation is direct evidence that the exact discovered host loaded the generated DLL and invoked its exported method.



It does **not** assert:

```text
The discovered application accepts an attacker-selected DLL:
    NOT PROVEN

The discovered application's plugin path is attacker-controllable:
    NOT PROVEN

WDAC is bypassed:
    NOT PROVEN
```

For an unknown application such as `copilotapp.exe`, the target observer remains the primary evidence:

```powershell
.\Run-TargetBehaviorObservation.ps1 `
    -TargetPath "C:\Program Files (x86)\Microsoft\Edge\Application\150.0.4078.83\copilotapp.exe"
```

The unmanaged-export test is supplemental until a Copilot-specific DLL/plugin loading surface is identified and the exact `copilotapp.exe` process can be driven to load the generated test DLL.

## AppLocker versus WDAC interpretation

This switch exists to support controlled application-control comparison testing.

AppLocker has a separate DLL rule collection for `.dll` and `.ocx`, and that collection isn't enabled by default. When DLL rules are enabled, AppLocker checks DLLs loaded by allowed applications.

A successful unmanaged-export test therefore should be recorded as policy-test evidence, not automatically labeled an AppLocker or WDAC bypass.

For WDAC/App Control for Business, evaluate the generated DLL and loader behavior against the **effective WDAC policy** on the test system.

---

# Critical validation workflow

Every executable Critical finding receives these test artifacts:

```text
Run-Validation.ps1
Run-TargetBehaviorObservation.ps1
Assert-ForagerClaims.ps1
README.txt
TargetEvidence\
```

Capability-specific PoCs may also be generated when a safe deterministic test exists.

The normal entry point is:

```powershell
.\Run-Validation.ps1
```

The validation sequence is:

```text
1. Run-TargetBehaviorObservation.ps1
   |
   +-- launches the exact discovered executable
   +-- records process identity
   +-- records loaded modules
   +-- records descendant processes
   +-- records TCP connections

2. Direct capability-specific PoC
   |
   +-- runs only when a safe deterministic interface is known
   +-- uses the exact discovered executable for known applications

3. Assert-ForagerClaims.ps1
   |
   +-- compares Forager capability claims with collected target evidence
   +-- writes CapabilityAssertions.csv
```

The CSV report contains:

```text
ValidationDirectory
ValidationType
ValidationInterface
ValidationCommand
DirectValidationCommand
RunBehaviorObservation
AssertionScript
ValidationExpectedResult
ValidationReadme
```

`ValidationCommand` points to `Run-Validation.ps1`.

`RunBehaviorObservation` points to the exact-target observer.

`DirectValidationCommand` records a direct application-specific PoC when one is available.

`AssertionScript` points to the claim-classification script.

---

# Capability assertion states

`Assert-ForagerClaims.ps1` writes:

```text
CapabilityAssertions.csv
```

Each capability receives a `ClaimStatus`.

## ObservedCorroboration

Runtime behavior consistent with the capability was observed, but the evidence does not establish every part of the static claim.

Examples:

```text
ChildProcess
    descendant process observed

NetworkRetrieval
    TCP activity observed

RemoteProtocol
    TCP activity observed
```

For `NetworkRetrieval`, TCP activity does not by itself prove that a download occurred.

For `RemoteProtocol`, TCP activity does not by itself prove HTTP, HTTPS, FTP, WebSocket, or attacker-controlled endpoint behavior.

---

## TargetModulesObserved

Modules were actually observed in the discovered target process tree.

Used for capability classes such as:

```text
PluginLoading
AssemblyLoading
```

This confirms runtime module loading.

It does not by itself assert:

```text
arbitrary plugin loading
attacker-controlled DLL loading
Assembly.LoadFrom specifically
LoadLibrary specifically
DLL search-order hijacking
```

Those stronger claims require an identified application-controlled loading surface or stronger runtime/API telemetry.

---

## NotObserved

The generic observation window did not capture behavior corresponding to the capability.

Examples:

```text
no descendant process observed
no TCP connection observed
```

`NotObserved` does not mean the static finding is false.

The behavior may require:

```text
specific user interaction
specific command-line arguments
specific input files
authentication
application state
longer observation
a product-specific code path
```

---

## StaticOnly

The capability remains a static fingerprint finding.

No generic observer evidence directly validates it.

---

## NotAssertableByObserver

The external observer cannot safely or reliably attribute the capability.

This status is used for claims such as:

```text
WMIExecution
AMSIOrETWInteraction
CredentialOrDumpAccess
ProcessInjectionPrimitives
TaskOrServiceCreation
```

Examples:

```text
CreateRemoteThread
WriteProcessMemory
MiniDumpWriteDump
AmsiScanBuffer
EventWrite
OpenSCManager
Win32_Process.Create
```

These require stronger evidence such as:

```text
ETW
WMI Activity logs
SCM telemetry
Task Scheduler telemetry
debugger/API tracing
code-level validation
vendor documentation
a documented direct application interface
```

The scanner does not automatically perform process injection, credential access, protected-process dumping, service creation, task creation, AMSI tampering, or ETW tampering to validate these indicators.

---

# Critical example: copilotapp.exe

A Critical finding may look like:

```text
Path:
C:\Program Files (x86)\Microsoft\Edge\Application\150.0.4078.83\copilotapp.exe

RiskLevel:
Critical

Capabilities:
PluginLoading
ChildProcess
NetworkRetrieval
RemoteProtocol
CredentialOrDumpAccess
ProcessInjectionPrimitives
AMSIOrETWInteraction
TaskOrServiceCreation
```

Representative static indicators may include:

```text
PluginLoading:LoadLibrary
PluginLoading:LoadLibraryEx
PluginLoading:GetProcAddress
ChildProcess:CreateProcess
ChildProcess:CreateProcessW
ChildProcess:ShellExecute
NetworkRetrieval:WinHttpOpen
NetworkRetrieval:WinHttpConnect
RemoteProtocol:http://
RemoteProtocol:https://
CredentialOrDumpAccess:MiniDumpWriteDump
CredentialOrDumpAccess:ReadProcessMemory
CredentialOrDumpAccess:OpenProcessToken
ProcessInjectionPrimitives:VirtualAllocEx
ProcessInjectionPrimitives:WriteProcessMemory
ProcessInjectionPrimitives:CreateRemoteThread
AMSIOrETWInteraction:EventWrite
TaskOrServiceCreation:OpenSCManager
```

These are static capability indicators. They do not by themselves prove that `copilotapp.exe` exposes an attacker-controlled path to any of these interfaces.

The primary validation for this finding is to execute the exact discovered application:

```powershell
.\Run-Validation.ps1

# Or run the observer directly:
.\Run-TargetBehaviorObservation.ps1 `
    -TargetPath "C:\Program Files (x86)\Microsoft\Edge\Application\150.0.4078.83\copilotapp.exe"
```

The observer launches `copilotapp.exe` and writes evidence under:

```text
TargetEvidence\
    Summary-<timestamp>.txt
    Process-<timestamp>.csv
    LoadedModules-<timestamp>.csv
    ChildProcesses-<timestamp>.csv
    NetworkConnections-<timestamp>.csv
```

The observer samples the target process tree throughout the observation window and accumulates unique module, child-process, and TCP records. This allows short-lived descendants and transient TCP connections to remain in the evidence files even if they disappear before the observation ends.

After `Run-Validation.ps1`, the directory also contains:

```text
CapabilityAssertions.csv
```

For the example Copilot finding, a valid assertion report can contain results such as:

```text
Capability                    ClaimStatus
----------                    -----------
PluginLoading                 TargetModulesObserved
ChildProcess                  ObservedCorroboration / NotObserved
NetworkRetrieval              ObservedCorroboration / NotObserved
RemoteProtocol                ObservedCorroboration / NotObserved
CredentialOrDumpAccess        NotAssertableByObserver
ProcessInjectionPrimitives    NotAssertableByObserver
AMSIOrETWInteraction          NotAssertableByObserver
TaskOrServiceCreation         NotAssertableByObserver
```

The assertion file reports only evidence actually collected from the executed `copilotapp.exe` process tree.



Example interpretation:

```text
Static capability:
    LoadLibrary
    GetProcAddress

Observed target behavior:
    copilotapp.exe loaded winhttp.dll
    copilotapp.exe loaded another module
```

This confirms that module loading occurred in the executed Copilot process tree.

It does not automatically prove:

```text
attacker-controlled DLL
        |
        v
copilotapp.exe
        |
        v
LoadLibrary(...)
        |
        v
arbitrary code execution
```

To validate `PluginLoading` as a WDAC-relevant externally controllable execution path, defenders must identify an actual Copilot-controlled loading surface such as:

```text
documented plugin argument
extension argument
plugin directory
configuration file
manifest
COM registration
DLL search path
IPC request
URL scheme
other product-specific input
```

Only when `copilotapp.exe` itself is driven through that interface and loads the benign test component should the capability be considered directly validated.

For this reason, findings should be interpreted as:

```text
PluginLoading static indicator:
    YES

copilotapp.exe executed:
    YES

Module loading observed:
    YES or NO

Attacker-controllable plugin loading:
    VALIDATED / NOT VALIDATED
```

The same rule applies to the other capabilities.

For example:

```text
VirtualAllocEx present:
    static process-injection indicator

VirtualAllocEx actually exercised by copilotapp.exe:
    requires runtime/API telemetry or deeper instrumentation

MiniDumpWriteDump present:
    static dump-capability indicator

copilotapp.exe actually performing a dump:
    requires observed target behavior

EventWrite present:
    static ETW interaction indicator

copilotapp.exe actually emitting the relevant event:
    requires ETW/runtime evidence
```

Supplemental capability PoCs may be generated to show what a primitive looks like when exercised, but those PoCs are not evidence that `copilotapp.exe` exposes or uses that primitive.

---

# Critical finding validation

Every Critical finding receives a dedicated validation directory unless `-DisableCriticalValidation` is specified.

The primary rule is:

> A Critical validation result must involve the exact discovered executable whenever the scanner can safely launch it.

For known applications with a deterministic interface, the scanner directly exercises that interface.

For heuristic-only findings, the scanner launches the discovered target and captures observable evidence from that process and its descendants.

Static capability strings are not represented as observed behavior.

---

## Target behavior observation

Heuristic-only Critical findings receive:

```text
Run-TargetBehaviorObservation.ps1
TargetEvidence\
```

The generated script contains the full path of the exact discovered executable.

It launches that target and records:

```text
TargetEvidence\
    Summary-<timestamp>.txt
    Process-<timestamp>.csv
    LoadedModules-<timestamp>.csv
    ChildProcesses-<timestamp>.csv
    NetworkConnections-<timestamp>.csv
```

### Process evidence

`Process-*.csv` records:

- target path,
- root process ID,
- start time,
- observation duration,
- arguments,
- whether the process remained running.

### Loaded module evidence

`LoadedModules-*.csv` records modules actually observed in the discovered process or its descendants.

Typical fields include:

```text
ProcessId
ProcessName
ModuleName
FileName
BaseAddress
ModuleSize
```

This evidence is relevant to capabilities such as:

```text
PluginLoading
AssemblyLoading
LoadLibrary
LoadLibraryEx
GetProcAddress
```

Observed module loading confirms that DLL or module loading occurred in the target process tree.

It does not by itself prove that an attacker can choose an arbitrary DLL or plugin.

### Child process evidence

`ChildProcesses-*.csv` records descendant processes observed beneath the discovered target.

Typical fields include:

```text
ProcessId
ParentProcessId
Name
ExecutablePath
CommandLine
```

This evidence is relevant to capabilities such as:

```text
ChildProcess
WMIExecution
TaskOrServiceCreation
ShellExecute
CreateProcess
CreateProcessW
CreateProcessA
```

Observed descendants confirm child-process activity.

They do not by themselves identify the exact creation API.

### Network evidence

`NetworkConnections-*.csv` records TCP connections associated with the target or its descendants when available.

Typical fields include:

```text
OwningProcess
State
LocalAddress
LocalPort
RemoteAddress
RemotePort
```

This evidence is relevant to capabilities such as:

```text
NetworkRetrieval
RemoteProtocol
WinHttpOpen
WinHttpConnect
HTTP
HTTPS
FTP
WebSocket
```

Observed connections confirm that network activity occurred in the target process tree.

They do not by themselves prove that an untrusted user can control the remote endpoint.

---

# Capability interpretation

The scanner reports capability classes separately from observed target behavior.

## PluginLoading

Representative indicators include:

```text
LoadLibrary
LoadLibraryEx
GetProcAddress
Assembly.Load
Assembly.LoadFrom
AssemblyLoadContext
MEF
Plugin
AddIn
```

For a Critical heuristic finding, the exact discovered application is launched and its loaded modules are captured.

A supplemental managed plugin PoC may also be generated that:

1. Builds a benign plugin DLL.
2. Loads the DLL dynamically.
3. Resolves an exported type.
4. Resolves a method through reflection.
5. Invokes that method.

The supplemental PoC demonstrates the risky loading primitive.

Only the target-observation evidence is treated as evidence about the discovered executable itself.

---

## ChildProcess

Representative indicators include:

```text
CreateProcess
CreateProcessW
CreateProcessA
ShellExecute
ShellExecuteEx
Process.Start
```

The target-observation harness launches the discovered executable and records descendants.

A child process appearing beneath the target is observed execution evidence.

The scanner does not claim a specific API was used unless that path is otherwise known.

---

## NetworkRetrieval

Representative indicators include:

```text
WinHttpOpen
WinHttpConnect
URLDownloadToFile
InternetOpen
InternetOpenUrl
HttpClient
WebClient
DownloadString
DownloadFile
```

The exact discovered executable is launched.

TCP connections from the target process tree are recorded where available.

Static networking indicators remain static evidence until corroborated by observed behavior or a documented application interface.

---

## RemoteProtocol

Representative indicators include:

```text
http://
https://
ftp://
ws://
wss://
UNC
NamedPipe
```

The exact discovered executable is launched and network activity is observed.

A supplemental localhost-only HTTP PoC may be generated to demonstrate the protocol primitive without contacting an external system.

The localhost PoC is supplemental evidence only.

---

## CredentialOrDumpAccess

Representative indicators include:

```text
MiniDumpWriteDump
MiniDump
DbgHelp
ReadProcessMemory
OpenProcessToken
DuplicateToken
AdjustTokenPrivileges
```

These indicators are reported as static capability evidence.

The target may be launched for behavior observation, but the scanner does not automatically attempt credential access, memory dumping, token manipulation, or privileged process access.

No destructive or credential-access PoC is generated.

---

## ProcessInjectionPrimitives

Representative indicators include:

```text
VirtualAllocEx
WriteProcessMemory
CreateRemoteThread
NtCreateThreadEx
QueueUserAPC
MapViewOfFile
SetThreadContext
```

These indicators are reported as static capability evidence.

The scanner does not automatically perform process injection.

The target may be launched and observed, but static injection-related strings remain unconfirmed until validated through safe instrumentation, code review, debugger telemetry, ETW, or vendor documentation.

---

## AMSIOrETWInteraction

Representative indicators include:

```text
AmsiInitialize
AmsiScanString
AmsiScanBuffer
EventWrite
EventSource
TraceEvent
```

The exact discovered executable is launched for target-specific observation.

A supplemental benign PoC may:

- initialize AMSI,
- submit benign content to AMSI,
- report the AMSI result,
- emit a normal ETW/EventSource event.

The scanner does not patch, disable, bypass, suppress, or tamper with AMSI or ETW.

The supplemental PoC demonstrates the interface itself.

It is not evidence that the discovered application exercised that interface.

---

## TaskOrServiceCreation

Representative indicators include:

```text
OpenSCManager
CreateService
StartService
TaskScheduler
ITaskService
schtasks
```

These indicators are reported as static capability evidence.

The exact discovered executable may be launched and descendant processes recorded.

The scanner does not automatically create services, scheduled tasks, persistence, or privileged configuration changes.

---

## WMIExecution

Representative indicators include:

```text
Win32_Process
Win32_Process.Create
IWbemServices
ManagementObject
ManagementClass
CIM
```

The exact discovered executable is launched and child-process behavior is recorded.

A supplemental benign WMI PoC may call:

```text
Win32_Process.Create
```

to create a local marker-producing command.

The supplemental PoC demonstrates WMI process creation.

It is not evidence that the discovered application used WMI unless WMI-specific telemetry or a documented application interface confirms that attribution.

---

# Direct interface validation

Known applications with deterministic interfaces can receive direct capability-specific validation.

Examples include:

| Application | Interface demonstrated |
|---|---|
| `powershell.exe` | PowerShell script execution |
| `pwsh.exe` | PowerShell script execution |
| `wscript.exe` | VBScript execution |
| `cscript.exe` | VBScript execution |
| `csc.exe` | C# source compilation |
| `vbc.exe` | Visual Basic source compilation |
| `csi.exe` | C# interactive execution |
| `dotnet.exe` | Managed application/project execution |
| `MSBuild.exe` | Inline MSBuild task execution |
| `mshta.exe` | Local HTA execution |

The full discovered path is used.

---

# Supplemental primitive PoCs

Supplemental PoCs exist to show defenders what a detected capability looks like when exercised.

They are not substitutes for target-specific evidence.

Examples include:

```text
PluginLoading
RemoteProtocol
AMSIOrETWInteraction
WMIExecution
```

A supplemental PoC is clearly described as independent primitive reproduction.

For unknown applications, it is never presented as proof that the target accepts attacker-controlled plugins, URLs, WMI commands, DLLs, or other inputs.

---

# Static indicators versus observed behavior

The CSV can contain a Critical finding with indicators such as:

```text
PluginLoading:LoadLibrary
PluginLoading:GetProcAddress
ChildProcess:CreateProcess
NetworkRetrieval:WinHttpOpen
RemoteProtocol:https://
CredentialOrDumpAccess:MiniDumpWriteDump
ProcessInjectionPrimitives:VirtualAllocEx
AMSIOrETWInteraction:EventWrite
TaskOrServiceCreation:OpenSCManager
```

These are **static indicators**.

The validation directory can then contain evidence such as:

```text
LoadedModules-*.csv
ChildProcesses-*.csv
NetworkConnections-*.csv
```

These are **observed target behaviors**.

The two are intentionally kept separate.

Example interpretation:

```text
Static:
    LoadLibrary
    GetProcAddress

Observed:
    copilotapp.exe loaded winhttp.dll
    copilotapp.exe loaded example.dll
```

This confirms that module loading occurred in the executed target.

It does not automatically prove that an attacker can make the application load an arbitrary DLL.

---

# Generated Critical README

Every Critical validation directory contains a `README.txt` recording:

```text
Finding
Category
Technique
Capabilities
Validation type
Risky interface demonstrated
Expected result
Suggested validation command
Notes
Generated artifacts
```

The README distinguishes:

```text
Static capability indicators
Observed target behavior
Direct interface validation
Supplemental primitive reproduction
```

---

# Validation safety

The scanner does not automatically execute generated validation commands. `-EnableUnmanagedDllExportTest` only generates the unmanaged-export artifacts; execution occurs when the defender runs the generated validation harness.

The generated target-observation harness launches the exact discovered executable only when the defender runs the harness.

Supplemental PoCs remain local and benign. PoCs requiring C# compilation default to `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe`.

The scanner does not automatically:

- inject into another process,
- dump credentials,
- dump protected process memory,
- disable AMSI,
- disable ETW,
- create persistence,
- create a service,
- create a scheduled task,
- use remote WMI,
- contact attacker-controlled infrastructure,
- modify WDAC policy.

Disable Critical validation artifact generation with:

```powershell
-DisableCriticalValidation
```

---


## Windows PowerShell 5.1 observer

The observer uses ordinary PowerShell arrays/objects for module export and does not pipe the generic module collection directly into `Sort-Object`. This avoids the Windows PowerShell 5.1 `Argument types do not match` failure.


The generated target observer materializes module, child-process, and network records into normal PowerShell objects before sorting and exporting them.

A working standalone observer can be used directly inside a Critical validation directory:

```powershell
.\Run-Validation.ps1

# Or run the observer directly:
.\Run-TargetBehaviorObservation.ps1 `
    -TargetPath "C:\Program Files (x86)\Microsoft\Edge\Application\150.0.4078.83\copilotapp.exe"
```

`Run-TargetBehaviorObservation.ps1` expects an executable or script target.

Do not pass a DLL directly:

```powershell
.\Run-TargetBehaviorObservation.ps1 .\BenignPlugin.dll
```

A DLL requires an appropriate loader or host. Plugin DLL PoCs use the generated plugin loader instead.


# Requirements

## Expected C# compiler path

Generated PoC harnesses that require `csc.exe` use the following compiler path by default:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
```

The generated harness validates that this file exists before compilation. If it is not present, the PoC stops with an explicit error rather than silently selecting another compiler from `PATH`.

For a Critical finding where the discovered application itself is `csc.exe`, direct target validation still uses the exact discovered `csc.exe` path so the reported finding is the binary being exercised.

- Windows PowerShell 5.1 or PowerShell 7+.
- Read access to all locations being scanned.
- Administrative privileges are recommended for complete Windows and Program Files coverage.
- Enough disk space for the CSV report and Critical validation directories.
- No decompiler is required by the current scanner.

For broad enterprise-software discovery, run the scanner elevated.

---

# Usage

## Standard discovery scan

```powershell
.\LOL-Forager.ps1 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This scans the default Windows, .NET, Program Files, dotnet, and ProgramData locations.

---

## Fast catalog-only inventory

```powershell
.\LOL-Forager.ps1 `
    -CatalogOnly
```

This skips capability byte scanning and reports known catalog entries only.

---

## Broader discovery

```powershell
.\LOL-Forager.ps1 `
    -IncludeWinSxS `
    -IncludeScripts `
    -MinimumRiskScore 20 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This is useful when building or reviewing a stricter WDAC policy and you want maximum discovery coverage.

---

## Higher-signal scan

```powershell
.\LOL-Forager.ps1 `
    -MinimumRiskScore 60 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This reduces lower-risk heuristic findings.

Catalog matches still emit.

---

## EXE-only scan

```powershell
.\LOL-Forager.ps1 `
    -ExeOnly
```

This reduces scan scope, but it will miss capability-bearing DLLs and scripts.

---

## Disable Critical validation files

```powershell
.\LOL-Forager.ps1 `
    -DisableCriticalValidation `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

---

## Target selected directories

```powershell
.\LOL-Forager.ps1 `
    -ScanPaths @(
        'C:\Program Files',
        'C:\Program Files (x86)',
        'C:\ProgramData',
        'C:\Tools'
    ) `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

Custom enterprise application and tooling directories are particularly useful when searching for previously unknown dual-use applications.

---

# Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-ScanPaths` | Windows framework/GAC trees, System32, SysWOW64, Program Files, dotnet, ProgramData | Roots to recursively inspect |
| `-IncludeWinSxS` | Off | Also scan `C:\Windows\WinSxS`; slower and potentially noisy |
| `-IncludeScripts` | Off | Include `.ps1`, `.cmd`, `.bat`, `.vbs`, `.js`, `.jse`, and `.wsf` |
| `-OutputCsv` | `.\WdacRiskDiscovery.csv` | CSV report destination |
| `-MaxFileSizeMB` | `96` | Maximum file size for string/capability scanning |
| `-MinimumRiskScore` | `20` | Minimum score required for non-catalog findings |
| `-ExeOnly` | Off | Inspect only `.exe` files |
| `-CatalogOnly` | Off | Only report known catalog entries |
| `-DisableCriticalValidation` | Off | Do not create Critical capability-specific PoC directories |
| `-EnableUnmanagedDllExportTest` | Off | Generate an opt-in x86 IL DLL with a real unmanaged export plus a `LoadLibrary`/`GetProcAddress` validation harness for relevant DLL-loading findings |

Known catalog findings are still considered even when a file is too large for the string scan.

---

# Default scan locations

The default configuration includes:

```text
C:\Windows\Microsoft.NET\Framework
C:\Windows\Microsoft.NET\Framework64
C:\Windows\Microsoft.NET\FrameworkArm64
C:\Windows\Microsoft.NET\assembly
C:\Windows\assembly
C:\Windows\System32
C:\Windows\SysWOW64
C:\Program Files
C:\Program Files (x86)
C:\Program Files\dotnet
C:\ProgramData
```

`C:\Windows\WinSxS` is added only when `-IncludeWinSxS` is supplied.

---

# Output columns

| Column | Meaning |
|---|---|
| `RiskScore` | Final weighted score |
| `RiskLevel` | `Critical`, `High`, `Medium`, `Low`, or `Informational` |
| `Path` | Full path to the finding |
| `FileName` | File name |
| `Extension` | File extension |
| `SizeKB` | File size in KB |
| `IsPE` | Whether the file has a PE `MZ` header |
| `IsManaged` | Whether the PE contains a CLR header |
| `UserWritableLocation` | Whether the path matches common user-writable locations |
| `CatalogMatch` | Whether the filename matched the known-risk catalog |
| `CatalogCategory` | Catalog capability category |
| `CatalogTechnique` | Catalog description of the relevant capability |
| `SignatureStatus` | Result from `Get-AuthenticodeSignature` |
| `Signer` | Signing certificate subject |
| `Company` | File-version company metadata |
| `Product` | File-version product metadata |
| `Description` | File description |
| `OriginalFileName` | Original filename from version metadata |
| `FileVersion` | File version |
| `Capabilities` | JSON array of capability categories detected |
| `MatchedIndicators` | JSON array of capability and string indicators |
| `ManagedIndicators` | JSON array of additional managed-code fingerprints |
| `ValidationDirectory` | Critical capability-PoC directory |
| `ValidationType` | Direct target validation, target-observation mode, or supplemental capability-PoC classification |
| `ValidationInterface` | Risky interface or target behavior being validated or observed |
| `ValidationCommand` | Suggested command for running the generated benign PoC |
| `ValidationExpectedResult` | Evidence expected from the exact target or from a clearly labeled supplemental primitive PoC |
| `ValidationReadme` | Path to the finding-specific validation README |
| `WdacRecommendation` | Suggested WDAC review action based on current evidence |

---

# WDAC recommendation examples

The scanner generates a recommendation based on the finding context.

Examples include:

- `Explicitly evaluate for deny/exception rule; validate operational dependency first`
- `Strong deny candidate; unsigned risky executable in writable location`
- `High-priority WDAC review; consider explicit deny unless business-required`
- `Review for signer/file-name scoped deny or managed-installer restrictions`
- `Inventory and validate business need; tighten publisher/path trust where practical`
- `Monitor/inventory; weak standalone signal`

These are triage recommendations, not automated policy decisions.

---

# Interpreting results

## Critical does not mean malware

`Critical` means the scanner observed enough capability and environmental risk signals to make the file a high-priority WDAC review target.

Examples can include legitimate:

- Microsoft operating-system utilities.
- Developer compilers.
- Enterprise management tools.
- Debuggers.
- Software deployment utilities.
- Administrative automation products.

The correct question is not simply:

> Is this file malicious?

For WDAC policy engineering, the more useful questions are:

> Does this binary need to be available to this user or workload?

and:

> If it remains trusted, can it be used to execute content that WDAC would otherwise prevent?

---

## Signature status is context, not immunity

A correctly signed binary can still be highly relevant.

In fact, signed trusted applications are often particularly important during WDAC policy review because an attacker may attempt to abuse an already trusted binary rather than introduce a new unsigned executable.

Conversely, an unsigned executable located in a user-writable directory receives additional risk weight because it combines execution capability with a weaker trust boundary.

---

## User-writable location detection is heuristic

The scanner currently treats paths such as the following as writable-risk indicators:

- User-profile locations.
- `AppData`.
- Downloads.
- Temp directories.
- `C:\Users\Public`.
- `C:\ProgramData`.

This is a path heuristic and does not inspect effective NTFS ACLs.

A future improvement could replace or supplement this with actual access-control evaluation.

---

## String fingerprints are not a call graph

Capability discovery uses raw ASCII and UTF-16 string inspection.

This provides broad native and managed coverage, but a matched API name can exist because of:

- a real imported function,
- a real managed reference,
- dead code,
- diagnostic functionality,
- documentation embedded in the binary,
- a string literal,
- a library that contains the capability but does not expose it to the user.

For that reason, multiple capability matches and environmental context are weighted more heavily than isolated strings.

Treat heuristic matches as review leads rather than definitive proof.

---

# Interpreting capability-PoC results

The generated PoCs are intended to improve triage quality.

For a known application, successful direct validation provides stronger evidence that the exact discovered binary exposes the documented risky surface.

For a heuristic-only finding, successful primitive reproduction confirms that the detected API/interface represents a meaningful capability class, but defenders must still determine how—or whether—the specific product exposes that capability to users, plugins, documents, configuration, IPC, or command-line input.

This distinction should be preserved when translating scan results into WDAC policy decisions.

---

# Using results to improve WDAC

A useful workflow is:

1. Run LOL-Forager on representative workstation and server builds.
2. Sort findings by `RiskLevel` and `RiskScore`.
3. Review all known catalog applications that are currently trusted.
4. Review Critical and High unknown applications.
5. Examine signer, company, location, and detected capability combinations.
6. Use Critical validation harnesses where appropriate.
7. Determine whether each application is operationally required.
8. Compare findings against your current WDAC allow and deny rules.
9. Test candidate restrictions in audit mode.
10. Move validated rules into enforcement through your normal change-control process.

Avoid creating deny rules solely from the numerical score.

---

# Known limitations

- The known-risk catalog is not exhaustive.
- LOLBAS and other living-off-the-land research evolves over time.
- Third-party applications can expose dangerous functionality under completely different filenames.
- Raw string inspection can produce false positives.
- Packed, encrypted, compressed, or obfuscated binaries may hide useful indicators.
- Runtime-resolved APIs may not appear as strings.
- User-writable detection does not currently evaluate NTFS ACLs.
- The scanner does not evaluate the effective WDAC policy.
- The scanner does not determine whether a specific application is currently allowed or denied.
- The scanner does not automatically execute generated capability PoCs.
- A successful capability PoC does not prove policy bypass.
- A failed capability PoC does not prove a finding is safe.

This tool should be treated as an **application-control attack-surface inventory and policy-engineering aid**, not an exploit scanner or incident-response detector.

---

# Safety

LOL-Forager is intended for defensive application-control assessment.

The scanner:

- inventories files,
- reads file metadata,
- checks signatures,
- scans file content for capability indicators,
- calculates a risk score,
- generates CSV output,
- creates benign, capability-specific PoC artifacts for Critical findings.

It does **not** automatically execute the discovered applications or validation commands.

Run generated PoCs only in an authorised test environment and evaluate the evidence in the context of your actual WDAC or AppLocker policy.
