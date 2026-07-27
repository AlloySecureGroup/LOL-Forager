# LOL-Forager

# WDAC / AppLocker Risky Application & LOLBin Capability Scanner

`Scan-WdacRiskyApplications-WithValidation.ps1` inventories trusted, signed, unsigned, native, managed, and script-based applications present on a Windows host that may provide capabilities useful for executing unapproved code or weakening application-control boundaries.

The goal is to help defenders, detection engineers, and WDAC/AppLocker policy authors discover both:

1. **Known LOLBins / dual-use applications**, and
2. **Previously unknown or third-party applications with similar risky capabilities.**

The scanner does **not** exploit findings. It inventories capability and assigns a WDAC-oriented risk score so you can decide what should be explicitly denied, allowed with tighter rules, monitored, or investigated further.

For findings rated **Critical**, the scanner can also create a benign validation harness containing PowerShell, VBScript, and C# `Hello World` samples. Where the discovered binary is a supported interpreter or compiler, the report includes a command that can use the **actual discovered binary** to run or compile the benign sample.

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
- Critical-finding validation directories.
- Benign PowerShell, VBScript, and C# `Hello World` proof artifacts.
- Validation commands for supported PowerShell, Windows Script Host, and C# compiler findings.
- CSV fields identifying the validation directory, type, command, and README.

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

# Critical finding validation

By default, every finding whose final `RiskLevel` is **Critical** receives a validation directory next to the CSV report.

For example:

```text
WdacRiskDiscovery.csv

WdacRiskDiscovery-CriticalValidation\
    powershell.exe_A1B2C3D4\
        HelloWorld.ps1
        HelloWorld.vbs
        HelloWorld.cs
        README.txt

    csc.exe_11223344\
        HelloWorld.ps1
        HelloWorld.vbs
        HelloWorld.cs
        README.txt
```

The suffix is derived from a short hash of the discovered file's full path so multiple copies of the same filename can be kept separate.

## Generated validation artifacts

Each Critical directory contains:

### PowerShell

```powershell
Write-Host "Hello World"
```

### VBScript

```vbscript
WScript.Echo "Hello World"
```

### C#

```csharp
using System;

public static class HelloWorld
{
    public static void Main()
    {
        Console.WriteLine("Hello World");
    }
}
```

These files are intentionally benign.

They are generated to help determine whether an application can perform the interpreter or compiler behavior identified by the scanner without requiring an offensive payload.

---

## Supported automatic validation commands

The scanner **does not execute validation automatically**.

For selected Critical findings, it writes a suggested command into the CSV and per-finding README.

Currently supported:

| Binary | Validation |
|---|---|
| `powershell.exe` | Runs generated `HelloWorld.ps1` with the discovered Windows PowerShell binary |
| `pwsh.exe` | Runs generated `HelloWorld.ps1` with the discovered PowerShell binary |
| `wscript.exe` | Runs generated `HelloWorld.vbs` |
| `cscript.exe` | Runs generated `HelloWorld.vbs` |
| `csc.exe` | Compiles generated `HelloWorld.cs`, then runs the resulting executable |
| C# compiler-like Critical findings matching `*csc*.exe` | Same C# compile-and-run validation |

For other Critical findings the artifacts are still created, but `ValidationType` is set to `ArtifactOnly` and no execution command is generated.

This is deliberate. A generic Hello World command would not meaningfully validate capabilities such as process dumping, DLL proxy execution, service creation, network retrieval, or process injection.

> A successful Hello World test confirms that the discovered application can perform the tested benign interpreter/compiler behavior. It does **not** prove maliciousness or a WDAC bypass. A failed Hello World test also does **not** automatically mean the original detection was a false positive.

Disable validation artifact creation with:

```powershell
-DisableCriticalValidation
```

---

# Requirements

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
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This scans the default Windows, .NET, Program Files, dotnet, and ProgramData locations.

---

## Fast catalog-only inventory

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -CatalogOnly
```

This skips capability byte scanning and reports known catalog entries only.

---

## Broader discovery

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -IncludeWinSxS `
    -IncludeScripts `
    -MinimumRiskScore 20 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This is useful when building or reviewing a stricter WDAC policy and you want maximum discovery coverage.

---

## Higher-signal scan

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -MinimumRiskScore 60 `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

This reduces lower-risk heuristic findings.

Catalog matches still emit.

---

## EXE-only scan

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -ExeOnly
```

This reduces scan scope, but it will miss capability-bearing DLLs and scripts.

---

## Disable Critical validation files

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
    -DisableCriticalValidation `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

---

## Target selected directories

```powershell
.\Scan-WdacRiskyApplications-WithValidation.ps1 `
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
| `-DisableCriticalValidation` | Off | Do not create Critical Hello World validation directories |

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
| `ValidationDirectory` | Critical validation harness directory |
| `ValidationType` | `PowerShellHost`, `VBScriptHost`, `CSharpCompiler`, `ArtifactOnly`, etc. |
| `ValidationCommand` | Suggested benign validation command when supported |
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

# False-positive validation

The Critical validation harness is designed to provide a simple, controlled proof for interpreter and compiler findings.

For example, if an unknown signed application is identified as a C# compiler, successfully compiling:

```text
Hello World
```

with that exact executable provides stronger evidence that the identified compiler capability is real.

However, the following distinction is important:

**Capability validation is not exploit validation.**

A Hello World test can demonstrate:

- script interpretation,
- compilation,
- execution of the resulting benign program.

It does not automatically demonstrate:

- WDAC bypass,
- arbitrary DLL proxy execution,
- remote payload retrieval,
- process injection,
- credential access,
- privilege escalation,
- persistence,
- policy escape.

Those capabilities require separate policy-aware review.

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
- The scanner does not automatically execute proof-of-capability tests.
- A successful validation test does not prove policy bypass.
- A failed validation test does not prove a finding is safe.

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
- creates benign Hello World validation artifacts for Critical findings.

It does **not** automatically execute the discovered applications or validation commands.

Run validation only in an authorised test environment and evaluate the results in the context of your actual WDAC or AppLocker policy.
