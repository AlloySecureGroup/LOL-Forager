# LOL-Forager v9

## WDAC / AppLocker Capability Discovery Scanner

`LOL-Forager-v9.ps1` discovers risky and dual-use applications from capability evidence.

v9 intentionally does **not** use a known-LOLBin filename catalog for discovery or scoring.

A binary is emitted because Forager found capability evidence in the file and its calculated score met the configured threshold.

The built-in self-test corpus is separate from discovery and exists only to verify that the detector and benign validation harness are working as expected.

> Run this only on systems you are authorised to assess. Findings identify capabilities and review targets; they do not automatically prove maliciousness or policy bypass.

---

# Discovery model

Normal scanning uses:

- managed-code capability fingerprints,
- native and managed string/API indicators,
- evidence-strength weighting,
- capability combinations,
- signer and publisher context,
- writable-location context,
- target-specific loading-surface discovery,
- target-specific runtime validation for Critical findings.

There is no filename-based LOLBin allowlist/blocklist/catalog feeding the detector.

The normal scan report uses:

```text
DiscoverySource = CapabilityHeuristics
```

There are no `CatalogMatch`, `CatalogCategory`, or `CatalogTechnique` fields in v9.

---

# Capability additions in v9

v9 includes capability fingerprints intended to rediscover representative trusted binaries without relying on their names.

## BuildTaskExecution

Representative indicators:

```text
CodeTaskFactory
RoslynCodeTaskFactory
Microsoft.Build.Tasks
Microsoft.Build.Execution
BuildManager
UsingTask
```

This is intended to surface build engines that can execute build tasks or inline code.

## InstallerExecution

Representative strong indicators include:

```text
System.Configuration.Install
ManagedInstallerClass
InstallHelper
RunInstallerAttribute
MsiInstallProduct
```

## ComRegistration

Representative indicators include:

```text
ComRegisterFunctionAttribute
ComUnregisterFunctionAttribute
RegistrationServices
RegisterAssembly
UnregisterAssembly
RegistrationClassContext
RegistrationConnectionType
```

## DllRegistrationLoader

Representative indicators:

```text
DllRegisterServer
DllUnregisterServer
DllInstall
```

This identifies native DLL-registration-loader functionality independently of an executable filename.

---

# Self-test corpus

Use:

```powershell
.\LOL-Forager-v9.ps1 `
    -RunSelfTestCorpus `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

For the complete corpus, including the temporary RegAsm registration test:

```powershell
.\LOL-Forager-v9.ps1 `
    -RunSelfTestCorpus `
    -AllowSelfTestStateChange `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

`-AllowSelfTestStateChange` should be used only in an authorised disposable test VM or snapshot.

The corpus contains four benchmark cases:

| Case | Detector must independently find | Benign direct PoC |
|---|---|---|
| MSBuild | `BuildTaskExecution` or `ManagedCompilation` | Exact discovered `MSBuild.exe` executes a generated inline `CodeTaskFactory` task |
| InstallUtil | `InstallerExecution` | Exact discovered `InstallUtil.exe` invokes a generated `[RunInstaller(true)]` installer class |
| RegAsm | `ComRegistration` | Exact discovered `RegAsm.exe` invokes a generated `[ComRegisterFunction]` hook |
| Regsvr32 | `DllRegistrationLoader` | Exact discovered x86 `regsvr32.exe` loads a generated IL DLL and invokes `DllRegisterServer` |

The corpus names are used **only after scanning** to select benchmark targets.

They do not:

```text
add a finding
increase a risk score
force a capability classification
bypass MinimumRiskScore
create a normal scan result
```

---

# What constitutes a corpus pass

Every benchmark case evaluates detection and execution independently.

A case passes only when all three are true:

```text
DetectorReported             = True
ExpectedCapabilityDetected   = True
PoCPassed                    = True
```

Therefore:

```text
OverallPassed = True
```

A successful PoC cannot hide a detector miss.

Likewise, a detector hit cannot hide a broken PoC.

---

# Self-test output

By default, the corpus is written beside the main report:

```text
WdacRiskDiscovery-SelfTestCorpus-v9\
```

The directory contains:

```text
SelfTestCorpusDefinitions.csv
SelfTestCorpusResults.csv
SelfTestCorpusSummary.txt

MSBuild\
InstallUtil\
RegAsm\
Regsvr32\
```

The output directory can be changed with:

```powershell
-SelfTestOutputDirectory C:\Reports\LOLForagerCorpus
```

---

# SelfTestCorpusResults.csv

Important fields include:

| Column | Meaning |
|---|---|
| `Case` | Benchmark case |
| `TargetPath` | Exact binary used for the benchmark |
| `DetectorReported` | Whether normal v9 discovery emitted this exact binary |
| `DetectorRiskScore` | Risk score assigned by normal capability discovery |
| `DetectorRiskLevel` | Risk level assigned by normal capability discovery |
| `ExpectedCapabilities` | Capability class expected from the benchmark |
| `DetectedCapabilities` | Capabilities actually emitted by Forager |
| `ExpectedCapabilityDetected` | Whether at least one expected capability was found |
| `PoCExecuted` | Whether the exact-binary PoC ran |
| `PoCPassed` | Whether the capability PoC created its expected evidence |
| `Status` | `Passed`, `DetectorMiss`, `CapabilityClassificationMiss`, `PoCSkipped`, `PoCFailed`, or `TargetNotPresent` |
| `MarkerPath` | Marker produced only after the capability-specific PoC executes |
| `Detail` | Description of the direct test |
| `OverallPassed` | Detector + classification + PoC all passed |

---

# MSBuild corpus case

v9 prefers:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
```

when that binary is present in the scanned candidates.

The detector is not told this filename during normal scanning.

The benchmark later checks whether normal discovery reported that exact file with:

```text
BuildTaskExecution
```

or:

```text
ManagedCompilation
```

The generated PoC creates:

```text
MSBuild-Capability-PoC.proj
MSBuild-PoC-Executed.txt
```

The project contains a benign inline `CodeTaskFactory` task.

The exact selected `MSBuild.exe` executes:

```text
MSBuild-Capability-PoC.proj /target:LOLForager
```

The test passes only when the inline task creates:

```text
MSBuild-PoC-Executed.txt
```

This verifies both:

```text
Forager independently discovered the capability
AND
the exact benchmark binary can exercise that capability
```

---

# InstallUtil corpus case

v9 prefers:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe
```

The expected discovery capability is:

```text
InstallerExecution
```

The benchmark generates:

```text
InstallUtil-Capability-PoC.cs
InstallUtil-Capability-PoC.exe
InstallUtil-PoC-Executed.txt
```

Compilation uses:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
```

with:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Configuration.Install.dll
```

The generated assembly contains:

```csharp
[RunInstaller(true)]
public sealed class LOLForagerInstaller : Installer
```

The exact selected `InstallUtil.exe` is then invoked against that assembly.

The test passes only when the installer class runs and creates:

```text
InstallUtil-PoC-Executed.txt
```

---

# RegAsm corpus case

v9 prefers:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
```

The detector must independently emit:

```text
ComRegistration
```

The benchmark generates a COM-visible managed class with:

```csharp
[ComRegisterFunction]
```

The registration hook creates:

```text
RegAsm-PoC-Executed.txt
```

This test requires:

```powershell
-AllowSelfTestStateChange
```

because actual RegAsm registration temporarily modifies COM registration state.

The runner unregisters the generated assembly in a `finally` cleanup path.

Without `-AllowSelfTestStateChange`, the case is reported as:

```text
PoCSkipped
```

rather than incorrectly passing.

---

# Regsvr32 corpus case

The self-test prefers:

```text
C:\Windows\SysWOW64\regsvr32.exe
```

because the generated corpus DLL is x86 and is assembled with:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\ilasm.exe
```

The detector must independently emit:

```text
DllRegistrationLoader
```

The benchmark creates:

```text
Regsvr32-Capability-PoC.il
Regsvr32-Capability-PoC.dll
Regsvr32-PoC-Executed.txt
```

The IL contains a real unmanaged export:

```text
DllRegisterServer
```

using:

```text
.vtfixup
.vtentry
.export
```

The exact selected `regsvr32.exe` runs:

```text
regsvr32.exe /s Regsvr32-Capability-PoC.dll
```

`DllRegisterServer` performs no registry registration. It only creates the benign marker and returns success.

The case passes only when:

```text
Regsvr32-PoC-Executed.txt
```

is created by that exported method.

---

# Interpreting failures

## DetectorMiss

Example:

```text
DetectorReported = False
PoCPassed        = True
Status           = DetectorMiss
```

The binary can perform the capability, but v9 failed to surface the target through normal heuristics.

This is a detector/signature gap.

## CapabilityClassificationMiss

Example:

```text
DetectorReported           = True
ExpectedCapabilityDetected = False
PoCPassed                  = True
```

Forager found the binary for some other reason but classified the expected benchmark capability incorrectly.

## PoCFailed

Example:

```text
DetectorReported           = True
ExpectedCapabilityDetected = True
PoCPassed                  = False
```

The detector behaved as expected but the validation harness did not successfully exercise the interface.

This is a test-harness, version, architecture, policy, or runtime compatibility issue.

## PoCSkipped

The benchmark could not safely execute automatically.

The primary v9 example is RegAsm without:

```powershell
-AllowSelfTestStateChange
```

## TargetNotPresent

The expected benchmark binary was not found among the scanned candidate files.

---

# Normal Critical validation

The v8 claim-specific validation model remains available for normal findings.

Critical findings can include:

```text
RuntimeValidationPlan.csv
DiscoveredExecutionSurfaces.csv
DiscoveredLoadingSurfaces.csv
Run-TargetBehaviorObservation.ps1
Run-ClaimRuntimeObservation.ps1
Run-Validation.ps1
Assert-ForagerClaims.ps1
```

The corpus does not replace these target-specific tests.

It exists to measure whether the detector and known-good validation adapters are behaving correctly.

---

# Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-ScanPaths` | Windows, .NET, Program Files, dotnet, ProgramData | Roots to inspect |
| `-IncludeWinSxS` | Off | Include WinSxS |
| `-IncludeScripts` | Off | Include supported script extensions |
| `-OutputCsv` | `.\WdacRiskDiscovery.csv` | Main capability-discovery report |
| `-MaxFileSizeMB` | `96` | Maximum file size for raw capability scanning |
| `-MinimumRiskScore` | `20` | Minimum heuristic score emitted |
| `-ExeOnly` | Off | Scan only executable files |
| `-DisableCriticalValidation` | Off | Disable Critical finding validation directories |
| `-EnableUnmanagedDllExportTest` | Off | Enable target-specific unmanaged DLL export validation where a loading surface is discovered |
| `-RunSelfTestCorpus` | Off | Run the isolated four-case detector/PoC benchmark after scanning |
| `-AllowSelfTestStateChange` | Off | Permit temporary RegAsm COM registration during the corpus |
| `-SelfTestOutputDirectory` | Beside OutputCsv | Override corpus output location |

Alias:

```text
-EnableUnmanagedExportTest
```

---

# Recommended v9 verification run

On an authorised disposable Windows test VM:

```powershell
.\LOL-Forager-v9.ps1 `
    -RunSelfTestCorpus `
    -AllowSelfTestStateChange `
    -OutputCsv C:\Reports\WdacRiskDiscovery.csv
```

Then review:

```powershell
Import-Csv C:\Reports\WdacRiskDiscovery-SelfTestCorpus-v9\SelfTestCorpusResults.csv |
    Format-Table -AutoSize
```

A healthy benchmark should show the distinction between detector and execution results explicitly.

Do not treat a benchmark pass as proof that the same application is allowed by every WDAC or AppLocker policy. The corpus verifies Forager's discovery and test harness against the system on which it is run.
