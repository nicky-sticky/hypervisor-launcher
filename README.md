# Hypervisor Launcher

Runs a target executable under a custom hardware hypervisor, loading the unsigned hypervisor driver (Intel VT-x or AMD SVM, auto-detected by CPUID) as a kernel service with Driver Signature Enforcement (DSE) suppressed by Kernel Vulnerability Capabilities Framework (KVC).

> [!WARNING]
> **Disclaimer & Legal Notice**
> This tool is provided "as is" and is intended strictly for learning and educational purposes. Disabling DSE and running unsigned drivers bypasses standard Windows kernel-level security protections, which can compromise system stability and security. Use this software entirely at your own risk.

## Features

- **Automated CPU Detection** — Identifies Intel (`GenuineIntel`) and AMD (`AuthenticAMD`) processors automatically to load matching kernel drivers.
- **Runtime DSE Bypass** — Loads unsigned kernel drivers on-the-fly without requiring system reboots via the external `KVC` engine (downloaded separately).
- **Automated Lifecycle Management** — Demand-starts kernel driver services during execution and unloads them cleanly upon target process termination.
- **Configurable Process Launch** — Supports configurable target executable paths and driver payloads via `hvlauncher.ini`.

---

## Requirements

**Supported platform: Windows only.** Relies on Windows kernel driver loading APIs, CPU hardware virtualization, and Windows DSE bypass mechanisms.

### Runtime Requirements (Running the Launcher)
- **OS**: Windows 10/11 (64-bit)
- **Hardware**: CPU hardware virtualization (Intel VT-x or AMD SVM) enabled in BIOS/UEFI
- [Kernel Vulnerability Capabilities Framework](https://github.com/wesmar/kvc): `kvc.exe` is not bundled and needs to be downloaded and added to the `tools/` subfolder before use.

### Build Requirements (Compiling from Source)
- [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) with the **Desktop development with C++** workload
- [Kernel Vulnerability Capabilities Framework](https://github.com/wesmar/kvc): `kvc.exe` is not bundled and must be downloaded and placed in `source/tools/` before running `build.bat`

### Standard Bundle Layout

The launcher comes bundled with **hypervisor drivers** (`driver_amd/SimpleSvm.sys` for AMD, `driver_intel/hyperkd.sys` for Intel). Users only need to download and place `kvc.exe` in the `tools/` subfolder next to the launcher executable and configuration file:

- **Pre-compiled Release**:
  ```text
  hypervisor-launcher/
  ├── hvlauncher.exe
  ├── hvlauncher.ini
  ├── driver_amd/
  │   └── SimpleSvm.sys    (standard AMD hypervisor, bundled)
  ├── driver_intel/
  │   ├── hyperkd.sys      (standard Intel hypervisor, bundled)
  │   └── ...              (Intel user-mode hypervisor components)
  └── tools/
      └── kvc.exe          (downloaded separately, required for DSE bypass)
  ```

- **Building from Source**:
  ```text
  hypervisor-launcher/
  ├── build.bat
  ├── scripts/
  │   ├── hv-readiness.bat (session readiness checker)
  │   └── hv-readiness.ps1 (PowerShell session verification script)
  └── source/
      ├── driver_amd/      (standard AMD hypervisor, staged into release/)
      ├── driver_intel/    (standard Intel hypervisor, staged into release/)
      └── tools/
          └── kvc.exe      (downloaded separately, required prior to running build.bat)
  ```

`[Driver]` and `[Tools]` in `hvlauncher.ini` default to this layout (`driver_amd\SimpleSvm.sys`,
`driver_intel\hyperkd.sys`, `tools\kvc.exe`) and resolve relative to the launcher directory.
Every setting is optional except `[Target] exe=`; omit a key to keep the bundled default.

## Installation & Build

### Option 1: Pre-compiled Release

1. Extract the release package into your target directory.
2. Download `kvc.exe` from [kvc releases](https://github.com/wesmar/kvc/releases/tag/latest) and place it inside the `tools/` subfolder.
3. Configure `hvlauncher.ini` with the target executable (driver and kvc paths are optional and default to the bundled layout).

### Option 2: Compiling from Source

1. Download `kvc.exe` from [kvc releases](https://github.com/wesmar/kvc/releases/tag/latest) and place it inside `source/tools/`.
2. Run `build.bat` from the repository root:

```powershell
.\build.bat
```
*(The build script compiles resources, builds `hvlauncher.exe`, and stages `hvlauncher.ini` along with tools into `release/`).*

### Configuration Template

`source/hvlauncher.ini` is the default configuration. `build.bat` stages it as `release/hvlauncher.ini`, so the bundled release ships with the same file. Edit `hvlauncher.ini` next to `hvlauncher.exe` to point at your own target.

## Configuration

### 1. Launcher Settings (`hvlauncher.ini`)

Edit `hvlauncher.ini` in the launcher directory:

```ini
[Target]
exe = target.exe

[Driver]
amd_sys   = driver_amd\SimpleSvm.sys
intel_sys = driver_intel\hyperkd.sys

[Tools]
kvc = tools\kvc.exe
```

| Key | Description |
| :--- | :--- |
| `exe` | Path to the target executable (absolute or relative to launcher). Required. |
| `amd_sys` | Path to the AMD SVM kernel driver (`.sys`). Optional, defaults to `driver_amd\SimpleSvm.sys`. |
| `intel_sys` | Path to the Intel VT-x kernel driver (`.sys`). Optional, defaults to `driver_intel\hyperkd.sys`. |
| `kvc` | Path to the `kvc.exe` engine (absolute or relative to launcher). Optional, defaults to `tools\kvc.exe`. |

---

## Usage

Launch `hvlauncher.exe` (requires Administrator privileges):

```powershell
.\hvlauncher.exe
```

### Execution Lifecycle

1. **Elevation**: Prompts for UAC Administrator privileges required for driver service operations.
2. **DSE Bypass**: Invokes `kvc.exe` to suppress driver signature enforcement.
3. **Driver Load**: Detects CPU vendor (`Intel` vs `AMD`) and starts the matching `.sys` driver service.
4. **Target Execution**: Launches the configured target executable and monitors its process ID.
5. **Session Cleanup**: Automatically stops and deletes the kernel driver service once the target exits.

## Troubleshooting

### Run Active Session Readiness Checker

If a target fails to launch, hangs, or driver loading encounters errors, run the bundled readiness checker:

```cmd
:: Run from Command Prompt or double-click (self-elevates to Administrator if needed):
scripts\hv-readiness.bat

:: Or run directly in PowerShell:
powershell -ExecutionPolicy Bypass -File .\scripts\hv-readiness.ps1 -Detailed -FixAdvice
```

The script performs a non-destructive audit of the running Windows session—verifying hardware virtualization, Hyper-V suppression, VBS/HVCI status, CPU extended register states (`XCR0`), DSE bypass readiness, and conflicting security software—and prints exact, copy-paste remediation commands for any detected issues.
