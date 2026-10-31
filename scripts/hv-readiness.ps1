<#
.SYNOPSIS
    Hypervisor Launcher - Active Session Readiness Checker
.DESCRIPTION
    Inspects the currently active Windows session to verify that all system settings,
    virtualization features, security services, CPU register states, and drivers
    are properly configured to run hypervisor-based launchers (SimpleSvm, HyperKD, KVC).
    
    Checks are non-destructive and read-only.
.PARAMETER Detailed
    Displays detailed technical breakdowns, registry keys, and status codes.
.PARAMETER FixAdvice
    Displays copy-paste remediation commands for any failed or warned checks.
.PARAMETER NoPause
    Suppresses the "Press any key to exit" prompt at the end of execution.
.PARAMETER Json
    Outputs the diagnostic results in JSON format.
#>

[CmdletBinding()]
param(
    [switch]$Detailed,
    [switch]$FixAdvice,
    [switch]$NoPause,
    [switch]$Json,
    [switch]$Elevated
)

# Set up terminal colors
$esc = [char]27
$cGreen  = "$esc[92m"
$cRed    = "$esc[91m"
$cYellow = "$esc[93m"
$cCyan   = "$esc[96m"
$cGray   = "$esc[90m"
$cBold   = "$esc[1m"
$cReset  = "$esc[0m"

# Track results
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$remediations = [System.Collections.Generic.List[string]]::new()

function Add-Result {
    param(
        [string]$Category,
        [string]$Name,
        [string]$Status,       # "PASS", "WARN", "FAIL", "INFO"
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Details,
        [string]$Remediation = $null
    )
    $obj = [PSCustomObject]@{
        Category      = $Category
        Name          = $Name
        Status        = $Status
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
        Details       = $Details
        Remediation   = $Remediation
    }
    $results.Add($obj)
    if ($Remediation -and ($Status -eq "FAIL" -or $Status -eq "WARN")) {
        $remediations.Add($Remediation)
    }
}

# --- System Architecture & Native Methods ---
$typeDef = @"
using System;
using System.Runtime.InteropServices;

public static class NativeMethods {
    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);
}
"@
if (-not ([System.Management.Automation.PSTypeName]'NativeMethods').Type) {
    try {
        Add-Type -TypeDefinition $typeDef -Language CSharp -ErrorAction Stop
    } catch {
        # Fallback if Add-Type fails
    }
}

# Check Admin Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Gather OS Information
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$osCaption = if ($os) { $os.Caption.Trim() } else { [System.Environment]::OSVersion.VersionString }
$osBuild   = if ($os) { $os.BuildNumber } else { [System.Environment]::OSVersion.Version.Build }
$osArch    = [System.Environment]::GetEnvironmentVariable("PROCESSOR_ARCHITECTURE")

# Gather CPU Information
$proc = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
$cpuName   = if ($proc) { $proc.Name.Trim() } else { "Unknown Processor" }
$cpuVendor = if ($proc) { $proc.Manufacturer } else { "Unknown" }

# Print Banner (if not JSON output)
if (-not $Json) {
    Write-Host ""
    Write-Host "$cBold$cCyan+==============================================================+$cReset"
    Write-Host "$cBold$cCyan|        Hypervisor Launcher - Active Session Readiness        |$cReset"
    Write-Host "$cBold$cCyan+==============================================================+$cReset"
    Write-Host "$cGray[*] OS: $osCaption (Build $osBuild) | Arch: $osArch$cReset"
    Write-Host "$cGray[*] CPU: $cpuVendor - $cpuName$cReset"
    if (-not $isAdmin) {
        Write-Host "$cYellow[!] Warning: Running with standard user privileges. Some deep system checks may be limited.$cReset"
    }
    Write-Host ""
}

# -------------------------------------------------------------
# 1. HARDWARE VIRTUALIZATION
# -------------------------------------------------------------
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$hvPresent = if ($cs) { [bool]$cs.HypervisorPresent } else { $false }
$fwVirtEnabled = if ($proc) { $proc.VirtualizationFirmwareEnabled } else { $null }

# If a hypervisor is currently running, firmware virt is implicitly enabled
$firmwareVirtActive = ($fwVirtEnabled -eq $true) -or $hvPresent

if ($firmwareVirtActive) {
    Add-Result -Category "Hardware Virtualization" `
               -Name "BIOS/UEFI Hardware Virtualization" `
               -Status "PASS" `
               -CurrentValue "Enabled (VT-x / AMD SVM Active)" `
               -ExpectedValue "Enabled" `
               -Details "Hardware virtualization is enabled in CPU firmware and available."
} else {
    Add-Result -Category "Hardware Virtualization" `
               -Name "BIOS/UEFI Hardware Virtualization" `
               -Status "FAIL" `
               -CurrentValue "Disabled" `
               -ExpectedValue "Enabled" `
               -Details "Intel VT-x or AMD SVM is disabled in BIOS/UEFI. Hypervisors cannot start without hardware virtualization." `
               -Remediation "Reboot into BIOS/UEFI and enable 'Intel Virtualization Technology' (VT-x) or 'SVM Mode' (AMD SVM)."
}

# -------------------------------------------------------------
# 2. WINDOWS HYPERVISOR (HYPER-V)
# -------------------------------------------------------------
if (-not $hvPresent) {
    Add-Result -Category "Windows Hypervisor" `
               -Name "Microsoft Hyper-V Hypervisor" `
               -Status "PASS" `
               -CurrentValue "Inactive (HypervisorPresent: False)" `
               -ExpectedValue "Inactive (False)" `
               -Details "Windows Hypervisor is not active in this session. Bare-metal hardware virtualization is accessible."
} else {
    Add-Result -Category "Windows Hypervisor" `
               -Name "Microsoft Hyper-V Hypervisor" `
               -Status "FAIL" `
               -CurrentValue "Active (HypervisorPresent: True)" `
               -ExpectedValue "Inactive (False)" `
               -Details "Microsoft Hyper-V hypervisor is currently running and intercepting CPU virtualization. Custom hypervisors (SimpleSvm/HyperKD) will fail to initialize." `
               -Remediation "1. Disable Hyper-V boot launch:`nbcdedit /set hypervisorlaunchtype Off`n2. If virtualization features are enabled, disable them:`nDisable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All, VirtualMachinePlatform, HypervisorPlatform -NoRestart`n3. Reboot your computer."
}

# -------------------------------------------------------------
# 3. VIRTUALIZATION-BASED SECURITY (VBS)
# -------------------------------------------------------------
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard -ErrorAction SilentlyContinue
$vbsStatus = if ($dg) { $dg.VirtualizationBasedSecurityStatus } else { 0 }
$runningServices = if ($dg -and $dg.SecurityServicesRunning) { $dg.SecurityServicesRunning } else { @() }

switch ($vbsStatus) {
    0 {
        Add-Result -Category "Virtualization-Based Security" `
                   -Name "VBS Status (Active Session)" `
                   -Status "PASS" `
                   -CurrentValue "Disabled / Inactive (Status: 0)" `
                   -ExpectedValue "Disabled (0)" `
                   -Details "Virtualization-Based Security is fully disabled in the current session."
    }
    1 {
        Add-Result -Category "Virtualization-Based Security" `
                   -Name "VBS Status (Active Session)" `
                   -Status "WARN" `
                   -CurrentValue "Enabled but Not Running (Status: 1)" `
                   -ExpectedValue "Disabled (0)" `
                   -Details "VBS is enabled in system configuration but not currently active in this session." `
                   -Remediation "Ensure BCD has 'vsmlaunchtype Off' to keep VBS suppressed on next boot."
    }
    2 {
        Add-Result -Category "Virtualization-Based Security" `
                   -Name "VBS Status (Active Session)" `
                   -Status "FAIL" `
                   -CurrentValue "Running (Status: 2)" `
                   -ExpectedValue "Disabled (0)" `
                   -Details "VBS is actively running in this session. It locks hardware virtualization under Windows Virtual Secure Mode." `
                   -Remediation "Disable VBS by executing:`nbcdedit /set vsmlaunchtype Off`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f`nThen reboot your computer."
    }
}

# -------------------------------------------------------------
# 4. MEMORY INTEGRITY / HVCI
# -------------------------------------------------------------
# Service Code 2 = Hypervisor-Enforced Code Integrity (HVCI)
$hvciRunning = $runningServices -contains 2
$hvciReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -ErrorAction SilentlyContinue

if (-not $hvciRunning -and (-not $hvciReg -or $hvciReg.Enabled -ne 1)) {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Memory Integrity (HVCI)" `
               -Status "PASS" `
               -CurrentValue "Inactive" `
               -ExpectedValue "Inactive" `
               -Details "Memory Integrity / HVCI is not active in this session."
} else {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Memory Integrity (HVCI)" `
               -Status "FAIL" `
               -CurrentValue "Active / Running" `
               -ExpectedValue "Inactive" `
               -Details "Hypervisor-Enforced Code Integrity prevents unsigned kernel driver hooks." `
               -Remediation "Turn off Memory Integrity in Windows Security > Device Security > Core Isolation, or run:`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`" /v Enabled /t REG_DWORD /d 0 /f`nThen reboot your computer."
}

# -------------------------------------------------------------
# 5. CREDENTIAL GUARD & HYPERVISOR PAGING TRANSLATION (HVPT)
# -------------------------------------------------------------
# Service Code 1 = Credential Guard
$cgRunning = $runningServices -contains 1
if (-not $cgRunning) {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Credential Guard (LSA ISO)" `
               -Status "PASS" `
               -CurrentValue "Inactive" `
               -ExpectedValue "Inactive" `
               -Details "Credential Guard is not running in this session."
} else {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Credential Guard (LSA ISO)" `
               -Status "FAIL" `
               -CurrentValue "Running" `
               -ExpectedValue "Inactive" `
               -Details "Credential Guard enforces VSM isolation and keeps the Windows Hypervisor active." `
               -Remediation "Disable Credential Guard by running:`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\Lsa`" /v LsaCfgFlags /t REG_DWORD /d 0 /f`nThen reboot your computer."
}

# Service Code 7 = HVPT
$hvptRunning = $runningServices -contains 7
if (-not $hvptRunning) {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Hypervisor-Enforced Paging (HVPT)" `
               -Status "PASS" `
               -CurrentValue "Inactive" `
               -ExpectedValue "Inactive" `
               -Details "HVPT is not active in this session."
} else {
    Add-Result -Category "Virtualization-Based Security" `
               -Name "Hypervisor-Enforced Paging (HVPT)" `
               -Status "WARN" `
               -CurrentValue "Active" `
               -ExpectedValue "Inactive" `
               -Details "Hypervisor-Enforced Paging Translation is running in this session." `
               -Remediation "Disable HVPT by running:`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`" /v DisableHypervisorEnforcedPagingTranslation /t REG_DWORD /d 1 /f"
}

# -------------------------------------------------------------
# 6. CPU EXTENDED REGISTER STATE (XCR0 / XSAVE)
# -------------------------------------------------------------
$xcr0 = 0
$xcr0Hex = "0x0"
try {
    $xcr0 = [UInt32][System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]0x7FFE03D8)
    $xcr0Hex = "0x" + $xcr0.ToString("X")
} catch {
    $xcr0 = 0
}

# Check if processor supports AVX-512 / extended states (Zen 4/5, Intel 11th+ Gen)
$isZen4or5 = ($cpuName -match "Ryzen.*(7\d00|8\d00|9\d00)" -or $cpuName -match "Threadripper.*(7\d00|9\d00)")
$isModernIntel = ($cpuVendor -match "Intel" -and $cpuName -match "(1[1-9]th Gen|Core Ultra)")

if ($xcr0 -lt 7) {
    Add-Result -Category "CPU Register State" `
               -Name "XCR0 Register State (AVX Support)" `
               -Status "FAIL" `
               -CurrentValue "$xcr0 ($xcr0Hex)" `
               -ExpectedValue ">= 7 (AVX Enabled)" `
               -Details "AVX is disabled or not supported on this processor. Modern hypervisors and target applications require AVX." `
               -Remediation "Ensure AVX instructions are supported and enabled by your CPU and operating system."
} elseif ($xcr0 -eq 7) {
    Add-Result -Category "CPU Register State" `
               -Name "XCR0 Register State (XSAVE Mask)" `
               -Status "PASS" `
               -CurrentValue "7 (0x7) [Base XSAVE]" `
               -ExpectedValue "7 (0x7) [Base XSAVE] or Native" `
               -Details "Extended CPU states are capped at AVX2 (256-bit). This guarantees maximum stability for custom hypervisors (SimpleSvm/HyperKD) by preventing VM-exit buffer truncation."
} else {
    # XCR0 > 7 (e.g. 0xE7 = 231)
    if ($isZen4or5 -or $isModernIntel) {
        Add-Result -Category "CPU Register State" `
                   -Name "XCR0 Register State (XSAVE Mask)" `
                   -Status "WARN" `
                   -CurrentValue "$xcr0 ($xcr0Hex) [Native XSAVE]" `
                   -ExpectedValue "7 (0x7) [Base XSAVE]" `
                   -Details "Full native CPU extended states (AVX-512/AMX) are active in this session. Custom hypervisors with 256-bit VM-exit buffers may crash when launching targets on Zen 4/5 or Intel AVX-512 CPUs." `
                   -Remediation "If the hypervisor or target crashes or hangs during launch, boot into the Base XSAVE profile or execute:`nbcdedit /set xsaveremovefeature 0xFFFFFFFFFFFFFFF8`nThen reboot your computer."
    } else {
        Add-Result -Category "CPU Register State" `
                   -Name "XCR0 Register State (XSAVE Mask)" `
                   -Status "PASS" `
                   -CurrentValue "$xcr0 ($xcr0Hex) [Native XSAVE]" `
                   -ExpectedValue "Native / 0x7" `
                   -Details "Native extended states active ($xcr0Hex). CPU does not require AVX-512 masking."
    }
}

# -------------------------------------------------------------
# 7. DRIVER SIGNATURE ENFORCEMENT & TEST SIGNING
# -------------------------------------------------------------
$secureBoot = $false
try {
    $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
} catch {
    $secureBoot = $false
}

$dseState = "Unknown"
$dseCode = -1
if (([System.Management.Automation.PSTypeName]'NativeMethods').Type) {
    try {
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($buf, 8)
        $retLen = [uint32]0
        $status = [NativeMethods]::NtQuerySystemInformation(103, $buf, 8, [ref]$retLen)
        if ($status -eq 0) {
            $options = [uint32][System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 4)
            if (($options -band 1) -eq 0) {
                $dseCode = 0  # Disabled
                $dseState = "Disabled (Runtime Bypass or F7 Active)"
            } elseif (($options -band 2) -ne 0) {
                $dseCode = 1  # Test Signing
                $dseState = "Test Signing Active"
            } else {
                $dseCode = 2  # Standard DSE Enforced
                $dseState = "Enforced (Standard Windows Mode)"
            }
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    } catch {
        # Fallback
    }
}

if ($dseCode -eq 0) {
    Add-Result -Category "Driver Signature Enforcement" `
               -Name "Driver Signature Enforcement (DSE)" `
               -Status "PASS" `
               -CurrentValue "Disabled (0)" `
               -ExpectedValue "Disabled or KVC Managed" `
               -Details "Driver Signature Enforcement is currently disabled. Unsigned kernel drivers can load freely."
} elseif ($dseCode -eq 1) {
    Add-Result -Category "Driver Signature Enforcement" `
               -Name "Driver Signature Enforcement (DSE)" `
               -Status "PASS" `
               -CurrentValue "Test Signing Active" `
               -ExpectedValue "Disabled or KVC Managed" `
               -Details "Windows Test Signing is active. Test-signed kernel drivers can load."
} else {
    # Standard DSE is on, which is normal because KVC bypasses DSE at runtime on-demand!
    Add-Result -Category "Driver Signature Enforcement" `
               -Name "Driver Signature Enforcement (DSE)" `
               -Status "PASS" `
               -CurrentValue "Enforced (KVC Runtime Bypass Ready)" `
               -ExpectedValue "KVC Runtime Bypass Ready" `
               -Details "Standard DSE is enforced by Windows. Hypervisor Launcher will suppress DSE on-demand via KVC during launch without requiring permanent changes."
}

# -------------------------------------------------------------
# 8. KVA SHADOW (MELTDOWN MITIGATION)
# -------------------------------------------------------------
$kvaRequired = $false
$kvaMitigated = $false
if (([System.Management.Automation.PSTypeName]'NativeMethods').Type) {
    try {
        $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
        $retLen = [uint32]0
        $status = [NativeMethods]::NtQuerySystemInformation(196, $buf, 4, [ref]$retLen)
        if ($status -eq 0) {
            $flags = [uint32][System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
            $kvaRequired = (($flags -band 0x01) -ne 0) -or ((($flags -band 0x20) -ne 0) -and (($flags -band 0x10) -ne 0))
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    } catch {
        # Fallback
    }
}

$memMgmt = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -ErrorAction SilentlyContinue
$kvaOverrideSet = ($memMgmt -and $memMgmt.FeatureSettingsOverride -eq 2 -and $memMgmt.FeatureSettingsOverrideMask -eq 3)

if (-not $kvaRequired) {
    Add-Result -Category "Kernel Architecture" `
               -Name "KVA Shadow (Meltdown Mitigation)" `
               -Status "PASS" `
               -CurrentValue "Not Required (Hardware Mitigated)" `
               -ExpectedValue "Not Required or Disabled" `
               -Details "This processor is architecturally immune to Meltdown. KVA Shadow is not active."
} elseif ($kvaOverrideSet) {
    Add-Result -Category "Kernel Architecture" `
               -Name "KVA Shadow (Meltdown Mitigation)" `
               -Status "PASS" `
               -CurrentValue "Disabled via Override" `
               -ExpectedValue "Disabled" `
               -Details "KVA Shadow is disabled via registry override, allowing custom syscall hooks to operate."
} else {
    Add-Result -Category "Kernel Architecture" `
               -Name "KVA Shadow (Meltdown Mitigation)" `
               -Status "WARN" `
               -CurrentValue "Active on Legacy CPU" `
               -ExpectedValue "Disabled" `
               -Details "KVA Shadow is active on an older processor. This may conflict with hypervisor syscall hook implementations." `
               -Remediation "Disable KVA Shadow by running:`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`" /v FeatureSettingsOverride /t REG_DWORD /d 2 /f`nreg add `"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f`nThen reboot your computer."
}

# -------------------------------------------------------------
# 9. CONFLICTING SECURITY SOFTWARE & ANTI-CHEATS
# -------------------------------------------------------------
# Smart App Control
$sacState = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy" -Name "VerifiedAndReputablePolicyState" -ErrorAction SilentlyContinue
if ($sacState) {
    switch ($sacState.VerifiedAndReputablePolicyState) {
        0 {
            Add-Result -Category "Conflicting Software" `
                       -Name "Smart App Control (SAC)" `
                       -Status "PASS" `
                       -CurrentValue "Disabled" `
                       -ExpectedValue "Disabled" `
                       -Details "Smart App Control is disabled."
        }
        1 {
            Add-Result -Category "Conflicting Software" `
                       -Name "Smart App Control (SAC)" `
                       -Status "WARN" `
                       -CurrentValue "Enabled" `
                       -ExpectedValue "Disabled" `
                       -Details "Smart App Control is currently enabled and may block hypervisor drivers or bypass binaries." `
                       -Remediation "Disable Smart App Control in Windows Security > App & browser control > Smart App Control."
        }
        2 {
            Add-Result -Category "Conflicting Software" `
                       -Name "Smart App Control (SAC)" `
                       -Status "WARN" `
                       -CurrentValue "Evaluation Mode" `
                       -ExpectedValue "Disabled" `
                       -Details "Smart App Control is in evaluation mode and may transition to enabled or block custom binaries." `
                       -Remediation "Consider setting Smart App Control to 'Off' in Windows Security."
        }
    }
} else {
    Add-Result -Category "Conflicting Software" `
               -Name "Smart App Control (SAC)" `
               -Status "PASS" `
               -CurrentValue "Not Present / Disabled" `
               -ExpectedValue "Disabled" `
               -Details "Smart App Control is not active on this system."
}

# FACEIT Anti-Cheat
$faceitService = Get-Service -Name "FACEIT", "FACEITService" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
$faceitFilter = $false
try {
    $fltOutput = & fltmc 2>&1
    if ($fltOutput -match "FACEIT") { $faceitFilter = $true }
} catch {}

if ($faceitService -or $faceitFilter) {
    Add-Result -Category "Conflicting Software" `
               -Name "FACEIT Anti-Cheat" `
               -Status "FAIL" `
               -CurrentValue "Running / Active" `
               -ExpectedValue "Stopped / Disabled" `
               -Details "FACEIT Anti-Cheat driver actively blocks custom hypervisors and unsigned kernel drivers." `
               -Remediation "Stop and disable FACEIT by running:`nsc stop FACEIT & sc stop FACEITService`nsc config FACEIT start= disabled & sc config FACEITService start= disabled"
} else {
    Add-Result -Category "Conflicting Software" `
               -Name "FACEIT Anti-Cheat" `
               -Status "PASS" `
               -CurrentValue "Inactive / Not Found" `
               -ExpectedValue "Inactive" `
               -Details "FACEIT Anti-Cheat is not running."
}

# Riot Vanguard
$vgkService = Get-Service -Name "vgk" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if ($vgkService) {
    Add-Result -Category "Conflicting Software" `
               -Name "Riot Vanguard (vgk)" `
               -Status "WARN" `
               -CurrentValue "Running" `
               -ExpectedValue "Stopped or Inactive" `
               -Details "Riot Vanguard kernel service is active. Vanguard may flag DSE bypass or prevent hypervisors from initializing." `
               -Remediation "Stop Vanguard from the system tray or run:`nsc stop vgk"
} else {
    Add-Result -Category "Conflicting Software" `
               -Name "Riot Vanguard (vgk)" `
               -Status "PASS" `
               -CurrentValue "Inactive / Not Found" `
               -ExpectedValue "Inactive" `
               -Details "Riot Vanguard is not running."
}

# MacType
$macTypeService = Get-Service -Name "MacType" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
$macTypeHooked = $false
try {
    $exp = Get-Process explorer -ErrorAction SilentlyContinue
    if ($exp -and ($exp.Modules | Where-Object { $_.ModuleName -like "*MacType*" })) {
        $macTypeHooked = $true
    }
} catch {}

if ($macTypeService -or $macTypeHooked) {
    Add-Result -Category "Conflicting Software" `
               -Name "MacType" `
               -Status "WARN" `
               -CurrentValue "Running / Injected" `
               -ExpectedValue "Inactive" `
               -Details "MacType is known to cause silent process crashes during target startup under hypervisors." `
               -Remediation "Exit MacType from the system tray or disable the MacType service before launching targets."
} else {
    Add-Result -Category "Conflicting Software" `
               -Name "MacType" `
               -Status "PASS" `
               -CurrentValue "Inactive / Not Found" `
               -ExpectedValue "Inactive" `
               -Details "MacType is not running."
}

# Bitdefender Advanced Threat Defense
$bdAv = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntiVirusProduct -ErrorAction SilentlyContinue | Where-Object { $_.displayName -match "Bitdefender" }
$bdAtcEnabled = $false
if ($bdAv) {
    $bdReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Bitdefender" -Name "atc_data" -ErrorAction SilentlyContinue
    if ($bdReg -and ($bdReg.atc_data -match 'monitor_state":true')) {
        $bdAtcEnabled = $true
    }
}

if ($bdAtcEnabled) {
    Add-Result -Category "Conflicting Software" `
               -Name "Bitdefender Advanced Threat Defense" `
               -Status "WARN" `
               -CurrentValue "Enabled" `
               -ExpectedValue "Disabled or Excluded" `
               -Details "Bitdefender ATC can cause 'Initialization error 5' in protected binaries." `
               -Remediation "Add the target directory as an exception in Bitdefender > Antivirus > Manage Exceptions, or toggle off Advanced Threat Defense."
} else {
    Add-Result -Category "Conflicting Software" `
               -Name "Bitdefender Advanced Threat Defense" `
               -Status "PASS" `
               -CurrentValue "Inactive / Not Installed" `
               -ExpectedValue "Inactive or Excluded" `
               -Details "Bitdefender ATC is not active or not installed."
}

# -------------------------------------------------------------
# 10. SYSTEM SUBSYSTEMS & NULL SERVICE
# -------------------------------------------------------------
# Null service (required for basic tool execution)
$nullService = Get-Service -Name "Null" -ErrorAction SilentlyContinue
if ($nullService -and $nullService.Status -eq "Running") {
    Add-Result -Category "System Subsystems" `
               -Name "Windows Null Driver Service" `
               -Status "PASS" `
               -CurrentValue "Running" `
               -ExpectedValue "Running" `
               -Details "Null device driver is operating normally."
} else {
    Add-Result -Category "System Subsystems" `
               -Name "Windows Null Driver Service" `
               -Status "WARN" `
               -CurrentValue "Stopped or Missing" `
               -ExpectedValue "Running" `
               -Details "Null driver is not running. Some Windows command tools may fail to execute." `
               -Remediation "Start the Null service: `nsc start Null & sc config Null start= system"
}

# WMI Responsiveness
if ($cs -ne $null) {
    Add-Result -Category "System Subsystems" `
               -Name "WMI / CIM Subsystem" `
               -Status "PASS" `
               -CurrentValue "Responsive" `
               -ExpectedValue "Responsive" `
               -Details "WMI repository is responsive and querying CIM instances cleanly."
} else {
    Add-Result -Category "System Subsystems" `
               -Name "WMI / CIM Subsystem" `
               -Status "FAIL" `
               -CurrentValue "Not Responding" `
               -ExpectedValue "Responsive" `
               -Details "WMI repository is corrupted or not responding. PowerShell management queries may fail." `
               -Remediation "Salvage or reset WMI repository by running as Administrator:`nwinmgmt /salvagerepository"
}

# -------------------------------------------------------------
# OUTPUT FORMATTING & VERDICT
# -------------------------------------------------------------
if ($Json) {
    $summary = @{
        Timestamp = (Get-Date).ToString("o")
        OS        = $osCaption
        Build     = $osBuild
        Arch      = $osArch
        Processor = $cpuName
        PassCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
        WarnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count
        FailCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count
        Results   = $results
    }
    $summary | ConvertTo-Json -Depth 4
    return
}

# Group and display results
$currentCat = ""
foreach ($item in $results) {
    if ($item.Category -ne $currentCat) {
        $currentCat = $item.Category
        Write-Host "$cBold$cCyan--- $currentCat ---$cReset"
    }

    $badge = switch ($item.Status) {
        "PASS" { "$cGreen[PASS]$cReset" }
        "WARN" { "$cYellow[WARN]$cReset" }
        "FAIL" { "$cRed[FAIL]$cReset" }
        default { "$cCyan[INFO]$cReset" }
    }

    Write-Host "  $badge $($item.Name): $($item.CurrentValue)"
    if ($Detailed -or ($item.Status -eq "FAIL" -or $item.Status -eq "WARN")) {
        Write-Host "         $cGray$($item.Details)$cReset"
    }
}

# Compute Totals
$passCount = ($results | Where-Object { $_.Status -eq "PASS" }).Count
$warnCount = ($results | Where-Object { $_.Status -eq "WARN" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "FAIL" }).Count

Write-Host ""
Write-Host "$cBold$cCyan+==============================================================+$cReset"
Write-Host "$cBold$cCyan|                     Session Check Summary                    |$cReset"
Write-Host "$cBold$cCyan+==============================================================+$cReset"
Write-Host "  Passed:   $cGreen$passCount$cReset"
Write-Host "  Warnings: $cYellow$warnCount$cReset"
Write-Host "  Failed:   $cRed$failCount$cReset"
Write-Host ""

if ($failCount -eq 0 -and $warnCount -eq 0) {
    Write-Host "$cBold$cGreen[+] VERDICT: READY. Your active session is 100% configured for hypervisor workloads!$cReset"
} elseif ($failCount -eq 0) {
    Write-Host "$cBold$cYellow[!] VERDICT: READY WITH WARNINGS. Targets should run, but review warnings above.$cReset"
} else {
    Write-Host "$cBold$cRed[-] VERDICT: NOT READY. Action required to fix blocking session settings.$cReset"
}

# Display Remediation Advice if requested or on failure
if ($remediations.Count -gt 0 -and ($FixAdvice -or $failCount -gt 0)) {
    Write-Host ""
    Write-Host "$cBold$cCyan+==============================================================+$cReset"
    Write-Host "$cBold$cCyan|                  Remediation Instructions                    |$cReset"
    Write-Host "$cBold$cCyan+==============================================================+$cReset"
    $idx = 1
    foreach ($rem in $remediations) {
        Write-Host "$cBold$cYellow[$idx] Step:$cReset"
        $lines = $rem -split "`n"
        foreach ($l in $lines) {
            Write-Host "    $l"
        }
        Write-Host ""
        $idx++
    }
}

Write-Host ""
if (-not $NoPause) {
    if ([System.Environment]::UserInteractive -and -not [System.Console]::IsInputRedirected) {
        Write-Host "$cGrayPress any key to exit...$cReset"
        try {
            [void][System.Console]::ReadKey($true)
        } catch {}
    }
}
