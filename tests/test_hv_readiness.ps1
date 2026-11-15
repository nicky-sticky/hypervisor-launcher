[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$targetScript = Join-Path $repoRoot "scripts\hv-readiness.ps1"

$failures = [System.Collections.Generic.List[string]]::new()

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        $failures.Add($Message)
        Write-Host "[-] FAIL: $Message" -ForegroundColor Red
    }
}

function Invoke-MockedHvReadiness {
    param(
        [string]$ScriptPath,
        [string]$MockPrelude
    )
    $ps = [System.Management.Automation.PowerShell]::Create()
    try {
        [void]$ps.AddScript($MockPrelude).Invoke()
        if ($ps.HadErrors) {
            $errText = ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join "; "
            throw "Mock prelude error: $errText"
        }
        $ps.Commands.Clear()
        [void]$ps.AddCommand($ScriptPath).AddParameter("NoPause").AddParameter("Json")
        $output = $ps.Invoke()
        if ($ps.HadErrors) {
            $errText = ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join "; "
            throw "Mocked runspace error: $errText"
        }
        $jsonText = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        return ($jsonText | ConvertFrom-Json)
    } finally {
        $ps.Dispose()
    }
}

Write-Host "[*] Running hv-readiness.ps1 tests..."

# 1. PowerShell AST Parse & Parameter Validation
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($targetScript, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) "AST parse errors found in hv-readiness.ps1: $($parseErrors.Count)"

$paramNames = @()
if ($ast.ParamBlock) {
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
}
foreach ($expectedParam in @("Detailed", "FixAdvice", "NoPause", "Json", "Elevated")) {
    Assert-True ($paramNames -contains $expectedParam) "Expected parameter -$expectedParam missing from hv-readiness.ps1"
}

$testTokens = $null
$testParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($PSCommandPath, [ref]$testTokens, [ref]$testParseErrors)
Assert-True ($testParseErrors.Count -eq 0) "AST parse errors found in test_hv_readiness.ps1"

# 2. Live non-destructive -NoPause -Json execution & schema check
$rawJson = (& $targetScript -NoPause -Json) -join "`n"
Assert-True (-not [string]::IsNullOrWhiteSpace($rawJson)) "hv-readiness.ps1 -NoPause -Json produced empty output"
$live = $rawJson | ConvertFrom-Json

foreach ($prop in @("Timestamp", "OS", "Build", "Arch", "Processor", "PassCount", "WarnCount", "FailCount", "Results")) {
    Assert-True ($null -ne $live.PSObject.Properties[$prop]) "Missing JSON property: $prop"
}
Assert-True ($live.Results.Count -gt 0) "Expected non-empty Results list from hv-readiness.ps1"

$validStatuses = @("PASS", "WARN", "FAIL", "INFO")
foreach ($entry in $live.Results) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($entry.Category)) "Result missing Category"
    Assert-True (-not [string]::IsNullOrWhiteSpace($entry.Name)) "Result missing Name"
    Assert-True ($validStatuses -contains $entry.Status) "Invalid status '$($entry.Status)' for $($entry.Name)"
}
Assert-True ($live.PassCount -eq @($live.Results | Where-Object { $_.Status -eq "PASS" }).Count) "PassCount mismatch"
Assert-True ($live.WarnCount -eq @($live.Results | Where-Object { $_.Status -eq "WARN" }).Count) "WarnCount mismatch"
Assert-True ($live.FailCount -eq @($live.Results | Where-Object { $_.Status -eq "FAIL" }).Count) "FailCount mismatch"

# 3. Mocked Clean/Ready System (offline, no host mutation)
$healthyPrelude = @'
function Write-Host { param([Parameter(ValueFromRemainingArguments=$true)]$ArgsIgnored) }
function fltmc { return @("Filter Name", "-----------") }
function Confirm-SecureBootUEFI { return $false }
function Get-Process { param([string]$Name, [string]$ErrorAction) return $null }
function Get-Service {
    param([string[]]$Name, [string]$ErrorAction)
    if ($Name -contains "Null") { return [PSCustomObject]@{ Name = "Null"; Status = "Running" } }
    return @()
}
function Get-ItemProperty {
    param([string]$Path, [string]$Name, [string]$ErrorAction)
    if ($Path -like "*HypervisorEnforcedCodeIntegrity*") { return [PSCustomObject]@{ Enabled = 0 } }
    if ($Path -like "*Control\Lsa*") { return [PSCustomObject]@{ LsaCfgFlags = 0 } }
    if ($Path -like "*Control\DeviceGuard*") { return [PSCustomObject]@{ ConfigureSystemGuardLaunch = 0 } }
    if ($Path -like "*CI\Policy*") { return [PSCustomObject]@{ VerifiedAndReputablePolicyState = 0 } }
    if ($Path -like "*Memory Management*") { return [PSCustomObject]@{ FeatureSettingsOverride = 3; FeatureSettingsOverrideMask = 3 } }
    return $null
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Class, [string]$ErrorAction)
    $target = if ($ClassName) { $ClassName } else { $Class }
    switch ($target) {
        "Win32_OperatingSystem" { return [PSCustomObject]@{ Caption = "Microsoft Windows 11 Pro"; BuildNumber = "26100" } }
        "Win32_Processor" { return [PSCustomObject]@{ Name = "AMD Ryzen 7 9800X3D"; Manufacturer = "AuthenticAMD"; VirtualizationFirmwareEnabled = $true } }
        "Win32_ComputerSystem" { return [PSCustomObject]@{ HypervisorPresent = $false } }
        "Win32_DeviceGuard" { return [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 0; SecurityServicesRunning = @() } }
        default { return $null }
    }
}
'@

$healthy = Invoke-MockedHvReadiness -ScriptPath $targetScript -MockPrelude $healthyPrelude
Assert-True ($healthy.OS -eq "Microsoft Windows 11 Pro") "Mocked OS mismatch"
Assert-True ($healthy.Processor -eq "AMD Ryzen 7 9800X3D") "Mocked CPU mismatch"

$byNameHealthy = @{}
foreach ($r in $healthy.Results) { $byNameHealthy[$r.Name] = $r }
Assert-True ($byNameHealthy["BIOS/UEFI Hardware Virtualization"].Status -eq "PASS") "Healthy Virtualization should PASS"
Assert-True ($byNameHealthy["Microsoft Hyper-V Hypervisor"].Status -eq "PASS") "Healthy Hyper-V should PASS"
Assert-True ($byNameHealthy["VBS Status (Active Session)"].Status -eq "PASS") "Healthy VBS should PASS"
Assert-True ($byNameHealthy["Memory Integrity (HVCI)"].Status -eq "PASS") "Healthy HVCI should PASS"
Assert-True ($byNameHealthy["Credential Guard (LSA ISO)"].Status -eq "PASS") "Healthy Credential Guard should PASS"
Assert-True ($byNameHealthy["Hypervisor-Enforced Paging (HVPT)"].Status -eq "PASS") "Healthy HVPT should PASS"
Assert-True ($byNameHealthy["Smart App Control (SAC)"].Status -eq "PASS") "Healthy SAC should PASS"
Assert-True ($byNameHealthy["FACEIT Anti-Cheat"].Status -eq "PASS") "Healthy FACEIT should PASS"
Assert-True ($byNameHealthy["Riot Vanguard (vgk)"].Status -eq "PASS") "Healthy Vanguard should PASS"
Assert-True ($byNameHealthy["MacType"].Status -eq "PASS") "Healthy MacType should PASS"
Assert-True ($byNameHealthy["Bitdefender Advanced Threat Defense"].Status -eq "PASS") "Healthy Bitdefender should PASS"
Assert-True ($byNameHealthy["Windows Null Driver Service"].Status -eq "PASS") "Healthy Null service should PASS"
Assert-True ($byNameHealthy["WMI / CIM Subsystem"].Status -eq "PASS") "Healthy WMI should PASS"

# 4. Mocked Unhealthy / Conflicting System
$failingPrelude = @'
function Write-Host { param([Parameter(ValueFromRemainingArguments=$true)]$ArgsIgnored) }
function fltmc { return @("FACEIT") }
function Confirm-SecureBootUEFI { return $true }
function Get-Process { param([string]$Name, [string]$ErrorAction) return [PSCustomObject]@{ Modules = @([PSCustomObject]@{ ModuleName = "MacType64.dll" }) } }
function Get-Service {
    param([string[]]$Name, [string]$ErrorAction)
    if ($Name -contains "Null") { return [PSCustomObject]@{ Name = "Null"; Status = "Stopped" } }
    if ($Name -contains "vgk") { return [PSCustomObject]@{ Name = "vgk"; Status = "Running" } }
    if ($Name -contains "MacType") { return [PSCustomObject]@{ Name = "MacType"; Status = "Running" } }
    if ($Name -contains "FACEIT") { return [PSCustomObject]@{ Name = "FACEIT"; Status = "Running" } }
    return @()
}
function Get-ItemProperty {
    param([string]$Path, [string]$Name, [string]$ErrorAction)
    if ($Path -like "*HypervisorEnforcedCodeIntegrity*") { return [PSCustomObject]@{ Enabled = 1 } }
    if ($Path -like "*Control\Lsa*") { return [PSCustomObject]@{ LsaCfgFlags = 1 } }
    if ($Path -like "*Control\DeviceGuard*") { return [PSCustomObject]@{ ConfigureSystemGuardLaunch = 1 } }
    if ($Path -like "*CI\Policy*") { return [PSCustomObject]@{ VerifiedAndReputablePolicyState = 1 } }
    if ($Path -like "*Bitdefender*") { return [PSCustomObject]@{ atc_data = '{"monitor_state":true}' } }
    return $null
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Namespace, [string]$Class, [string]$ErrorAction)
    $target = if ($ClassName) { $ClassName } else { $Class }
    switch ($target) {
        "Win32_OperatingSystem" { return [PSCustomObject]@{ Caption = "Microsoft Windows 11 Pro"; BuildNumber = "26100" } }
        "Win32_Processor" { return [PSCustomObject]@{ Name = "Intel Core Ultra 9"; Manufacturer = "GenuineIntel"; VirtualizationFirmwareEnabled = $false } }
        "Win32_ComputerSystem" { return [PSCustomObject]@{ HypervisorPresent = $true } }
        "Win32_DeviceGuard" { return [PSCustomObject]@{ VirtualizationBasedSecurityStatus = 2; SecurityServicesRunning = @(1, 2, 7) } }
        "AntiVirusProduct" { return [PSCustomObject]@{ displayName = "Bitdefender Total Security"; productState = 397312 } }
        default { return $null }
    }
}
'@

$unhealthy = Invoke-MockedHvReadiness -ScriptPath $targetScript -MockPrelude $failingPrelude
$byNameUnhealthy = @{}
foreach ($r in $unhealthy.Results) { $byNameUnhealthy[$r.Name] = $r }
Assert-True ($byNameUnhealthy["BIOS/UEFI Hardware Virtualization"].Status -eq "PASS") "Virt implicit from HypervisorPresent=true should PASS"
Assert-True ($byNameUnhealthy["Microsoft Hyper-V Hypervisor"].Status -eq "FAIL") "Active Hyper-V should FAIL"
Assert-True ($byNameUnhealthy["Microsoft Hyper-V Hypervisor"].Remediation -match "hypervisorlaunchtype Off") "Hyper-V remediation missing"
Assert-True ($byNameUnhealthy["VBS Status (Active Session)"].Status -eq "FAIL") "Running VBS should FAIL"
Assert-True ($byNameUnhealthy["Memory Integrity (HVCI)"].Status -eq "FAIL") "Enabled HVCI should FAIL"
Assert-True ($byNameUnhealthy["Credential Guard (LSA ISO)"].Status -eq "FAIL") "Enabled Credential Guard should FAIL"
Assert-True ($byNameUnhealthy["Hypervisor-Enforced Paging (HVPT)"].Status -eq "WARN") "Enabled HVPT should WARN"
Assert-True ($byNameUnhealthy["Smart App Control (SAC)"].Status -eq "WARN") "Enabled SAC should WARN"
Assert-True ($byNameUnhealthy["FACEIT Anti-Cheat"].Status -eq "FAIL") "Running FACEIT should FAIL"
Assert-True ($byNameUnhealthy["Riot Vanguard (vgk)"].Status -eq "WARN") "Running vgk should WARN"
Assert-True ($byNameUnhealthy["MacType"].Status -eq "WARN") "Running MacType should WARN"
Assert-True ($byNameUnhealthy["Bitdefender Advanced Threat Defense"].Status -eq "WARN") "Active Bitdefender should WARN"
Assert-True ($byNameUnhealthy["Windows Null Driver Service"].Status -eq "WARN") "Stopped Null service should WARN"

# 5. Mocked Disabled Firmware Virtualization + VBS Status 1 (Enabled Not Running)
$virtDisabledPrelude = $failingPrelude -replace 'HypervisorPresent = \$true', 'HypervisorPresent = $false' -replace 'VirtualizationBasedSecurityStatus = 2', 'VirtualizationBasedSecurityStatus = 1'
$virtDisabled = Invoke-MockedHvReadiness -ScriptPath $targetScript -MockPrelude $virtDisabledPrelude
$byNameVirt = @{}
foreach ($r in $virtDisabled.Results) { $byNameVirt[$r.Name] = $r }
Assert-True ($byNameVirt["BIOS/UEFI Hardware Virtualization"].Status -eq "FAIL") "Disabled firmware virt with HypervisorPresent=false should FAIL"
Assert-True ($byNameVirt["BIOS/UEFI Hardware Virtualization"].Remediation -match "VT-x|SVM") "Firmware virt remediation missing"
Assert-True ($byNameVirt["VBS Status (Active Session)"].Status -eq "WARN") "VBS status 1 should WARN"

if ($failures.Count -gt 0) {
    Write-Host "[-] $($failures.Count) PowerShell test assertion(s) failed." -ForegroundColor Red
    exit 1
}

Write-Host "[+] All hv-readiness.ps1 tests passed." -ForegroundColor Green
exit 0
