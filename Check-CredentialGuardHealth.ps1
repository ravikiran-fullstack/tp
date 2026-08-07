<#
.SYNOPSIS
    Read-only Credential Guard / VBS health check.
    Collects every surface relevant to "configured but not running" and writes
    a summary to console plus a JSON snapshot for diffing two machines.

.NOTES
    - Read-only. Makes NO changes to the system.
    - Run in an elevated PowerShell (needed for some registry/event reads).
    - Run on the affected device AND a known-good device, then diff the JSON.

.USAGE
    Elevated PowerShell:
        .\Check-CredentialGuardHealth.ps1
    Custom output path:
        .\Check-CredentialGuardHealth.ps1 -OutFile C:\Temp\CG_pilot.json
    Then compare two snapshots:
        .\Check-CredentialGuardHealth.ps1 -Compare C:\Temp\CG_pilot.json C:\Temp\CG_good.json
#>

[CmdletBinding()]
param(
    [string]$OutFile = "$env:TEMP\CG_Health_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).json",
    [string[]]$Compare
)

# ------------------------------------------------------------------
# COMPARE MODE: diff two previously-saved snapshots and exit.
# ------------------------------------------------------------------
if ($Compare) {
    if ($Compare.Count -ne 2) { throw "Provide exactly two JSON paths: -Compare <pilot.json> <good.json>" }
    $a = Get-Content $Compare[0] -Raw | ConvertFrom-Json
    $b = Get-Content $Compare[1] -Raw | ConvertFrom-Json
    Write-Host "`n=== DIFF: $($a.ComputerName) (A)  vs  $($b.ComputerName) (B) ===`n" -ForegroundColor Cyan
    $flat = {
        param($o,$prefix='')
        foreach ($p in $o.PSObject.Properties) {
            $val = $p.Value
            if ($val -is [pscustomobject]) { & $flat $val "$prefix$($p.Name)." }
            else { [pscustomobject]@{ Key = "$prefix$($p.Name)"; Value = ($val -join ', ') } }
        }
    }
    $fa = & $flat $a
    $fb = & $flat $b
    $keys = ($fa.Key + $fb.Key | Select-Object -Unique | Sort-Object)
    foreach ($k in $keys) {
        $va = ($fa | Where-Object Key -eq $k).Value
        $vb = ($fb | Where-Object Key -eq $k).Value
        if ($va -ne $vb) {
            Write-Host ("{0,-55} A=[{1}]  B=[{2}]" -f $k, $va, $vb) -ForegroundColor Yellow
        }
    }
    Write-Host "`n(only differing keys shown)`n"
    return
}

# ------------------------------------------------------------------
# COLLECT MODE
# ------------------------------------------------------------------
function Get-RegVal {
    param($Path,$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { $null }
}

Write-Host "`nCollecting Credential Guard / VBS state on $env:COMPUTERNAME ...`n" -ForegroundColor Cyan

# --- 1. DeviceGuard WMI (the authoritative running/configured state) ---
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
        -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue

$svcMap = @{ 1 = 'CredentialGuard'; 2 = 'HVCI'; 3 = 'SystemGuard(SMM)'; 4 = 'SecureLaunch' }
$configured = @($dg.SecurityServicesConfigured | ForEach-Object { $svcMap[$_] })
$running    = @($dg.SecurityServicesRunning    | ForEach-Object { $svcMap[$_] })

$vbsMap = @{ 0='Not enabled'; 1='Enabled but not running'; 2='Running' }
$vbsStatus = $vbsMap[[int]$dg.VirtualizationBasedSecurityStatus]

# --- 2. Registry surfaces (the two that must agree) ---
$scenarioKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
$lsaKey      = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$dgKey       = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"

$reg = [pscustomobject]@{
    Scenario_Enabled      = Get-RegVal $scenarioKey 'Enabled'          # 1 = CG on
    LsaCfgFlags           = Get-RegVal $lsaKey      'LsaCfgFlags'       # 1=UEFI lock,2=no lock,0=off
    LsaCfgFlagsDefault    = Get-RegVal $lsaKey      'LsaCfgFlagsDefault'
    EnableVBS             = Get-RegVal $dgKey       'EnableVirtualizationBasedSecurity'
    RequirePlatformSecurityFeatures = Get-RegVal $dgKey 'RequirePlatformSecurityFeatures'
    HVCI_Enabled          = Get-RegVal "$dgKey\Scenarios\HypervisorEnforcedCodeIntegrity" 'Enabled'
}

# --- 3. lsaiso trustlet ---
$lsaiso = Get-Process lsaiso -ErrorAction SilentlyContinue
$lsaisoRunning = [bool]$lsaiso
$lsaisoFileExists = Test-Path "$env:SystemRoot\System32\lsaiso.exe"

# --- 4. Hypervisor launch type ---
$hvLaunch = $null
try { $hvLaunch = (bcdedit /enum '{current}' | Select-String 'hypervisorlaunchtype').ToString().Trim() } catch {}

# --- 5. Reboot pending? ---
$pendingReasons = @()
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $pendingReasons += 'CBS' }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $pendingReasons += 'WindowsUpdate' }
if (Get-RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" 'PendingFileRenameOperations') { $pendingReasons += 'PendingFileRename' }

# --- 6. Boot time vs last GP apply ---
$os = Get-CimInstance Win32_OperatingSystem
$lastBoot = $os.LastBootUpTime
$gpApply  = Get-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\{00000000-0000-0000-0000-000000000000}" 'EndTime'

# --- 7. Device Guard operational events (7000-7010) ---
$dgEvents = @()
try {
    $dgEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-DeviceGuard/Operational'; Id=7000,7001,7002,7003,7010
    } -MaxEvents 15 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n='Msg';e={($_.Message -split "`n")[0]}}
} catch {}

# --- 8. Code Integrity events (3004/3089) - reference only ---
$ciEvents = @()
try {
    $ciEvents = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3004,3089
    } -MaxEvents 10 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{n='Msg';e={($_.Message -split "`n")[0]}}
} catch {}

# ------------------------------------------------------------------
# VERDICT
# ------------------------------------------------------------------
$verdict = @()
if ($running -contains 'CredentialGuard' -and $lsaisoRunning) {
    $verdict += "OK: Credential Guard is RUNNING (lsaiso alive)."
} else {
    $verdict += "PROBLEM: Credential Guard NOT running."
    if ($configured -contains 'CredentialGuard') { $verdict += "  - It IS configured, so the policy landed." }
    else { $verdict += "  - It is NOT even configured. Check policy/registry targeting." }

    if ($reg.Scenario_Enabled -eq 1 -or $reg.LsaCfgFlags -in 1,2) {
        if ($pendingReasons.Count -gt 0) {
            $verdict += "  - Config is on AND a reboot is pending ($($pendingReasons -join ',')). >>> REBOOT is the likely fix."
        } elseif ($lastBoot -lt (Get-Date).AddDays(-1)) {
            $verdict += "  - Config is on, no reboot since $lastBoot. CG only activates at boot. >>> Try a REBOOT first."
        } else {
            $verdict += "  - Config is on and machine booted recently but CG still didn't start. >>> Inspect DeviceGuard events 7000-7003 (boot-time trustlet failure)."
        }
    }
    if (-not $lsaisoFileExists) { $verdict += "  - WARNING: lsaiso.exe missing from System32 (unexpected - possible image/servicing issue)." }
    if ([int]$dg.VirtualizationBasedSecurityStatus -lt 2) { $verdict += "  - NOTE: VBS itself is '$vbsStatus'. CG can't run without VBS running." }
}

# ------------------------------------------------------------------
# OUTPUT
# ------------------------------------------------------------------
$snapshot = [pscustomobject]@{
    ComputerName        = $env:COMPUTERNAME
    Collected           = (Get-Date).ToString('s')
    VBS_Status          = "$([int]$dg.VirtualizationBasedSecurityStatus) ($vbsStatus)"
    Configured          = $configured
    Running             = $running
    Registry            = $reg
    lsaiso_Running      = $lsaisoRunning
    lsaiso_FileExists   = $lsaisoFileExists
    HypervisorLaunch    = $hvLaunch
    RebootPending       = if ($pendingReasons) { $pendingReasons -join ',' } else { 'No' }
    LastBootUpTime      = $lastBoot.ToString('s')
    DeviceGuardEvents   = $dgEvents
    CodeIntegrityEvents = $ciEvents
}

Write-Host "==================== SUMMARY ====================" -ForegroundColor Green
Write-Host ("VBS status        : {0}" -f $snapshot.VBS_Status)
Write-Host ("Configured        : {0}" -f ($configured -join ', '))
Write-Host ("Running           : {0}" -f ($running -join ', '))
Write-Host ("Scenario Enabled  : {0}" -f $reg.Scenario_Enabled)
Write-Host ("LsaCfgFlags       : {0}  (Default {1})" -f $reg.LsaCfgFlags, $reg.LsaCfgFlagsDefault)
Write-Host ("lsaiso running    : {0}   (file present: {1})" -f $lsaisoRunning, $lsaisoFileExists)
Write-Host ("Hypervisor        : {0}" -f $hvLaunch)
Write-Host ("Reboot pending    : {0}" -f $snapshot.RebootPending)
Write-Host ("Last boot         : {0}" -f $lastBoot)
Write-Host ""
Write-Host "-------------------- VERDICT --------------------" -ForegroundColor Green
$verdict | ForEach-Object { Write-Host $_ }

if ($dgEvents) {
    Write-Host "`n--- DeviceGuard events (7000-7010) ---" -ForegroundColor DarkCyan
    $dgEvents | Format-Table -Auto | Out-String | Write-Host
}
if ($ciEvents) {
    Write-Host "--- CodeIntegrity events (3004/3089) - reference only, not a CG blocker ---" -ForegroundColor DarkGray
    $ciEvents | Format-Table -Auto | Out-String | Write-Host
}

$snapshot | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutFile -Encoding UTF8
Write-Host "`nSnapshot saved: $OutFile" -ForegroundColor Cyan
Write-Host "Run on a good device too, then diff:  .\Check-CredentialGuardHealth.ps1 -Compare <pilot.json> <good.json>`n"
