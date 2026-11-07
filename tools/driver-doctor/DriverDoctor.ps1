<#
.SYNOPSIS
    Driver Doctor - finds broken, failing, or out-of-date drivers and firmware on Windows,
    explains the evidence, and (only when asked) applies safe, confirmed fixes.

.DESCRIPTION
    Diagnose (default) is read-only. It sweeps every device with a Device Manager problem,
    the Kernel-PnP device configuration log, display topology (to explain a dark built-in
    screen), firmware update status, pending restarts, driver files, Code Integrity / LSA
    module blocks, WHEA hardware errors, Windows Update driver offers, and HP Image Assistant
    (if present). It writes an HTML report, a findings JSON, and a snapshot JSON.

    Repair creates a restore point and a driver backup first, then walks an ordered plan.
    Every step asks for confirmation; -WhatIf shows the plan without changing anything.
    After the steps it re-collects and shows what is fixed, still present, or new.

.EXAMPLE
    .\DriverDoctor.ps1
    Read-only sweep and report.

.EXAMPLE
    .\DriverDoctor.ps1 -Mode Repair -WhatIf
    Shows exactly what Repair would do. Changes nothing.

.EXAMPLE
    .\DriverDoctor.ps1 -Mode Repair
    Restore point + driver backup, then confirmed fixes, then a before/after check.

.EXAMPLE
    .\DriverDoctor.ps1 -SnapshotPath .\snapshot.json
    Re-analyzes a saved snapshot offline (works on any OS with PowerShell 7).
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateSet('Diagnose', 'Repair')]
    [string]$Mode = 'Diagnose',

    # How far back to read event logs.
    [ValidateRange(1, 3650)]
    [int]$Days = 180,

    # Report folder, for runs WITHOUT administrator rights. Default: Desktop\DriverDoctor\<timestamp>.
    # An administrator run refuses it and writes to a new administrators-only folder under
    # %ProgramData%\DriverDoctor instead (printed at the end).
    [string]$OutputPath,

    [switch]$SkipWindowsUpdate,
    [switch]$SkipHPIA,

    # Folder or full path of HPImageAssistant.exe if it is not in a standard place.
    [string]$HPIAPath,

    # Allow BIOS/firmware installs in Repair (requires AC power and >= 50% battery).
    [switch]$IncludeFirmware,

    # Allow Repair to schedule a full restart at the end (it still asks).
    [switch]$AllowRestart,

    # Analyze a saved snapshot instead of this computer (no system access at all).
    [string]$SnapshotPath,

    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$libDir = Join-Path $PSScriptRoot 'lib'
. (Join-Path $libDir 'DD.Analysis.ps1')
. (Join-Path $libDir 'DD.Report.ps1')

$onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
if ($Mode -eq 'Repair' -and $SnapshotPath) { throw 'Repair works on the live computer only; it cannot be combined with -SnapshotPath.' }
if (-not $SnapshotPath -and -not $onWindows) { throw 'Live collection needs Windows. Use -SnapshotPath to analyze a saved snapshot.' }

$elevated = $false
if ($onWindows) { $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if ($elevated) {
    # NEW-2: as administrator, never write into a folder the user chose or controls (see
    # Get-DDElevatedOutputDir). Run without administrator rights to use -OutputPath.
    if ($OutputPath) { throw '-OutputPath is not accepted when running as administrator: the report goes to a new administrators-only folder under %ProgramData%\DriverDoctor (printed at the end). Run from a normal PowerShell window to choose the folder.' }
    . (Join-Path $libDir 'DD.Collect.ps1')
    $OutputPath = Get-DDElevatedOutputDir
}
else {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if (-not $OutputPath) {
        $base = if ($onWindows) { [Environment]::GetFolderPath('Desktop') } else { (Get-Location).Path }
        $OutputPath = Join-Path (Join-Path $base 'DriverDoctor') $stamp
    }
    New-Item -ItemType Directory -Force -Path $OutputPath -WhatIf:$false | Out-Null
}
$transcript = $false
# Reports are always written, even under -WhatIf (which only governs system changes).
try { Start-Transcript -Path (Join-Path $OutputPath 'console-log.txt') -Force -WhatIf:$false | Out-Null; $transcript = $true }
catch { Write-Verbose "Transcript unavailable: $($_.Exception.Message)" }

try {
    Write-Host "Driver Doctor - mode: $Mode" -ForegroundColor Cyan
    Write-Host "Output: $OutputPath"

    if ($SnapshotPath) {
        $snapshot = Get-Content -Raw -LiteralPath $SnapshotPath | ConvertFrom-Json
    }
    else {
        . (Join-Path $libDir 'DD.Collect.ps1')
        if (-not (Test-DDIsAdmin)) {
            if ($Mode -eq 'Repair') { throw 'Repair must run as Administrator. Use Run-Repair.cmd or an elevated PowerShell.' }
            Write-Warning 'Not running as Administrator: some logs and driver details will be missing. Run-Diagnose.cmd elevates automatically.'
        }
        $snapshot = Get-DDSnapshot -Days $Days -SkipWindowsUpdate:$SkipWindowsUpdate -SkipHPIA:$SkipHPIA -HPIAPath $HPIAPath
        $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputPath 'snapshot.json') -Encoding UTF8 -WhatIf:$false
    }

    $analysis = Invoke-DDAnalysis -Snapshot $snapshot
    $plan = @(Get-DDRepairPlan -Findings $analysis.Findings -IncludeFirmware:$IncludeFirmware)
    $repairResults = @()
    $comparison = $null
    $finalAnalysis = $analysis
    $finalSnapshot = $snapshot

    Write-DDConsoleSummary -Analysis $analysis

    if ($Mode -eq 'Repair') {
        . (Join-Path $libDir 'DD.Repair.ps1')
        $repairStart = (Get-Date).ToUniversalTime()
        $repairResults = @(Invoke-DDRepair -Plan $plan -Snapshot $snapshot -HPIAPath $HPIAPath)
        $applied = @($repairResults | Where-Object { $_.Result -like 'Applied*' }).Count
        if ($applied -gt 0 -and -not $WhatIfPreference) {
            Write-Host "`nVerifying: re-collecting state after repair..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            $finalSnapshot = Get-DDSnapshot -Days $Days -Quick
            $finalSnapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputPath 'snapshot-after.json') -Encoding UTF8 -WhatIf:$false
            $finalAnalysis = Invoke-DDAnalysis -Snapshot $finalSnapshot -EventsSince $repairStart
            $comparison = Compare-DDFindings -Before $analysis.Findings -After $finalAnalysis.Findings
            Write-DDConsoleSummary -Analysis $finalAnalysis -Comparison $comparison
            if (@($comparison.New).Count -gt 0) {
                $backup = @($repairResults | Where-Object { $_.Type -eq 'DriverBackup' -and $_.Result -eq 'Done' } | ForEach-Object { $_.Target }) | Select-Object -First 1
                if (-not $backup) { $backup = '<backup>' }
                Write-Warning "New problems appeared after repair. To undo: Device Manager > device > Driver > Roll Back Driver, or restore the backed-up driver from an elevated prompt with `"pnputil /add-driver $backup\<oemNN>\*.inf /install`", or use System Restore (restore point `"Driver Doctor ...`")."
            }
        }
        if (@($plan | Where-Object { $_.Type -eq 'RestartComputer' }).Count -gt 0) {
            $rAction = [pscustomobject]@{ Type = 'RestartComputer'; Target = ''; Detail = 'Full restart' }
            $repairResults += Invoke-DDRestartComputer -Action $rAction -AllowRestart:$AllowRestart
        }
    }
    elseif (@($plan).Count -gt 0) {
        Write-Host "`nRepair plan (not applied; run Run-Repair.cmd or -Mode Repair -WhatIf to preview):" -ForegroundColor Cyan
        $i = 0
        foreach ($p in $plan) { $i++; Write-Host ("  {0}. {1} {2} - {3}" -f $i, (ConvertTo-DDConsoleText $p.Type), (ConvertTo-DDConsoleText $p.Target), (ConvertTo-DDConsoleText $p.Detail)) }
    }

    $html = ConvertTo-DDHtmlReport -Snapshot $finalSnapshot -Analysis $finalAnalysis -Plan $plan -RepairResults $repairResults -Comparison $comparison -Mode $Mode
    $reportPath = Join-Path $OutputPath 'report.html'
    Set-Content -LiteralPath $reportPath -Value $html -Encoding UTF8 -WhatIf:$false
    [pscustomobject]@{ Verdict = $finalAnalysis.Verdict; Findings = $finalAnalysis.Findings; Plan = $plan; Repair = $repairResults; Comparison = $comparison } |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputPath 'findings.json') -Encoding UTF8 -WhatIf:$false

    Write-Host "`nReport: $reportPath" -ForegroundColor Green
    # NEW-1: an administrator process never opens the report. ShellExecute would pick the browser
    # through HKCU\Software\Classes, which any program running as the user can redirect, and the
    # browser itself would run as administrator. Open it from File Explorer instead.
    if ($elevated) { Write-Host 'It is not opened automatically from an administrator window. Paste the folder path above into File Explorer''s address bar (ProgramData is a hidden folder) and open report.html from there.' -ForegroundColor Green }
    elseif (-not $NoOpen -and $onWindows) { & { $WhatIfPreference = $false; Start-Process $reportPath } }
}
finally {
    if ($transcript) { try { Stop-Transcript | Out-Null } catch { Write-Verbose 'Transcript already stopped.' } }
}
