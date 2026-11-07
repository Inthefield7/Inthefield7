# DD.Repair.ps1 - safe, confirm-each-step repair actions (Windows only).
#
# Safety contract:
#   - A restore point and a backup of the affected driver packages come first.
#   - Every action asks for confirmation (ShouldProcess, ConfirmImpact High) and honors -WhatIf.
#   - No action uninstalls drivers, deletes driver-store packages, edits BIOS settings,
#     disables security features, or installs unsigned code.
#   - Display changes never remove the display that currently works (Extend, never "PC screen only").
#   - Firmware/BIOS installs are held back unless -IncludeFirmware, and then require AC power.
#   - The computer is never restarted without -AllowRestart and a confirmation.

function New-DDResult {
    # Builds an in-memory result object only; "New" is not a system change.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param($Action, [string]$Result, [string]$Detail)
    return [pscustomobject]@{ Type = $Action.Type; Target = $Action.Target; Result = $Result; Detail = $Detail }
}

function Invoke-DDNative {
    # Runs a console tool and returns exit code + output. pnputil returns 3010 for "reboot required".
    param([string]$File, [string[]]$Arguments)
    # Under 'Stop', Windows PowerShell 5.1 throws on the first stderr line of a native tool;
    # 'Continue' lets the exit code decide success.
    $ErrorActionPreference = 'Continue'
    $out = & $File @Arguments 2>&1 | ForEach-Object { "$_" } | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $out.Trim() }
}

function New-DDRestorePoint {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([bool])]
    param([string]$Description)
    if (-not $PSCmdlet.ShouldProcess('System', "Create restore point '$Description'")) { return $false }
    try {
        $r = Invoke-CimMethod -Namespace root/default -ClassName SystemRestore -MethodName CreateRestorePoint `
            -Arguments @{ Description = $Description; RestorePointType = [uint32]12; EventType = [uint32]100 } -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { Write-Warning "CreateRestorePoint returned $($r.ReturnValue)."; return $false }
        # Windows silently skips creation if one was made in the last 24h; verify it exists.
        $made = @(Get-CimInstance -Namespace root/default -ClassName SystemRestore -ErrorAction SilentlyContinue | Where-Object { $_.Description -eq $Description })
        return ($made.Count -gt 0)
    }
    catch { Write-Warning "Restore point failed: $($_.Exception.Message)"; return $false }
}

function Backup-DDDrivers {
    param([object[]]$Devices, [string]$Folder)
    New-Item -ItemType Directory -Force -Path $Folder | Out-Null
    (Invoke-DDNative 'pnputil.exe' @('/enum-drivers')).Output | Set-Content -LiteralPath (Join-Path $Folder 'driver-store-before.txt') -Encoding UTF8
    $infs = @($Devices | ForEach-Object { $_.DriverInf } | Where-Object { $_ -match '^oem\d+\.inf$' } | Sort-Object -Unique)
    $ok = @()
    foreach ($inf in $infs) {
        $dest = Join-Path $Folder ($inf -replace '\.inf$', '')
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        $r = Invoke-DDNative 'pnputil.exe' @('/export-driver', $inf, $dest)
        if ($r.ExitCode -eq 0) { $ok += $inf } else { Write-Warning "Could not export ${inf}: $($r.Output)" }
    }
    return $ok
}

function Get-DDDeviceState {
    param([string]$InstanceId)
    $d = Get-PnpDevice -InstanceId $InstanceId -ErrorAction SilentlyContinue
    if (-not $d) { return 'not found' }
    return "status $($d.Status), code $($d.ConfigManagerErrorCode)"
}

function Invoke-DDRestartDevice {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action)
    $dev = Get-PnpDevice -InstanceId $Action.Target -ErrorAction SilentlyContinue
    # Never bounce storage or core platform devices: the system may depend on them to keep running.
    if ($dev -and $dev.Class -in 'DiskDrive', 'SCSIAdapter', 'HDC', 'Volume', 'VolumeSnapshot', 'Processor', 'Computer') {
        return (New-DDResult $Action 'Skipped' "Class $($dev.Class) is never restarted by this tool.")
    }
    $isGpu = $dev -and $dev.Class -eq 'Display'
    $what = if ($isGpu) { 'Restart GPU device (all screens go black for a few seconds, then return)' } else { 'Restart device' }
    if (-not $PSCmdlet.ShouldProcess($Action.Target, $what)) { return (New-DDResult $Action 'Declined' '') }
    $before = Get-DDDeviceState $Action.Target
    $r = Invoke-DDNative 'pnputil.exe' @('/restart-device', $Action.Target)
    Start-Sleep -Seconds 6
    $after = Get-DDDeviceState $Action.Target
    $result = if ($r.ExitCode -eq 0) { 'Applied' } elseif ($r.ExitCode -eq 3010) { 'Applied (restart required)' } else { 'Failed' }
    return (New-DDResult $Action $result "before: $before; after: $after; pnputil exit $($r.ExitCode): $($r.Output)")
}

function Invoke-DDScanDevices {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action)
    if (-not $PSCmdlet.ShouldProcess('Plug and Play', 'Rescan hardware and re-evaluate installed drivers')) { return (New-DDResult $Action 'Declined' '') }
    $r = Invoke-DDNative 'pnputil.exe' @('/scan-devices')
    $result = if ($r.ExitCode -eq 0) { 'Applied' } else { 'Failed' }
    return (New-DDResult $Action $result "pnputil exit $($r.ExitCode): $($r.Output)")
}

function Invoke-DDEnableDevice {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action)
    if (-not $PSCmdlet.ShouldProcess($Action.Target, 'Enable device')) { return (New-DDResult $Action 'Declined' '') }
    try {
        Enable-PnpDevice -InstanceId $Action.Target -Confirm:$false -ErrorAction Stop
        return (New-DDResult $Action 'Applied' "now: $(Get-DDDeviceState $Action.Target)")
    }
    catch { return (New-DDResult $Action 'Failed' $_.Exception.Message) }
}

function Invoke-DDExtendTopology {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action)
    if (-not $PSCmdlet.ShouldProcess('Display layout', 'Switch to Extend (keeps the external screen on; undo with Win+P)')) { return (New-DDResult $Action 'Declined' '') }
    try {
        Import-DDDisplayConfig
        $rc = [DriverDoctor.DisplayConfigReader]::ApplyExtendTopology()
        $result = if ($rc -eq 0) { 'Applied' } else { 'Failed' }
        return (New-DDResult $Action $result "SetDisplayConfig returned $rc")
    }
    catch { return (New-DDResult $Action 'Failed' $_.Exception.Message) }
}

function Invoke-DDSetBrightness {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action)
    $level = [byte]([int]$Action.Target)
    if (-not $PSCmdlet.ShouldProcess('Built-in panel', "Set brightness to $level%")) { return (New-DDResult $Action 'Declined' '') }
    try {
        Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop |
            Invoke-CimMethod -MethodName WmiSetBrightness -Arguments @{ Timeout = [uint32]0; Brightness = $level } -ErrorAction Stop | Out-Null
        return (New-DDResult $Action 'Applied' "Brightness set to $level%")
    }
    catch { return (New-DDResult $Action 'Failed' $_.Exception.Message) }
}

function Invoke-DDInstallWindowsUpdate {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action, [string]$Title)
    # SEC-004: firmware from Windows Update gets the same power gate as firmware from HPIA. A plan step
    # marked as firmware only exists with -IncludeFirmware (Get-DDRepairPlan holds it back otherwise).
    # Firmware the plan did not mark (by title now, by Windows Update's own data after the search) is
    # not installed at all, so the gate cannot be bypassed by a misclassified offer.
    $unmarked = 'Windows Update lists this update as firmware, but the plan did not mark it as firmware. Firmware needs -IncludeFirmware; not installed.'
    $isFirmware = [bool]$Action.RequiresFirmwareConsent
    if (-not $isFirmware -and (Test-DDFirmwareUpdate -Title $Title)) { return (New-DDResult $Action 'Skipped' $unmarked) }
    if ($isFirmware) {
        $gate = Test-DDFirmwareSafe
        if (-not $gate[0]) { return (New-DDResult $Action 'Skipped' "Firmware safety gate: $($gate[1])") }
        Write-DDBitLockerWarning
    }
    if (-not $PSCmdlet.ShouldProcess($Title, 'Download and install from Windows Update')) { return (New-DDResult $Action 'Declined' '') }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $search = $session.CreateUpdateSearcher().Search("UpdateID='$($Action.Target)'")
        if ($search.Updates.Count -eq 0) { return (New-DDResult $Action 'Skipped' 'No longer offered by Windows Update.') }
        $liveFirmware = @($search.Updates | Where-Object { Test-DDFirmwareUpdate -DriverClass ([string]$_.DriverClass) -Title ([string]$_.Title) }).Count -gt 0
        if ($liveFirmware -and -not $isFirmware) { return (New-DDResult $Action 'Skipped' $unmarked) }
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $search.Updates) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$coll.Add($u) }
        $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
        $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
        $res = $inst.Install()
        $codes = @{ 2 = 'Applied'; 3 = 'Applied with errors'; 4 = 'Failed'; 5 = 'Aborted' }
        $text = if ($codes.ContainsKey([int]$res.ResultCode)) { $codes[[int]$res.ResultCode] } else { "ResultCode $($res.ResultCode)" }
        if ($res.RebootRequired) { $text += ' (restart required)' }
        return (New-DDResult $Action $text "HResult $('0x{0:X8}' -f $res.HResult)")
    }
    catch { return (New-DDResult $Action 'Failed' $_.Exception.Message) }
}

function Test-DDFirmwareSafe {
    # Conservative gate for BIOS/firmware installs (this tool's policy): AC connected and battery >= 50%.
    # Collects the facts only; the decision (fail closed) is Get-DDFirmwareGate in DD.Analysis.ps1.
    $failed = $false
    $b = @()
    try { $b = @(Get-CimInstance Win32_Battery -ErrorAction Stop) } catch { $failed = $true }
    $status = @(Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue)
    $type = $null
    try { $type = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PCSystemType } catch { Write-Verbose "PCSystemType unavailable: $($_.Exception.Message)" }
    return (Get-DDFirmwareGate -Batteries $b -BatteryStatus $status -PCSystemType $type -QueryFailed $failed)
}

function Write-DDBitLockerWarning {
    $bl = $null
    try { $bl = Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop }
    catch { Write-Verbose "BitLocker state unavailable: $($_.Exception.Message)" }
    if ($bl -and $bl.ProtectionStatus -eq 1) {
        Write-Warning 'BitLocker is ON for the system drive. Make sure you have the recovery key (https://account.microsoft.com/devices/recoverykey) before a BIOS update.'
    }
}

function Invoke-DDHPIAInstall {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action, [string]$HPIAPath)
    $found = Find-DDHPIA $HPIAPath
    $exe = $found.Path
    if (-not $exe) {
        $why = if (@($found.Rejected).Count -gt 0) { 'HP Image Assistant not run: ' + (@($found.Rejected) -join '; ') } else { 'HP Image Assistant not found.' }
        return (New-DDResult $Action 'Skipped' $why)
    }
    $categories = [string]$Action.Target
    if ($categories -match 'BIOS|Firmware') {
        $gate = Test-DDFirmwareSafe
        if (-not $gate[0]) { return (New-DDResult $Action 'Skipped' "Firmware safety gate: $($gate[1])") }
        Write-DDBitLockerWarning
    }
    if (-not $PSCmdlet.ShouldProcess("HP Image Assistant ($categories)", 'Download and install HP-recommended updates for this model')) { return (New-DDResult $Action 'Declined' '') }
    # SEC-002: SoftPaqs are downloaded and then run as administrator, so they live in a fresh
    # admin-only folder under %ProgramData%\DriverDoctor, never in the user-writable Desktop folder.
    try { $base = Get-DDHPIAWorkDir }
    catch { return (New-DDResult $Action 'Skipped' "HPIA not run: no safe work folder ($($_.Exception.Message))") }
    $report = Join-Path $base 'hpia-install'
    $softpaqs = Join-Path $base 'hpia-softpaqs'
    New-DDSecureDirectory $report
    New-DDSecureDirectory $softpaqs
    $hpiaArgs = @('/Operation:Analyze', "/Category:$categories", '/Selection:All', '/Action:Install', '/Silent', "/ReportFolder:`"$report`"", "/SoftpaqDownloadFolder:`"$softpaqs`"")
    $p = Start-Process -FilePath $exe -ArgumentList $hpiaArgs -Wait -PassThru -WindowStyle Hidden
    $known = @{ 0 = 'Applied'; 256 = 'Nothing to install'; 257 = 'Nothing selected'; 3010 = 'Applied (restart required)'; 4096 = 'Platform not supported'; 4097 = 'Invalid parameters' }
    $text = if ($known.ContainsKey($p.ExitCode)) { $known[$p.ExitCode] } else { "Exit code $($p.ExitCode)" }
    return (New-DDResult $Action $text "Report: $report")
}

function Invoke-DDRestartComputer {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param($Action, [switch]$AllowRestart)
    if (-not $AllowRestart) { return (New-DDResult $Action 'Advised' 'Restart yourself: plug in AC power, then Start > Power > Restart (not Shut down).') }
    if (-not $PSCmdlet.ShouldProcess('This computer', 'Full restart in 60 seconds (cancel: shutdown /a)')) { return (New-DDResult $Action 'Declined' '') }
    $r = Invoke-DDNative 'shutdown.exe' @('/r', '/t', '60', '/c', 'Driver Doctor: restarting to finish driver/firmware updates. Cancel with: shutdown /a')
    return (New-DDResult $Action $(if ($r.ExitCode -eq 0) { 'Scheduled' } else { 'Failed' }) $r.Output)
}

function Invoke-DDRepair {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [object[]]$Plan,
        $Snapshot,
        [string]$WorkDir,
        [string]$HPIAPath
    )
    # No -AllowRestart here: RestartComputer steps are skipped below. The only restart path is
    # Invoke-DDRestartComputer, which DriverDoctor.ps1 calls last, gated by -AllowRestart + a confirmation.
    $results = New-Object System.Collections.Generic.List[object]
    $changing = @($Plan | Where-Object { $_.Type -notin 'Manual', 'RestartComputer' })
    if ($changing.Count -eq 0) {
        Write-Host 'Nothing to change automatically.' -ForegroundColor Green
    }
    else {
        Write-Host "`nSafety net first:" -ForegroundColor Cyan
        $rp = New-DDRestorePoint -Description "Driver Doctor $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        if ($rp) { $results.Add([pscustomobject]@{ Type = 'RestorePoint'; Target = 'System'; Result = 'Created'; Detail = '' }) }
        else {
            $results.Add([pscustomobject]@{ Type = 'RestorePoint'; Target = 'System'; Result = 'Not created'; Detail = 'System Protection off, or one already made in the last 24h.' })
            if (-not $WhatIfPreference) {
                $answer = Read-Host 'No new restore point. Driver packages will still be backed up. Continue? (y/N)'
                if ($answer -notmatch '^(?i)y') { $results.Add([pscustomobject]@{ Type = 'Repair'; Target = ''; Result = 'Stopped by user'; Detail = '' }); return $results.ToArray() }
            }
        }
        if (-not $WhatIfPreference) {
            $backupDir = Join-Path $WorkDir 'driver-backup'
            $relevant = @($Snapshot.Devices | Where-Object { $_.Present -and ($_.ProblemCode -ne 0 -or $_.ClassGuid -in $script:DDClassGuid.Display, $script:DDClassGuid.Monitor, $script:DDClassGuid.Firmware) })
            $exported = Backup-DDDrivers -Devices $relevant -Folder $backupDir
            $results.Add([pscustomobject]@{ Type = 'DriverBackup'; Target = $backupDir; Result = 'Done'; Detail = "Exported: $($exported -join ', ')" })
        }
    }

    $titles = @{}
    foreach ($u in @($Snapshot.WindowsUpdate.Updates)) { if ($u) { $titles[[string]$u.UpdateId] = $u.Title } }
    Write-Host "`nRepair steps (each one asks first):" -ForegroundColor Cyan
    foreach ($a in $Plan) {
        Write-Host "`n> $(ConvertTo-DDConsoleText $a.Type) $(ConvertTo-DDConsoleText $a.Target)`n  $(ConvertTo-DDConsoleText $a.Detail)" -ForegroundColor White
        $r = switch ($a.Type) {
            'EnableDevice' { Invoke-DDEnableDevice -Action $a }
            'ExtendTopology' { Invoke-DDExtendTopology -Action $a }
            'SetBrightness' { Invoke-DDSetBrightness -Action $a }
            'RestartDevice' { Invoke-DDRestartDevice -Action $a }
            'ScanDevices' { Invoke-DDScanDevices -Action $a }
            'InstallWindowsUpdate' { Invoke-DDInstallWindowsUpdate -Action $a -Title $titles[[string]$a.Target] }
            'HPIAInstall' { Invoke-DDHPIAInstall -Action $a -HPIAPath $HPIAPath }
            'RestartComputer' { $null }  # handled last, once
            default { New-DDResult $a 'Manual step' $a.Detail }
        }
        if ($r) { $results.Add($r); Write-Host "  -> $(ConvertTo-DDConsoleText $r.Result) $(ConvertTo-DDConsoleText $r.Detail)" -ForegroundColor DarkGray }
    }
    return $results.ToArray()
}
