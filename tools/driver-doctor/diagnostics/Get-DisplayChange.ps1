<#
.SYNOPSIS
    Read-only: what changed between the dark built-in screen (2026-08-26) and now?

.DESCRIPTION
    Writes one text file with the facts that can explain why the built-in panel works again:
      - the GPU driver installed now (INF, version, date) vs. oem39.inf, which failed to start on 2026-08-26
      - whether the built-in panel (CMN163B) is present and active, and how it is connected
      - whether the staged UEFI firmware capsule {f9a422c9-...} was applied, plus the BIOS version
      - boots and shutdowns, with full boot vs. Fast Startup
      - a timeline since -Since: Kernel-PnP configuration events for the GPU, panel and firmware,
        Windows Update history, setupapi device installs, and (last 3 days) sleep/resume
    It lists facts only; it does not decide the cause. Changes nothing.
    Run it in an elevated PowerShell for full event-log access.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Get-DisplayChange.ps1
#>
[CmdletBinding()]
param(
    [datetime]$Since = '2026-08-20',
    [string]$OutputPath,
    [string[]]$Match = @('DEV_7D45', 'CMN163B', 'UEFI\RES_', 'DISPLAY\', 'Default_Monitor', 'iigd'),
    # Development only: run as administrator from a folder that is not administrators-only (a checkout).
    [switch]$SkipInstallFolderCheck
)

. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\DD.Analysis.ps1')
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\DD.Report.ps1')   # ConvertTo-DDConsoleText (NEW-6)

# What the 2026-08-26 Event Viewer screenshots showed (VERIFIED from the screenshots).
$script:DCBaseline = @{
    Date         = '2026-08-26'
    GpuInf       = 'oem39.inf'
    GpuId        = 'DEV_7D45'
    PanelId      = 'CMN163B'
    FirmwareGuid = 'f9a422c9-7892-42c3-a237-218610bfd215'
}

# Kernel-Boot event 27 boot type, as Microsoft documents it.
$script:DCBootType = @{ 0 = 'full boot (cold start)'; 1 = 'Fast Startup (hybrid boot)'; 2 = 'resume from hibernate' }

# ---------------------------------------------------------------------------
# Pure helpers (tested in tests\Run-Tests.ps1)
# ---------------------------------------------------------------------------

function ConvertTo-DCLine {
    # Flattens an event message to one line: the first sentence plus the key fields.
    param([string]$Message)
    if (-not $Message) { return '' }
    $lines = @($Message -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -eq 0) { return '' }
    $keep = 'Driver Name|Driver Version|Driver Date|Driver Provider|Problem Status|Problem|Present|Last Device Instance Id|Service|Shutdown Type|Reason Code|Status'
    $parts = @($lines[0])
    foreach ($l in @($lines | Select-Object -Skip 1)) {
        if ($l -match "^($keep)\s*:\s*(.+)$") { $parts += ('{0}={1}' -f $Matches[1], $Matches[2].Trim()) }
    }
    $text = $parts -join ' | '
    if ($text.Length -gt 400) { $text = $text.Substring(0, 400) + '...' }
    return $text
}

function Get-DCMatchRegex {
    param([string[]]$Pattern)
    return '(?i)(' + (@($Pattern | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')'
}

function Get-DCSetupApiInstalls {
    # Parses setupapi.dev.log sections whose header matches a pattern. Times are local, as logged.
    param($Lines, [datetime]$Since, [string[]]$Pattern)
    $rx = Get-DCMatchRegex $Pattern
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^>>>\s+\[(.+)\]\s*$') {
            $header = $Matches[1]
            $current = $null
            if ($header -match $rx) { $current = [pscustomobject]@{ Time = $null; Source = 'setupapi'; Text = $header; Status = '' } }
            continue
        }
        if ($null -eq $current) { continue }
        if ($null -eq $current.Time -and $line -match '^>>>\s+Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})') {
            $current.Time = [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
            continue
        }
        if ($line -match '^<<<\s+\[Exit status:\s*(.+?)\]') {
            $current.Status = $Matches[1]
            if ($current.Time -and $current.Time -ge $Since) { $current }
            $current = $null
        }
    }
}

function Get-DCBootTypeText {
    param([string]$Message)
    if ($Message -match '(?i)boot type was (0x[0-9a-f]+|\d+)') {
        $n = ConvertTo-DDInt $Matches[1]
        $name = $script:DCBootType[[int]$n]
        if (-not $name) { $name = 'unrecognized' }
        return ('Boot type {0}: {1}' -f $Matches[1], $name)
    }
    return (ConvertTo-DCLine $Message)
}

function Get-DCEventDevice {
    # The device an event is ABOUT, never a referenced one. Event 442 also carries
    # "Last Device Instance Id=<other device>"; matching the whole text would credit that
    # other device with the event. English text: "Device [settings for ]<id> ...".
    # Otherwise (localized): the first sentence only, before the flattened key fields.
    param([string]$Text)
    if (-not $Text) { return '' }
    if ($Text -match '^Device (?:settings for )?(\S+)') { return $Matches[1] }
    return (($Text -split ' \| ')[0])
}

function Get-DCObservations {
    # Facts only, each with its source. Interpretation is left to the reader.
    param($State)
    $b = $script:DCBaseline
    $out = New-Object System.Collections.Generic.List[string]

    foreach ($g in @($State.Gpus | Where-Object { $_.Present })) {
        $note = 'driver package unknown'
        if ($g.Inf -and $g.Inf -ieq $b.GpuInf) { $note = "same package name as the one that failed on $($b.Date) ($($b.GpuInf)); not replaced [INFERRED from name]" }
        elseif ($g.Inf -and $g.InstanceId -match $b.GpuId) { $note = "DIFFERENT package than the one that failed on $($b.Date) ($($b.GpuInf)): a new driver was installed since [VERIFIED by package name]" }
        elseif ($g.Inf) { $note = 'not the Intel GPU from the screenshots' }
        $out.Add(("GPU '{0}': status {1}, problem code {2}, driver {3} v{4} dated {5}. {6}" -f $g.Name, $g.Status, $g.Problem, $g.Inf, $g.Version, $g.Date, $note))
        if ($g.Inf -match '(?i)^(basicdisplay|display)\.inf$' -or $g.Name -match '(?i)Basic Display') {
            $out.Add('  The Microsoft Basic Display fallback driver is in use for this adapter [VERIFIED].')
        }
    }
    if ($null -eq $State.Gpus) { $out.Add('Display adapters: NOT READ (see collection errors).') }
    elseif (@($State.Gpus | Where-Object { $_.Present }).Count -eq 0) { $out.Add('No present display adapter.') }

    $panel = @($State.Monitors | Where-Object { $_.InstanceId -match $b.PanelId })
    if ($null -eq $State.Monitors) { $out.Add('Monitor devices: NOT READ (see collection errors).') }
    elseif ($panel.Count -eq 0) { $out.Add("No device record exists for the built-in panel ($($b.PanelId)).") }
    foreach ($p in $panel) { $out.Add(("Panel device {0}: present={1}, status {2} [VERIFIED]" -f $p.InstanceId, $p.Present, $p.Status)) }
    foreach ($m in @(Get-DDArray $State.ActiveMonitors)) {
        $kind = 'external'
        if ($m.Internal) { $kind = 'INTERNAL' }
        $out.Add(("Active monitor now: {0} ({1}, connection {2}, {3}) [VERIFIED]" -f $m.InstanceName, $m.Name, $m.Technology, $kind))
    }
    if ($null -eq $State.ActiveMonitors) { $out.Add('Active monitors: NOT READ (see collection errors).') }
    elseif (@($State.ActiveMonitors | Where-Object { $_.Internal }).Count -eq 0) { $out.Add('Windows reports NO active internal monitor right now.') }

    $fw = @($State.Firmware | Where-Object { $_.Guid -match $b.FirmwareGuid })
    if ($null -eq $State.Firmware) { $out.Add('Firmware resources: NOT READ (see collection errors).') }
    elseif ($fw.Count -eq 0) { $out.Add("No FirmwareResources entry for {$($b.FirmwareGuid)}.") }
    foreach ($f in $fw) {
        $info = Get-DDFirmwareAttemptInfo $f.LastAttemptStatus
        $applied = ($null -ne $info -and $info.Value -eq 0 -and "$($f.Version)" -eq "$($f.LastAttemptVersion)")
        $verdict = 'NOT applied, or the result is unknown'
        if ($applied) { $verdict = 'APPLIED: installed version equals the last attempted version and the last attempt succeeded' }
        $statusText = '(none)'
        if ($info) { $statusText = '{0} {1}' -f $info.Hex, $info.Name }
        $out.Add(("Firmware capsule {{{0}}}: version {1}, last attempted {2}, last status {3}. {4} [VERIFIED registry]" -f $b.FirmwareGuid, $f.Version, $f.LastAttemptVersion, $statusText, $verdict))
    }
    if ($State.Bios) { $out.Add(("BIOS now: {0}, release date {1} [VERIFIED]" -f $State.Bios.Version, $State.Bios.ReleaseDate)) }

    $pnp = @($State.Timeline | Where-Object { $_.Source -eq 'Kernel-PnP' } | Sort-Object Time)
    $last411 = @($pnp | Where-Object { $_.Id -eq 411 -and (Get-DCEventDevice $_.Text) -match $b.GpuId }) | Select-Object -Last 1
    if (-not $State.PnpRead) { $out.Add('Kernel-PnP configuration log: NOT READ (see collection errors); no event-based conclusions below.') }
    elseif ($last411) { $out.Add(("Last GPU start failure (411): {0:yyyy-MM-dd HH:mm:ss} [VERIFIED]" -f $last411.Time)) }
    else { $out.Add('No GPU start failure (411) since -Since in the Kernel-PnP log [VERIFIED].') }
    # 442 is matched on the device it is about. A 442 for another monitor that merely names the
    # panel as "Last Device Instance Id" is not a panel event.
    $lost = @($pnp | Where-Object { $_.Id -eq 442 -and (Get-DCEventDevice $_.Text) -match $b.PanelId }) | Select-Object -Last 1
    if ($lost) { $out.Add(("Last settings-migration event (442) for the panel device itself ({0}): {1:yyyy-MM-dd HH:mm:ss} [VERIFIED]" -f (Get-DCEventDevice $lost.Text), $lost.Time)) }
    # -ge: Windows logs the 442 and the panel's 400/410 in the same second.
    $back = @($pnp | Where-Object { (@(400, 410) -contains $_.Id) -and (Get-DCEventDevice $_.Text) -match $b.PanelId -and (-not $lost -or $_.Time -ge $lost.Time) }) | Select-Object -First 1
    if ($back) {
        $after = 'since -Since'
        if ($lost) { $after = 'at or after that 442' }
        $out.Add(("First panel configure/start event {0}: {1:yyyy-MM-dd HH:mm:ss} (event {2}, {3}) [VERIFIED]" -f $after, $back.Time, $back.Id, (Get-DCEventDevice $back.Text)))
    }
    $gpuInstalls = @($pnp | Where-Object { $_.Id -eq 400 -and (Get-DCEventDevice $_.Text) -match $b.GpuId })
    foreach ($e in $gpuInstalls) { $out.Add(("GPU driver configured (400) at {0:yyyy-MM-dd HH:mm:ss}: {1}" -f $e.Time, $e.Text)) }

    if ($State.Os) {
        $out.Add(("Last boot: {0}; Fast Startup enabled: {1} [VERIFIED]" -f $State.Os.LastBoot, $State.FastStartup))
    }
    $boot = @($State.Timeline | Where-Object { $_.Source -eq 'Kernel-Boot' } | Sort-Object Time) | Select-Object -Last 1
    if ($boot) { $out.Add(("Most recent boot record: {0:yyyy-MM-dd HH:mm:ss} {1}" -f $boot.Time, $boot.Text)) }
    return $out
}

function Write-DCObservations {
    # NEW-6: observation lines carry device names and event text; clean them before they reach the console.
    param($State)
    foreach ($o in @(Get-DCObservations -State $State)) { Write-Host (ConvertTo-DDConsoleText $o) }
}

# Dot-sourced (tests): stop here, functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------------------------------------------------------------------
# Collection (read-only). Each block is isolated; failures are reported, not guessed.
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$state = [ordered]@{ Errors = New-Object System.Collections.Generic.List[string]; Timeline = New-Object System.Collections.Generic.List[object] }
$rx = Get-DCMatchRegex $Match
$recent = (Get-Date).AddDays(-3)

function Invoke-DCStep {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body } catch { $state.Errors.Add(('{0}: {1}' -f $Name, $_.Exception.Message)) }
}

function Get-DCEvent {
    param([hashtable]$Filter)
    try { Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop }
    catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
}

function Add-DCEvents {
    param([string]$Source, [hashtable]$Filter, [scriptblock]$Where, [switch]$BootType)
    foreach ($e in @(Get-DCEvent $Filter)) {
        if ($Where -and -not (& $Where $e)) { continue }
        $text = if ($BootType) { Get-DCBootTypeText $e.Message } else { ConvertTo-DCLine $e.Message }
        $state.Timeline.Add([pscustomobject]@{ Time = $e.TimeCreated; Source = $Source; Id = $e.Id; Text = $text })
    }
}

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $isAdmin = $false }
if (-not $isAdmin) { $state.Errors.Add('Not elevated: some event logs may be incomplete. Re-run in an elevated PowerShell.') }
# NEW-2: as administrator, never write to a path the user chose (its parent may be user-controlled).
# Checked here, before the slow collection, so a wrong invocation fails at once.
if ($isAdmin -and $OutputPath) { throw '-OutputPath is not accepted when running as administrator: the file goes to a new administrators-only folder under %ProgramData%\DriverDoctor (printed at the end). Run from a normal PowerShell window to choose the path.' }
# NEW-11: the README rule, enforced: an administrator run only from a folder that only administrators can change.
if ($isAdmin -and -not $SkipInstallFolderCheck) {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\DD.Collect.ps1')
    $why = Test-DDInstallFolder -ToolRoot (Split-Path $PSScriptRoot -Parent)
    if ($why) { throw "This script runs as administrator only from a folder that only administrators can change, such as C:\Program Files\DriverDoctor (README, Quick start): $why. Copy the whole Driver Doctor folder there and run it again. (-SkipInstallFolderCheck is for development from a checkout.)" }
}

Invoke-DCStep 'System info' {
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $os = Get-CimInstance Win32_OperatingSystem
    $state.Model = '{0} {1}' -f $cs.Manufacturer, $cs.Model
    $state.Bios = [pscustomobject]@{ Version = $bios.SMBIOSBIOSVersion; ReleaseDate = $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') }) }
    $state.Os = [pscustomobject]@{ Caption = $os.Caption; Build = $os.BuildNumber; InstallDate = $os.InstallDate.ToString('yyyy-MM-dd HH:mm'); LastBoot = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') }
}
Invoke-DCStep 'Fast Startup' {
    $v = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled
    $state.FastStartup = ($v -eq 1)
}

function Get-DCDevice {
    param([string]$Class)
    foreach ($d in @(Get-PnpDevice -Class $Class -ErrorAction SilentlyContinue)) {
        $p = @{}
        foreach ($prop in @(Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverVersion', 'DEVPKEY_Device_DriverDate', 'DEVPKEY_Device_ProblemCode' -ErrorAction SilentlyContinue)) {
            $p[$prop.KeyName] = $prop.Data
        }
        $date = $p['DEVPKEY_Device_DriverDate']
        [pscustomobject]@{
            Name       = $d.FriendlyName
            InstanceId = $d.InstanceId
            Present    = [bool]$d.Present
            Status     = [string]$d.Status
            Problem    = $p['DEVPKEY_Device_ProblemCode']
            Inf        = $p['DEVPKEY_Device_DriverInfPath']
            Version    = $p['DEVPKEY_Device_DriverVersion']
            Date       = $(if ($date -is [datetime]) { $date.ToString('yyyy-MM-dd') } else { $date })
        }
    }
}
Invoke-DCStep 'Display adapters' { $state.Gpus = @(Get-DCDevice 'Display') }
Invoke-DCStep 'Monitor devices' { $state.Monitors = @(Get-DCDevice 'Monitor') }

$techName = @{ '0' = 'VGA'; '4' = 'DVI'; '5' = 'HDMI'; '6' = 'LVDS'; '10' = 'DisplayPort'; '11' = 'eDP (embedded DisplayPort)'; '13' = 'UDI embedded'; '15' = 'Miracast'; '2147483648' = 'INTERNAL' }
Invoke-DCStep 'Active monitors' {
    $ids = @{}
    foreach ($m in @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID -ErrorAction Stop)) {
        $name = (@($m.UserFriendlyName | Where-Object { $_ -ne 0 } | ForEach-Object { [char]$_ }) -join '')
        $ids[$m.InstanceName] = $name
    }
    $state.ActiveMonitors = @(foreach ($c in @(Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorConnectionParams -ErrorAction Stop)) {
            $t = ConvertTo-DDInt $c.VideoOutputTechnology
            $tn = $techName["$t"]
            if (-not $tn) { $tn = 'type ' + $t }
            [pscustomobject]@{ InstanceName = $c.InstanceName; Name = $ids[$c.InstanceName]; Technology = $tn; Internal = (Test-DDInternalOutputTechnology $t) }
        })
}

Invoke-DCStep 'Firmware resources' {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources'
    $state.Firmware = @(foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath
            [pscustomobject]@{ Guid = $k.PSChildName; Version = $p.Version; LastAttemptVersion = $p.LastAttemptVersion; LastAttemptStatus = $p.LastAttemptStatus }
        })
}

Invoke-DCStep 'Kernel-PnP configuration log' {
    $log = 'Microsoft-Windows-Kernel-PnP/Configuration'
    Add-DCEvents 'Kernel-PnP' @{ LogName = $log; StartTime = $Since } { param($e) $e.Message -match $rx }
    $state.PnpRead = $true
}
Invoke-DCStep 'OS start/stop (Kernel-General 12/13)' { Add-DCEvents 'Kernel-General' @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12, 13; StartTime = $Since } }
Invoke-DCStep 'Boot type (Kernel-Boot 27)' { Add-DCEvents 'Kernel-Boot' @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27; StartTime = $Since } -BootType }
Invoke-DCStep 'Unexpected power loss (Kernel-Power 41)' { Add-DCEvents 'Kernel-Power' @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $Since } }
Invoke-DCStep 'Restart/shutdown requests (User32 1074)' { Add-DCEvents 'User32' @{ LogName = 'System'; ProviderName = 'User32'; Id = 1074; StartTime = $Since } }
Invoke-DCStep 'Unexpected shutdown (EventLog 6008)' { Add-DCEvents 'EventLog' @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $Since } }
Invoke-DCStep 'Sleep and resume (last 3 days)' {
    Add-DCEvents 'Power' @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 42, 107, 506, 507; StartTime = $recent }
}
Invoke-DCStep 'Display driver resets (4101)' {
    Add-DCEvents 'Display' @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $Since }
}
Invoke-DCStep 'Windows Update history' {
    $resultName = @{ 1 = 'in progress'; 2 = 'succeeded'; 3 = 'succeeded with errors'; 4 = 'FAILED'; 5 = 'aborted' }
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $n = $searcher.GetTotalHistoryCount()
    if ($n -gt 0) {
        foreach ($h in @($searcher.QueryHistory(0, $n))) {
            $t = $h.Date.ToLocalTime()
            if ($t -lt $Since -or -not $h.Title) { continue }
            $op = if ($h.Operation -eq 2) { 'uninstall' } else { 'install' }
            $state.Timeline.Add([pscustomobject]@{ Time = $t; Source = 'WindowsUpdate'; Id = $h.ResultCode; Text = ('{0} {1}: {2}' -f $op, $resultName[[int]$h.ResultCode], $h.Title) })
        }
    }
}
Invoke-DCStep 'setupapi.dev.log' {
    $path = Join-Path $env:SystemRoot 'INF\setupapi.dev.log'
    # Open with ReadWrite sharing: setup may hold the log open for writing.
    $reader = New-Object IO.StreamReader((New-Object IO.FileStream($path, 'Open', 'Read', 'ReadWrite')))
    try { $logLines = $reader.ReadToEnd() -split "`r?`n" } finally { $reader.Dispose() }
    foreach ($i in @(Get-DCSetupApiInstalls -Lines $logLines -Since $Since -Pattern $Match)) {
        $state.Timeline.Add([pscustomobject]@{ Time = $i.Time; Source = 'setupapi'; Id = ''; Text = ('{0} -> {1}' -f $i.Text, $i.Status) })
    }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('DISPLAY CHANGE REPORT (read-only) - generated {0:yyyy-MM-dd HH:mm:ss} local time' -f (Get-Date))
$lines.Add(('Machine: {0} | OS: {1} build {2}, installed {3}' -f $state.Model, $state.Os.Caption, $state.Os.Build, $state.Os.InstallDate))
$lines.Add('Baseline: the 2026-08-26 screenshots (GPU oem39.inf failed with 0xC00000E5; panel CMN163B lost).')
$lines.Add('')
$lines.Add('== COLLECTION ERRORS ==')
if ($state.Errors.Count -eq 0) { $lines.Add('(none)') } else { foreach ($e in $state.Errors) { $lines.Add($e) } }
$lines.Add('')
$lines.Add('== OBSERVATIONS (facts, with source) ==')
foreach ($o in @(Get-DCObservations -State $state)) { $lines.Add($o) }
$lines.Add('')
$lines.Add('== DISPLAY ADAPTERS (all, including not present) ==')
foreach ($g in @(Get-DDArray $state.Gpus)) { $lines.Add(('{0} | present={1} | {2} | problem {3} | {4} v{5} {6} | {7}' -f $g.Name, $g.Present, $g.Status, $g.Problem, $g.Inf, $g.Version, $g.Date, $g.InstanceId)) }
$lines.Add('')
$lines.Add('== MONITOR DEVICES (all, including not present) ==')
foreach ($m in @(Get-DDArray $state.Monitors)) { $lines.Add(('{0} | present={1} | {2} | {3}' -f $m.Name, $m.Present, $m.Status, $m.InstanceId)) }
$lines.Add('')
$lines.Add('== FIRMWARE RESOURCES ==')
foreach ($f in @(Get-DDArray $state.Firmware)) { $lines.Add(('{0} | version {1} | last attempted {2} | last status {3}' -f $f.Guid, $f.Version, $f.LastAttemptVersion, (Format-DDHex $f.LastAttemptStatus))) }
$lines.Add('')
$lines.Add(('== TIMELINE since {0:yyyy-MM-dd} (local time; sleep/resume only for the last 3 days) ==' -f $Since))
foreach ($t in @($state.Timeline | Sort-Object Time)) { $lines.Add(('{0:yyyy-MM-dd HH:mm:ss} | {1,-14} | {2,-4} | {3}' -f $t.Time, $t.Source, $t.Id, $t.Text)) }
$lines.Add('')
$lines.Add('This file holds the computer name, user name (in restart events) and device IDs. Read it before sharing.')

$fileName = 'DisplayChange-{0:yyyyMMdd-HHmmss}.txt' -f (Get-Date)
if ($isAdmin) {
    # NEW-2: as administrator, never write to a predictable name in a user-controlled folder (the
    # Desktop path comes from HKCU and the name could be pre-planted as a link). An explicit path was
    # refused above. A new administrators-only folder the user can read.
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\DD.Collect.ps1')
    $OutputPath = Join-Path (Get-DDElevatedOutputDir) $fileName
}
elseif (-not $OutputPath) { $OutputPath = Join-Path ([Environment]::GetFolderPath('Desktop')) $fileName }
$lines | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Host ''
Write-Host '== OBSERVATIONS ==' -ForegroundColor Cyan
Write-DCObservations -State $state
if ($state.Errors.Count -gt 0) { Write-Host ''; Write-Host ('{0} collection error(s); see the file.' -f $state.Errors.Count) -ForegroundColor Yellow }
Write-Host ''
Write-Host "Full report: $OutputPath" -ForegroundColor Green
