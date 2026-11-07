# DD.Analysis.ps1 - pure analysis layer for Driver Doctor.
#
# Nothing in this file touches the system. Every function takes data that the
# collector (DD.Collect.ps1) produced - or a saved snapshot JSON - and returns
# objects. That keeps the reasoning testable on any OS (see tests/Run-Tests.ps1)
# and lets a snapshot be re-analyzed offline.
#
# Evidence rules enforced here:
#   - Every finding lists the concrete evidence lines it is based on.
#   - Confidence is VERIFIED when Windows reports the state directly, and
#     INFERRED when the conclusion connects separate facts (same device id,
#     same INF, same time window). Unconnected facts are never joined into a cause.

$script:DDClassGuid = @{
    Display  = '{4d36e968-e325-11ce-bfc1-08002be10318}'
    Monitor  = '{4d36e96e-e325-11ce-bfc1-08002be10318}'
    Firmware = '{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}'
}

$script:DDSeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

# Device Manager problem codes (CM_PROB_*). Action is the safest first step.
$script:DDProblemCodes = @{
    1  = @('CM_PROB_NOT_CONFIGURED', 'Device is not configured (no driver selected).', 'ScanDevices')
    3  = @('CM_PROB_OUT_OF_MEMORY', 'Driver may be corrupted, or the system ran low on memory.', 'DriverUpdate')
    10 = @('CM_PROB_FAILED_START', 'Device cannot start; its driver returned an error while starting.', 'RestartDevice')
    12 = @('CM_PROB_NORMAL_CONFLICT', 'Not enough free resources for this device.', 'Manual')
    14 = @('CM_PROB_NEED_RESTART', 'Device cannot work until the computer restarts (a driver or firmware update is staged).', 'RestartComputer')
    18 = @('CM_PROB_REINSTALL', 'Drivers for this device must be reinstalled.', 'ScanDevices')
    19 = @('CM_PROB_REGISTRY', 'Registry configuration for this device is incomplete or damaged.', 'DriverUpdate')
    21 = @('CM_PROB_WILL_BE_REMOVED', 'Windows is removing this device.', 'RestartComputer')
    22 = @('CM_PROB_DISABLED', 'Device is disabled.', 'EnableDevice')
    24 = @('CM_PROB_DEVLOADER_NOT_FOUND', 'Device is not present, not working, or has no driver.', 'ScanDevices')
    28 = @('CM_PROB_FAILED_INSTALL', 'Drivers for this device are not installed.', 'ScanDevices')
    29 = @('CM_PROB_HARDWARE_DISABLED', 'Device is disabled by the firmware (BIOS/UEFI setting).', 'Manual')
    31 = @('CM_PROB_FAILED_ADD', 'Windows cannot load the driver for this device.', 'DriverUpdate')
    32 = @('CM_PROB_DISABLED_SERVICE', 'The driver service for this device is disabled.', 'Manual')
    37 = @('CM_PROB_FAILED_DRIVER_ENTRY', 'Windows cannot initialize the driver (DriverEntry failed).', 'DriverUpdate')
    38 = @('CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD', 'A previous instance of the driver is still in memory.', 'RestartComputer')
    39 = @('CM_PROB_DRIVER_FAILED_LOAD', 'Driver is corrupted or missing.', 'DriverUpdate')
    40 = @('CM_PROB_DRIVER_SERVICE_KEY_INVALID', 'Driver service registry key is missing or invalid.', 'DriverUpdate')
    41 = @('CM_PROB_LEGACY_SERVICE_NO_DEVICES', 'Driver loaded but cannot find its hardware.', 'DriverUpdate')
    42 = @('CM_PROB_DUPLICATE_DEVICE', 'A duplicate device was detected.', 'RestartComputer')
    43 = @('CM_PROB_FAILED_POST_START', 'Device reported a problem and Windows stopped it (Code 43).', 'RestartDevice')
    44 = @('CM_PROB_HALTED', 'An application or service shut this device down.', 'RestartDevice')
    45 = @('CM_PROB_PHANTOM', 'Device is not currently connected.', 'None')
    47 = @('CM_PROB_HELD_FOR_EJECT', 'Device was prepared for safe removal; reconnect it.', 'Manual')
    48 = @('CM_PROB_DRIVER_BLOCKED', 'Driver was blocked from starting (known compatibility problem).', 'DriverUpdate')
    49 = @('CM_PROB_REGISTRY_TOO_LARGE', 'System registry hive is too large.', 'Manual')
    50 = @('CM_PROB_SETPROPERTIES_FAILED', 'Windows cannot apply all properties for this device.', 'DriverUpdate')
    51 = @('CM_PROB_WAITING_ON_DEPENDENCY', 'Device is waiting on another device to start.', 'None')
    52 = @('CM_PROB_UNSIGNED_DRIVER', 'Windows cannot verify the driver signature (Code 52).', 'DriverUpdate')
    53 = @('CM_PROB_USED_BY_DEBUGGER', 'Device is reserved for the kernel debugger.', 'Manual')
    54 = @('CM_PROB_DEVICE_RESET', 'Device failed and is undergoing a reset.', 'RestartDevice')
    56 = @('CM_PROB_NEED_CLASS_CONFIG', 'Windows is still setting up this device class.', 'RestartComputer')
}

# NTSTATUS values seen in Kernel-PnP events and firmware status. Unknown codes are shown raw.
$script:DDNtStatus = @{
    0x00000000 = @('STATUS_SUCCESS', 'Success.')
    0xC0000001 = @('STATUS_UNSUCCESSFUL', 'The operation failed (generic).')
    0xC000000E = @('STATUS_NO_SUCH_DEVICE', 'The device does not exist or did not respond.')
    0xC0000010 = @('STATUS_INVALID_DEVICE_REQUEST', 'The driver rejected the request.')
    0xC0000022 = @('STATUS_ACCESS_DENIED', 'Access denied (for firmware: authentication/signature failure).')
    0xC0000034 = @('STATUS_OBJECT_NAME_NOT_FOUND', 'A required object or file was not found.')
    0xC0000059 = @('STATUS_REVISION_MISMATCH', 'Incorrect version (for firmware: version rejected).')
    0xC000007B = @('STATUS_INVALID_IMAGE_FORMAT', 'Invalid image format.')
    0xC000009A = @('STATUS_INSUFFICIENT_RESOURCES', 'Insufficient resources.')
    0xC00000BB = @('STATUS_NOT_SUPPORTED', 'The request is not supported.')
    0xC00000E5 = @('STATUS_INTERNAL_ERROR', 'The driver hit an internal error while starting the device.')
    0xC0000182 = @('STATUS_DEVICE_CONFIGURATION_ERROR', 'The device configuration is invalid.')
    0xC00002D2 = @('STATUS_PNP_REBOOT_REQUIRED', 'The device needs a full restart before it can start.')
    0xC00002D3 = @('STATUS_POWER_STATE_INVALID', 'Power event: AC adapter was not connected.')
    0xC00002DE = @('STATUS_INSUFFICIENT_POWER', 'Power event: battery charge was too low.')
    0xC0000365 = @('STATUS_FAILED_DRIVER_ENTRY', 'The driver failed to initialize (DriverEntry).')
    0xC0000428 = @('STATUS_INVALID_IMAGE_HASH', 'The driver file signature is invalid.')
}

# Firmware LastAttemptStatus: Windows stores NTSTATUS values; raw UEFI ESRT values (1-8) are also decoded.
# Transient = Windows keeps retrying; non-transient = Windows stops retrying.
$script:DDFirmwareStatus = @{
    0x00000000 = @('Success', $false, 'Last firmware update attempt succeeded.')
    0xC0000001 = @('Unsuccessful', $false, 'The firmware rejected or failed the update.')
    0xC000009A = @('Insufficient resources', $false, 'Firmware did not have the resources to apply the update.')
    0xC0000059 = @('Incorrect version', $false, 'Firmware refused the version (for example a downgrade).')
    0xC000007B = @('Invalid image format', $false, 'The capsule image was rejected as invalid.')
    0xC0000022 = @('Authentication error', $false, 'The capsule failed signature verification.')
    0xC00002D3 = @('Power event: AC not connected', $true, 'The update was deferred because the AC adapter was not connected.')
    0xC00002DE = @('Power event: insufficient battery', $true, 'The update was deferred because the battery was too low.')
    1          = @('Unsuccessful (ESRT)', $false, 'The firmware rejected or failed the update.')
    2          = @('Insufficient resources (ESRT)', $false, 'Firmware did not have the resources to apply the update.')
    3          = @('Incorrect version (ESRT)', $false, 'Firmware refused the version.')
    4          = @('Invalid image format (ESRT)', $false, 'The capsule image was rejected as invalid.')
    5          = @('Authentication error (ESRT)', $false, 'The capsule failed signature verification.')
    6          = @('Power event: AC not connected (ESRT)', $true, 'The update was deferred because the AC adapter was not connected.')
    7          = @('Power event: insufficient battery (ESRT)', $true, 'The update was deferred because the battery was too low.')
    8          = @('Unsatisfied dependencies (ESRT)', $false, 'Another firmware component must be updated first.')
}

# DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY values that mean "built-in panel".
$script:DDInternalOutputTech = @(6, 11, 13, 0x80000000)  # LVDS, DisplayPort embedded (eDP), UDI embedded, INTERNAL

# Common laptop panel manufacturers (EDID PnP vendor codes). Used only as a labeled INFERRED hint.
$script:DDPanelVendors = @('AUO', 'BOE', 'CMN', 'CSO', 'IVO', 'LGD', 'SDC', 'SHP', 'NCP', 'TMA', 'KDB', 'STA', 'MNE')

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

function Get-DDArray {
    # Emits the items (or nothing). Always consume as @(Get-DDArray $x), foreach, or a pipeline.
    param($Value)
    if ($null -eq $Value) { return }
    foreach ($v in @($Value)) { $v }
}

function ConvertTo-DDInt {
    # Accepts 14, "14", "0xE", -1073741101 (signed DWORD) and returns an unsigned 64-bit view.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if ($s -match '^0[xX]([0-9a-fA-F]+)$') { $n = [Convert]::ToInt64($Matches[1], 16) }
        elseif ($s -match '^-?\d+$') { $n = [int64]$s }
        else { return $null }
    }
    elseif ($Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { $n = [int64]$Value }
    elseif ($Value -is [ValueType]) {
        try { $n = [int64]$Value } catch { return $null }
    }
    else { return $null }
    if ($n -lt 0 -and $n -ge [int32]::MinValue) { $n += 4294967296 }
    return $n
}

function Format-DDHex {
    param($Value)
    $n = ConvertTo-DDInt $Value
    if ($null -eq $n) { return '(none)' }
    return ('0x{0:X8}' -f $n)
}

function ConvertTo-DDDate {
    # Returns a UTC DateTime or $null. Handles DateTime objects and ISO-8601 strings.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $d = [datetime]::MinValue
    $styles = [Globalization.DateTimeStyles]::RoundtripKind
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) {
        return $d.ToUniversalTime()
    }
    return $null
}

function Format-DDDate {
    param($Value)
    $d = ConvertTo-DDDate $Value
    if ($null -eq $d) { return '(unknown time)' }
    return $d.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
}

function Get-DDProblemInfo {
    param([int64]$Code)
    if ($script:DDProblemCodes.ContainsKey([int]$Code)) {
        $e = $script:DDProblemCodes[[int]$Code]
        return [pscustomobject]@{ Code = $Code; Name = $e[0]; Meaning = $e[1]; Action = $e[2] }
    }
    return [pscustomobject]@{ Code = $Code; Name = "CM_PROB_$Code"; Meaning = 'Undocumented problem code.'; Action = 'Manual' }
}

function Get-DDNtStatusInfo {
    param($Status)
    $n = ConvertTo-DDInt $Status
    if ($null -eq $n) { return $null }
    $key = [int64]$n
    foreach ($k in $script:DDNtStatus.Keys) {
        # Hex literals such as 0xC0000001 parse as negative Int32; normalize before comparing.
        if ((ConvertTo-DDInt $k) -eq $key) {
            $e = $script:DDNtStatus[$k]
            return [pscustomobject]@{ Value = $key; Hex = (Format-DDHex $key); Name = $e[0]; Meaning = $e[1] }
        }
    }
    return [pscustomobject]@{ Value = $key; Hex = (Format-DDHex $key); Name = 'Unrecognized status'; Meaning = 'Not decoded by this tool.' }
}

function Get-DDFirmwareAttemptInfo {
    param($Status)
    $n = ConvertTo-DDInt $Status
    if ($null -eq $n) { return $null }
    foreach ($k in $script:DDFirmwareStatus.Keys) {
        if ((ConvertTo-DDInt $k) -eq [int64]$n) {
            $e = $script:DDFirmwareStatus[$k]
            return [pscustomobject]@{ Value = $n; Hex = (Format-DDHex $n); Name = $e[0]; Transient = $e[1]; Meaning = $e[2] }
        }
    }
    return [pscustomobject]@{ Value = $n; Hex = (Format-DDHex $n); Name = 'Unrecognized status'; Transient = $false; Meaning = 'Not decoded by this tool; treat as a failed attempt.' }
}

function Format-DDStatusText {
    param($Status)
    $i = Get-DDNtStatusInfo $Status
    if ($null -eq $i) { return '(none)' }
    return "$($i.Hex) $($i.Name)"
}

function Test-DDInternalOutputTechnology {
    param($Value)
    $n = ConvertTo-DDInt $Value
    if ($null -eq $n) { return $false }
    foreach ($t in $script:DDInternalOutputTech) { if ((ConvertTo-DDInt $t) -eq $n) { return $true } }
    return $false
}

function ConvertFrom-DDMonitorDevicePath {
    # \\?\DISPLAY#CMN163B#4&5423816&0&UID0#{e6f07b5f-...} -> DISPLAY\CMN163B\4&5423816&0&UID0
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path -replace '^\\\\\?\\', ''
    $p = $p -replace '#\{[0-9A-Fa-f-]+\}$', ''
    return ($p -replace '#', '\')
}

function Get-DDMonitorVendor {
    # DISPLAY\CMN163B\... -> CMN
    param([string]$InstanceId)
    if ($InstanceId -match '^DISPLAY\\([A-Za-z]{3})[0-9A-Fa-f]{4}\\') { return $Matches[1].ToUpperInvariant() }
    return $null
}

function Test-DDLikelyPanelInstance {
    param([string]$InstanceId)
    $v = Get-DDMonitorVendor $InstanceId
    if ($null -eq $v) { return $false }
    return ($script:DDPanelVendors -contains $v)
}

function Test-DDHPPublisher {
    # SEC-001: exact match on the parsed organization (O=) of an Authenticode signer subject.
    # The name is decoded one RDN per line without quotes, so a quoted CN such as
    # "Evil, O=HP Inc." or an organization such as "HP Inc, Evil" cannot pass.
    param([string]$Subject)
    if (-not $Subject) { return $false }
    # A control character inside a value (e.g. a line break in the CN) would forge an extra decoded line.
    if ($Subject -match '[\x00-\x1F\x7F]') { return $false }
    try {
        $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($Subject)
        $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]'UseNewLines, DoNotUseQuotes'
        $orgs = @($dn.Decode($flags) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -like 'O=*' })
    }
    catch { return $false }
    return ($orgs.Count -eq 1 -and $orgs[0] -ceq 'O=HP Inc.')
}

function Test-DDUnderFolder {
    # SEC-001: true only when Path, fully resolved, lies inside one of Roots (case-insensitive).
    param([string]$Path, [string[]]$Roots)
    if (-not $Path) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
    foreach ($r in @($Roots | Where-Object { $_ })) {
        $root = [System.IO.Path]::GetFullPath($r).TrimEnd('\') + '\'
        if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-DDFirmwareGuidFromInstance {
    param([string]$InstanceId)
    if ($InstanceId -match 'RES_(\{[0-9A-Fa-f-]{36}\})') { return $Matches[1].ToLowerInvariant() }
    return $null
}

function Test-DDClass {
    param($Device, [string]$Name)
    if ($null -eq $Device) { return $false }
    $guid = $script:DDClassGuid[$Name]
    if ($Device.ClassGuid -and ([string]$Device.ClassGuid).ToLowerInvariant() -eq $guid) { return $true }
    return ([string]$Device.Class -eq $Name)
}

# ---------------------------------------------------------------------------
# Parsers (event messages and tool output)
# ---------------------------------------------------------------------------

function Get-DDField {
    param([string]$Text, [string]$Label)
    $rx = '(?im)^\s*' + [regex]::Escape($Label) + '\s*:[ \t]*(.*?)\s*$'
    $m = [regex]::Match($Text, $rx)
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function ConvertFrom-DDPnpEvent {
    # Normalizes a Kernel-PnP Device Configuration event (400/410/411/412/430/441/442).
    # Named EventData values win; the rendered English message fills any gaps.
    param(
        [int]$Id,
        $TimeCreated,
        [string]$Message,
        $EventData
    )
    $data = @{}
    if ($EventData) {
        if ($EventData -is [hashtable]) { foreach ($k in $EventData.Keys) { $data[$k] = $EventData[$k] } }
        else { foreach ($p in $EventData.PSObject.Properties) { $data[$p.Name] = $p.Value } }
    }
    $pick = {
        param([string[]]$Names)
        foreach ($n in $Names) { if ($data.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$data[$n])) { return [string]$data[$n] } }
        return $null
    }
    $msg = [string]$Message

    $deviceId = & $pick @('DeviceInstanceId', 'DeviceInstanceID', 'InstanceId')
    if (-not $deviceId -and $msg -match '^\s*Device(?: settings for)?\s+(\S+)\s') { $deviceId = $Matches[1] }

    $o = [ordered]@{
        Id               = $Id
        Time             = (ConvertTo-DDDate $TimeCreated)
        DeviceInstanceId = $deviceId
        DriverName       = (& $pick @('DriverName'))
        ClassGuid        = (& $pick @('ClassGuid', 'ClassGUID'))
        Service          = (& $pick @('ServiceName', 'Service'))
        Problem          = (ConvertTo-DDInt (& $pick @('Problem')))
        ProblemStatus    = (ConvertTo-DDInt (& $pick @('ProblemStatus', 'Status')))
        DriverVersion    = (& $pick @('DriverVersion'))
        DriverDate       = (& $pick @('DriverDate'))
        DriverProvider   = (& $pick @('DriverProvider'))
        LastInstanceId   = (& $pick @('LastDeviceInstanceId', 'LastDeviceInstanceID'))
        Present          = $null
        Summary          = $null
    }
    if (-not $o.DriverName) { $o.DriverName = Get-DDField $msg 'Driver Name' }
    if (-not $o.ClassGuid) { $o.ClassGuid = Get-DDField $msg 'Class GUID' }
    if (-not $o.ClassGuid) { $o.ClassGuid = Get-DDField $msg 'Class Guid' }
    if (-not $o.Service) { $o.Service = Get-DDField $msg 'Service' }
    if ($null -eq $o.Problem) { $o.Problem = ConvertTo-DDInt (Get-DDField $msg 'Problem') }
    if ($null -eq $o.ProblemStatus) { $o.ProblemStatus = ConvertTo-DDInt (Get-DDField $msg 'Problem Status') }
    if ($null -eq $o.ProblemStatus -and $Id -eq 442) { $o.ProblemStatus = ConvertTo-DDInt (Get-DDField $msg 'Status') }
    if (-not $o.DriverVersion) { $o.DriverVersion = Get-DDField $msg 'Driver Version' }
    if (-not $o.DriverDate) { $o.DriverDate = Get-DDField $msg 'Driver Date' }
    if (-not $o.DriverProvider) { $o.DriverProvider = Get-DDField $msg 'Driver Provider' }
    if (-not $o.LastInstanceId) { $o.LastInstanceId = Get-DDField $msg 'Last Device Instance ID' }
    $present = Get-DDField $msg 'Present'
    if ($data.ContainsKey('Present')) { $present = [string]$data['Present'] }
    if ($present) { $o.Present = ($present -match '^(?i)(true|1)$') }
    if ($o.ClassGuid) { $o.ClassGuid = $o.ClassGuid.ToLowerInvariant() }
    if ($msg) { $o.Summary = (($msg -split "`r?`n")[0]).Trim() }
    return [pscustomobject]$o
}

function ConvertFrom-DDCodeIntegrityEvent {
    # "Code Integrity determined that a process (\Device\...\lsass.exe) attempted to load \Device\...\x.dll that did not meet ..."
    param([int]$Id, $TimeCreated, [string]$Message)
    $o = [ordered]@{ Id = $Id; Time = (ConvertTo-DDDate $TimeCreated); Process = $null; Module = $null; Reason = $null; Enforced = $null }
    $m = [regex]::Match([string]$Message, 'process \((?<p>[^)]+)\) attempted to load (?<m>.+?) that did not meet (?<r>[^.]+)')
    if ($m.Success) {
        $o.Process = $m.Groups['p'].Value.Trim()
        $o.Module = $m.Groups['m'].Value.Trim()
        $o.Reason = $m.Groups['r'].Value.Trim()
    }
    elseif ([string]$Message -match '(?i)(\\Device\\HarddiskVolume\d+\\[^\r\n]+?\.(?:dll|sys|exe))') {
        $o.Module = $Matches[1]
    }
    # 3033/3063 are enforced blocks; 3065/3066 are LSA audit-mode reports; 3077 is a policy block.
    if ($Id -in 3033, 3063, 3077) { $o.Enforced = $true } elseif ($Id -in 3065, 3066) { $o.Enforced = $false }
    return [pscustomobject]$o
}

function ConvertFrom-DDWindowsUpdateEvent {
    # WindowsUpdateClient 19 (installed) / 20 (failed).
    param([int]$Id, $TimeCreated, [string]$Message)
    $o = [ordered]@{ Id = $Id; Time = (ConvertTo-DDDate $TimeCreated); Title = $null; ErrorCode = $null }
    $m = [regex]::Match([string]$Message, '(?i)with error (0x[0-9a-f]{8}):\s*(.+?)\s*$')
    if ($m.Success) { $o.ErrorCode = $m.Groups[1].Value; $o.Title = $m.Groups[2].Value.TrimEnd('.') }
    else {
        $m = [regex]::Match([string]$Message, '(?i)following update:\s*(.+?)\s*$')
        if ($m.Success) { $o.Title = $m.Groups[1].Value.TrimEnd('.') }
    }
    return [pscustomobject]$o
}

function ConvertFrom-DDPnputilDriverList {
    # Parses `pnputil /enum-drivers` (English output) into objects.
    param([string]$Text)
    $result = New-Object System.Collections.Generic.List[object]
    $blocks = [regex]::Split([string]$Text, '(\r?\n){2,}')
    foreach ($b in $blocks) {
        $pub = Get-DDField $b 'Published Name'
        if (-not $pub) { continue }
        $verLine = Get-DDField $b 'Driver Version'
        $date = $null; $ver = $verLine
        if ($verLine -match '^(\d{1,2}/\d{1,2}/\d{4})\s+(\S+)$') { $date = $Matches[1]; $ver = $Matches[2] }
        $result.Add([pscustomobject]@{
                PublishedName = $pub
                OriginalName  = (Get-DDField $b 'Original Name')
                Provider      = (Get-DDField $b 'Provider Name')
                ClassName     = (Get-DDField $b 'Class Name')
                ClassGuid     = ([string](Get-DDField $b 'Class GUID')).ToLowerInvariant()
                Version       = $ver
                Date          = $date
                Signer        = (Get-DDField $b 'Signer Name')
            })
    }
    return $result.ToArray()
}

# ---------------------------------------------------------------------------
# Correlation: connect events by shared time window (labeled as correlation)
# ---------------------------------------------------------------------------

function Get-DDEventClusters {
    # Groups timestamped records whose gap is <= GapMinutes. Returns clusters that
    # involve 2+ distinct devices - the "connected" moments.
    param([object[]]$Records, [int]$GapMinutes = 10)
    $items = @($Records | Where-Object { $null -ne $_.Time } | Sort-Object Time)
    $clusters = New-Object System.Collections.Generic.List[object]
    $current = New-Object System.Collections.Generic.List[object]
    $prev = $null
    foreach ($r in $items) {
        if ($null -ne $prev -and (($r.Time - $prev).TotalMinutes -gt $GapMinutes)) {
            $clusters.Add($current.ToArray()); $current = New-Object System.Collections.Generic.List[object]
        }
        $current.Add($r); $prev = $r.Time
    }
    if ($current.Count -gt 0) { $clusters.Add($current.ToArray()) }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in $clusters) {
        $devs = @($c | ForEach-Object { $_.DeviceInstanceId } | Where-Object { $_ } | Sort-Object -Unique)
        $ids = @($c | ForEach-Object { $_.Id } | Sort-Object -Unique)
        # Two or more distinct devices: one device's own install sequence (400 then 412) is not a connection.
        if ($devs.Count -ge 2) {
            $out.Add([pscustomobject]@{ Start = $c[0].Time; End = $c[-1].Time; Records = $c; Devices = $devs; EventIds = $ids })
        }
    }
    return $out.ToArray()
}

# ---------------------------------------------------------------------------
# Domain logic
# ---------------------------------------------------------------------------

function New-DDFinding {
    # Builds an in-memory object only; "New" is not a system change.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [string]$Id, [string]$Severity, [string]$Category, [string]$Title,
        [string[]]$Evidence, [string]$Interpretation, [string]$Confidence,
        [string]$Recommendation, [object[]]$Actions, [bool]$StateBased = $false
    )
    return [pscustomobject]@{
        Id             = $Id
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Evidence       = @($Evidence | Where-Object { $_ })
        Interpretation = $Interpretation
        Confidence     = $Confidence
        Recommendation = $Recommendation
        Actions        = @($Actions | Where-Object { $_ })
        StateBased     = $StateBased
    }
}

function New-DDAction {
    # Builds an in-memory object only; "New" is not a system change.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([string]$Type, [string]$Target, [string]$Detail, [bool]$Firmware = $false)
    return [pscustomobject]@{ Type = $Type; Target = $Target; Detail = $Detail; RequiresFirmwareConsent = $Firmware }
}

function Get-DDDeviceLabel {
    param($Device, [string]$InstanceId)
    if ($Device -and $Device.Name) { return "$($Device.Name) [$($Device.InstanceId)]" }
    if ($Device) { return "[$($Device.InstanceId)]" }
    return "[$InstanceId]"
}

function Get-DDDriverUpdateActions {
    # Driver-update actions for a device, using only sources the snapshot proves exist.
    param($Snapshot, $Device)
    $actions = New-Object System.Collections.Generic.List[object]
    $actions.Add((New-DDAction 'ScanDevices' '' 'Ask Plug and Play to re-evaluate drivers already in the driver store.'))
    $hwIds = @(Get-DDArray $Device.HardwareIds | ForEach-Object { ([string]$_).ToUpperInvariant() })
    foreach ($u in (Get-DDArray $Snapshot.WindowsUpdate.Updates)) {
        $match = $false
        if ($u.HardwareId -and ($hwIds -contains ([string]$u.HardwareId).ToUpperInvariant())) { $match = $true }
        if ($match) {
            $isFw = ([string]$u.DriverClass -eq 'Firmware')
            $actions.Add((New-DDAction 'InstallWindowsUpdate' ([string]$u.UpdateId) "Windows Update offers: $($u.Title)" $isFw))
        }
    }
    if ($Snapshot.HPIA -and $Snapshot.HPIA.Present) {
        $actions.Add((New-DDAction 'HPIAInstall' 'Drivers' 'Install HP-certified drivers for this exact model via HP Image Assistant.'))
    }
    else {
        $actions.Add((New-DDAction 'Manual' '' 'Get the driver from HP support for this exact model (or install HP Image Assistant and re-run).'))
    }
    return $actions.ToArray()
}

function Get-DDGpuHealth {
    param($Snapshot, [datetime]$Since)
    $result = New-Object System.Collections.Generic.List[object]
    $events = @(Get-DDArray $Snapshot.PnpEvents)
    $services = @(Get-DDArray $Snapshot.ServiceChecks)
    foreach ($d in (Get-DDArray $Snapshot.Devices)) {
        if (-not (Test-DDClass $d 'Display')) { continue }
        if ($d.Present -eq $false) { continue }
        $faults = New-Object System.Collections.Generic.List[string]
        $code = ConvertTo-DDInt $d.ProblemCode
        if ($code -and $code -ne 0) {
            $pi = Get-DDProblemInfo $code
            $faults.Add("Device Manager reports Code $code ($($pi.Name)): $($pi.Meaning) Problem status: $(Format-DDStatusText $d.ProblemStatus).")
        }
        $basic = ([string]$d.Service -eq 'BasicDisplay') -and ([string]$d.InstanceId -like 'PCI\*')
        if ($basic) { $faults.Add('The GPU is running on the Microsoft Basic Display driver, so the vendor driver is not loaded.') }
        $mine = @($events | Where-Object { $_.Id -eq 411 -and $_.DeviceInstanceId -and ([string]$_.DeviceInstanceId -eq [string]$d.InstanceId) })
        $sinceFailures = @($mine | Where-Object { $_.Time -and $_.Time -ge $Since })
        if ($sinceFailures.Count -gt 0) {
            $statuses = ($sinceFailures | ForEach-Object { Format-DDStatusText $_.ProblemStatus } | Sort-Object -Unique) -join ', '
            $faults.Add("Kernel-PnP event 411: driver failed to start $($sinceFailures.Count) time(s) since $(Format-DDDate $Since) (status: $statuses).")
        }
        $svc = $services | Where-Object { $_.Name -and ([string]$_.Name -eq [string]$d.Service) } | Select-Object -First 1
        if ($svc -and $svc.ImageExists -eq $false) { $faults.Add("Driver binary for service '$($svc.Name)' is missing: $($svc.ResolvedPath).") }
        $result.Add([pscustomobject]@{
                Device         = $d
                Faults         = $faults.ToArray()
                Hard           = (($code -and $code -ne 0) -or $basic -or ($svc -and $svc.ImageExists -eq $false))
                FailuresSince  = $sinceFailures
                FailuresAll    = $mine
                IsBasicDisplay = $basic
            })
    }
    return $result.ToArray()
}

function Get-DDInternalDisplayVerdict {
    # Decides why the built-in panel is (not) showing, using only connected evidence.
    param($Snapshot, $GpuHealth)
    $targets = @(Get-DDArray $Snapshot.DisplayTargets)
    $internal = @($targets | Where-Object { Test-DDInternalOutputTechnology $_.OutputTechnology })
    $monitors = @(Get-DDArray $Snapshot.Devices | Where-Object { Test-DDClass $_ 'Monitor' })
    # Two different 442 facts. Every 442 for ANY new monitor names the panel's old instance as
    # "Last Device Instance ID" with present=false, so:
    #  - $migrations (matched on LastInstanceId) only feeds the GPU same-boot link below, which
    #    cites that field explicitly;
    #  - $panelMigrations (matched on the event's own device) are the only 442s listed as panel events.
    $migrations = @(Get-DDArray $Snapshot.PnpEvents | Where-Object { $_.Id -eq 442 -and $_.LastInstanceId -and (Test-DDLikelyPanelInstance $_.LastInstanceId) })
    $panelMigrations = @(Get-DDArray $Snapshot.PnpEvents | Where-Object { $_.Id -eq 442 -and $_.DeviceInstanceId -and (Test-DDLikelyPanelInstance $_.DeviceInstanceId) })
    $evidence = New-Object System.Collections.Generic.List[string]

    $internalIds = @($internal | ForEach-Object { ConvertFrom-DDMonitorDevicePath $_.DevicePath } | Where-Object { $_ })
    $wmiInternal = @(Get-DDArray $Snapshot.MonitorConnections | Where-Object { Test-DDInternalOutputTechnology $_.VideoOutputTechnology })
    foreach ($w in $wmiInternal) { $internalIds += ([string]$w.InstanceName -replace '_\d+$', '') }
    $panelDevices = @($monitors | Where-Object { ($internalIds -contains [string]$_.InstanceId) -or (Test-DDLikelyPanelInstance $_.InstanceId) })

    foreach ($t in $internal) {
        $evidence.Add("Display path: internal connector (output technology $(Format-DDHex $t.OutputTechnology)) '$($t.FriendlyName)' available=$($t.Available) active=$($t.Active).")
    }
    foreach ($p in $panelDevices) {
        $evidence.Add("Monitor device $($p.InstanceId) '$($p.Name)': present=$($p.Present), problem code=$(ConvertTo-DDInt $p.ProblemCode).")
    }
    foreach ($m in $panelMigrations) {
        $evidence.Add("Event 442 at $(Format-DDDate $m.Time): settings for $($m.DeviceInstanceId) were not migrated; last instance $($m.LastInstanceId) present=$($m.Present).")
    }

    $state = $null
    if ($Snapshot.CollectionErrors -and @($Snapshot.CollectionErrors | Where-Object { $_.Collector -eq 'DisplayTargets' }).Count -gt 0 -and $targets.Count -eq 0) {
        $state = 'Unknown'
    }
    $activeInternal = @($internal | Where-Object { $_.Active })
    $availableInternal = @($internal | Where-Object { $_.Available })
    $disabledPanel = @($panelDevices | Where-Object { $_.Present -ne $false -and (ConvertTo-DDInt $_.ProblemCode) -eq 22 })
    $zeroBrightness = @(Get-DDArray $Snapshot.Brightness | Where-Object { $_.Active -ne $false -and (ConvertTo-DDInt $_.CurrentBrightness) -eq 0 })
    $gpuFaulted = @($GpuHealth | Where-Object { $_.Faults.Count -gt 0 })
    # Historical link: a GPU start failure within 10 minutes of the panel's 442 migration event
    # means the panel vanished in the same boot the GPU driver failed.
    $linked = @()
    foreach ($g in $GpuHealth) {
        foreach ($f in @($g.FailuresAll)) {
            $ft = ConvertTo-DDDate $f.Time
            foreach ($mg in $migrations) {
                $mt = ConvertTo-DDDate $mg.Time
                if ($ft -and $mt -and [math]::Abs(($ft - $mt).TotalMinutes) -le 10) {
                    $linked += "Connection: GPU start failure at $(Format-DDDate $ft) ($(Format-DDStatusText $f.ProblemStatus)) and panel $($mg.LastInstanceId) reported not present at $(Format-DDDate $mt) (event 442 for $($mg.DeviceInstanceId), last instance field) - same boot."
                }
            }
        }
    }

    if ($state -eq 'Unknown') { }
    elseif ($activeInternal.Count -gt 0 -and $zeroBrightness.Count -gt 0) { $state = 'BrightnessZero' }
    elseif ($activeInternal.Count -gt 0) { $state = 'Active' }
    elseif ($disabledPanel.Count -gt 0) { $state = 'Disabled' }
    elseif ($availableInternal.Count -gt 0) { $state = 'Inactive' }
    elseif ($gpuFaulted.Count -gt 0) { $state = 'NotDetected-GpuFault' }
    elseif ($linked.Count -gt 0) { $state = 'NotDetected-GpuHistory' }
    else { $state = 'NotDetected' }

    foreach ($g in $gpuFaulted) { foreach ($f in $g.Faults) { $evidence.Add("GPU $($g.Device.InstanceId): $f") } }
    foreach ($l in ($linked | Sort-Object -Unique)) { $evidence.Add($l) }
    foreach ($b in $zeroBrightness) { $evidence.Add("Panel brightness is 0% on $($b.InstanceName).") }

    $texts = @{
        'Active'               = @('Info', 'VERIFIED', 'Windows has the internal panel active.', 'If the screen still looks black, it is backlight or hardware: shine a flashlight at the panel and run the HP F2 display test.')
        'BrightnessZero'       = @('High', 'VERIFIED', 'The internal panel is active but its brightness is 0%, so it looks off.', 'Raise brightness (the repair step sets it to 70%).')
        'Disabled'             = @('High', 'VERIFIED', 'The internal panel''s monitor device is disabled in Windows.', 'Re-enable the monitor device (repair step).')
        'Inactive'             = @('High', 'VERIFIED', 'Windows detects the internal panel but the display layout does not use it (e.g. "Second screen only").', 'Switch the layout to Extend (repair step, or Win+P > Extend).')
        'NotDetected-GpuFault' = @('Critical', 'INFERRED', 'Windows does not see the internal panel, and the GPU that drives it has recorded faults. The GPU fault is the most likely cause because the panel can only be detected through that GPU driver.', 'Fix the GPU driver first (restart device, then HP/Windows Update driver). If the panel still does not appear, run the HP F2 hardware display test.')
        'NotDetected-GpuHistory' = @('High', 'INFERRED', 'Windows does not see the internal panel. It disappeared in the same boot that the GPU driver failed to start; the GPU is not failing now, but the panel never came back. That connects the panel loss to the graphics driver, not yet to hardware.', 'Restart the GPU device and reinstall the HP-certified graphics driver. If the panel is still missing after that, the F2 hardware display test decides.')
        'NotDetected'          = @('High', 'INFERRED', 'Windows does not see the internal panel and the GPU shows no recorded fault. That points to panel/cable/firmware rather than the Windows driver.', 'Check whether the HP logo shows on the internal screen at power-on, then run HP PC Hardware Diagnostics (F2) > Component Tests > Video/Display.')
        'Unknown'              = @('Medium', 'INFERRED', 'The display layout could not be read, so the panel state is undetermined.', 'Re-run as administrator; see collection errors.')
    }
    $t = $texts[$state]
    return [pscustomobject]@{
        State          = $state
        Severity       = $t[0]
        Confidence     = $t[1]
        Summary        = $t[2]
        NextStep       = $t[3]
        Evidence       = $evidence.ToArray()
        PanelDevices   = $panelDevices
        InternalTargets = $internal
    }
}

function Invoke-DDAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        # Only events at/after this time count as "current". Defaults to the last boot.
        $EventsSince
    )
    $findings = New-Object System.Collections.Generic.List[object]
    $lastBoot = ConvertTo-DDDate $Snapshot.Meta.LastBoot
    $since = ConvertTo-DDDate $EventsSince
    if ($null -eq $since) { $since = $lastBoot }
    if ($null -eq $since) { $since = [datetime]::MinValue }

    # Normalize events once (snapshot JSON may hold strings instead of dates).
    foreach ($e in (Get-DDArray $Snapshot.PnpEvents)) { $e.Time = ConvertTo-DDDate $e.Time }
    $devices = @(Get-DDArray $Snapshot.Devices)
    $byId = @{}
    foreach ($d in $devices) { if ($d.InstanceId) { $byId[[string]$d.InstanceId] = $d } }
    $events = @(Get-DDArray $Snapshot.PnpEvents)

    # 1. GPUs -----------------------------------------------------------------
    $gpuHealth = @(Get-DDGpuHealth -Snapshot $Snapshot -Since $since)
    foreach ($g in $gpuHealth) {
        $d = $g.Device
        $ev = New-Object System.Collections.Generic.List[string]
        $ev.Add("Driver in use: $($d.DriverProvider) $($d.DriverVersion) dated $($d.DriverDate), INF $($d.DriverInf), service $($d.Service).")
        foreach ($f in $g.Faults) { $ev.Add($f) }
        $installs = @($events | Where-Object { $_.Id -eq 400 -and ([string]$_.DeviceInstanceId -eq [string]$d.InstanceId) } | Sort-Object Time | Select-Object -Last 3)
        foreach ($i in $installs) { $ev.Add("Event 400 at $(Format-DDDate $i.Time): driver configured $($i.DriverName) version $($i.DriverVersion) ($($i.DriverProvider)).") }
        $allFail = @($g.FailuresAll | Sort-Object Time)
        if ($allFail.Count -gt 0) {
            $ev.Add("Event 411 history in the lookback window: $($allFail.Count) start failure(s), first $(Format-DDDate $allFail[0].Time), last $(Format-DDDate $allFail[-1].Time).")
            $lastInstall = $installs | Where-Object { $_.Time -le $allFail[0].Time } | Select-Object -Last 1
            if ($lastInstall) {
                $mins = [math]::Round(($allFail[0].Time - $lastInstall.Time).TotalMinutes, 1)
                $ev.Add("Connection (timing only, not proof): first failure came $mins minute(s) after the driver configuration at $(Format-DDDate $lastInstall.Time).")
            }
        }
        if ($g.Faults.Count -eq 0 -and $allFail.Count -eq 0) { continue }
        $sev = 'Low'; $title = "GPU had start failures earlier but none since $(Format-DDDate $since): $($d.Name)"
        $interp = 'Past start failures with no current fault. On their own they need no change; the built-in display section says whether they connect to the missing panel.'
        $actions = @(); $state = $false; $cat = 'History'
        if ($g.Hard) {
            $state = $true; $cat = 'Display'
            $sev = 'Critical'; $title = "GPU driver is not working: $($d.Name)"
            $interp = 'Windows reports the GPU itself in a failed state. Every display connected to this GPU depends on it.'
            $actions = @((New-DDAction 'RestartDevice' $d.InstanceId 'Restart the GPU device (screens blank for a few seconds).')) + @(Get-DDDriverUpdateActions $Snapshot $d)
        }
        elseif ($g.FailuresSince.Count -gt 0) {
            $state = $true; $cat = 'Display'
            $sev = 'High'; $title = "GPU driver failed to start during the current session: $($d.Name)"
            $interp = 'The GPU driver hit start errors in this boot. Even if it recovered, a failed start can leave the built-in panel undetected.'
            $actions = @((New-DDAction 'RestartDevice' $d.InstanceId 'Restart the GPU device (screens blank for a few seconds).')) + @(Get-DDDriverUpdateActions $Snapshot $d)
        }
        $findings.Add((New-DDFinding -Id "GPU:$($d.InstanceId)" -Severity $sev -Category $cat -Title $title -Evidence $ev.ToArray() `
                    -Interpretation $interp -Confidence 'VERIFIED' -Recommendation 'Restart the GPU device; if the fault returns, install the HP-certified graphics driver for this model.' `
                    -Actions $actions -StateBased $state))
    }

    # 2. Internal panel verdict ---------------------------------------------
    $verdict = Get-DDInternalDisplayVerdict -Snapshot $Snapshot -GpuHealth $gpuHealth
    $vActions = @()
    switch ($verdict.State) {
        'BrightnessZero' { $vActions = @(New-DDAction 'SetBrightness' '70' 'Set internal panel brightness to 70%.') }
        'Disabled' { $vActions = @($verdict.PanelDevices | Where-Object { (ConvertTo-DDInt $_.ProblemCode) -eq 22 } | ForEach-Object { New-DDAction 'EnableDevice' $_.InstanceId 'Re-enable the internal monitor device.' }) }
        'Inactive' { $vActions = @(New-DDAction 'ExtendTopology' '' 'Switch display layout to Extend so the internal panel is used (undo: Win+P).') }
        'NotDetected' { $vActions = @(New-DDAction 'Manual' '' 'Power on and watch the internal screen: HP logo visible = panel works, software issue; nothing visible = run HP F2 diagnostics display test / hardware service.') }
        'NotDetected-GpuFault' { $vActions = @(New-DDAction 'Manual' '' 'After the GPU fix, if the internal screen is still dark: check for the HP logo at power-on and run the HP F2 display test.') }
        'NotDetected-GpuHistory' {
            $gpu = @($gpuHealth | Where-Object { @($_.FailuresAll).Count -gt 0 } | Select-Object -First 1)
            if ($gpu.Count -gt 0) {
                $vActions = @((New-DDAction 'RestartDevice' $gpu[0].Device.InstanceId 'Restart the GPU device so it re-detects the panel (screens blank for a few seconds).')) + @(Get-DDDriverUpdateActions $Snapshot $gpu[0].Device)
            }
            $vActions += New-DDAction 'Manual' '' 'If the panel is still missing after the driver steps: check for the HP logo at power-on and run the HP F2 display test.'
        }
    }
    $findings.Add((New-DDFinding -Id 'INTERNAL-PANEL' -Severity $verdict.Severity -Category 'Display' -Title "Built-in display: $($verdict.State)" `
                -Evidence $verdict.Evidence -Interpretation $verdict.Summary -Confidence $verdict.Confidence -Recommendation $verdict.NextStep -Actions $vActions -StateBased $true))

    # 3. Other devices with Device Manager problems --------------------------
    $gpuIds = @($gpuHealth | ForEach-Object { [string]$_.Device.InstanceId })
    foreach ($d in $devices) {
        if ($d.Present -eq $false) { continue }
        $code = ConvertTo-DDInt $d.ProblemCode
        if ($null -eq $code -or $code -eq 0) { continue }
        if ($gpuIds -contains [string]$d.InstanceId) { continue }
        $pi = Get-DDProblemInfo $code
        $ev = New-Object System.Collections.Generic.List[string]
        $ev.Add("Device Manager: Code $code $($pi.Name) - $($pi.Meaning)")
        $ev.Add("Problem status: $(Format-DDStatusText $d.ProblemStatus). Driver: $($d.DriverInf) $($d.DriverVersion) ($($d.DriverProvider)). Class: $($d.Class).")
        $sev = 'High'; $interp = $pi.Meaning; $actions = @(); $conf = 'VERIFIED'
        switch ($pi.Action) {
            'RestartDevice' { $actions = @((New-DDAction 'RestartDevice' $d.InstanceId 'Restart this device.')) + @(Get-DDDriverUpdateActions $Snapshot $d) }
            'ScanDevices' { $actions = @(Get-DDDriverUpdateActions $Snapshot $d) }
            'DriverUpdate' { $actions = @(Get-DDDriverUpdateActions $Snapshot $d) }
            'RestartComputer' { $actions = @(New-DDAction 'RestartComputer' '' 'Full restart (Start > Power > Restart, not Shut down).') }
            'EnableDevice' {
                if ((Test-DDClass $d 'Monitor') -or (Test-DDClass $d 'Display')) { $actions = @(New-DDAction 'EnableDevice' $d.InstanceId 'Re-enable this display device.') }
                else { $sev = 'Info'; $interp = 'Disabled devices are often disabled on purpose; left as is.' }
            }
            'None' { $sev = 'Low' }
            default { $actions = @(New-DDAction 'Manual' $d.InstanceId $pi.Meaning) }
        }
        if ($code -eq 14) {
            $sev = 'Medium'
            $req = @($events | Where-Object { $_.Id -eq 412 -and ([string]$_.DeviceInstanceId -eq [string]$d.InstanceId) } | Sort-Object Time)
            $fwGuid = Get-DDFirmwareGuidFromInstance $d.InstanceId
            if ($req.Count -gt 0) {
                $last = $req[-1].Time
                $ev.Add("Event 412 (restart required) logged $($req.Count) time(s); latest $(Format-DDDate $last).")
                if ($lastBoot -and $last -gt $lastBoot) {
                    $ev.Add("Last full boot was $(Format-DDDate $lastBoot), before that request: the computer has not fully restarted since.")
                    $interp = 'A staged update is waiting for a full restart. This is the normal install flow, not a failure yet.'
                }
                elseif ($lastBoot) {
                    $sev = 'High'
                    $ev.Add("Last full boot was $(Format-DDDate $lastBoot), after that request, yet the device still needs a restart.")
                    $interp = 'The restart happened but the staged update did not apply. For firmware this usually means the update was refused or deferred at boot (see firmware status).'
                }
            }
            if ($fwGuid) {
                $fw = Get-DDArray $Snapshot.Firmware | Where-Object { ([string]$_.Guid).ToLowerInvariant() -eq $fwGuid } | Select-Object -First 1
                if ($fw) {
                    $fi = Get-DDFirmwareAttemptInfo $fw.LastAttemptStatus
                    $ev.Add("Firmware resource $fwGuid : current version $(Format-DDHex $fw.Version), last attempted $(Format-DDHex $fw.LastAttemptVersion), last status $($fi.Hex) $($fi.Name).")
                    if ($sev -eq 'High' -and $fi.Value -eq 0) {
                        # The registry says the last capsule attempt succeeded, so "refused at boot" would contradict the evidence.
                        $sev = 'Medium'
                        $interp = 'Firmware reports its last attempted version installed successfully. The device still waits for a restart, so a package staged after that attempt has not been applied yet. A full Restart (not Shut down) on AC power applies it.'
                    }
                    elseif ($fi.Value -ne 0) {
                        $interp = "The staged firmware was not applied: last attempt status $($fi.Hex) ($($fi.Name)). $($fi.Meaning)"
                    }
                }
                $actions = @($actions) + @(New-DDAction 'Manual' '' 'Before restarting: plug in the AC adapter and keep it connected; let the update screen finish.')
            }
        }
        $findings.Add((New-DDFinding -Id "DEVICE:$($d.InstanceId)" -Severity $sev -Category 'Device' -Title "$($pi.Name): $(Get-DDDeviceLabel $d)" `
                    -Evidence $ev.ToArray() -Interpretation $interp -Confidence $conf -Recommendation (($actions | ForEach-Object { $_.Detail }) -join ' ') -Actions $actions -StateBased $true))
    }

    # 4. Non-GPU devices with start failures in this session ---------------
    $failGroups = $events | Where-Object { $_.Id -eq 411 -and $_.DeviceInstanceId -and ($gpuIds -notcontains [string]$_.DeviceInstanceId) } | Group-Object DeviceInstanceId
    foreach ($grp in $failGroups) {
        $d = $byId[[string]$grp.Name]
        $code = if ($d) { ConvertTo-DDInt $d.ProblemCode } else { $null }
        if ($code -and $code -ne 0) { continue }  # already reported by section 3
        $recent = @($grp.Group | Where-Object { $_.Time -ge $since })
        $sorted = @($grp.Group | Sort-Object Time)
        $statuses = ($grp.Group | ForEach-Object { Format-DDStatusText $_.ProblemStatus } | Sort-Object -Unique) -join ', '
        $sev = if ($recent.Count -gt 0) { 'Medium' } else { 'Low' }
        $findings.Add((New-DDFinding -Id "START-FAIL:$($grp.Name)" -Severity $sev -Category 'History' -Title "Start failures logged: $(Get-DDDeviceLabel $d $grp.Name)" `
                    -Evidence @("Event 411 x$($grp.Count): first $(Format-DDDate $sorted[0].Time), last $(Format-DDDate $sorted[-1].Time); since $(Format-DDDate $since): $($recent.Count).", "Statuses: $statuses.", "Driver: $($sorted[-1].DriverName), service $($sorted[-1].Service).") `
                    -Interpretation 'The device is not currently in a failed state; failures are historical unless they keep recurring.' -Confidence 'VERIFIED' `
                    -Recommendation 'No action unless the device misbehaves; re-run after the next restart to see if failures recur.' -Actions @()))
    }

    # 5. Firmware resources ----------------------------------------------------
    foreach ($fw in (Get-DDArray $Snapshot.Firmware)) {
        $fi = Get-DDFirmwareAttemptInfo $fw.LastAttemptStatus
        if ($null -eq $fi -or $fi.Value -eq 0) { continue }
        $guid = ([string]$fw.Guid).ToLowerInvariant()
        $dev = $devices | Where-Object { (Get-DDFirmwareGuidFromInstance $_.InstanceId) -eq $guid } | Select-Object -First 1
        $sev = if ($fi.Transient) { 'Medium' } else { 'High' }
        $actions = if ($fi.Transient) {
            @((New-DDAction 'Manual' '' 'Connect the AC adapter, charge the battery well, then do a full Restart and let the update finish.'), (New-DDAction 'RestartComputer' '' 'Full restart to retry the staged firmware update.'))
        }
        else {
            @((New-DDAction 'HPIAInstall' 'Firmware' 'Install the HP BIOS/firmware package for this model through HP Image Assistant.' $true), (New-DDAction 'Manual' '' 'Windows will not retry this firmware automatically. Get the BIOS/firmware SoftPaq from HP support for this model.'))
        }
        $findings.Add((New-DDFinding -Id "FIRMWARE:$guid" -Severity $sev -Category 'Firmware' -Title "Firmware update did not apply: $(Get-DDDeviceLabel $dev "UEFI\RES_$guid")" `
                    -Evidence @("FirmwareResources\$guid : Version $(Format-DDHex $fw.Version), LastAttemptVersion $(Format-DDHex $fw.LastAttemptVersion), LastAttemptStatus $($fi.Hex) ($($fi.Name)).") `
                    -Interpretation $fi.Meaning -Confidence 'VERIFIED' -Recommendation (($actions | ForEach-Object { $_.Detail }) -join ' ') -Actions $actions -StateBased $true))
    }

    # 6. Pending restart ---------------------------------------------------------
    $pr = $Snapshot.PendingRestart
    if ($pr) {
        $reasons = New-Object System.Collections.Generic.List[string]
        if ($pr.ComponentServicing) { $reasons.Add('Component Based Servicing: RebootPending') }
        if ($pr.WindowsUpdate) { $reasons.Add('Windows Update: RebootRequired') }
        if ($pr.FileRename) { $reasons.Add('Session Manager: PendingFileRenameOperations') }
        $needRestartDevices = @($devices | Where-Object { $_.Present -ne $false -and (ConvertTo-DDInt $_.ProblemCode) -eq 14 })
        foreach ($n in $needRestartDevices) { $reasons.Add("Device needs restart: $(Get-DDDeviceLabel $n)") }
        if ($reasons.Count -gt 0) {
            $ev = @($reasons.ToArray())
            if ($lastBoot) { $ev += "Last full boot: $(Format-DDDate $lastBoot)." }
            if ($pr.FastStartup) { $ev += 'Fast Startup is ON: "Shut down" then power on does NOT finish pending updates. Use Restart.' }
            $findings.Add((New-DDFinding -Id 'PENDING-RESTART' -Severity 'Medium' -Category 'Restart' -Title 'Windows is waiting for a full restart' -Evidence $ev `
                        -Interpretation 'Staged driver/firmware/OS changes are waiting. Diagnosing further before restarting can chase problems that a restart resolves.' `
                        -Confidence 'VERIFIED' -Recommendation 'Plug in AC power, then Start > Power > Restart.' -Actions @(New-DDAction 'RestartComputer' '' 'Full restart.') -StateBased $true))
        }
    }

    # 7. Missing driver binaries ----------------------------------------------
    foreach ($s in (Get-DDArray $Snapshot.ServiceChecks)) {
        if ($s.ImageExists -ne $false) { continue }
        $findings.Add((New-DDFinding -Id "DRIVER-FILE:$($s.Name)" -Severity 'High' -Category 'DriverFiles' -Title "Driver file missing for service $($s.Name)" `
                    -Evidence @("ImagePath $($s.ImagePath) resolves to $($s.ResolvedPath), which does not exist.", "Start type: $($s.Start).") `
                    -Interpretation 'The driver package is damaged or partially removed.' -Confidence 'VERIFIED' `
                    -Recommendation 'Reinstall the driver package from HP or Windows Update.' -Actions @((New-DDAction 'ScanDevices' '' 'Re-evaluate drivers.')) -StateBased $true))
    }

    # 8. System log history ------------------------------------------------------
    $sys = @(Get-DDArray $Snapshot.SystemEvents)
    $tdr = @($sys | Where-Object { $_.Provider -eq 'Display' -and $_.Id -eq 4101 })
    if ($tdr.Count -gt 0) {
        $sorted = @($tdr | Sort-Object { ConvertTo-DDDate $_.Time })
        $findings.Add((New-DDFinding -Id 'TDR' -Severity 'Medium' -Category 'History' -Title "Graphics driver stopped responding $($tdr.Count) time(s) (TDR, event 4101)" `
                    -Evidence @("First $(Format-DDDate $sorted[0].Time), last $(Format-DDDate $sorted[-1].Time).", "Latest: $($sorted[-1].Message)") `
                    -Interpretation 'Windows reset the graphics driver after it hung. Repeated resets point to the graphics driver or GPU firmware.' -Confidence 'VERIFIED' `
                    -Recommendation 'Install the HP-certified graphics driver; re-check after.' -Actions @()))
    }
    $loadFail = $sys | Where-Object { $_.Provider -eq 'Microsoft-Windows-Kernel-PnP' -and $_.Id -eq 219 } | Group-Object Message
    foreach ($g in $loadFail) {
        $findings.Add((New-DDFinding -Id "PNP219:$($g.Name.GetHashCode())" -Severity 'Low' -Category 'History' -Title "Driver failed to load (Kernel-PnP 219) x$($g.Count)" `
                    -Evidence @($g.Name) -Interpretation 'Often a device that is slow to enumerate at boot; important only if the named device is not working now.' `
                    -Confidence 'VERIFIED' -Recommendation 'Check whether the named device works; no action otherwise.' -Actions @()))
    }
    $whea = @($sys | Where-Object { $_.Provider -eq 'Microsoft-Windows-WHEA-Logger' })
    if ($whea.Count -gt 0) {
        $sorted = @($whea | Sort-Object { ConvertTo-DDDate $_.Time })
        $fatal = @($whea | Where-Object { $_.Id -in 1, 18, 20, 46, 47 }).Count
        $sev = if ($fatal -gt 0) { 'High' } else { 'Low' }
        $findings.Add((New-DDFinding -Id 'WHEA' -Severity $sev -Category 'History' -Title "Hardware error reports (WHEA) x$($whea.Count)" `
                    -Evidence @("Latest $(Format-DDDate $sorted[-1].Time): $($sorted[-1].Message)", "Uncorrected/fatal-class reports: $fatal.") `
                    -Interpretation 'Hardware-reported errors. Not linked to any other finding unless the same device appears in both.' -Confidence 'VERIFIED' `
                    -Recommendation 'If uncorrected errors exist, run HP PC Hardware Diagnostics (F2) full test.' -Actions @()))
    }

    # 9. Code Integrity / LSA protection module blocks ------------------------
    $ci = Get-DDArray $Snapshot.CodeIntegrityEvents | Where-Object { $_.Module } | Group-Object Module
    foreach ($g in $ci) {
        $first = $g.Group[0]
        $owner = $first.OwnerProduct
        $isLsa = ([string]$first.Process -match '(?i)lsass\.exe$')
        $enforced = @($g.Group | Where-Object { $_.Enforced }).Count -gt 0
        $leaf = ([string]$g.Name -split '\\')[-1]
        $title = if ($isLsa) { "LSA protection blocked a module: $leaf" } else { "Code Integrity blocked a module: $leaf" }
        $ev = @("Module: $($g.Name)", "Loaded by: $($first.Process)", "Reason: $($first.Reason)", "Events: $($g.Count) (ids $((($g.Group | ForEach-Object { $_.Id }) | Sort-Object -Unique) -join ', ')), enforced=$enforced.")
        if ($owner) { $ev += "Installed by: $owner (module path is inside its install folder)." }
        if ($isLsa -and $Snapshot.Security -and $null -ne $Snapshot.Security.LsaRunAsPPL) { $ev += "LSA protection setting RunAsPPL=$($Snapshot.Security.LsaRunAsPPL)." }
        $rec = 'Update or uninstall the software that owns this module. Do not turn off LSA protection / Memory integrity to silence it.'
        if ([string]$g.Name -match '(?i)\\Bonjour\\mdnsNSP\.dll$') {
            $rec = 'Bonjour (Apple) installs mdnsNSP.dll as a network name provider; per the event, LSA protection refused it for not meeting the Microsoft signing level that protected LSA requires. If you do not need Bonjour (AirPlay/Apple printers discovery), uninstall "Bonjour" in Settings > Apps; if you need it, keep it and tick "Don''t show this message again". Keep LSA protection ON.'
        }
        $findings.Add((New-DDFinding -Id "CI:$($g.Name)" -Severity 'Low' -Category 'Security' -Title $title -Evidence $ev `
                    -Interpretation 'A Windows security feature is working as designed and refused a third-party module. No connection to the display or GPU issue was found (different component, no shared device or driver).' `
                    -Confidence 'VERIFIED' -Recommendation $rec -Actions @(New-DDAction 'Manual' '' $rec)))
    }

    # 10. Windows Update ------------------------------------------------------
    $wuEvents = @(Get-DDArray $Snapshot.WindowsUpdateEvents | Where-Object { $_.Id -eq 20 -and $_.Title })
    foreach ($g in ($wuEvents | Group-Object Title)) {
        $codes = (($g.Group | ForEach-Object { $_.ErrorCode }) | Sort-Object -Unique) -join ', '
        $benign = ($codes -eq '0x80070103')
        $sev = if ($benign) { 'Info' } else { 'Medium' }
        $interp = if ($benign) { '0x80070103 means Windows offered a driver that is already installed or not better than the current one. Harmless.' } else { 'Windows Update could not install this update.' }
        $findings.Add((New-DDFinding -Id "WU-FAIL:$($g.Name)" -Severity $sev -Category 'History' -Title "Windows Update install failed x$($g.Count): $($g.Name)" `
                    -Evidence @("Error code(s): $codes.", "Latest: $(Format-DDDate (($g.Group | Sort-Object Time)[-1].Time)).") -Interpretation $interp -Confidence 'VERIFIED' `
                    -Recommendation 'If it keeps failing and is not 0x80070103, install the same component from HP for this model.' -Actions @()))
    }
    $wu = $Snapshot.WindowsUpdate
    if ($wu -and $wu.Error) {
        $findings.Add((New-DDFinding -Id 'WU-SEARCH' -Severity 'Info' -Category 'Updates' -Title 'Windows Update driver search could not run' -Evidence @([string]$wu.Error) `
                    -Interpretation 'Available driver updates are unknown, not absent.' -Confidence 'VERIFIED' -Recommendation 'Check Settings > Windows Update > Advanced options > Optional updates > Driver updates.' -Actions @()))
    }
    $problemHw = @{}
    foreach ($d in $devices) {
        $c = ConvertTo-DDInt $d.ProblemCode
        if (($c -and $c -ne 0) -or ($gpuIds -contains [string]$d.InstanceId)) {
            foreach ($h in (Get-DDArray $d.HardwareIds)) { $problemHw[([string]$h).ToUpperInvariant()] = $d }
        }
    }
    foreach ($u in (Get-DDArray $wu.Updates)) {
        $hit = $null
        if ($u.HardwareId) { $hit = $problemHw[([string]$u.HardwareId).ToUpperInvariant()] }
        $cls = [string]$u.DriverClass
        $sev = 'Low'
        if ($hit) { $sev = 'High' } elseif ($cls -in 'Display', 'Firmware', 'Monitor') { $sev = 'Medium' }
        $ev = @("Class $cls, provider $($u.DriverProvider), model $($u.DriverModel), driver date $($u.DriverVerDate), hardware id $($u.HardwareId).")
        if ($hit) { $ev += "Connection: same hardware id as $(Get-DDDeviceLabel $hit), which has a current fault." }
        $findings.Add((New-DDFinding -Id "WU-UPDATE:$($u.UpdateId)" -Severity $sev -Category 'Updates' -Title "Driver update available: $($u.Title)" -Evidence $ev `
                    -Interpretation 'Offered by Windows Update for this PC (Microsoft-signed, targeted by the manufacturer).' -Confidence 'VERIFIED' `
                    -Recommendation 'Install (repair mode asks per update).' -Actions @(New-DDAction 'InstallWindowsUpdate' ([string]$u.UpdateId) "Install: $($u.Title)" ($cls -eq 'Firmware'))))
    }

    # 11. Driver update policy ---------------------------------------------------
    $pol = $Snapshot.DriverPolicy
    if ($pol) {
        $ev = @()
        if ((ConvertTo-DDInt $pol.ExcludeWUDriversInQualityUpdate) -eq 1) { $ev += 'Policy "Do not include drivers with Windows Updates" is enabled (ExcludeWUDriversInQualityUpdate=1).' }
        if ($null -ne $pol.SearchOrderConfig -and (ConvertTo-DDInt $pol.SearchOrderConfig) -eq 0) { $ev += 'Device installation settings: automatic driver download is OFF (SearchOrderConfig=0).' }
        if ($ev.Count -gt 0) {
            $findings.Add((New-DDFinding -Id 'DRIVER-POLICY' -Severity 'Medium' -Category 'Updates' -Title 'Windows is set not to fetch drivers automatically' -Evidence $ev `
                        -Interpretation 'Fixed drivers from HP/Microsoft will not arrive on their own while this is set.' -Confidence 'VERIFIED' `
                        -Recommendation 'Your choice: re-enable in System Properties > Hardware > Device Installation Settings, or rely on HP Image Assistant.' -Actions @()))
        }
    }

    # 12. HP Image Assistant -----------------------------------------------------
    $hp = $Snapshot.HPIA
    $isHp = ([string]$Snapshot.Meta.Manufacturer -match '^(?i)(HP|Hewlett)')
    if ($hp -and $hp.Present) {
        $recs = @(Get-DDArray $hp.Recommendations)
        if ($hp.Error) {
            $findings.Add((New-DDFinding -Id 'HPIA' -Severity 'Info' -Category 'Updates' -Title 'HP Image Assistant analysis did not complete' -Evidence @([string]$hp.Error) `
                        -Interpretation 'HP-recommended updates are unknown.' -Confidence 'VERIFIED' -Recommendation 'Run HP Image Assistant manually.' -Actions @()))
        }
        elseif ($recs.Count -gt 0) {
            $findings.Add((New-DDFinding -Id 'HPIA' -Severity 'Medium' -Category 'Updates' -Title "HP Image Assistant recommends $($recs.Count) update(s)" -Evidence $recs `
                        -Interpretation 'Compared against HP''s reference image for this exact model.' -Confidence 'VERIFIED' `
                        -Recommendation 'Install drivers via HPIA (repair mode). BIOS/firmware only with -IncludeFirmware.' -Actions @(New-DDAction 'HPIAInstall' 'Drivers' 'Install HP-recommended driver updates.')))
        }
    }
    elseif ($hp -and @(Get-DDArray $hp.Rejected).Count -gt 0) {
        # SEC-001: a copy exists but was not run. Say so; "not found" would be false.
        $findings.Add((New-DDFinding -Id 'HPIA-REJECTED' -Severity 'Low' -Category 'Updates' -Title 'HP Image Assistant found but not run' `
                    -Evidence @(Get-DDArray $hp.Rejected | ForEach-Object { [string]$_ }) `
                    -Interpretation 'Driver Doctor runs as administrator, so it only runs HP Image Assistant from Program Files and only when it carries a valid HP Inc. signature.' `
                    -Confidence 'VERIFIED' -Recommendation 'Download HP Image Assistant from HP (https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html), extract it to %ProgramFiles%\HP\HPIA\bin, and re-run. Do not run a copy from a folder other users can change.' -Actions @()))
    }
    elseif ($hp -and $isHp) {
        # Only when the search actually ran (HPIA = $null means it was skipped, which proves nothing).
        $searched = 'No HPImageAssistant.exe in the searched locations.'
        if ($null -ne $hp.PSObject.Properties['HPIAPathGiven']) {
            $searched = if ($hp.HPIAPathGiven) { 'No HPImageAssistant.exe at the -HPIAPath given.' } else { 'No HPImageAssistant.exe in %ProgramFiles%\HP\HPIA\bin.' }
        }
        $findings.Add((New-DDFinding -Id 'HPIA-MISSING' -Severity 'Info' -Category 'Updates' -Title 'HP Image Assistant not found' `
                    -Evidence @($searched) -Interpretation 'Without it, this tool cannot compare against HP''s certified driver set for your model.' `
                    -Confidence 'VERIFIED' -Recommendation 'Download HP Image Assistant from HP (https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html), extract it to %ProgramFiles%\HP\HPIA\bin (only administrators can change that folder), and re-run.' -Actions @()))
    }

    # 13. Driver store context for displays ------------------------------------
    $displayPkgs = @(Get-DDArray $Snapshot.DriverStore | Where-Object { $_.ClassGuid -eq $script:DDClassGuid.Display })
    if ($displayPkgs.Count -gt 0) {
        $ev = @($displayPkgs | ForEach-Object { "$($_.PublishedName) = $($_.OriginalName), $($_.Provider) $($_.Version) ($($_.Date))" })
        $findings.Add((New-DDFinding -Id 'DISPLAY-DRIVERSTORE' -Severity 'Info' -Category 'Display' -Title "$($displayPkgs.Count) graphics driver package(s) in the driver store" -Evidence $ev `
                    -Interpretation 'More than one package means Device Manager > Roll Back Driver may be possible.' -Confidence 'VERIFIED' -Recommendation 'Reference only.' -Actions @()))
    }

    # 14. Correlated moments ---------------------------------------------------
    $clusterInput = @($events | Where-Object { $_.Id -in 400, 411, 412, 430, 441, 442 })
    $clusters = @(Get-DDEventClusters -Records $clusterInput -GapMinutes 10)
    foreach ($c in ($clusters | Sort-Object Start -Descending | Select-Object -First 5)) {
        $hasProblem = @($c.Records | Where-Object { $_.Id -in 411, 412, 442 }).Count -gt 0
        if (-not $hasProblem) { continue }
        $ev = @($c.Records | ForEach-Object { "$(Format-DDDate $_.Time) event $($_.Id): $($_.DeviceInstanceId) $(if ($_.Id -eq 411) { '(start failure ' + (Format-DDStatusText $_.ProblemStatus) + ')' } elseif ($_.Id -eq 412) { '(restart required)' } elseif ($_.Id -eq 442) { '(settings not migrated from previous OS install; last instance ' + $_.LastInstanceId + ', present=' + $_.Present + ')' } else { '(driver configured ' + $_.DriverName + ')' })" })
        $migr = @($c.Records | Where-Object { $_.Id -in 441, 442 }).Count -gt 0
        $interp = 'These events happened within minutes of each other. That is a timing connection only.'
        if ($migr) { $interp = 'Events 441/442 mark the first boot after a Windows upgrade or reinstall. Problems in the same window started with that OS change (timing connection, same boot).' }
        $findings.Add((New-DDFinding -Id "TIMELINE:$($c.Start.ToString('yyyyMMddHHmm'))" -Severity 'Info' -Category 'Timeline' -Title "Connected events around $(Format-DDDate $c.Start)" `
                    -Evidence $ev -Interpretation $interp -Confidence 'INFERRED' -Recommendation 'Context for the findings above.' -Actions @()))
    }

    $sorted = @($findings | Sort-Object @{ Expression = { $script:DDSeverityRank[$_.Severity] } }, Id)
    return [pscustomobject]@{ Findings = $sorted; Verdict = $verdict; GpuHealth = $gpuHealth; Since = $since }
}

function Get-DDRepairPlan {
    # Turns findings into an ordered, de-duplicated list of actions. Firmware/BIOS
    # actions are held back unless explicitly allowed.
    param([object[]]$Findings, [switch]$IncludeFirmware)
    $order = @{ EnableDevice = 10; ExtendTopology = 20; SetBrightness = 30; RestartDevice = 40; ScanDevices = 50; InstallWindowsUpdate = 60; HPIAInstall = 70; RestartComputer = 90; Manual = 100 }
    $plan = New-Object System.Collections.Generic.List[object]
    $index = @{}
    $hpiaFirmware = $false
    foreach ($f in ($Findings | Sort-Object @{ Expression = { $script:DDSeverityRank[$_.Severity] } })) {
        foreach ($a in (Get-DDArray $f.Actions)) {
            $type = $a.Type; $target = [string]$a.Target; $detail = $a.Detail
            if ($type -eq 'HPIAInstall') {
                if ($a.RequiresFirmwareConsent) { $hpiaFirmware = $true }
                $target = 'Drivers'
            }
            if ($a.RequiresFirmwareConsent -and -not $IncludeFirmware) {
                $type = 'Manual'; $target = 'firmware'
                $detail = 'Firmware/BIOS updates are held back. Re-run Repair with -IncludeFirmware (on AC power) to allow them.'
            }
            $key = "$type|$target|$(if ($type -eq 'Manual') { $detail })"
            if ($index.ContainsKey($key)) { $index[$key].Reasons += $f.Id; continue }
            $item = [pscustomobject]@{ Order = $order[$type]; Type = $type; Target = $target; Detail = $detail; Reasons = @($f.Id); Severity = $f.Severity }
            $index[$key] = $item
            $plan.Add($item)
        }
    }
    if ($IncludeFirmware -and $hpiaFirmware) {
        $h = $plan | Where-Object { $_.Type -eq 'HPIAInstall' } | Select-Object -First 1
        if ($h) { $h.Target = 'Drivers,BIOS,Firmware' }
    }
    return @($plan | Sort-Object Order, @{ Expression = { $script:DDSeverityRank[$_.Severity] } })
}

function Compare-DDFindings {
    # Before/after diff limited to state-based findings (history and update lists are
    # not re-collected after a repair, so they cannot prove anything either way).
    param([object[]]$Before, [object[]]$After)
    $isProblem = { param($f) $f.StateBased -and $script:DDSeverityRank[$f.Severity] -le 2 }
    $b = @{}; foreach ($f in $Before) { if (& $isProblem $f) { $b[$f.Id] = $f } }
    $a = @{}; foreach ($f in $After) { if (& $isProblem $f) { $a[$f.Id] = $f } }
    $fixed = @($b.Keys | Where-Object { -not $a.ContainsKey($_) } | ForEach-Object { $b[$_] })
    $remaining = @($b.Keys | Where-Object { $a.ContainsKey($_) } | ForEach-Object { $a[$_] })
    $new = @($a.Keys | Where-Object { -not $b.ContainsKey($_) } | ForEach-Object { $a[$_] })
    return [pscustomobject]@{ Fixed = $fixed; Remaining = $remaining; New = $new }
}
