# DD.Collect.ps1 - read-only data collection on Windows.
#
# Every collector is isolated: a failure is recorded in CollectionErrors and the
# rest still runs, so the report says what is unknown instead of guessing.
# Nothing here changes system state. (HP Image Assistant runs in /Action:List mode,
# which only analyzes.)

function Invoke-DDCollector {
    param([string]$Name, [scriptblock]$Script, $Snapshot)
    Write-Host "  - $Name" -ForegroundColor DarkGray
    try { return (& $Script) }
    catch {
        $Snapshot.CollectionErrors += [pscustomobject]@{ Collector = $Name; Error = $_.Exception.Message }
        return  # emit nothing, so @(...) stays empty instead of holding $null
    }
}

function ConvertTo-DDProblemCode {
    # Get-PnpDevice may surface the code as an int, an enum, or an enum name; normalize to int.
    param($Value)
    if ($null -eq $Value) { return 0 }
    if ($Value -is [Enum] -or $Value -is [ValueType]) { return [int]$Value }
    $s = [string]$Value
    if ($s -match '^\d+$') { return [int]$s }
    if ($s -eq 'CM_PROB_NONE') { return 0 }
    foreach ($k in $script:DDProblemCodes.Keys) { if ($script:DDProblemCodes[$k][0] -eq $s) { return [int]$k } }
    return -1
}

function Get-DDRegistryValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Test-DDIsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DDMeta {
    $cs = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    return [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        BiosVersion  = $bios.SMBIOSBIOSVersion
        BiosDate     = $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') })
        OsCaption    = $os.Caption
        OsBuild      = "$($os.BuildNumber).$(Get-DDRegistryValue $cv 'UBR') ($(Get-DDRegistryValue $cv 'DisplayVersion'))"
        LastBoot     = $os.LastBootUpTime.ToUniversalTime().ToString('o')
        CollectedAt  = (Get-Date).ToUniversalTime().ToString('o')
        IsAdmin      = (Test-DDIsAdmin)
        PSVersion    = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-DDDevices {
    # All present devices with a problem, plus every display/monitor/firmware device
    # (present or not) because the built-in panel diagnosis needs the non-present ones.
    $classes = @($script:DDClassGuid.Display, $script:DDClassGuid.Monitor, $script:DDClassGuid.Firmware)
    $all = @(Get-PnpDevice -ErrorAction Stop)
    $selected = @($all | Where-Object {
            ($_.Present -and (ConvertTo-DDProblemCode $_.ConfigManagerErrorCode) -ne 0) -or
            ($classes -contains ([string]$_.ClassGuid).ToLowerInvariant())
        })
    $keys = @('DEVPKEY_Device_ProblemStatus', 'DEVPKEY_Device_DriverInfPath', 'DEVPKEY_Device_DriverVersion',
        'DEVPKEY_Device_DriverDate', 'DEVPKEY_Device_DriverProvider', 'DEVPKEY_Device_Service', 'DEVPKEY_Device_HardwareIds')
    foreach ($d in $selected) {
        $props = @{}
        try {
            foreach ($p in @(Get-PnpDeviceProperty -InstanceId $d.InstanceId -KeyName $keys -ErrorAction Stop)) { $props[$p.KeyName] = $p.Data }
        }
        catch { Write-Verbose "Properties unavailable for $($d.InstanceId): $($_.Exception.Message)" }
        $code = if ($d.Present) { ConvertTo-DDProblemCode $d.ConfigManagerErrorCode } else { 45 }
        $date = $props['DEVPKEY_Device_DriverDate']
        [pscustomobject]@{
            InstanceId     = $d.InstanceId
            Name           = $d.FriendlyName
            Class          = $d.Class
            ClassGuid      = ([string]$d.ClassGuid).ToLowerInvariant()
            Present        = [bool]$d.Present
            Status         = [string]$d.Status
            ProblemCode    = $code
            ProblemStatus  = $props['DEVPKEY_Device_ProblemStatus']
            Service        = $props['DEVPKEY_Device_Service']
            DriverInf      = $props['DEVPKEY_Device_DriverInfPath']
            DriverVersion  = $props['DEVPKEY_Device_DriverVersion']
            DriverDate     = $(if ($date -is [datetime]) { $date.ToString('yyyy-MM-dd') } else { $date })
            DriverProvider = $props['DEVPKEY_Device_DriverProvider']
            HardwareIds    = @($props['DEVPKEY_Device_HardwareIds'])
        }
    }
}

function ConvertFrom-DDEventXml {
    param($Record)
    $data = @{}
    try {
        $xml = [xml]$Record.ToXml()
        foreach ($n in @($xml.Event.EventData.Data)) { if ($n.Name) { $data[$n.Name] = $n.'#text' } }
    }
    catch { Write-Verbose "EventData unavailable; the message text is used instead: $($_.Exception.Message)" }
    return $data
}

function Get-DDPnpEvents {
    param([int]$Days, [string[]]$KeepInstallsFor)
    # Resolve the channel by listing it, instead of assuming its exact name.
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Kernel-PnP/*' -ErrorAction Stop |
        Where-Object { $_.LogName -match 'Configuration' } | Select-Object -First 1
    if (-not $log) { throw 'Kernel-PnP device configuration log not found.' }
    $filter = @{ LogName = $log.LogName; Id = @(400, 410, 411, 412, 430, 441, 442); StartTime = (Get-Date).AddDays(-$Days) }
    $raw = @()
    try { $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 5000 -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw } }
    $interesting = @($script:DDClassGuid.Display, $script:DDClassGuid.Monitor, $script:DDClassGuid.Firmware)
    foreach ($e in $raw) {
        $p = ConvertFrom-DDPnpEvent -Id $e.Id -TimeCreated $e.TimeCreated -Message $e.Message -EventData (ConvertFrom-DDEventXml $e)
        # 400/410 are routine; keep them only for display/monitor/firmware devices and problem devices.
        if ($e.Id -in 400, 410) {
            if (-not (($interesting -contains $p.ClassGuid) -or ($KeepInstallsFor -contains [string]$p.DeviceInstanceId))) { continue }
        }
        $p.Time = $p.Time.ToString('o')
        $p
    }
}

function Get-DDSystemEvents {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $queries = @(
        @{ LogName = 'System'; ProviderName = 'Display'; Id = 4101; StartTime = $start },
        @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 219; StartTime = $start },
        @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7026; StartTime = $start },
        @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $start }
    )
    foreach ($q in $queries) {
        try { $events = @(Get-WinEvent -FilterHashtable $q -MaxEvents 300 -ErrorAction Stop) }
        catch { continue }
        foreach ($e in $events) {
            $msg = [string]$e.Message
            if ($msg.Length -gt 600) { $msg = $msg.Substring(0, 600) + '...' }
            [pscustomobject]@{ Provider = $e.ProviderName; Id = $e.Id; Time = $e.TimeCreated.ToUniversalTime().ToString('o'); Message = ($msg -replace '\s+', ' ').Trim() }
        }
    }
}

function Resolve-DDDevicePath {
    # \Device\HarddiskVolume3\Program Files\X -> C:\Program Files\X (when the file exists there)
    param([string]$Path)
    if ($Path -match '^\\Device\\HarddiskVolume\d+(\\.+)$') {
        $rest = $Matches[1]
        foreach ($drive in (Get-PSDrive -PSProvider FileSystem)) {
            $candidate = "$($drive.Name):$rest"
            if (Test-Path -LiteralPath $candidate) { return $candidate }
        }
    }
    return $null
}

function Get-DDInstalledProducts {
    $roots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($r in $roots) {
        foreach ($k in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.InstallLocation) {
                [pscustomobject]@{ Name = $p.DisplayName; Version = $p.DisplayVersion; Publisher = $p.Publisher; Location = ([string]$p.InstallLocation).TrimEnd('\') }
            }
        }
    }
}

function Get-DDCodeIntegrityEvents {
    param([int]$Days)
    $filter = @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = @(3033, 3063, 3065, 3066, 3077); StartTime = (Get-Date).AddDays(-$Days) }
    $raw = @()
    try { $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw } }
    if ($raw.Count -eq 0) { return }
    $products = @(Get-DDInstalledProducts)
    foreach ($e in $raw) {
        $c = ConvertFrom-DDCodeIntegrityEvent -Id $e.Id -TimeCreated $e.TimeCreated -Message $e.Message
        $owner = $null
        $local = if ($c.Module) { Resolve-DDDevicePath $c.Module } else { $null }
        if ($local) {
            $hit = $products | Where-Object { $_.Location -and $local.StartsWith($_.Location + '\', [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
            if ($hit) { $owner = "$($hit.Name) $($hit.Version) ($($hit.Publisher))" }
        }
        $c | Add-Member -NotePropertyName LocalPath -NotePropertyValue $local
        $c | Add-Member -NotePropertyName OwnerProduct -NotePropertyValue $owner
        $c.Time = $c.Time.ToString('o')
        $c
    }
}

function Get-DDWindowsUpdateEvents {
    param([int]$Days)
    $filter = @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = @(19, 20); StartTime = (Get-Date).AddDays(-$Days) }
    $raw = @()
    try { $raw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { throw } }
    foreach ($e in $raw) {
        $w = ConvertFrom-DDWindowsUpdateEvent -Id $e.Id -TimeCreated $e.TimeCreated -Message $e.Message
        # Driver/firmware updates are titled "Vendor - Class - Version".
        if ($w.Title -and $w.Title -match ' - ') { $w.Time = $w.Time.ToString('o'); $w }
    }
}

function Get-DDFirmwareResources {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\FirmwareResources'
    foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath
        [pscustomobject]@{
            Guid               = $k.PSChildName.ToLowerInvariant()
            Version            = $p.Version
            LastAttemptVersion = $p.LastAttemptVersion
            LastAttemptStatus  = $p.LastAttemptStatus
            Type               = $p.Type
            Filename           = $p.Filename
        }
    }
}

function Get-DDPendingRestart {
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    return [pscustomobject]@{
        ComponentServicing = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        WindowsUpdate      = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        FileRename         = ($null -ne (Get-DDRegistryValue $sm 'PendingFileRenameOperations'))
        FastStartup        = ((Get-DDRegistryValue "$sm\Power" 'HiberbootEnabled') -eq 1)
    }
}

function Import-DDDisplayConfig {
    if (-not ('DriverDoctor.DisplayConfigReader' -as [type])) {
        Add-Type -TypeDefinition (Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'DisplayConfig.cs')) -ErrorAction Stop
    }
}

function Get-DDDisplayTargets {
    Import-DDDisplayConfig
    foreach ($t in [DriverDoctor.DisplayConfigReader]::GetTargets()) {
        [pscustomobject]@{
            AdapterLuid = $t.AdapterLuid; TargetId = $t.TargetId; FriendlyName = $t.FriendlyName; DevicePath = $t.DevicePath
            OutputTechnology = $t.OutputTechnology; Available = $t.Available; Active = $t.Active
        }
    }
}

function Get-DDMonitorConnections {
    foreach ($c in @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorConnectionParams -ErrorAction Stop)) {
        [pscustomobject]@{ InstanceName = $c.InstanceName; VideoOutputTechnology = $c.VideoOutputTechnology; Active = $c.Active }
    }
}

function Get-DDBrightness {
    try { $items = @(Get-CimInstance -Namespace root/wmi -ClassName WmiMonitorBrightness -ErrorAction Stop) }
    catch { return }  # absent when no internal panel is active - not an error
    foreach ($b in $items) { [pscustomobject]@{ InstanceName = $b.InstanceName; CurrentBrightness = $b.CurrentBrightness; Active = $b.Active } }
}

function Resolve-DDImagePath {
    param([string]$ImagePath)
    if (-not $ImagePath) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim('"'))
    $p = $p -replace '^\\\?\?\\', ''
    if ($p -match '^(?i)\\SystemRoot\\(.*)$') { return (Join-Path $env:SystemRoot $Matches[1]) }
    if ($p -match '^(?i)(System32\\.*)$') { return (Join-Path $env:SystemRoot $Matches[1]) }
    return $p
}

function Get-DDServiceChecks {
    param([string[]]$Names)
    foreach ($n in ($Names | Where-Object { $_ } | Sort-Object -Unique)) {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$n"
        if (-not (Test-Path -LiteralPath $key)) {
            [pscustomobject]@{ Name = $n; Start = $null; ImagePath = $null; ResolvedPath = $null; ImageExists = $false }
            continue
        }
        $img = Get-DDRegistryValue $key 'ImagePath'
        $resolved = Resolve-DDImagePath $img
        $exists = if ($resolved) { Test-Path -LiteralPath $resolved } else { $null }
        [pscustomobject]@{ Name = $n; Start = (Get-DDRegistryValue $key 'Start'); ImagePath = $img; ResolvedPath = $resolved; ImageExists = $exists }
    }
}

function Get-DDDriverStore {
    param([string[]]$KeepInfs)
    $ErrorActionPreference = 'Continue'  # 5.1 would turn native stderr into a terminating error under Stop
    $text = (& pnputil.exe /enum-drivers 2>&1 | ForEach-Object { "$_" } | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "pnputil /enum-drivers exited $LASTEXITCODE" }
    $keepClasses = @($script:DDClassGuid.Display, $script:DDClassGuid.Monitor, $script:DDClassGuid.Firmware)
    ConvertFrom-DDPnputilDriverList $text | Where-Object { ($keepClasses -contains $_.ClassGuid) -or ($KeepInfs -contains $_.PublishedName) }
}

function Get-DDDriverPolicy {
    return [pscustomobject]@{
        ExcludeWUDriversInQualityUpdate = (Get-DDRegistryValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ExcludeWUDriversInQualityUpdate')
        SearchOrderConfig               = (Get-DDRegistryValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig')
    }
}

function Get-DDSecurityState {
    $dg = $null
    try { $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop }
    catch { Write-Verbose "Device Guard state unavailable: $($_.Exception.Message)" }
    return [pscustomobject]@{
        LsaRunAsPPL            = (Get-DDRegistryValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
        MemoryIntegrityRunning = $(if ($dg) { @($dg.SecurityServicesRunning) -contains 2 } else { $null })
    }
}

function Get-DDWindowsUpdateDrivers {
    # Uses the documented Windows Update Agent COM API. Search only; nothing is installed here.
    $result = [pscustomobject]@{ Searched = $true; Error = $null; Updates = @() }
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $found = $searcher.Search("IsInstalled=0 and Type='Driver' and IsHidden=0")
        $list = @()
        foreach ($u in $found.Updates) {
            $list += [pscustomobject]@{
                UpdateId       = $u.Identity.UpdateID
                Title          = $u.Title
                DriverClass    = $u.DriverClass
                DriverModel    = $u.DriverModel
                DriverProvider = $u.DriverProvider
                DriverVerDate  = $(if ($u.DriverVerDate) { ([datetime]$u.DriverVerDate).ToString('yyyy-MM-dd') })
                HardwareId     = $u.DriverHardwareID
            }
        }
        $result.Updates = $list
    }
    catch { $result.Error = $_.Exception.Message }
    return $result
}

function Find-DDHPIA {
    param([string]$HPIAPath)
    $candidates = @()
    if ($HPIAPath) { $candidates += $HPIAPath; $candidates += (Join-Path $HPIAPath 'HPImageAssistant.exe') }
    $candidates += @(
        (Join-Path $env:ProgramFiles 'HP\HPIA\bin\HPImageAssistant.exe'),
        'C:\HPIA\HPImageAssistant.exe',
        (Join-Path (Split-Path $PSScriptRoot -Parent) 'HPIA\HPImageAssistant.exe')
    )
    $candidates += @(Get-ChildItem 'C:\SWSetup\SP*\HPImageAssistant.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c } }
    return $null
}

function Get-DDHPIAAnalysis {
    param([string]$HPIAPath, [string]$WorkDir)
    $exe = Find-DDHPIA $HPIAPath
    $r = [pscustomobject]@{ Present = [bool]$exe; Path = $exe; ExitCode = $null; Error = $null; ReportFolder = $null; Recommendations = @() }
    if (-not $exe) { return $r }
    $report = Join-Path $WorkDir 'hpia-analyze'
    New-Item -ItemType Directory -Force -Path $report -WhatIf:$false | Out-Null
    $r.ReportFolder = $report
    Write-Host '    HP Image Assistant is analyzing (read-only, may take several minutes)...' -ForegroundColor DarkGray
    $hpiaArgs = @('/Operation:Analyze', '/Category:All', '/Selection:All', '/Action:List', '/Silent', "/ReportFolder:`"$report`"")
    # /Action:List only analyzes, so it also runs under -WhatIf. (Start-Process has no -WhatIf in 5.1.)
    $WhatIfPreference = $false
    $p = Start-Process -FilePath $exe -ArgumentList $hpiaArgs -Wait -PassThru -WindowStyle Hidden
    $r.ExitCode = $p.ExitCode
    $known = @{ 0 = 'OK'; 256 = 'No recommendations'; 257 = 'No recommendations selected'; 3010 = 'OK, reboot required'; 4096 = 'Platform not supported by HPIA'; 4097 = 'Invalid parameters' }
    if ($p.ExitCode -notin 0, 256, 257, 3010) {
        $r.Error = "HPIA exit code $($p.ExitCode): $(if ($known.ContainsKey($p.ExitCode)) { $known[$p.ExitCode] } else { 'see HPIA log in ' + $report })"
        return $r
    }
    # Report schema varies across HPIA versions: read any JSON and pull out recommendation-like entries.
    $recs = @()
    foreach ($j in (Get-ChildItem -LiteralPath $report -Filter *.json -Recurse -ErrorAction SilentlyContinue)) {
        try { $doc = Get-Content -Raw -LiteralPath $j.FullName | ConvertFrom-Json } catch { continue }
        $stack = New-Object System.Collections.Stack
        $stack.Push($doc)
        while ($stack.Count -gt 0) {
            $node = $stack.Pop()
            if ($null -eq $node) { continue }
            if ($node -is [System.Array]) { foreach ($x in $node) { $stack.Push($x) }; continue }
            if ($node -isnot [pscustomobject]) { continue }
            foreach ($prop in $node.PSObject.Properties) {
                if ($prop.Name -eq 'Recommendations' -and $prop.Value) {
                    foreach ($rec in @($prop.Value)) {
                        $parts = @()
                        foreach ($f in 'Name', 'TargetComponent', 'TargetVersion', 'ReferenceVersion', 'Comments') { if ($rec.$f) { $parts += "$f=$($rec.$f)" } }
                        if ($rec.Recommendation -and $rec.Recommendation.SoftPaqId) { $parts += "SoftPaq=$($rec.Recommendation.SoftPaqId)" }
                        if ($parts.Count -eq 0) { $parts = @(($rec | ConvertTo-Json -Compress -Depth 3)) }
                        $recs += ($parts -join '; ')
                    }
                }
                elseif ($prop.Value -is [pscustomobject] -or $prop.Value -is [System.Array]) { $stack.Push($prop.Value) }
            }
        }
    }
    $r.Recommendations = @($recs | Sort-Object -Unique)
    return $r
}

function Get-DDSnapshot {
    [CmdletBinding()]
    param(
        [int]$Days = 180,
        [switch]$SkipWindowsUpdate,
        [switch]$SkipHPIA,
        [string]$HPIAPath,
        [string]$WorkDir,
        [switch]$Quick  # skip slow network-backed collectors (used for the post-repair re-check)
    )
    $s = [pscustomobject]@{
        SchemaVersion = 1; Meta = $null; Devices = @(); PnpEvents = @(); SystemEvents = @(); CodeIntegrityEvents = @()
        WindowsUpdateEvents = @(); Firmware = @(); PendingRestart = $null; DisplayTargets = @(); MonitorConnections = @()
        Brightness = @(); ServiceChecks = @(); DriverStore = @(); DriverPolicy = $null; Security = $null
        WindowsUpdate = $null; HPIA = $null; CollectionErrors = @()
    }
    Write-Host 'Collecting (read-only):' -ForegroundColor Cyan
    $s.Meta = Invoke-DDCollector 'System info' { Get-DDMeta } $s
    $s.Devices = @(Invoke-DDCollector 'Devices' { Get-DDDevices } $s)
    $problemIds = @($s.Devices | Where-Object { $_.Present -and $_.ProblemCode -ne 0 } | ForEach-Object { $_.InstanceId })
    $s.PnpEvents = @(Invoke-DDCollector 'Kernel-PnP events' { Get-DDPnpEvents -Days $Days -KeepInstallsFor $problemIds } $s)
    $s.SystemEvents = @(Invoke-DDCollector 'System log (TDR, driver load, WHEA)' { Get-DDSystemEvents -Days $Days } $s)
    $s.CodeIntegrityEvents = @(Invoke-DDCollector 'Code Integrity / LSA blocks' { Get-DDCodeIntegrityEvents -Days $Days } $s)
    $s.WindowsUpdateEvents = @(Invoke-DDCollector 'Windows Update history' { Get-DDWindowsUpdateEvents -Days $Days } $s)
    $s.Firmware = @(Invoke-DDCollector 'Firmware resources' { Get-DDFirmwareResources } $s)
    $s.PendingRestart = Invoke-DDCollector 'Pending restart' { Get-DDPendingRestart } $s
    $s.DisplayTargets = @(Invoke-DDCollector 'DisplayTargets' { Get-DDDisplayTargets } $s)
    $s.MonitorConnections = @(Invoke-DDCollector 'Monitor connections' { Get-DDMonitorConnections } $s)
    $s.Brightness = @(Invoke-DDCollector 'Brightness' { Get-DDBrightness } $s)
    $svcNames = @($s.Devices | Where-Object { ($_.ClassGuid -eq $script:DDClassGuid.Display -and $_.Present) -or ($_.Present -and $_.ProblemCode -ne 0) } | ForEach-Object { $_.Service })
    $s.ServiceChecks = @(Invoke-DDCollector 'Driver files' { Get-DDServiceChecks -Names $svcNames } $s)
    $infs = @($s.Devices | ForEach-Object { $_.DriverInf } | Where-Object { $_ })
    $s.DriverStore = @(Invoke-DDCollector 'Driver store' { Get-DDDriverStore -KeepInfs $infs } $s)
    $s.DriverPolicy = Invoke-DDCollector 'Driver update policy' { Get-DDDriverPolicy } $s
    $s.Security = Invoke-DDCollector 'Security state' { Get-DDSecurityState } $s
    if (-not $Quick -and -not $SkipWindowsUpdate) {
        Write-Host '    Windows Update driver search can take a few minutes...' -ForegroundColor DarkGray
        $s.WindowsUpdate = Invoke-DDCollector 'Windows Update driver search' { Get-DDWindowsUpdateDrivers } $s
    }
    if (-not $Quick -and -not $SkipHPIA) {
        $s.HPIA = Invoke-DDCollector 'HP Image Assistant' { Get-DDHPIAAnalysis -HPIAPath $HPIAPath -WorkDir $WorkDir } $s
    }
    return $s
}
