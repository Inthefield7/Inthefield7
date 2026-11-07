# Run-Tests.ps1 - dependency-free tests for the analysis, report, and offline pipeline.
# Runs on Windows PowerShell 5.1 and PowerShell 7 (any OS). Exit code = number of failures.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib\DD.Analysis.ps1')
. (Join-Path $root 'lib\DD.Report.ps1')
$fixtures = Join-Path $PSScriptRoot 'fixtures'

$script:passed = 0
$script:failed = New-Object System.Collections.Generic.List[string]
function Test-That {
    param([string]$Name, [scriptblock]$Body)
    try {
        $ok = & $Body
        if ($ok -eq $true) { $script:passed++; Write-Host "  PASS $Name" -ForegroundColor Green }
        else { $script:failed.Add($Name); Write-Host "  FAIL $Name (got: $ok)" -ForegroundColor Red }
    }
    catch { $script:failed.Add($Name); Write-Host "  FAIL $Name (threw: $($_.Exception.Message))" -ForegroundColor Red }
}

function Get-Base { Get-Content -Raw -LiteralPath (Join-Path $fixtures 'envy-screenshots.snapshot.json') | ConvertFrom-Json }
function Find-F { param($A, [string]$Id) $A.Findings | Where-Object { $_.Id -eq $Id } | Select-Object -First 1 }
function Find-FLike { param($A, [string]$Pattern) $A.Findings | Where-Object { $_.Id -like $Pattern } | Select-Object -First 1 }

$gpuId = 'PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C&REV_08\3&11583659&0&10'
$fwId = 'UEFI\RES_{F9A422C9-7892-42C3-A237-218610BFD215}\0'

Write-Host 'Primitives' -ForegroundColor Cyan
Test-That 'hex string parses' { (ConvertTo-DDInt '0xE') -eq 14 }
Test-That 'signed DWORD NTSTATUS normalizes' { (ConvertTo-DDInt -1073741102) -eq 3221226194 }
Test-That 'hex literal keys decode (0xC00002D2)' { (Get-DDNtStatusInfo '0xC00002D2').Name -eq 'STATUS_PNP_REBOOT_REQUIRED' }
Test-That 'internal error decodes' { (Get-DDNtStatusInfo 3221225701).Name -eq 'STATUS_INTERNAL_ERROR' }
Test-That 'unknown status stays raw, not guessed' { (Get-DDNtStatusInfo '0xC0000719').Name -eq 'Unrecognized status' }
Test-That 'problem code 14 is NEED_RESTART' { (Get-DDProblemInfo 14).Name -eq 'CM_PROB_NEED_RESTART' }
Test-That 'firmware AC status from signed registry value' { $i = Get-DDFirmwareAttemptInfo -1073741101; $i.Transient -and $i.Name -like 'Power event: AC*' }
Test-That 'eDP / INTERNAL output tech detected' { (Test-DDInternalOutputTechnology 11) -and (Test-DDInternalOutputTechnology 2147483648) -and -not (Test-DDInternalOutputTechnology 10) }
Test-That 'monitor path -> instance id' { (ConvertFrom-DDMonitorDevicePath '\\?\DISPLAY#CMN163B#4&5423816&0&UID0#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7}') -eq 'DISPLAY\CMN163B\4&5423816&0&UID0' }
Test-That 'CMN panel recognized as likely internal' { (Test-DDLikelyPanelInstance 'DISPLAY\CMN163B\4&5423816&0&UID0') -and -not (Test-DDLikelyPanelInstance 'DISPLAY\DELA1F0\5&x&0&UID1') }
Test-That 'Get-DDArray unrolls for @()' { @(Get-DDArray @(1, 2, 3)).Count -eq 3 -and @(Get-DDArray $null).Count -eq 0 -and @(Get-DDArray 5).Count -eq 1 }

Write-Host 'Parsers (exact text from the screenshots)' -ForegroundColor Cyan
$m411 = "Device PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C&REV_08\3&11583659&0&10 had a problem starting.`r`n`r`nDriver Name: oem39.inf`r`nClass GUID: {4d36e968-e325-11ce-bfc1-08002be10318}`r`nService: igfxn`r`nLower Filters: `r`nUpper Filters: `r`nProblem: 0x0`r`nProblem Status: 0xC00000E5"
$e411 = ConvertFrom-DDPnpEvent -Id 411 -TimeCreated '2026-08-27T00:49:44Z' -Message $m411
Test-That '411 device id' { $e411.DeviceInstanceId -eq $gpuId }
Test-That '411 fields' { $e411.DriverName -eq 'oem39.inf' -and $e411.Service -eq 'igfxn' -and $e411.Problem -eq 0 -and $e411.ProblemStatus -eq 3221225701 }
$m412 = "Device UEFI\RES_{f9a422c9-7892-42c3-a237-218610bfd215}\0 requires a system reboot before it can be started.`r`n`r`nDriver Name: oem32.inf`r`nClass GUID: {f2e7dd72-6468-4e36-b6f1-6488f42c1b52}`r`nService: `r`nLower Filters: `r`nUpper Filters: `r`nProblem: 0xE`r`nProblem Status: 0xC00002D2"
$e412 = ConvertFrom-DDPnpEvent -Id 412 -TimeCreated '2026-08-27T00:28:43Z' -Message $m412
Test-That '412 empty Service stays empty (no line bleed)' { [string]::IsNullOrEmpty($e412.Service) -and $e412.Problem -eq 14 -and $e412.ProblemStatus -eq 3221226194 }
$m442 = "Device settings for DISPLAY\Default_Monitor\1&8713bca&0&UID0 were not migrated from previous OS installation due to partial or ambiguous device match.`r`n`r`nLast Device Instance ID: DISPLAY\CMN163B\4&5423816&0&UID0`r`nClass GUID: {4d36e96e-e325-11ce-bfc1-08002be10318}`r`nLocation Path: `r`nMigration Rank: 0xF000FFFF0000F120`r`nPresent: false`r`nStatus: 0xC0000719"
$e442 = ConvertFrom-DDPnpEvent -Id 442 -TimeCreated '2026-08-27T00:49:44Z' -Message $m442
Test-That '442 migration fields' { $e442.DeviceInstanceId -eq 'DISPLAY\Default_Monitor\1&8713bca&0&UID0' -and $e442.LastInstanceId -eq 'DISPLAY\CMN163B\4&5423816&0&UID0' -and $e442.Present -eq $false }
Test-That 'EventData wins over message' { (ConvertFrom-DDPnpEvent -Id 411 -TimeCreated '2026-01-01T00:00:00Z' -Message $m411 -EventData @{ Problem = '10' }).Problem -eq 10 }
$ci = ConvertFrom-DDCodeIntegrityEvent -Id 3033 -TimeCreated '2026-10-02T15:00:00Z' -Message 'Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\lsass.exe) attempted to load \Device\HarddiskVolume3\Program Files\Bonjour\mdnsNSP.dll that did not meet the Microsoft signing level requirements.'
Test-That 'Code Integrity LSA block parsed' { $ci.Process -like '*lsass.exe' -and $ci.Module -like '*\Bonjour\mdnsNSP.dll' -and $ci.Enforced -eq $true }
$wu = ConvertFrom-DDWindowsUpdateEvent -Id 20 -TimeCreated '2026-08-27T00:00:00Z' -Message 'Installation Failure: Windows failed to install the following update with error 0x80070103: Intel Corporation - Display - 31.0.101.4502.'
Test-That 'WU failure parsed' { $wu.ErrorCode -eq '0x80070103' -and $wu.Title -eq 'Intel Corporation - Display - 31.0.101.4502' }
$store = @(ConvertFrom-DDPnputilDriverList (Get-Content -Raw -LiteralPath (Join-Path $fixtures 'pnputil-enum-drivers.txt')))
Test-That 'pnputil list parsed' { $store.Count -eq 3 -and $store[0].PublishedName -eq 'oem39.inf' -and $store[0].Version -eq '32.0.101.5768' -and $store[0].Date -eq '07/12/2024' }

Write-Host 'Scenario A: screenshots (GPU start failure this boot, panel missing, firmware staged)' -ForegroundColor Cyan
$a = Invoke-DDAnalysis -Snapshot (Get-Base)
Test-That 'verdict = NotDetected-GpuFault' { $a.Verdict.State -eq 'NotDetected-GpuFault' }
Test-That 'verdict is INFERRED, not VERIFIED (it connects facts)' { $a.Verdict.Confidence -eq 'INFERRED' }
Test-That 'verdict evidence cites the missing CMN163B panel and event 442' { (($a.Verdict.Evidence -join "`n") -match 'CMN163B') -and (($a.Verdict.Evidence -join "`n") -match 'Event 442') }
$g = Find-F $a "GPU:$gpuId"
Test-That 'GPU finding is High (failed this boot, currently code 0)' { $g.Severity -eq 'High' }
Test-That 'GPU action: restart device first' { $g.Actions[0].Type -eq 'RestartDevice' -and $g.Actions[0].Target -eq $gpuId }
Test-That 'GPU evidence decodes 0xC00000E5' { ($g.Evidence -join ' ') -match 'STATUS_INTERNAL_ERROR' }
$fw = Find-F $a "DEVICE:$fwId"
Test-That 'code 14 after a later boot + registry success -> Medium, no "refused" claim' { $fw.Severity -eq 'Medium' -and (($fw.Evidence -join ' ') -match 'after that request') -and ($fw.Interpretation -match 'installed successfully') }
$s = Get-Base; $s.Firmware = @()
Test-That 'code 14 after a later boot, no registry record -> High (update not applying)' { (Find-F (Invoke-DDAnalysis -Snapshot $s) "DEVICE:$fwId").Severity -eq 'High' }
Test-That 'timeline ignores a single device install pair (400+412)' { @($a.Findings | Where-Object { $_.Category -eq 'Timeline' }).Count -eq 1 }
$pr = Find-F $a 'PENDING-RESTART'
Test-That 'pending restart mentions Fast Startup' { ($pr.Evidence -join ' ') -match 'Fast Startup is ON' }
$bon = Find-FLike $a 'CI:*'
Test-That 'Bonjour LSA block is Low and explicitly NOT linked to display' { $bon.Severity -eq 'Low' -and $bon.Interpretation -match 'No connection to the display' }
Test-That 'Bonjour recommendation keeps LSA protection on' { $bon.Recommendation -match 'Keep LSA protection ON' }
$tl = @($a.Findings | Where-Object { $_.Category -eq 'Timeline' })
Test-That 'timeline links 411 + 442 in the same window as OS migration' { @($tl | Where-Object { $_.Interpretation -match 'Windows upgrade or reinstall' }).Count -eq 1 }
Test-That 'HPIA skipped -> no false "not found" claim' { $null -eq (Find-F $a 'HPIA-MISSING') }
# SEC-001: HPIA runs elevated, so the publisher check must be exact and a refused copy must be reported.
Test-That 'HP publisher: real HP Inc. signer subject accepted' { Test-DDHPPublisher 'CN=HP Inc., OU=HP Cybersecurity, O=HP Inc., L=Palo Alto, S=California, C=US' }
Test-That 'HP publisher: O=HP Inc. inside a quoted CN refused' { -not (Test-DDHPPublisher 'CN="Evil Ltd, O=HP Inc., x", O=Evil Ltd, C=US') }
Test-That 'HP publisher: organization "HP Inc, Evil" refused' { -not (Test-DDHPPublisher 'CN=x, O="HP Inc, Evil"') }
Test-That 'HP publisher: line break inside a CN cannot forge an O= line' { -not (Test-DDHPPublisher ('CN="x' + "`n" + 'O=HP Inc.", C=US')) }
Test-That 'HP publisher: Microsoft, empty and unparsable subjects refused' { -not (Test-DDHPPublisher 'CN=Microsoft Windows, O=Microsoft Corporation, C=US') -and -not (Test-DDHPPublisher '') -and -not (Test-DDHPPublisher 'not a DN ===') }
Test-That 'under-folder: only paths inside Program Files pass' {
    $pf = @('C:\Program Files', 'C:\Program Files (x86)')
    (Test-DDUnderFolder 'C:\Program Files\HP\HPIA\bin\HPImageAssistant.exe' $pf) -and (Test-DDUnderFolder 'c:\program files (x86)\HP\x.exe' $pf) -and
    -not (Test-DDUnderFolder 'C:\SWSetup\SP1\HPImageAssistant.exe' $pf) -and -not (Test-DDUnderFolder 'C:\HPIA\HPImageAssistant.exe' $pf) -and
    -not (Test-DDUnderFolder 'C:\Program Files\..\HPIA\HPImageAssistant.exe' $pf) -and -not (Test-DDUnderFolder 'C:\Program FilesX\HPImageAssistant.exe' $pf)
}
$s = Get-Base; $s.HPIA = [pscustomobject]@{ Present = $false; HPIAPathGiven = $true; Rejected = @('C:\SWSetup\SP1\HPImageAssistant.exe - not under Program Files, so other users may be able to change it'); Recommendations = @() }
$hr = Invoke-DDAnalysis -Snapshot $s
Test-That 'HPIA copy refused -> HPIA-REJECTED with the reason, no "not found" claim' { $f = Find-F $hr 'HPIA-REJECTED'; $f -and (($f.Evidence -join ' ') -match 'SWSetup.*not under Program Files') -and $null -eq (Find-F $hr 'HPIA-MISSING') }
Test-That 'HPIA copy refused -> report says refused, not "not installed"' { $h = ConvertTo-DDHtmlReport -Snapshot $s -Analysis $hr -Plan @() -RepairResults @() -Comparison $null -Mode 'Diagnose'; $h -match 'HP Image Assistant: found but refused' -and $h -notmatch 'HP Image Assistant: not installed' }
$s = Get-Base; $s.HPIA = [pscustomobject]@{ Present = $false; HPIAPathGiven = $false; Rejected = @(); Recommendations = @() }
Test-That 'HPIA absent, no -HPIAPath -> evidence names only Program Files' { $e = (Find-F (Invoke-DDAnalysis -Snapshot $s) 'HPIA-MISSING').Evidence -join ' '; $e -match 'ProgramFiles' -and $e -notmatch 'HPIAPath' }
$s = Get-Base; $s.HPIA = [pscustomobject]@{ Present = $false; HPIAPathGiven = $true; Rejected = @(); Recommendations = @() }
Test-That 'HPIA absent at -HPIAPath -> evidence names only -HPIAPath (default not searched)' { $e = (Find-F (Invoke-DDAnalysis -Snapshot $s) 'HPIA-MISSING').Evidence -join ' '; $e -match 'HPIAPath' -and $e -notmatch 'ProgramFiles' }
$s = Get-Base; $s.HPIA = [pscustomobject]@{ Present = $false; Recommendations = @() }
Test-That 'older snapshot without HPIAPathGiven -> generic searched-locations evidence' { ((Find-F (Invoke-DDAnalysis -Snapshot $s) 'HPIA-MISSING').Evidence -join ' ') -eq 'No HPImageAssistant.exe in the searched locations.' }
$plan = @(Get-DDRepairPlan -Findings $a.Findings)
Test-That 'plan: RestartDevice before ScanDevices before RestartComputer' {
    $types = @($plan | ForEach-Object { $_.Type })
    $types.IndexOf('RestartDevice') -lt $types.IndexOf('ScanDevices') -and $types.IndexOf('ScanDevices') -lt $types.IndexOf('RestartComputer')
}
Test-That 'plan: RestartComputer appears once (deduplicated)' { @($plan | Where-Object { $_.Type -eq 'RestartComputer' }).Count -eq 1 }
Test-That 'plan: never contains uninstall/disable/delete actions' { @($plan | Where-Object { $_.Type -match 'Uninstall|Disable|Delete|Remove' }).Count -eq 0 }

Write-Host 'Scenario B: healthy' -ForegroundColor Cyan
$s = Get-Base
$s.PnpEvents = @(); $s.Devices = @($s.Devices | Where-Object { $_.Class -ne 'Firmware' })
$s.PendingRestart.FastStartup = $false
$s.CodeIntegrityEvents = @()
$s.DisplayTargets[0].Available = $true; $s.DisplayTargets[0].Active = $true
$b = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict Active' { $b.Verdict.State -eq 'Active' }
Test-That 'no Critical/High/Medium findings' { @($b.Findings | Where-Object { $_.Severity -in 'Critical', 'High', 'Medium' }).Count -eq 0 }
Test-That 'empty plan' { @(Get-DDRepairPlan -Findings $b.Findings).Count -eq 0 }

Write-Host 'Scenario C: panel detected but layout excludes it' -ForegroundColor Cyan
$s = Get-Base; $s.PnpEvents = @(); $s.DisplayTargets[0].Available = $true
$c = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict Inactive (VERIFIED)' { $c.Verdict.State -eq 'Inactive' -and $c.Verdict.Confidence -eq 'VERIFIED' }
Test-That 'action ExtendTopology (never internal-only)' { (Find-F $c 'INTERNAL-PANEL').Actions[0].Type -eq 'ExtendTopology' }

Write-Host 'Scenario D: internal monitor disabled' -ForegroundColor Cyan
$s = Get-Base; $s.PnpEvents = @()
$panel = $s.Devices | Where-Object { $_.InstanceId -like 'DISPLAY\CMN163B*' }; $panel.Present = $true; $panel.ProblemCode = 22
$d = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict Disabled + EnableDevice on the panel' { $d.Verdict.State -eq 'Disabled' -and (Find-F $d 'INTERNAL-PANEL').Actions[0].Type -eq 'EnableDevice' -and (Find-F $d 'INTERNAL-PANEL').Actions[0].Target -like 'DISPLAY\CMN163B*' }

Write-Host 'Scenario E: brightness 0' -ForegroundColor Cyan
$s = Get-Base; $s.PnpEvents = @(); $s.DisplayTargets[0].Available = $true; $s.DisplayTargets[0].Active = $true
$s.Brightness = @([pscustomobject]@{ InstanceName = 'DISPLAY\CMN163B\4&5423816&0&UID0_0'; CurrentBrightness = 0; Active = $true })
$e = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict BrightnessZero + SetBrightness' { $e.Verdict.State -eq 'BrightnessZero' -and (Find-F $e 'INTERNAL-PANEL').Actions[0].Type -eq 'SetBrightness' }

Write-Host 'Scenario F: GPU on Microsoft Basic Display driver' -ForegroundColor Cyan
$s = Get-Base; $s.PnpEvents = @(); ($s.Devices | Where-Object { $_.Class -eq 'Display' }).Service = 'BasicDisplay'
$f = Invoke-DDAnalysis -Snapshot $s
Test-That 'GPU Critical' { (Find-F $f "GPU:$gpuId").Severity -eq 'Critical' }
Test-That 'verdict NotDetected-GpuFault even without events' { $f.Verdict.State -eq 'NotDetected-GpuFault' }

Write-Host 'Scenario G: no GPU fault, panel missing -> points away from the driver' -ForegroundColor Cyan
$s = Get-Base; $s.PnpEvents = @()
$gg = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict NotDetected with hardware next step' { $gg.Verdict.State -eq 'NotDetected' -and $gg.Verdict.NextStep -match 'F2' }

Write-Host 'Scenario G2: GPU failed in an earlier boot, same moment the panel vanished' -ForegroundColor Cyan
$s = Get-Base; $s.Meta.LastBoot = '2026-10-01T12:00:00.0000000Z'
$g2 = Invoke-DDAnalysis -Snapshot $s
Test-That 'verdict NotDetected-GpuHistory (connected by same boot)' { $g2.Verdict.State -eq 'NotDetected-GpuHistory' -and (($g2.Verdict.Evidence -join ' ') -match 'same boot') }
Test-That 'GPU finding downgraded to Low history (not current state)' { $gf = Find-F $g2 "GPU:$gpuId"; $gf.Severity -eq 'Low' -and -not $gf.StateBased }
Test-That 'history verdict still plans GPU restart + driver steps' { $t = @((Find-F $g2 'INTERNAL-PANEL').Actions | ForEach-Object { $_.Type }); ($t -contains 'RestartDevice') -and ($t -contains 'ScanDevices') }
$s = Get-Base; $s.Meta.LastBoot = '2026-10-01T12:00:00.0000000Z'; $s.PnpEvents = @($s.PnpEvents | Where-Object { $_.Id -ne 442 })
Test-That 'without the 442 link, no driver blame (NotDetected)' { (Invoke-DDAnalysis -Snapshot $s).Verdict.State -eq 'NotDetected' }
# Review finding 2: every new monitor's 442 names the panel as last instance, so an external
# monitor's 442 in the GPU-failure boot must not be read as "panel not present".
$s = Get-Base; $s.Meta.LastBoot = '2026-10-01T12:00:00.0000000Z'
foreach ($e in @($s.PnpEvents | Where-Object { $_.Id -eq 442 })) { $e.DeviceInstanceId = 'DISPLAY\ACR0EAB\4&5423816&e&UID49' }
Test-That 'external monitor 442 in the GPU-failure boot -> no same-boot link (NotDetected)' { $x = Invoke-DDAnalysis -Snapshot $s; $x.Verdict.State -eq 'NotDetected' -and (($x.Verdict.Evidence -join ' ') -notmatch 'same boot') }

Write-Host 'Scenario H: firmware deferred for AC power' -ForegroundColor Cyan
$s = Get-Base; $s.Firmware[0].LastAttemptStatus = -1073741101
$h = Invoke-DDAnalysis -Snapshot $s
$hf = Find-FLike $h 'FIRMWARE:*'
Test-That 'firmware finding Medium + transient advice' { $hf.Severity -eq 'Medium' -and $hf.Recommendation -match 'AC adapter' }
Test-That 'device evidence shows decoded firmware status' { ((Find-F $h "DEVICE:$fwId").Evidence -join ' ') -match 'Power event: AC not connected' }
Test-That 'device interpretation follows the failed firmware status' { (Find-F $h "DEVICE:$fwId").Interpretation -match 'not applied' }

Write-Host 'Scenario I: restart requested after last boot (normal staging)' -ForegroundColor Cyan
$s = Get-Base; $s.Meta.LastBoot = '2026-08-26T12:00:00.0000000Z'
$i = Invoke-DDAnalysis -Snapshot $s
Test-That 'firmware code 14 = Medium, "has not fully restarted since"' { $fd = Find-F $i "DEVICE:$fwId"; $fd.Severity -eq 'Medium' -and (($fd.Evidence -join ' ') -match 'has not fully restarted') }

Write-Host 'Scenario J: firmware held back without consent' -ForegroundColor Cyan
$s = Get-Base; $s.Firmware[0].LastAttemptStatus = '0xC0000022'
$s.HPIA = [pscustomobject]@{ Present = $true; Recommendations = @() }
$j = Invoke-DDAnalysis -Snapshot $s
$pj = @(Get-DDRepairPlan -Findings $j.Findings)
Test-That 'no HPIA firmware install without -IncludeFirmware' { @($pj | Where-Object { $_.Type -eq 'HPIAInstall' -and $_.Target -match 'BIOS|Firmware' }).Count -eq 0 -and @($pj | Where-Object { $_.Type -eq 'Manual' -and $_.Target -eq 'firmware' }).Count -eq 1 }
$pj2 = @(Get-DDRepairPlan -Findings $j.Findings -IncludeFirmware)
Test-That 'with -IncludeFirmware the HPIA step covers BIOS/Firmware' { @($pj2 | Where-Object { $_.Type -eq 'HPIAInstall' -and $_.Target -eq 'Drivers,BIOS,Firmware' }).Count -eq 1 }

Write-Host 'Scenario S4: SEC-004 firmware power gate fails closed, and covers Windows Update' -ForegroundColor Cyan
$bat = { param($c, $st) [pscustomobject]@{ EstimatedChargeRemaining = $c; BatteryStatus = $st } }
$ac = @([pscustomobject]@{ PowerOnline = $true })
Test-That 'gate: battery query failed -> refused' { $g = Get-DDFirmwareGate -Batteries @() -BatteryStatus @() -PCSystemType 1 -QueryFailed $true; -not $g[0] -and $g[1] -match 'could not be read' }
Test-That 'gate: no battery on a mobile or unknown PC -> refused' { -not (Get-DDFirmwareGate -Batteries @() -BatteryStatus @() -PCSystemType 2 -QueryFailed $false)[0] -and -not (Get-DDFirmwareGate -Batteries @() -BatteryStatus @() -PCSystemType $null -QueryFailed $false)[0] -and -not (Get-DDFirmwareGate -Batteries @() -BatteryStatus @() -PCSystemType 8 -QueryFailed $false)[0] }
Test-That 'gate: no battery on a confirmed desktop -> allowed' { (Get-DDFirmwareGate -Batteries @() -BatteryStatus @() -PCSystemType 1 -QueryFailed $false)[0] }
Test-That 'gate: on AC at 80% -> allowed' { (Get-DDFirmwareGate -Batteries @((& $bat 80 2)) -BatteryStatus $ac -PCSystemType 2 -QueryFailed $false)[0] }
Test-That 'gate: on battery (no AC) -> refused' { $g = Get-DDFirmwareGate -Batteries @((& $bat 80 1)) -BatteryStatus @() -PCSystemType 2 -QueryFailed $false; -not $g[0] -and $g[1] -match 'AC adapter' }
Test-That 'gate: Win32_Battery charging status counts as AC when BatteryStatus is empty' { (Get-DDFirmwareGate -Batteries @((& $bat 80 6)) -BatteryStatus @() -PCSystemType 2 -QueryFailed $false)[0] }
Test-That 'gate: on AC at 30% -> refused' { $g = Get-DDFirmwareGate -Batteries @((& $bat 30 2)) -BatteryStatus $ac -PCSystemType 2 -QueryFailed $false; -not $g[0] -and $g[1] -match '30%' }
Test-That 'gate: unknown charge -> refused' { $g = Get-DDFirmwareGate -Batteries @((& $bat $null 2)) -BatteryStatus $ac -PCSystemType 2 -QueryFailed $false; -not $g[0] -and $g[1] -match 'unknown' }
Test-That 'gate: two batteries, the lower charge decides (either order)' { -not (Get-DDFirmwareGate -Batteries @((& $bat 80 2), (& $bat 40 2)) -BatteryStatus $ac -PCSystemType 2 -QueryFailed $false)[0] -and -not (Get-DDFirmwareGate -Batteries @((& $bat 40 2), (& $bat 80 2)) -BatteryStatus $ac -PCSystemType 2 -QueryFailed $false)[0] }
Test-That 'firmware detection: class in any case, or BIOS/UEFI/firmware/capsule in the title' {
    (Test-DDFirmwareUpdate -DriverClass 'firmware' -Title 'x') -and (Test-DDFirmwareUpdate -DriverClass 'Firmware' -Title 'x') -and
    (Test-DDFirmwareUpdate -DriverClass 'System' -Title 'HP Inc. - Firmware - 1.2.3') -and (Test-DDFirmwareUpdate -DriverClass '' -Title 'System BIOS update 01.02') -and
    -not (Test-DDFirmwareUpdate -DriverClass 'Display' -Title 'Intel Corporation - Display - 32.0.101.9999') -and -not (Test-DDFirmwareUpdate -DriverClass 'Net' -Title 'BIOSTAR LAN driver')
}
$s = Get-Base
$s.WindowsUpdate = [pscustomobject]@{ Searched = $true; Error = $null; Updates = @([pscustomobject]@{ UpdateId = 'fw-1'; Title = 'HP Inc. - Firmware - 01.05.00'; DriverClass = 'firmware'; DriverModel = 'System Firmware'; DriverProvider = 'HP Inc.'; DriverVerDate = '2026-09-01'; HardwareId = 'UEFI\RES_{00000000-0000-0000-0000-000000000001}' }) }
$wf = Invoke-DDAnalysis -Snapshot $s
Test-That 'WU firmware with a lowercase class is held back without -IncludeFirmware' { @(Get-DDRepairPlan -Findings $wf.Findings | Where-Object { $_.Type -eq 'InstallWindowsUpdate' -and $_.Target -eq 'fw-1' }).Count -eq 0 }
Test-That 'WU firmware is planned with -IncludeFirmware' { @(Get-DDRepairPlan -Findings $wf.Findings -IncludeFirmware | Where-Object { $_.Type -eq 'InstallWindowsUpdate' -and $_.Target -eq 'fw-1' }).Count -eq 1 }
# Repair step itself (no system access: the gate is stubbed and -WhatIf stops before Windows Update).
. (Join-Path $root 'lib\DD.Repair.ps1')
function Test-DDFirmwareSafe { $script:gateCalls++; return @($false, 'stub: on battery') }
$script:gateCalls = 0
$r1 = Invoke-DDInstallWindowsUpdate -Action (New-DDAction 'InstallWindowsUpdate' 'fw-1' 'x' $true) -Title 'HP Inc. - Firmware - 01.05.00' -WhatIf
Test-That 'WU firmware install is refused by the power gate before it asks' { $r1.Result -eq 'Skipped' -and $r1.Detail -match 'Firmware safety gate: stub' -and $script:gateCalls -eq 1 }
$r2 = Invoke-DDInstallWindowsUpdate -Action (New-DDAction 'InstallWindowsUpdate' 'u-2' 'x' $false) -Title 'System BIOS update 01.02' -WhatIf
Test-That 'WU firmware the plan did not mark is not installed' { $r2.Result -eq 'Skipped' -and $r2.Detail -match 'IncludeFirmware' }
$script:gateCalls = 0
$r3 = Invoke-DDInstallWindowsUpdate -Action (New-DDAction 'InstallWindowsUpdate' 'u-1' 'x' $false) -Title 'Intel Corporation - Display - 32.0.101.9999' -WhatIf
Test-That 'WU driver (not firmware) skips the gate and still asks first' { $r3.Result -eq 'Declined' -and $script:gateCalls -eq 0 }

Write-Host 'Scenario K: Windows Update offer connected to a faulted device' -ForegroundColor Cyan
$s = Get-Base
$s.WindowsUpdate = [pscustomobject]@{ Searched = $true; Error = $null; Updates = @([pscustomobject]@{ UpdateId = 'u-1'; Title = 'Intel Corporation - Display - 32.0.101.9999'; DriverClass = 'Display'; DriverModel = 'Intel(R) Graphics'; DriverProvider = 'Intel Corporation'; DriverVerDate = '2026-09-01'; HardwareId = 'PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C' }) }
$k = Invoke-DDAnalysis -Snapshot $s
Test-That 'update linked by hardware id -> High' { $u = Find-F $k 'WU-UPDATE:u-1'; $u.Severity -eq 'High' -and (($u.Evidence -join ' ') -match 'same hardware id') }
Test-That 'GPU actions include that exact update' { @((Find-F $k "GPU:$gpuId").Actions | Where-Object { $_.Type -eq 'InstallWindowsUpdate' -and $_.Target -eq 'u-1' }).Count -eq 1 }

Write-Host 'Before/after comparison' -ForegroundColor Cyan
$after = Invoke-DDAnalysis -Snapshot (Get-Base) -EventsSince '2026-10-03T00:00:00Z'
$cmp = Compare-DDFindings -Before $a.Findings -After $after.Findings
Test-That 'GPU failures before the repair window no longer count as current' { @($cmp.Fixed | Where-Object { $_.Id -eq "GPU:$gpuId" }).Count -eq 1 }
Test-That 'history-only findings never reported as fixed' { @($cmp.Fixed | Where-Object { -not $_.StateBased }).Count -eq 0 }

Write-Host 'Report' -ForegroundColor Cyan
$evil = Get-Base; ($evil.Devices | Where-Object { $_.Class -eq 'Display' }).Name = '<script>alert(1)</script>'
$html = ConvertTo-DDHtmlReport -Snapshot $evil -Analysis (Invoke-DDAnalysis -Snapshot $evil) -Plan @() -Mode 'Diagnose'
Test-That 'device names are HTML-encoded' { ($html -notmatch '<script>alert') -and ($html -match '&lt;script&gt;') }
Test-That 'report leads with the built-in display verdict' { $html.IndexOf('Built-in display') -lt $html.IndexOf('<h2>Findings') }
# SEC-005: severity reaches class attributes; a crafted snapshot must not break out of them.
$ea = Invoke-DDAnalysis -Snapshot (Get-Base)
$ea.Verdict.Severity = 'High" onmouseover="alert(1)'
$ef = @($ea.Findings | Where-Object { $_.Id -ne 'INTERNAL-PANEL' })[0]; $ef.Severity = '<img src=x onerror=alert(2)>'
$eh = ConvertTo-DDHtmlReport -Snapshot (Get-Base) -Analysis $ea -Plan @() -Mode 'Diagnose'
Test-That 'crafted verdict severity cannot add an attribute' { ($eh -notmatch '" onmouseover="') -and ($eh -match 'class="card Unknown"') -and ($eh -match 'High&quot; onmouseover=&quot;alert\(1\)') }
Test-That 'crafted finding severity is encoded, not markup' { ($eh -notmatch '<img src=x') -and ($eh -match '&lt;img src=x onerror=alert\(2\)&gt;') }
Test-That 'known severities keep their class names' { ($html -match 'class="card High"|class="card Medium"|class="card Low"|class="card Info"') -and (ConvertTo-DDSeverityClass 'High') -eq 'High' -and (ConvertTo-DDSeverityClass 'high') -eq 'Unknown' -and (ConvertTo-DDSeverityClass $null) -eq 'Unknown' }
Test-That 'report carries a restrictive CSP before any content' {
    $csp = [regex]::Match($html, '<meta http-equiv="Content-Security-Policy" content="([^"]+)">')
    $csp.Success -and $csp.Groups[1].Value -match "default-src 'none'" -and $csp.Groups[1].Value -notmatch 'script-src' -and
    $csp.Groups[1].Value -match "base-uri 'none'" -and $csp.Groups[1].Value -match "form-action 'none'" -and $csp.Index -lt $html.IndexOf('<title>') -and $html -notmatch '<script'
}

Write-Host 'Scenario L: live snapshot from the laptop (2026-11-06, panel working again)' -ForegroundColor Cyan
# Real Run-Diagnose output, computer name replaced. Regression guard for the first live verdict.
$liveRaw = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $fixtures 'envy-live.snapshot.json')
$liveSnap = $liveRaw | ConvertFrom-Json
$la = Invoke-DDAnalysis -Snapshot $liveSnap
$lplan = @(Get-DDRepairPlan -Findings $la.Findings)
Test-That 'live: fixture is redacted and had no collection errors' { ($liveRaw -notmatch '(?i)ENVY7') -and ($liveSnap.Meta.ComputerName -eq 'REDACTED-PC') -and (@($liveSnap.CollectionErrors).Count -eq 0) }
Test-That 'live: verdict Active, VERIFIED' { $la.Verdict.State -eq 'Active' -and $la.Verdict.Confidence -eq 'VERIFIED' }
Test-That 'live: verdict evidence = active internal path + present CMN163B panel' {
    $ev = $la.Verdict.Evidence -join "`n"
    ($ev -match 'internal connector.*active=True') -and ($ev -match 'DISPLAY\\CMN163B\\4&5423816&E&UID8388688.*present=True, problem code=0')
}
Test-That 'live: 2026-08-26 GPU failure is Low history, not a current fault' {
    $gpu = @($la.Findings | Where-Object { ($_.Evidence -join ' ') -match 'oem39\.inf' -and $_.Title -match '^GPU' })
    $gpu.Count -eq 1 -and $gpu[0].Severity -eq 'Low' -and $gpu[0].Category -eq 'History' -and -not $gpu[0].StateBased -and @($gpu[0].Actions).Count -eq 0
}
Test-That 'live: no Critical finding and no High finding about the GPU or display' { @($la.Findings | Where-Object { $_.Severity -eq 'Critical' -or ($_.Severity -eq 'High' -and $_.Category -in 'Display', 'History') -or ($_.Severity -eq 'High' -and $_.Title -match 'Graphics|DEV_7D45|Monitor') }).Count -eq 0 }
Test-That 'live: plan touches neither the display nor the GPU' { @($lplan | Where-Object { $_.Type -in 'ExtendTopology', 'EnableDevice', 'SetBrightness' -or "$($_.Target)" -match 'DEV_7D45|DISPLAY\\' }).Count -eq 0 }
Test-That 'live: plan never uninstalls, disables or deletes' { @($lplan | Where-Object { $_.Type -match 'Uninstall|Disable|Delete|Remove' }).Count -eq 0 }
Test-That 'live: un-applied firmware capsule still reported (working panel hides nothing)' { @($la.Findings | Where-Object { $_.Category -eq 'Firmware' -and $_.Severity -eq 'High' -and $_.Title -match 'F9A422C9' }).Count -eq 1 }
# Kernel-PnP 219: the live log has 8 devices x 28 events each (224 = the System log's own count).
# Equal titles are real (they fail together every boot), so pin per-device counting directly.
$is219 = { $_.Provider -eq 'Microsoft-Windows-Kernel-PnP' -and $_.Id -eq 219 }
Test-That 'live: each 219 finding counts only its own device''s events' {
    $f219 = @($la.Findings | Where-Object { $_.Id -like 'PNP219:*' })
    $ok = $f219.Count -eq 8
    foreach ($f in $f219) {
        $own = @($liveSnap.SystemEvents | Where-Object $is219 | Where-Object { $_.Message -eq $f.Evidence[0] }).Count
        if ($f.Title -ne "Driver failed to load (Kernel-PnP 219) x$own") { $ok = $false }
    }
    $ok -and @($liveSnap.SystemEvents | Where-Object $is219).Count -eq 224
}
Test-That '219: a device with fewer events gets its own count, not a shared one' {
    $m = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $fixtures 'envy-live.snapshot.json') | ConvertFrom-Json
    $face = 'The driver \Driver\WUDFRd failed to load. Device: ROOT\WINDOWSHELLOFACESOFTWAREDRIVER\0000 Status: 0xC0000365'
    $drop = @($m.SystemEvents | Where-Object $is219 | Where-Object { $_.Message -eq $face } | Select-Object -First 5)
    $m.SystemEvents = @($m.SystemEvents | Where-Object { $drop -notcontains $_ })
    $t = @((Invoke-DDAnalysis -Snapshot $m).Findings | Where-Object { $_.Id -like 'PNP219:*' })
    $faceT = @($t | Where-Object { $_.Evidence[0] -eq $face } | ForEach-Object { $_.Title })
    $restT = @($t | Where-Object { $_.Evidence[0] -ne $face } | ForEach-Object { $_.Title } | Sort-Object -Unique)
    $faceT.Count -eq 1 -and $faceT[0] -like '* x23' -and $restT.Count -eq 1 -and $restT[0] -like '* x28'
}
# Regression: the live log has 14 442s naming the panel as "last instance"; only 2 are ABOUT the panel.
Test-That 'live: verdict lists only 442s whose own device is the panel' {
    $l442 = @($la.Verdict.Evidence | Where-Object { $_ -like 'Event 442 at *' })
    $l442.Count -eq 2 -and @($l442 | Where-Object { $_ -notmatch '^Event 442 at \S+ \S+: settings for DISPLAY\\CMN163B\\' }).Count -eq 0 -and
    (($l442 -join "`n") -match [regex]::Escape((Format-DDDate '2026-08-29T18:57:54Z'))) -and (($la.Verdict.Evidence -join "`n") -notmatch 'settings for DISPLAY\\(DELD081|VIZ0301|ACR0EAB|MS_0001|Default_Monitor)')
}
# Fixture times are UTC and the report prints local time, so expected times go through Format-DDDate too.
Test-That 'live: GPU same-boot link still cites the 442 it relies on, by its own device' { ($la.Verdict.Evidence -join "`n") -match ('Connection: GPU start failure at ' + [regex]::Escape((Format-DDDate '2026-08-27T00:49:44Z')) + ' .*event 442 for DISPLAY\\Default_Monitor\\1&8713bca&0&UID0, last instance field') }

Write-Host 'Display change diagnostic' -ForegroundColor Cyan
. (Join-Path $root 'diagnostics\Get-DisplayChange.ps1')
$setupLog = @(
    '>>>  [Device Install (Hardware initiated) - PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C&REV_08\3&11583659&0&10]',
    '>>>  Section start 2026/11/06 21:14:03.512',
    '     dvi: Selected Driver: iigd_dch.inf',
    '<<<  Section end 2026/11/06 21:14:09.001',
    '<<<  [Exit status: SUCCESS]',
    '>>>  [Device Install (Hardware initiated) - USB\VID_046D&PID_C52B\5&1]',
    '>>>  Section start 2026/11/06 21:20:00.000',
    '<<<  [Exit status: SUCCESS]',
    '>>>  [Device Install (Hardware initiated) - DISPLAY\CMN163B\4&5423816&0&UID0]',
    '>>>  Section start 2026/08/01 08:00:00.000',
    '<<<  [Exit status: SUCCESS]'
)
$si = @(Get-DCSetupApiInstalls -Lines $setupLog -Since ([datetime]'2026-08-20') -Pattern @('DEV_7D45', 'CMN163B'))
Test-That 'setupapi: keeps matching installs after -Since only' { $si.Count -eq 1 -and $si[0].Text -like '*DEV_7D45*' -and $si[0].Status -eq 'SUCCESS' -and $si[0].Time -eq [datetime]'2026-11-06T21:14:03' }
Test-That 'boot type 0x1 = Fast Startup' { (Get-DCBootTypeText 'The boot type was 0x1.') -like '*Fast Startup*' }
Test-That 'boot type 0x0 = full boot' { (Get-DCBootTypeText 'The boot type was 0x0.') -like '*full boot*' }
Test-That 'event message flattens to key fields' { (ConvertTo-DCLine $m442) -match 'Present=false' -and (ConvertTo-DCLine $m442) -match 'Last Device Instance Id=DISPLAY\\CMN163B' }

$recovered = [pscustomobject]@{
    Gpus           = @([pscustomobject]@{ Name = 'Intel(R) Graphics'; InstanceId = $gpuId; Present = $true; Status = 'OK'; Problem = 0; Inf = 'oem52.inf'; Version = '32.0.101.6299'; Date = '2026-10-01' })
    Monitors       = @([pscustomobject]@{ Name = 'Generic PnP Monitor'; InstanceId = 'DISPLAY\CMN163B\4&5423816&0&UID0'; Present = $true; Status = 'OK' })
    ActiveMonitors = @([pscustomobject]@{ InstanceName = 'DISPLAY\CMN163B\4&5423816&0&UID0_0'; Name = ''; Technology = 'INTERNAL'; Internal = $true })
    Firmware       = @([pscustomobject]@{ Guid = '{F9A422C9-7892-42C3-A237-218610BFD215}'; Version = 16842752; LastAttemptVersion = 16842752; LastAttemptStatus = 0 })
    Bios           = [pscustomobject]@{ Version = 'F.10'; ReleaseDate = '2026-09-15' }
    Os             = [pscustomobject]@{ LastBoot = '2026-11-07 09:00:00' }
    FastStartup    = $true
    PnpRead        = $true
    Timeline       = @(
        [pscustomobject]@{ Time = [datetime]'2026-08-26T19:49:44'; Source = 'Kernel-PnP'; Id = 411; Text = "Device $gpuId had a problem starting." },
        [pscustomobject]@{ Time = [datetime]'2026-08-26T19:49:44'; Source = 'Kernel-PnP'; Id = 442; Text = 'Device settings for DISPLAY\Default_Monitor were not migrated | Last Device Instance Id=DISPLAY\CMN163B\4&5423816&0&UID0 | Present=false' },
        [pscustomobject]@{ Time = [datetime]'2026-11-07T09:00:05'; Source = 'Kernel-PnP'; Id = 400; Text = "Device $gpuId was configured. | Driver Name=oem52.inf" },
        [pscustomobject]@{ Time = [datetime]'2026-11-07T09:00:06'; Source = 'Kernel-PnP'; Id = 400; Text = 'Device DISPLAY\CMN163B\4&5423816&0&UID0 was configured.' },
        [pscustomobject]@{ Time = [datetime]'2026-11-07T09:00:00'; Source = 'Kernel-Boot'; Id = 27; Text = 'Boot type 0x0: full boot (cold start)' }
    )
}
$ob = @(Get-DCObservations -State $recovered) -join "`n"
Test-That 'observations: new GPU package is called out as VERIFIED' { $ob -match 'DIFFERENT package.*oem39\.inf.*VERIFIED' }
Test-That 'observations: firmware capsule reported APPLIED from registry' { $ob -match 'APPLIED' }
Test-That 'observations: active internal monitor reported' { $ob -match 'Active monitor now: DISPLAY\\CMN163B.*INTERNAL' -and $ob -notmatch 'NO active internal' }
Test-That 'observations: panel configure time reported; a Default_Monitor 442 is not a panel event' { ($ob -match 'First panel configure/start event since -Since: 2026-11-07 09:00:06') -and ($ob -notmatch 'event \(442\) for the panel') }

# Regression: shapes copied from the live DisplayChange report of 2026-11-06. Every 442 names the
# panel in "Last Device Instance ID"; only the 08-29 one is ABOUT the panel.
Test-That 'event device: 442 yields its own device, not Last Device Instance ID' { (Get-DCEventDevice 'Device settings for DISPLAY\DELD081\4&5423816&e&UID4165 were not migrated from previous OS installation due to partial or ambiguous device match. | Last Device Instance ID=DISPLAY\CMN163B\4&5423816&0&UID0 | Present=false') -eq 'DISPLAY\DELD081\4&5423816&e&UID4165' }
Test-That 'event device: 400/411 yield the configured device' { ((Get-DCEventDevice "Device $gpuId had a problem starting. | Driver Name=oem39.inf") -eq $gpuId) -and ((Get-DCEventDevice 'Device DISPLAY\CMN163B\4&5423816&e&UID8388688 was started. | Service=monitor') -eq 'DISPLAY\CMN163B\4&5423816&e&UID8388688') }
Test-That 'event device: unparsed (localized) text drops the key fields' { (Get-DCEventDevice 'Geraet X wurde konfiguriert. | Last Device Instance ID=DISPLAY\CMN163B\4&5423816&0&UID0') -notmatch 'CMN163B' }
$live = $recovered.PSObject.Copy()
$live.Timeline = @(
    [pscustomobject]@{ Time = [datetime]'2026-08-29T13:57:54.100'; Source = 'Kernel-PnP'; Id = 442; Text = 'Device settings for DISPLAY\CMN163B\4&5423816&e&UID8388688 were not migrated from previous OS installation due to partial or ambiguous device match. | Last Device Instance ID=DISPLAY\CMN163B\4&5423816&0&UID0 | Present=false | Status=0xC0000719' },
    [pscustomobject]@{ Time = [datetime]'2026-08-29T13:57:54.100'; Source = 'Kernel-PnP'; Id = 400; Text = 'Device DISPLAY\CMN163B\4&5423816&e&UID8388688 was configured. | Driver Name=monitor.inf' },
    [pscustomobject]@{ Time = [datetime]'2026-08-29T13:57:54.300'; Source = 'Kernel-PnP'; Id = 410; Text = 'Device DISPLAY\CMN163B\4&5423816&e&UID8388688 was started. | Driver Name=monitor.inf | Service=monitor' },
    [pscustomobject]@{ Time = [datetime]'2026-09-26T20:42:45'; Source = 'Kernel-PnP'; Id = 442; Text = 'Device settings for DISPLAY\VIZ0301\4&5423816&e&UID49 were not migrated from previous OS installation due to partial or ambiguous device match. | Last Device Instance ID=DISPLAY\CMN163B\4&5423816&0&UID0 | Present=false' },
    [pscustomobject]@{ Time = [datetime]'2026-10-31T16:49:38'; Source = 'Kernel-PnP'; Id = 442; Text = 'Device settings for DISPLAY\DELD081\4&5423816&e&UID4165 were not migrated from previous OS installation due to partial or ambiguous device match. | Last Device Instance ID=DISPLAY\CMN163B\4&5423816&0&UID0 | Present=false' },
    [pscustomobject]@{ Time = [datetime]'2026-10-31T16:49:38'; Source = 'Kernel-PnP'; Id = 400; Text = 'Device DISPLAY\DELD081\4&5423816&e&UID4165 was configured. | Driver Name=monitor.inf' }
)
$ob4 = @(Get-DCObservations -State $live) -join "`n"
Test-That 'regression: 442 for another monitor naming the panel as last instance is not a panel event' { ($ob4 -notmatch '2026-10-31') -and ($ob4 -notmatch '2026-09-26') }
Test-That 'regression: the panel''s own 442 is reported' { $ob4 -match 'event \(442\) for the panel device itself \(DISPLAY\\CMN163B\\4&5423816&e&UID8388688\): 2026-08-29 13:57:54' }
Test-That 'regression: panel configure in the same second as its 442 is found' { $ob4 -match 'First panel configure/start event at or after that 442: 2026-08-29 13:57:54 \(event 400' }

$still = $recovered.PSObject.Copy()
$still.Gpus = @([pscustomobject]@{ Name = 'Intel(R) Graphics'; InstanceId = $gpuId; Present = $true; Status = 'OK'; Problem = 0; Inf = 'oem39.inf'; Version = '32.0.101.5768'; Date = '2024-07-12' })
$still.Firmware = @([pscustomobject]@{ Guid = '{F9A422C9-7892-42C3-A237-218610BFD215}'; Version = 16842496; LastAttemptVersion = 16842752; LastAttemptStatus = -1073741102 })
$still.ActiveMonitors = @()
$ob2 = @(Get-DCObservations -State $still) -join "`n"
Test-That 'observations: same oem39.inf is not claimed as a new driver' { $ob2 -match 'same package name' -and $ob2 -notmatch 'DIFFERENT package' }
Test-That 'observations: un-applied capsule is not reported as applied' { $ob2 -match 'NOT applied' -and $ob2 -notmatch 'APPLIED:' }
Test-That 'observations: no active internal monitor is stated' { $ob2 -match 'NO active internal monitor' }
$unread = [pscustomobject]@{ Gpus = $null; Monitors = $null; ActiveMonitors = $null; Firmware = $null; Bios = $null; Os = $null; PnpRead = $false; Timeline = @() }
$ob3 = @(Get-DCObservations -State $unread) -join "`n"
Test-That 'observations: failed collection says NOT READ, never "none"' { ($ob3 -match 'Active monitors: NOT READ') -and ($ob3 -match 'Kernel-PnP configuration log: NOT READ') -and ($ob3 -notmatch 'NO active internal') -and ($ob3 -notmatch 'No GPU start failure') -and ($ob3 -notmatch 'Active monitor now') }

Write-Host 'End to end (offline snapshot mode)' -ForegroundColor Cyan
$out = Join-Path ([IO.Path]::GetTempPath()) ("dd-test-" + [guid]::NewGuid().ToString('N'))
$pwshExe = (Get-Process -Id $PID).Path
& $pwshExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'DriverDoctor.ps1') -SnapshotPath (Join-Path $fixtures 'envy-screenshots.snapshot.json') -OutputPath $out -NoOpen | Out-Null
Test-That 'DriverDoctor.ps1 exits 0' { $LASTEXITCODE -eq 0 }
Test-That 'report.html and findings.json written' { (Test-Path (Join-Path $out 'report.html')) -and (Test-Path (Join-Path $out 'findings.json')) }
Test-That 'findings.json verdict round-trips' { (Get-Content -Raw (Join-Path $out 'findings.json') | ConvertFrom-Json).Verdict.State -eq 'NotDetected-GpuFault' }
# The refusal is written to stderr. In 5.1, 'Stop' turns the first native stderr line into a
# terminating NativeCommandError, so relax it around this one call (see Invoke-DDNative).
$eap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & $pwshExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'DriverDoctor.ps1') -SnapshotPath (Join-Path $fixtures 'envy-screenshots.snapshot.json') -Mode Repair -OutputPath $out -NoOpen 2>$null | Out-Null }
finally { $ErrorActionPreference = $eap }
Test-That 'Repair refuses to run on a snapshot' { $LASTEXITCODE -ne 0 }

Write-Host ''
$color = if ($script:failed.Count -eq 0) { 'Green' } else { 'Red' }
Write-Host "Passed: $script:passed  Failed: $($script:failed.Count)" -ForegroundColor $color
foreach ($n in $script:failed) { Write-Host "  - $n" -ForegroundColor Red }
exit $script:failed.Count
