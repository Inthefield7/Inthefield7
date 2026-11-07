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
# NEW-5: this fixture has a staged UEFI capsule (code-14 UEFI\RES_ device), so every restart would flash
# firmware. Without -IncludeFirmware the restart is held back as a Manual note; with it the restart is
# planned once and flagged firmware so the executor runs the power gate.
$planHeld = @(Get-DDRepairPlan -Findings $a.Findings)
Test-That 'plan: with a staged capsule, no restart is planned without -IncludeFirmware (held back)' {
    @($planHeld | Where-Object { $_.Type -eq 'RestartComputer' }).Count -eq 0 -and
    @($planHeld | Where-Object { $_.Type -eq 'Manual' -and $_.Target -eq 'firmware' -and $_.Detail -match 'IncludeFirmware' }).Count -eq 1
}
$plan = @(Get-DDRepairPlan -Findings $a.Findings -IncludeFirmware)
Test-That 'plan: RestartDevice before ScanDevices before RestartComputer' {
    $types = @($plan | ForEach-Object { $_.Type })
    $types.IndexOf('RestartDevice') -lt $types.IndexOf('ScanDevices') -and $types.IndexOf('ScanDevices') -lt $types.IndexOf('RestartComputer')
}
Test-That 'plan: RestartComputer appears once (deduplicated) and is flagged firmware' { $rc = @($plan | Where-Object { $_.Type -eq 'RestartComputer' }); $rc.Count -eq 1 -and $rc[0].RequiresFirmwareConsent -eq $true }
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

Write-Host 'Scenario S2: SEC-002 HPIA work folder is administrators-only' -ForegroundColor Cyan
$ao = 'O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;OW)'
Test-That 'ACL: the tool''s own SDDL is administrators-only' { (Test-DDAdminOnlySddl $script:DDAdminOnlySddl) -and [string]::Equals($script:DDAdminOnlySddl, $ao, 'Ordinal') }
# What a file HPIA creates inside the folder looks like: owned by the user's SID, ACEs inherited.
$um = 'O:S-1-5-21-1-2-3-1001D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)'
Test-That 'ACL: a user-owned child is fine only while OWNER RIGHTS (read-only) applies to it' { (Test-DDAdminOnlySddl ($um + '(A;OICIID;0x1200a9;;;OW)')) -and -not (Test-DDAdminOnlySddl $um) -and -not (Test-DDAdminOnlySddl ($um + '(A;OICIIOID;0x1200a9;;;OW)')) }
Test-That 'ACL: OWNER RIGHTS with write access is refused' { -not (Test-DDAdminOnlySddl ($um + '(A;OICIID;FA;;;OW)')) }
# The real C:\ProgramData ACL (read on the laptop 2026-11-07): Users may create files and folders.
Test-That 'ACL: C:\ProgramData itself is not administrators-only' { -not (Test-DDAdminOnlySddl 'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)') }
Test-That 'ACL: a folder owned by a standard user is refused' { -not (Test-DDAdminOnlySddl 'O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') }
Test-That 'ACL: write for Authenticated Users or Users is refused' { -not (Test-DDAdminOnlySddl ($ao + '(A;OICI;0x1301bf;;;AU)')) -and -not (Test-DDAdminOnlySddl ($ao + '(A;;0x4;;;BU)')) }
Test-That 'ACL: read-only access for others and deny ACEs are fine' { (Test-DDAdminOnlySddl ($ao + '(A;OICI;FR;;;WD)')) -and (Test-DDAdminOnlySddl ($ao + '(D;;FA;;;WD)')) }
Test-That 'ACL: CREATOR OWNER only as inherit-only' { (Test-DDAdminOnlySddl 'O:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)') -and -not (Test-DDAdminOnlySddl 'O:SYD:PAI(A;OICI;FA;;;CO)(A;OICI;FA;;;SY)') }
Test-That 'ACL: NULL DACL, empty and unparsable descriptors are refused' { -not (Test-DDAdminOnlySddl 'O:BAD:NO_ACCESS_CONTROL') -and -not (Test-DDAdminOnlySddl '') -and -not (Test-DDAdminOnlySddl 'garbage') }
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    . (Join-Path $root 'lib\DD.Collect.ps1')
    $sroot = Join-Path ([IO.Path]::GetTempPath()) ('dd-sec002-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $sroot | Out-Null
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    try {
        $sd = Join-Path $sroot 'secure'
        New-DDSecureDirectory -Path $sd -Sddl "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$me)"
        $acl = Get-Acl -LiteralPath $sd
        Test-That 'folder gets its ACL at creation: protected, nothing inherited, only the given SIDs' {
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            $acl.AreAccessRulesProtected -and @($rules | Where-Object { $_.IsInherited }).Count -eq 0 -and
            @($rules | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique).Count -eq 3 -and
            @($rules | Where-Object { $_.IdentityReference.Value -notin 'S-1-5-18', 'S-1-5-32-544', $me }).Count -eq 0
        }
        Test-That 'an existing folder is never reused' { $threw = $false; try { New-DDSecureDirectory -Path $sd -Sddl "D:PAI(A;;FA;;;$me)" } catch { $threw = $true }; $threw }
        $plain = Join-Path $sroot 'plain'; New-Item -ItemType Directory -Path $plain | Out-Null
        Test-That 'work folder refused when the root is user-writable' { $m = ''; try { Get-DDAdminWorkDir -Root $plain | Out-Null } catch { $m = $_.Exception.Message }; $m -match 'non-administrators' -and @(Get-ChildItem -LiteralPath $plain).Count -eq 0 }
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        # Elevated: the target itself is admin-only, so only the link check can refuse it.
        $jt = Join-Path $sroot 'tgt'
        if ($elevated) { New-DDSecureDirectory $jt } else { New-Item -ItemType Directory -Path $jt | Out-Null }
        $jn = Join-Path $sroot 'lnk'; New-Item -ItemType Junction -Path $jn -Value $jt | Out-Null
        Test-That 'work folder refused when the root is a junction' { $m = ''; try { Get-DDAdminWorkDir -Root $jn | Out-Null } catch { $m = $_.Exception.Message }; $m -match 'is a link or junction' -and @(Get-ChildItem -LiteralPath $jt -Force).Count -eq 0 }
        if ($elevated) {
            $wr = Join-Path $sroot 'pd'
            $leaf = Get-DDAdminWorkDir -Root $wr
            Test-That 'elevated: fresh work folder is administrators-only, inside an administrators-only root' { $leaf -like "$wr\*" -and (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $wr).Sddl) -and (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $leaf).Sddl) }
            $leaf2 = Get-DDAdminWorkDir -Root $wr
            Test-That 'elevated: each call gets a new folder; HPIA subfolders are administrators-only' { $sub = Join-Path $leaf2 'hpia-softpaqs'; New-DDSecureDirectory $sub; $leaf2 -ne $leaf -and (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $sub).Sddl) }
            Test-That 'elevated: a file created there by plain means stays administrators-only' { $f = Join-Path $leaf2 'hpia-softpaqs\sp1.exe'; Set-Content -LiteralPath $f -Value 'x' -Encoding Ascii; Test-DDAdminOnlySddl (Get-Acl -LiteralPath $f).Sddl }
        }
        else { Write-Host '  SKIP elevated work-folder creation (not running as administrator)' -ForegroundColor Yellow }

        # Driver backup (SEC-002 residual). Every system call is stubbed; the originals come back after.
        $saved = @{}
        foreach ($n in 'Invoke-DDNative', 'New-DDRestorePoint', 'Invoke-DDScanDevices', 'Get-DDAdminWorkDir') { $saved[$n] = (Get-Item "function:$n").ScriptBlock }
        try {
            $script:nativeCalls = New-Object System.Collections.Generic.List[string]
            $script:scanCalls = 0
            function Invoke-DDNative { $script:nativeCalls.Add((@($args[1]) -join ' ')); [pscustomobject]@{ ExitCode = 0; Output = 'stub' } }   # args: file, arguments
            function New-DDRestorePoint { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')] param() $true }
            function Invoke-DDScanDevices { param($Action) $script:scanCalls++; New-DDResult $Action 'Applied' 'stub' }
            $bsnap = [pscustomobject]@{ Devices = @([pscustomobject]@{ Present = $true; ProblemCode = 0; ClassGuid = $script:DDClassGuid.Display; DriverInf = 'oem39.inf' }); WindowsUpdate = $null }
            $bplan = @(New-DDAction 'ScanDevices' 'pnp' 'x')
            function Get-DDAdminWorkDir { throw 'stub: root is a junction' }
            $br = @(Invoke-DDRepair -Plan $bplan -Snapshot $bsnap 6>$null)
            Test-That 'Repair stops before any change when there is no safe backup folder' {
                @($br | Where-Object { $_.Type -eq 'DriverBackup' -and $_.Result -eq 'Failed' -and $_.Detail -match 'stub: root is a junction' }).Count -eq 1 -and
                @($br | Where-Object { $_.Type -eq 'Repair' -and $_.Result -eq 'Stopped' }).Count -eq 1 -and $script:scanCalls -eq 0 -and $script:nativeCalls.Count -eq 0
            }
            $pb = Join-Path $sroot 'exists'; New-Item -ItemType Directory -Path $pb | Out-Null
            Test-That 'driver backup never reuses an existing folder' { $t = $false; try { Backup-DDDrivers -Devices $bsnap.Devices -Folder $pb | Out-Null } catch { $t = $true }; $t -and $script:nativeCalls.Count -eq 0 }
            if ($elevated) {
                $origWork = $saved['Get-DDAdminWorkDir']
                $pd2 = Join-Path $sroot 'pd2'
                function Get-DDAdminWorkDir { & $origWork -Root $pd2 }
                $br2 = @(Invoke-DDRepair -Plan $bplan -Snapshot $bsnap 6>$null)
                $bk = @($br2 | Where-Object { $_.Type -eq 'DriverBackup' })[0]
                Test-That 'elevated: driver backup goes to a new administrators-only folder, then the repair runs' {
                    $bk.Result -eq 'Done' -and $bk.Target -like "$pd2\*\driver-backup" -and
                    (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $bk.Target).Sddl) -and
                    (Test-DDAdminOnlySddl (Get-Acl -LiteralPath (Join-Path $bk.Target 'oem39')).Sddl) -and
                    (Test-DDAdminOnlySddl (Get-Acl -LiteralPath (Join-Path $bk.Target 'driver-store-before.txt')).Sddl) -and $script:scanCalls -eq 1
                }
                Test-That 'elevated: the driver package is exported into that folder' { @($script:nativeCalls | Where-Object { $_ -eq "/export-driver oem39.inf $(Join-Path $bk.Target 'oem39')" }).Count -eq 1 }
            }
            else { Write-Host '  SKIP elevated driver-backup folder (not running as administrator)' -ForegroundColor Yellow }
        }
        finally { foreach ($n in $saved.Keys) { Set-Item "function:$n" $saved[$n] } }
    }
    finally {
        if (Test-Path -LiteralPath $jn) { cmd /c rmdir "$jn" | Out-Null }
        Remove-Item -LiteralPath $sroot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host 'Scenario S9: NEW-9 crafted numbers never throw; NEW-7 HPIA folder chain; NEW-10 gate re-checked before install' -ForegroundColor Cyan
# NEW-9: pure.
$n9big = '0x' + ('F' * 17)
Test-That 'NEW-9: hex beyond 16 digits, a decimal beyond Int64 and a huge double convert to $null, not an exception' {
    ($null -eq (ConvertTo-DDInt $n9big)) -and ($null -eq (ConvertTo-DDInt '99999999999999999999')) -and ($null -eq (ConvertTo-DDInt '-99999999999999999999')) -and ($null -eq (ConvertTo-DDInt ([double]1e30))) -and
    ((ConvertTo-DDInt '0xE') -eq 14) -and ((ConvertTo-DDInt ' 14 ') -eq 14) -and ((ConvertTo-DDInt -1073741101) -eq 3221226195)
}
Test-That 'NEW-9: a problem code beyond Int32 is reported as undocumented, not an exception' { $pi = Get-DDProblemInfo 281474976710655; $pi.Name -eq 'CM_PROB_281474976710655' -and $pi.Action -eq 'Manual' -and (Get-DDProblemInfo 14).Name -eq 'CM_PROB_NEED_RESTART' }
$s9 = Get-Base
$s9.Devices = @($s9.Devices) + @(
    [pscustomobject]@{ Present = $true; ProblemCode = '0xFFFFFFFFFFFF'; ProblemStatus = $n9big; InstanceId = 'SWD\TESTDEV\0009'; Name = 'Crafted 1'; HardwareIds = @(); Class = 'System'; ClassGuid = ''; DriverInf = 'oem97.inf'; DriverVersion = '1'; DriverProvider = 'x' },
    [pscustomobject]@{ Present = $true; ProblemCode = '99999999999999999999'; ProblemStatus = '99999999999999999999'; InstanceId = 'SWD\TESTDEV\0010'; Name = 'Crafted 2'; HardwareIds = @(); Class = 'System'; ClassGuid = ''; DriverInf = 'oem96.inf'; DriverVersion = '1'; DriverProvider = 'x' }
)
$s9a = $null; $s9html = $null; $s9err = ''
try { $s9a = Invoke-DDAnalysis -Snapshot $s9; $s9html = ConvertTo-DDHtmlReport -Snapshot $s9 -Analysis $s9a -Plan @(Get-DDRepairPlan -Findings $s9a.Findings) -Mode 'Diagnose' } catch { $s9err = $_.Exception.Message }
Test-That 'NEW-9: a crafted snapshot goes through analysis and the report without throwing' { $s9err -eq '' -and $null -ne $s9a -and $s9html -match '<html' -and (Find-F $s9a 'DEVICE:SWD\TESTDEV\0009').Title -match 'CM_PROB_281474976710655' -and $null -eq (Find-F $s9a 'DEVICE:SWD\TESTDEV\0010') }
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    . (Join-Path $root 'lib\DD.Collect.ps1')
    . (Join-Path $root 'lib\DD.Repair.ps1')
    # NEW-7: the real Program Files roots must pass the chain check, or every HPIA would be refused.
    $n7roots = @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('ProgramFilesX86') | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
    Test-That 'NEW-7: the real Program Files roots are administrators-only with a trusted owner' { $n7roots.Count -ge 1 -and @($n7roots | Where-Object { -not (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $_).Sddl -RequireTrustedOwner) }).Count -eq 0 }
    $n7text = [IO.File]::ReadAllText((Join-Path $root 'lib\DD.Collect.ps1'))
    Test-That 'NEW-7: Find-DDHPIA checks the folder chain after the path check and before the signature' { $n7text -match '(?s)Test-DDUnderFolder -Path \$c -Roots \$roots\).*?Test-DDAdminOnlyPath -Path \$c -Root \$under.*?Get-DDHPSignatureProblem \$c' }
    $n7elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($n7elev) {
        $n7root = Join-Path ([IO.Path]::GetTempPath()) ('dd-new7-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $n7pf = Join-Path $n7roots[0] ('dd-new7-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            New-DDSecureDirectory $n7root
            $n7good = Join-Path $n7root 'HP\HPIA\bin'; New-DDSecureDirectory (Join-Path $n7root 'HP'); New-DDSecureDirectory (Join-Path $n7root 'HP\HPIA'); New-DDSecureDirectory $n7good
            $n7exe = Join-Path $n7good 'HPImageAssistant.exe'; Set-Content -LiteralPath $n7exe -Value 'x' -Encoding Ascii
            Test-That 'NEW-7: an administrators-only chain up to the root passes' { (Test-DDAdminOnlyPath -Path $n7exe -Root $n7root) -eq '' }
            $n7weak = Join-Path $n7root 'Vendor'; New-DDSecureDirectory -Path $n7weak -Sddl 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)'
            $n7weakExe = Join-Path $n7weak 'HPImageAssistant.exe'; Set-Content -LiteralPath $n7weakExe -Value 'x' -Encoding Ascii
            Test-That 'NEW-7: a user-writable folder in the chain is refused' { (Test-DDAdminOnlyPath -Path $n7weakExe -Root $n7root) -match 'Vendor can be changed by non-administrators' }
            $n7lnk = Join-Path $n7root 'Link'; New-Item -ItemType Junction -Path $n7lnk -Value $n7good | Out-Null
            Test-That 'NEW-7: a junction in the chain is refused' { (Test-DDAdminOnlyPath -Path (Join-Path $n7lnk 'HPImageAssistant.exe') -Root $n7root) -match 'Link is a link or junction' }
            $n7fileAcl = Get-Acl -LiteralPath $n7exe
            $n7fileAcl.SetAccessRuleProtection($true, $false)
            $n7fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'Allow')))
            $n7fileAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('BUILTIN\Users', 'Modify', 'Allow')))
            Set-Acl -LiteralPath $n7exe -AclObject $n7fileAcl
            Test-That 'NEW-7: an exe that users may rewrite is refused even in a good chain' { (Test-DDAdminOnlyPath -Path $n7exe -Root $n7root) -match 'HPImageAssistant\.exe can be changed by non-administrators' }
            Test-That 'NEW-7: a path outside the root is refused' { (Test-DDAdminOnlyPath -Path $n7exe -Root (Join-Path $n7root 'HP\HPIA\other')) -match 'is not under' }
            # The root itself is part of the chain: a weak root with an administrators-only subfolder is refused, naming the root.
            $n7weakRoot = Join-Path $n7root 'WeakRoot'; New-DDSecureDirectory -Path $n7weakRoot -Sddl 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)'
            $n7wrBin = Join-Path $n7weakRoot 'bin'; New-DDSecureDirectory $n7wrBin
            $n7wrExe = Join-Path $n7wrBin 'HPImageAssistant.exe'; Set-Content -LiteralPath $n7wrExe -Value 'x' -Encoding Ascii
            Test-That 'NEW-7: a user-writable root is refused even when the exe folder is administrators-only' { (Test-DDAdminOnlyPath -Path $n7wrExe -Root $n7weakRoot) -match 'WeakRoot can be changed by non-administrators' }
            # NEW-4 rule applies here too: a folder the user owns is refused even with an administrators-only-looking DACL.
            $n7owned = Join-Path $n7root 'Owned'; New-DDSecureDirectory $n7owned
            $n7me = [Security.Principal.WindowsIdentity]::GetCurrent().User
            $n7ownAcl = Get-Acl -LiteralPath $n7owned; $n7ownAcl.SetOwner($n7me); Set-Acl -LiteralPath $n7owned -AclObject $n7ownAcl
            $n7ownExe = Join-Path $n7owned 'HPImageAssistant.exe'; Set-Content -LiteralPath $n7ownExe -Value 'x' -Encoding Ascii
            Test-That 'NEW-7: a folder owned by the user is refused even with an administrators-only DACL' { (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $n7owned).Sddl) -and ((Test-DDAdminOnlyPath -Path $n7ownExe -Root $n7root) -match 'Owned can be changed by non-administrators') }
            # Wiring: a user-writable folder planted under the real Program Files is refused by Find-DDHPIA before the signature check.
            New-DDSecureDirectory $n7pf
            $n7pfWeak = Join-Path $n7pf 'weak'; New-DDSecureDirectory -Path $n7pfWeak -Sddl 'D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)'
            $n7pfExe = Join-Path $n7pfWeak 'HPImageAssistant.exe'; Set-Content -LiteralPath $n7pfExe -Value 'x' -Encoding Ascii
            $n7found = Find-DDHPIA -HPIAPath $n7pfExe 3>$null
            Test-That 'NEW-7: Find-DDHPIA refuses a user-writable folder under Program Files, before the signature check' { $null -eq $n7found.Path -and @($n7found.Rejected).Count -eq 1 -and $n7found.Rejected[0] -match 'weak can be changed by non-administrators' -and $n7found.Rejected[0] -notmatch 'Authenticode' }
        }
        finally {
            if ($n7lnk -and (Test-Path -LiteralPath $n7lnk)) { cmd /c rmdir "$n7lnk" | Out-Null }
            if (Test-Path -LiteralPath $n7root) { [IO.Directory]::Delete($n7root, $true) }
            if (Test-Path -LiteralPath $n7pf) { [IO.Directory]::Delete($n7pf, $true) }
        }
    }
    else { Write-Host '  SKIP NEW-7 folder-chain checks on real ACLs (not running as administrator)' -ForegroundColor Yellow }
    # NEW-10: the real install code paths, with the Windows Update COM session and Start-Process shadowed.
    $n10saved = @{}
    foreach ($n in 'Test-DDFirmwareSafe', 'Write-DDBitLockerWarning', 'Find-DDHPIA', 'Get-DDAdminWorkDir', 'New-DDSecureDirectory') { $n10saved[$n] = (Get-Item "function:$n").ScriptBlock }
    $n10work = Join-Path ([IO.Path]::GetTempPath()) ('dd-new10-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        function Write-DDBitLockerWarning { }
        # Gate: passes on the first call (before the prompt), fails on the second (right before the install).
        function Test-DDFirmwareSafe { $script:n10gate++; if ($script:n10gate -ge 2 -and $script:n10failSecond) { return @($false, 'stub: AC unplugged') }; return @($true, 'ok') }
        $script:n10dl = 0; $script:n10inst = 0
        $n10update = [pscustomobject]@{ DriverClass = 'Firmware'; Title = 'HP Inc. - Firmware - 1.0'; EulaAccepted = $true }
        $n10search = [pscustomobject]@{ Updates = @($n10update) }
        $n10searcher = [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name Search -Value { $script:n10search } -PassThru
        $n10dlr = [pscustomobject]@{ Updates = $null } | Add-Member -MemberType ScriptMethod -Name Download -Value { $script:n10dl++; 0 } -PassThru
        $n10installer = [pscustomobject]@{ Updates = $null } | Add-Member -MemberType ScriptMethod -Name Install -Value { $script:n10inst++; [pscustomobject]@{ ResultCode = 2; RebootRequired = $false; HResult = 0 } } -PassThru
        $script:n10session = [pscustomobject]@{} |
            Add-Member -MemberType ScriptMethod -Name CreateUpdateSearcher -Value { $script:n10searcher } -PassThru |
            Add-Member -MemberType ScriptMethod -Name CreateUpdateDownloader -Value { $script:n10dlr } -PassThru |
            Add-Member -MemberType ScriptMethod -Name CreateUpdateInstaller -Value { $script:n10installer } -PassThru
        $script:n10coll = [pscustomobject]@{} | Add-Member -MemberType ScriptMethod -Name Add -Value { 0 } -PassThru
        $script:n10search = $n10search; $script:n10searcher = $n10searcher; $script:n10dlr = $n10dlr; $script:n10installer = $n10installer
        function New-Object {
            # Test shadow of the cmdlet: hands back fake Windows Update COM objects, passes everything else through. Removed below.
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
            param([Parameter(Position = 0)][string]$TypeName, [string]$ComObject, [object[]]$ArgumentList, [switch]$Strict, $Property)
            if ($ComObject -eq 'Microsoft.Update.Session') { return $script:n10session }
            if ($ComObject -eq 'Microsoft.Update.UpdateColl') { return $script:n10coll }
            Microsoft.PowerShell.Utility\New-Object @PSBoundParameters
        }
        $n10act = New-DDAction 'InstallWindowsUpdate' 'u-1' 'x' $true
        $script:n10gate = 0; $script:n10failSecond = $true; $script:n10dl = 0; $script:n10inst = 0
        $n10r1 = Invoke-DDInstallWindowsUpdate -Action $n10act -Title 'HP Inc. - Firmware - 1.0' -Confirm:$false
        Test-That 'NEW-10: WU firmware: the gate is re-checked after the download and before the install; a failed re-check installs nothing' { $n10r1.Result -eq 'Skipped' -and $n10r1.Detail -match 're-checked before install.*AC unplugged' -and $script:n10gate -eq 2 -and $script:n10dl -eq 1 -and $script:n10inst -eq 0 }
        $script:n10gate = 0; $script:n10failSecond = $false; $script:n10dl = 0; $script:n10inst = 0
        $n10r2 = Invoke-DDInstallWindowsUpdate -Action $n10act -Title 'HP Inc. - Firmware - 1.0' -Confirm:$false
        Test-That 'NEW-10: WU firmware: both gate checks pass -> installed once' { $n10r2.Result -eq 'Applied' -and $script:n10gate -eq 2 -and $script:n10inst -eq 1 }
        Remove-Item function:New-Object
        # HPIA
        function Find-DDHPIA { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($HPIAPath) [pscustomobject]@{ Path = 'C:\fake\HPImageAssistant.exe'; Rejected = @() } }
        function Get-DDAdminWorkDir { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param($Root, $LeafSddl) New-Item -ItemType Directory -Path $n10work -Force | Out-Null; $n10work }
        function New-DDSecureDirectory { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')] [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')] param([string]$Path, [string]$Sddl) New-Item -ItemType Directory -Path $Path -Force | Out-Null }
        $script:n10sp = 0
        function Start-Process {
            # Test shadow of the cmdlet: records the call instead of running HPIA. Removed below.
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
            param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle)
            $script:n10sp++; [pscustomobject]@{ ExitCode = 0 }
        }
        $n10hp = New-DDAction 'HPIAInstall' 'Drivers,BIOS,Firmware' 'x' $true
        $script:n10gate = 0; $script:n10failSecond = $true; $script:n10sp = 0
        $n10h1 = Invoke-DDHPIAInstall -Action $n10hp -Confirm:$false
        Test-That 'NEW-10: HPIA firmware: the gate is re-checked right before HPIA runs; a failed re-check runs nothing' { $n10h1.Result -eq 'Skipped' -and $n10h1.Detail -match 're-checked before HPIA runs.*AC unplugged' -and $script:n10gate -eq 2 -and $script:n10sp -eq 0 }
        $script:n10gate = 0; $script:n10failSecond = $false; $script:n10sp = 0
        $n10h2 = Invoke-DDHPIAInstall -Action $n10hp -Confirm:$false
        Test-That 'NEW-10: HPIA firmware: both gate checks pass -> HPIA runs once' { $n10h2.Result -eq 'Applied' -and $script:n10gate -eq 2 -and $script:n10sp -eq 1 }
        $script:n10gate = 0; $script:n10failSecond = $true; $script:n10sp = 0
        $n10h3 = Invoke-DDHPIAInstall -Action (New-DDAction 'HPIAInstall' 'Drivers' 'x' $false) -Confirm:$false
        Test-That 'NEW-10: HPIA drivers only: no gate at all, HPIA runs' { $n10h3.Result -eq 'Applied' -and $script:n10gate -eq 0 -and $script:n10sp -eq 1 }
        Remove-Item function:Start-Process
    }
    finally {
        if (Test-Path function:New-Object) { Remove-Item function:New-Object }
        if (Test-Path function:Start-Process) { Remove-Item function:Start-Process }
        foreach ($n in $n10saved.Keys) { Set-Item "function:$n" $n10saved[$n] }
        Remove-Item -LiteralPath $n10work -Recurse -Force -ErrorAction SilentlyContinue
    }
}
else { Write-Host '  SKIP NEW-7/NEW-10 system-level checks (Windows only)' -ForegroundColor Yellow }

Write-Host 'Scenario S8: NEW-3 Add-Type compiles with TMP/TEMP in a fresh administrators-only folder' -ForegroundColor Cyan
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    . (Join-Path $root 'lib\DD.Collect.ps1')
    $n3same = { param($a, $b) [string]::Equals([string]$a, [string]$b, [System.StringComparison]::Ordinal) }
    $n3tmp0 = $env:TMP; $n3temp0 = $env:TEMP
    $n3saved = @{}
    foreach ($n in 'Test-DDIsAdmin', 'Get-DDAdminWorkDir') { $n3saved[$n] = (Get-Item "function:$n").ScriptBlock }
    try {
        # Not elevated: no boundary to protect; the body runs with the normal Temp and nothing is created.
        function Test-DDIsAdmin { $false }
        $script:n3calls = 0
        $n3seen = Invoke-DDWithPrivateTemp { $script:n3calls++; $env:TEMP }
        Test-That 'NEW-3: not elevated -> body runs once with the normal Temp, environment untouched' { $script:n3calls -eq 1 -and (& $n3same $n3seen $n3temp0) -and (& $n3same $env:TMP $n3tmp0) -and (& $n3same $env:TEMP $n3temp0) }
        # Elevated but no safe folder: fail closed. The body never runs, Temp is untouched, the reason propagates.
        function Test-DDIsAdmin { $true }
        function Get-DDAdminWorkDir { throw 'stub: root is a junction' }
        $script:n3calls = 0; $n3msg = ''
        try { Invoke-DDWithPrivateTemp { $script:n3calls++ } | Out-Null } catch { $n3msg = $_.Exception.Message }
        Test-That 'NEW-3: elevated with no safe folder -> body not run, Temp untouched, the error propagates' { $script:n3calls -eq 0 -and $n3msg -match 'stub: root is a junction' -and (& $n3same $env:TMP $n3tmp0) -and (& $n3same $env:TEMP $n3temp0) }
    }
    finally { foreach ($n in $n3saved.Keys) { Set-Item "function:$n" $n3saved[$n] } }
    $n3elev = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($n3elev) {
        $n3root = Join-Path ([IO.Path]::GetTempPath()) ('dd-new3-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        try {
            $n3in = Invoke-DDWithPrivateTemp -Root $n3root -Body { [pscustomobject]@{ Tmp = $env:TMP; Temp = $env:TEMP; Acl = (Get-Acl -LiteralPath $env:TEMP).Sddl; Exists = (Test-Path -LiteralPath $env:TEMP) } }
            Test-That 'NEW-3: elevated -> TMP and TEMP point at one fresh administrators-only folder during the body' { $n3in.Exists -and (& $n3same $n3in.Tmp $n3in.Temp) -and $n3in.Temp -like "$n3root\*" -and -not (& $n3same $n3in.Temp $n3temp0) -and (Test-DDAdminOnlySddl $n3in.Acl) }
            Test-That 'NEW-3: elevated -> TMP and TEMP are restored and the folder is removed afterwards' { (& $n3same $env:TMP $n3tmp0) -and (& $n3same $env:TEMP $n3temp0) -and -not (Test-Path -LiteralPath $n3in.Temp) }
            $n3thrown = $false
            try { Invoke-DDWithPrivateTemp -Root $n3root -Body { throw 'body failed' } | Out-Null } catch { $n3thrown = $true }
            Test-That 'NEW-3: a failing body still restores TMP and TEMP and removes the folder' { $n3thrown -and (& $n3same $env:TMP $n3tmp0) -and (& $n3same $env:TEMP $n3temp0) -and @(Get-ChildItem -LiteralPath $n3root -Force).Count -eq 0 }
        }
        finally { Remove-Item -LiteralPath $n3root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    else { Write-Host '  SKIP elevated private-temp folder (not running as administrator)' -ForegroundColor Yellow }
    # The tool's only compile goes through the wrapper, and the compile works through it.
    $n3text = [IO.File]::ReadAllText((Join-Path $root 'lib\DD.Collect.ps1'))
    Test-That 'NEW-3: Import-DDDisplayConfig is the only Add-Type and it runs inside Invoke-DDWithPrivateTemp' { $n3text -match '(?s)function Import-DDDisplayConfig \{.*?Invoke-DDWithPrivateTemp.*?Add-Type -TypeDefinition' -and @([regex]::Matches($n3text, 'Add-Type -')).Count -eq 1 }   # invocations only; comments also say "Add-Type"
    $n3pd = Join-Path $env:ProgramData 'DriverDoctor'; $n3pdExisted = Test-Path -LiteralPath $n3pd
    Import-DDDisplayConfig
    Test-That 'NEW-3: DisplayConfig.cs compiles through the wrapper and TMP/TEMP are back' { ($null -ne ('DriverDoctor.DisplayConfigReader' -as [type])) -and (& $n3same $env:TMP $n3tmp0) -and (& $n3same $env:TEMP $n3temp0) }
    if (-not $n3pdExisted -and (Test-Path -LiteralPath $n3pd)) { [IO.Directory]::Delete($n3pd, $true) }
}
else { Write-Host '  SKIP NEW-3 private temp (Windows only)' -ForegroundColor Yellow }

Write-Host 'Scenario S7: NEW-6 the remaining console sinks are cleaned; Bonjour lookup ignores HKCU' -ForegroundColor Cyan
$n6esc = [string][char]27; $n6bel = [string][char]7
$n6ctl = { param($x) [string]$x -match '[\p{Cc}\p{Cf}]' }
# WU title in the confirmation prompt: a real -WhatIf run in a child process, so the prompt text is what the user would see.
$n6exe = (Get-Process -Id $PID).Path
$n6script = Join-Path ([IO.Path]::GetTempPath()) ('dd-new6-wu-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
@(
    "`$dir = '$root'",
    ". (Join-Path `$dir 'lib\DD.Analysis.ps1'); . (Join-Path `$dir 'lib\DD.Report.ps1'); . (Join-Path `$dir 'lib\DD.Repair.ps1')",
    "`$t = 'Intel' + [char]27 + '[2JGPU' + [char]27 + ']0;pwned' + [char]7 + ' Display'",
    "Invoke-DDInstallWindowsUpdate -Action (New-DDAction 'InstallWindowsUpdate' 'u-1' 'x' `$false) -Title `$t -WhatIf | Out-Null"
) | Set-Content -LiteralPath $n6script -Encoding Ascii
try {
    $n6out = & $n6exe -NoProfile -ExecutionPolicy Bypass -File $n6script 2>&1 | Out-String -Width 500
    Test-That 'NEW-6: the Windows Update title is cleaned before it is shown in the prompt' { $n6out -match 'What if' -and $n6out.Contains('IntelGPU Display') -and $n6out.IndexOf([char]27) -lt 0 -and $n6out.IndexOf([char]7) -lt 0 }
}
finally { Remove-Item -LiteralPath $n6script -Force -ErrorAction SilentlyContinue }
# Test-BonjourLsa.ps1: dot-sourcing stops at its guard, so only its functions and roots load.
. (Join-Path $root 'diagnostics\Test-BonjourLsa.ps1')
$blText = [IO.File]::ReadAllText((Join-Path $root 'diagnostics\Test-BonjourLsa.ps1'))
Test-That 'NEW-6: Bonjour lookup reads only machine-wide (HKLM) uninstall keys, never HKCU' {
    @($script:BLUninstallRoots).Count -eq 2 -and @($script:BLUninstallRoots | Where-Object { $_ -notmatch '^HKLM:' }).Count -eq 0 -and
    $blText -notmatch 'HKCU:' -and $blText -match 'foreach \(\$r in \$script:BLUninstallRoots\)'
}
$blApps = @(
    [pscustomobject]@{ Name = ('Bonjour' + $n6esc + '[2J' + $n6esc + ']0;pwned' + $n6bel); Version = ('3.1' + "`r" + 'FAKE'); Publisher = 'Apple Inc.'; InstallDate = '20260101' },
    [pscustomobject]@{ Name = ('iTunes' + [char]0x202E + 'senutI'); Version = '12'; Publisher = 'Apple Inc.'; InstallDate = '20260101' }
)
$blLines = @(Get-BLInstallerLines -Apps $blApps)
Test-That 'NEW-6: installer lines are cleaned (escape, OSC title, CR, bidi) and keep the facts' {
    $j = $blLines -join "`n"
    -not (& $n6ctl ($blLines -join '')) -and $j -match 'Bonjour 3\.1 FAKE \(Apple Inc\.\), installed 20260101' -and $j -match 'same install date: iTunessenutI 12' -and $j -match 'known Bonjour user: iTunessenutI 12'
}
Test-That 'NEW-6: no Bonjour entry -> one plain line' { $l = @(Get-BLInstallerLines -Apps @([pscustomobject]@{ Name = 'Foo'; Version = '1'; Publisher = 'x'; InstallDate = '1' })); $l.Count -eq 1 -and $l[0] -match 'No "Bonjour" entry' }
$wc = @(Write-Check 'test' $true ('ver 1' + $n6esc + '[31m; signer: CN=' + $n6esc + ']2;pwned' + $n6bel + 'Evil' + "`r" + 'HP Inc.') 6>&1 | ForEach-Object { [string]$_ })
Test-That 'NEW-6: Write-Check detail (certificate subject, event text) is cleaned' { -not (& $n6ctl ($wc -join '')) -and (($wc -join "`n") -match 'ver 1; signer: CN=Evil HP Inc\.') }
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    . (Join-Path $root 'lib\DD.Collect.ps1')
    . (Join-Path $root 'lib\DD.Repair.ps1')
    # HPIA rejection warning: a real file whose name carries a bidi override (NTFS allows it) outside Program Files.
    $n6hp = Join-Path ([IO.Path]::GetTempPath()) ('dd-new6-' + [char]0x202E + 'HPIA-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.exe')
    $n6saved = @{}
    foreach ($n in 'Invoke-DDNative', 'New-DDSecureDirectory') { $n6saved[$n] = (Get-Item "function:$n").ScriptBlock }
    $n6bk = Join-Path ([IO.Path]::GetTempPath()) ('dd-new6-bk-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        Set-Content -LiteralPath $n6hp -Value 'x' -Encoding Ascii
        $hw = @(Find-DDHPIA -HPIAPath $n6hp 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        Test-That 'NEW-6: the HPIA rejection warning is cleaned (bidi override removed, reason kept)' { $hw.Count -ge 1 -and $hw[0].Message -match 'Not running HP Image Assistant: .*HPIA-.*not under Program Files' -and -not (& $n6ctl $hw[0].Message) }
        # pnputil export failure: the native tool's text is cleaned in the warning.
        function Invoke-DDNative { if (@($args[1])[0] -eq '/export-driver') { [pscustomobject]@{ ExitCode = 1; Output = ('Access' + [char]27 + '[31m denied' + "`r" + 'FAKE OK') } } else { [pscustomobject]@{ ExitCode = 0; Output = 'stub' } } }
        function New-DDSecureDirectory { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')] param([string]$Path) New-Item -ItemType Directory -Path $Path | Out-Null }
        $bw = @(Backup-DDDrivers -Devices @([pscustomobject]@{ DriverInf = 'oem39.inf' }) -Folder $n6bk 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        Test-That 'NEW-6: the pnputil export warning is cleaned (color code removed, CR cannot overwrite the line)' { $bw.Count -eq 1 -and $bw[0].Message -match '^Could not export oem39\.inf: Access denied FAKE OK' -and -not (& $n6ctl $bw[0].Message) }
    }
    finally {
        foreach ($n in $n6saved.Keys) { Set-Item "function:$n" $n6saved[$n] }
        Remove-Item -LiteralPath $n6hp -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $n6bk -Recurse -Force -ErrorAction SilentlyContinue
    }
}
else { Write-Host '  SKIP HPIA and pnputil warning sinks (Windows only)' -ForegroundColor Yellow }

Write-Host 'Scenario S6: NEW-5 a restart that flashes staged firmware is power-gated' -ForegroundColor Cyan
# Analysis marks restart actions firmware when a capsule would flash on the next restart.
# The base fixture has a code-14 UEFI capsule device (UEFI\RES_{F9A422C9...}), so a staged capsule is present.
$s6base = Invoke-DDAnalysis -Snapshot (Get-Base)
$s6devFw = Find-F $s6base "DEVICE:$fwId"
Test-That 'NEW-5: a staged code-14 firmware (UEFI capsule) device restart is marked firmware' {
    $r = @($s6devFw.Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $true
}
# A firmware resource with a transient (retry-on-restart) status produces a retry-restart; it is firmware.
$s6retry = Get-Base
$s6retry.Firmware = @([pscustomobject]@{ Guid = '{abcdabcd-0000-0000-0000-000000000abc}'; Version = 1; LastAttemptVersion = 2; LastAttemptStatus = -1073741101 })
$s6ra = Invoke-DDAnalysis -Snapshot $s6retry
$s6fwFinding = Find-FLike $s6ra 'FIRMWARE:*'
Test-That 'NEW-5: the staged-firmware retry restart is marked firmware' {
    $r = @($s6fwFinding.Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $true
}
# With no capsule staged, a plain code-14 restart is NOT firmware (firmware-staged is a per-snapshot flag).
$s6clean = Get-Base
$s6clean.Firmware = @()
$s6clean.Devices = @($s6clean.Devices | Where-Object { ([string]$_.InstanceId) -notlike 'UEFI\RES_*' }) +
@([pscustomobject]@{ Present = $true; ProblemCode = 14; ProblemStatus = 0; InstanceId = 'SWD\TESTDEV\0001'; Name = 'Test device'; HardwareIds = @(); Class = 'System'; ClassGuid = ''; DriverInf = 'oem99.inf'; DriverVersion = '1.0'; DriverProvider = 'Test' })
$s6ca = Invoke-DDAnalysis -Snapshot $s6clean
$s6devPlain = Find-F $s6ca 'DEVICE:SWD\TESTDEV\0001'
Test-That 'NEW-5: a non-firmware code-14 restart is not marked firmware when no capsule is staged' {
    $r = @($s6devPlain.Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $false
}
# Plan: a firmware restart is held back without -IncludeFirmware, and flagged firmware with it.
$s6fwR = New-DDFinding -Id 'T-FW' -Severity 'Medium' -Category 'Firmware' -Title 't' -Evidence @('e') -Interpretation 'i' -Confidence 'VERIFIED' -Recommendation 'r' -Actions @(New-DDAction 'RestartComputer' '' 'Full restart to retry the staged firmware update.' $true) -StateBased $true
$s6plR = New-DDFinding -Id 'T-PLAIN' -Severity 'Medium' -Category 'Restart' -Title 't' -Evidence @('e') -Interpretation 'i' -Confidence 'VERIFIED' -Recommendation 'r' -Actions @(New-DDAction 'RestartComputer' '' 'Full restart.' $false) -StateBased $true
Test-That 'NEW-5: a firmware restart is held back from the plan without -IncludeFirmware' { @(Get-DDRepairPlan -Findings @($s6fwR) | Where-Object { $_.Type -eq 'RestartComputer' }).Count -eq 0 }
Test-That 'NEW-5: with -IncludeFirmware the restart is planned and the item is flagged firmware' { $it = @(Get-DDRepairPlan -Findings @($s6fwR) -IncludeFirmware | Where-Object { $_.Type -eq 'RestartComputer' }); $it.Count -eq 1 -and $it[0].RequiresFirmwareConsent -eq $true }
Test-That 'NEW-5: a non-firmware restart is planned without -IncludeFirmware and is not flagged firmware' { $it = @(Get-DDRepairPlan -Findings @($s6plR) | Where-Object { $_.Type -eq 'RestartComputer' }); $it.Count -eq 1 -and $it[0].RequiresFirmwareConsent -eq $false }
# A capsule staged only as a retry-pending firmware resource (no code-14 UEFI device) still makes every restart firmware.
$s6tr = Get-Base
$s6tr.Firmware = @([pscustomobject]@{ Guid = '{abcdabcd-0000-0000-0000-000000000abc}'; Version = 1; LastAttemptVersion = 2; LastAttemptStatus = -1073741101 })
$s6tr.Devices = @($s6tr.Devices | Where-Object { ([string]$_.InstanceId) -notlike 'UEFI\RES_*' }) +
@([pscustomobject]@{ Present = $true; ProblemCode = 14; ProblemStatus = 0; InstanceId = 'SWD\TESTDEV\0002'; Name = 'Test device'; HardwareIds = @(); Class = 'System'; ClassGuid = ''; DriverInf = 'oem98.inf'; DriverVersion = '1.0'; DriverProvider = 'Test' })
$s6ta = Invoke-DDAnalysis -Snapshot $s6tr
Test-That 'NEW-5: with only a retry-pending firmware resource staged, an unrelated code-14 restart is firmware too' {
    $r = @((Find-F $s6ta 'DEVICE:SWD\TESTDEV\0002').Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $true
}
# The pending-restart finding's restart follows the same flag: firmware while a capsule is staged, plain otherwise.
$s6pr = Get-Base
$s6pr.PendingRestart = [pscustomobject]@{ ComponentServicing = $true; WindowsUpdate = $false; FileRename = $false; FastStartup = $false }
$s6pa = Invoke-DDAnalysis -Snapshot $s6pr
Test-That 'NEW-5: the pending-restart action is firmware while a capsule is staged' {
    $r = @((Find-F $s6pa 'PENDING-RESTART').Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $true
}
$s6prc = Get-Base
$s6prc.Firmware = @()
$s6prc.Devices = @($s6prc.Devices | Where-Object { ([string]$_.InstanceId) -notlike 'UEFI\RES_*' })
$s6prc.PendingRestart = [pscustomobject]@{ ComponentServicing = $true; WindowsUpdate = $false; FileRename = $false; FastStartup = $false }
$s6pca = Invoke-DDAnalysis -Snapshot $s6prc
Test-That 'NEW-5: the pending-restart action is not firmware when no capsule is staged' {
    $r = @((Find-F $s6pca 'PENDING-RESTART').Actions | Where-Object { $_.Type -eq 'RestartComputer' })[0]
    $null -ne $r -and $r.RequiresFirmwareConsent -eq $false
}
# Merged restart items: a plain restart planned first must still end up flagged when a firmware restart joins it.
$s6plHigh = New-DDFinding -Id 'T-PLAIN-HIGH' -Severity 'High' -Category 'Restart' -Title 't' -Evidence @('e') -Interpretation 'i' -Confidence 'VERIFIED' -Recommendation 'r' -Actions @(New-DDAction 'RestartComputer' '' 'Full restart.' $false) -StateBased $true
Test-That 'NEW-5: merged restart items keep the firmware flag when a later firmware restart joins a plain one' {
    $it = @(Get-DDRepairPlan -Findings @($s6plHigh, $s6fwR) -IncludeFirmware | Where-Object { $_.Type -eq 'RestartComputer' })
    $it.Count -eq 1 -and $it[0].RequiresFirmwareConsent -eq $true -and @($it[0].Reasons).Count -eq 2
}
# The executor's decision is a pure helper, so DriverDoctor.ps1 only passes its result through.
Test-That 'NEW-5: Test-DDPlanNeedsFirmwareRestart is true only when a planned restart is flagged firmware' {
    (Test-DDPlanNeedsFirmwareRestart -Plan @(Get-DDRepairPlan -Findings @($s6fwR) -IncludeFirmware)) -and
    -not (Test-DDPlanNeedsFirmwareRestart -Plan @(Get-DDRepairPlan -Findings @($s6plR))) -and
    -not (Test-DDPlanNeedsFirmwareRestart -Plan @()) -and
    -not (Test-DDPlanNeedsFirmwareRestart -Plan @(Get-DDRepairPlan -Findings @($s6fwR)))
}
# Executor: Invoke-DDRestartComputer runs Test-DDFirmwareSafe before shutdown /r only for a firmware restart.
. (Join-Path $root 'lib\DD.Repair.ps1')
$s6saved = @{}
foreach ($n in 'Test-DDFirmwareSafe', 'Invoke-DDNative', 'Write-DDBitLockerWarning') { $s6saved[$n] = (Get-Item "function:$n").ScriptBlock }
try {
    $script:nativeCalls = New-Object System.Collections.Generic.List[string]
    $script:gateCalls = 0
    function Invoke-DDNative { $script:nativeCalls.Add((@($args[1]) -join ' ')); [pscustomobject]@{ ExitCode = 0; Output = 'stub' } }
    function Write-DDBitLockerWarning { }
    $s6act = New-DDAction 'RestartComputer' '' 'Full restart'
    function Test-DDFirmwareSafe { $script:gateCalls++; return @($false, 'stub: on battery') }
    $script:gateCalls = 0; $script:nativeCalls.Clear()
    $s6g1 = Invoke-DDRestartComputer -Action $s6act -AllowRestart -Firmware -Confirm:$false
    Test-That 'NEW-5: a firmware restart is refused by the power gate; no shutdown is scheduled' {
        $s6g1.Result -eq 'Skipped' -and $s6g1.Detail -match 'Firmware safety gate: stub' -and $script:gateCalls -eq 1 -and $script:nativeCalls.Count -eq 0
    }
    function Test-DDFirmwareSafe { $script:gateCalls++; return @($true, 'ok') }
    $script:gateCalls = 0; $script:nativeCalls.Clear()
    $s6g2 = Invoke-DDRestartComputer -Action $s6act -AllowRestart -Firmware -Confirm:$false
    Test-That 'NEW-5: a firmware restart that passes the gate schedules shutdown /r' {
        $s6g2.Result -eq 'Scheduled' -and $script:gateCalls -eq 1 -and @($script:nativeCalls | Where-Object { $_ -match '^/r ' }).Count -eq 1
    }
    function Test-DDFirmwareSafe { $script:gateCalls++; return @($false, 'should not be called') }
    $script:gateCalls = 0; $script:nativeCalls.Clear()
    $s6g3 = Invoke-DDRestartComputer -Action $s6act -AllowRestart -Confirm:$false
    Test-That 'NEW-5: a non-firmware restart skips the gate and schedules shutdown /r' {
        $s6g3.Result -eq 'Scheduled' -and $script:gateCalls -eq 0 -and @($script:nativeCalls | Where-Object { $_ -match '^/r ' }).Count -eq 1
    }
    $script:gateCalls = 0; $script:nativeCalls.Clear()
    $s6g4 = Invoke-DDRestartComputer -Action $s6act -Firmware
    Test-That 'NEW-5: a firmware restart without -AllowRestart is only advised; the gate and shutdown never run' {
        $s6g4.Result -eq 'Advised' -and $script:gateCalls -eq 0 -and $script:nativeCalls.Count -eq 0
    }
}
finally { foreach ($n in $s6saved.Keys) { Set-Item "function:$n" $s6saved[$n] } }

function Invoke-DDOffline {
    # Runs DriverDoctor.ps1 on the screenshot snapshot in a child process. Not elevated: -OutputPath
    # points at a temp folder. Elevated: no -OutputPath (it is refused), the folder is read from the
    # "Output:" line; Remove-DDOfflineOutput deletes it (and %ProgramData%\DriverDoctor if the run made it).
    param([string[]]$ExtraArgs = @())   # not $Args: that is an automatic variable and would not bind
    $elev = ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $pdRoot = if ($env:ProgramData) { Join-Path $env:ProgramData 'DriverDoctor' } else { '' }
    $rootExisted = $pdRoot -and (Test-Path -LiteralPath $pdRoot)
    $dir = Join-Path ([IO.Path]::GetTempPath()) ("dd-test-" + [guid]::NewGuid().ToString('N'))
    $all = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $root 'DriverDoctor.ps1'), '-SnapshotPath', (Join-Path $fixtures 'envy-screenshots.snapshot.json'), '-NoOpen') + $ExtraArgs
    if (-not $elev -and ($ExtraArgs -notcontains '-OutputPath')) { $all += @('-OutputPath', $dir) }
    $errFile = Join-Path ([IO.Path]::GetTempPath()) ("dd-err-" + [guid]::NewGuid().ToString('N') + '.txt')
    # Stderr goes to a file: in 5.1, 'Stop' turns the first native stderr line into a terminating error.
    $p = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $all -Wait -PassThru -NoNewWindow -RedirectStandardError $errFile -RedirectStandardOutput ($errFile + '.out')
    $out = [IO.File]::ReadAllText($errFile + '.out'); $err = [IO.File]::ReadAllText($errFile)
    Remove-Item -LiteralPath $errFile, ($errFile + '.out') -Force -ErrorAction SilentlyContinue
    if ($elev) { $m = [regex]::Match($out, '(?m)^Output: (.+?)\s*$'); $dir = if ($m.Success) { $m.Groups[1].Value } else { '' } }
    # Both hosts wrap a long error message when stderr is a file (pwsh adds "|" margins), so matches
    # run against a one-line copy.
    $errFlat = ($err -replace '[\r\n]+\s*\|?\s*', ' ') -replace '\s{2,}', ' '
    return [pscustomobject]@{ Exit = $p.ExitCode; Out = $out; Err = $err; ErrFlat = $errFlat; Dir = $dir; Elevated = $elev; RootExisted = $rootExisted; PdRoot = $pdRoot }
}
function Remove-DDOfflineOutput {
    # .NET delete: Remove-Item -Recurse on 5.1 sometimes leaves the folder behind ("directory not empty").
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param($Run)
    if ($Run.Dir -and (Test-Path -LiteralPath $Run.Dir)) { try { [IO.Directory]::Delete($Run.Dir, $true) } catch { Write-Host "  (cleanup: could not delete $($Run.Dir): $($_.Exception.Message))" -ForegroundColor Yellow } }
    if ($Run.Elevated -and -not $Run.RootExisted -and $Run.PdRoot -and (Test-Path -LiteralPath $Run.PdRoot) -and @(Get-ChildItem -LiteralPath $Run.PdRoot -Force).Count -eq 0) { try { [IO.Directory]::Delete($Run.PdRoot) } catch { Write-Host "  (cleanup: could not delete $($Run.PdRoot))" -ForegroundColor Yellow } }
}

Write-Host 'Scenario S5: NEW-1/2/4 elevated output and report opening' -ForegroundColor Cyan
$uo = 'O:S-1-5-21-1-2-3-1001D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;OW)'
Test-That 'NEW-4: a user-owned root is refused even with an administrators-only-looking DACL' { (Test-DDAdminOnlySddl $uo) -and -not (Test-DDAdminOnlySddl $uo -RequireTrustedOwner) -and (Test-DDAdminOnlySddl $script:DDAdminOnlySddl -RequireTrustedOwner) }
$ddText = [IO.File]::ReadAllText((Join-Path $root 'DriverDoctor.ps1'))
Test-That 'NEW-1: the report is opened only on the non-elevated branch' {
    @([regex]::Matches($ddText, 'Start-Process \$reportPath')).Count -eq 1 -and $ddText -match 'if \(\$elevated\) \{ Write-Host ''It is not opened automatically from an administrator window[^\r\n]*\r?\n\s*elseif \(-not \$NoOpen -and \$onWindows\) \{ & \{ \$WhatIfPreference = \$false; Start-Process \$reportPath \} \}'
}
if (($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    . (Join-Path $root 'lib\DD.Collect.ps1')
    $s5 = Join-Path ([IO.Path]::GetTempPath()) ('dd-new2-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $s5 | Out-Null
    $me5 = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    try {
        $od = Get-DDElevatedOutputDir -Root (Join-Path $s5 'pd')
        $oacl = Get-Acl -LiteralPath $od
        $mine = @($oacl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq $me5 })
        Test-That 'elevated: output folder is administrators-only, and the user may only read it' {
            (Test-DDAdminOnlySddl $oacl.Sddl) -and $mine.Count -eq 1 -and $mine[0].AccessControlType -eq 'Allow' -and
            ([int]$mine[0].FileSystemRights -band (0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000)) -eq 0 -and ([int]$mine[0].FileSystemRights -band 0x1) -ne 0
        }
        $uroot = Join-Path $s5 'userroot'
        New-DDSecureDirectory -Path $uroot -Sddl "O:$($me5)D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;OW)"
        Test-That 'elevated: work-folder root owned by the user is refused (NEW-4)' { $m = ''; try { Get-DDAdminWorkDir -Root $uroot | Out-Null } catch { $m = $_.Exception.Message }; $m -match 'non-administrators' -and @(Get-ChildItem -LiteralPath $uroot -Force).Count -eq 0 }
        # End to end, elevated: -OutputPath is refused before anything is written, even an empty new folder.
        $pre = Join-Path $s5 'chosen'
        $r5 = Invoke-DDOffline -ExtraArgs @('-OutputPath', $pre)
        Test-That 'elevated: DriverDoctor refuses -OutputPath and writes nothing' { $r5.Exit -ne 0 -and $r5.ErrFlat -match 'not accepted when running as administrator' -and -not (Test-Path -LiteralPath $pre) }
        # End to end, elevated, default: a new administrators-only folder under %ProgramData%\DriverDoctor.
        $r6 = Invoke-DDOffline
        Test-That 'elevated: DriverDoctor writes the report into a new administrators-only ProgramData folder and does not open it' {
            $r6.Exit -eq 0 -and $r6.Dir -like (Join-Path $env:ProgramData 'DriverDoctor\*') -and (Test-Path -LiteralPath (Join-Path $r6.Dir 'report.html')) -and
            (Test-DDAdminOnlySddl (Get-Acl -LiteralPath $r6.Dir).Sddl) -and $r6.Out -match 'not opened automatically'
        }
        Remove-DDOfflineOutput $r6
        $dcText = [IO.File]::ReadAllText((Join-Path $root 'diagnostics\Get-DisplayChange.ps1'))
        Test-That 'Get-DisplayChange refuses -OutputPath when elevated, before collecting' { $dcText -match '(?s)if \(\$isAdmin -and \$OutputPath\) \{ throw ''-OutputPath is not accepted.*?Invoke-DCStep ''System info''' }
    }
    finally { Remove-Item -LiteralPath $s5 -Recurse -Force -ErrorAction SilentlyContinue }
}
else { Write-Host '  SKIP elevated output-folder tests (not running as administrator)' -ForegroundColor Yellow }

Write-Host 'Scenario S3: SEC-003 launchers pass their own path safely' -ForegroundColor Cyan
foreach ($ln in 'Run-Diagnose.cmd', 'Run-Repair.cmd') {
    $lt = [IO.File]::ReadAllText((Join-Path $root $ln))
    Test-That "${ln}: path goes through DD_SELF, never inside PowerShell quotes" {
        $lt.Contains('set "DD_SELF=%~f0"') -and $lt.Contains('Start-Process -FilePath $env:DD_SELF -Verb RunAs') -and -not $lt.Contains("'%~f0'")
    }
    Test-That "${ln}: CRLF line endings and ASCII only" { $lt -notmatch '(?<!\r)\n' -and $lt -notmatch '[^\x00-\x7F]' }
}
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
    # Runs the real elevation block with two swaps: the admin check always fails (so the block runs)
    # and Start-Process becomes a file write of the path PowerShell received. Each swap must match
    # exactly once, so a changed launcher fails here instead of passing untested.
    $ldir = Join-Path ([IO.Path]::GetTempPath()) ("dd-sec003 it's `$(x) & (1);" + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Path $ldir | Out-Null
    try {
        $lt = [IO.File]::ReadAllText((Join-Path $root 'Run-Repair.cmd'))
        $swaps = @(
            @('fltmc >nul 2>&1 ||', 'cmd /c exit 1 ||'),
            @('Start-Process -FilePath $env:DD_SELF -Verb RunAs', '[IO.File]::WriteAllText($env:DD_OUT, $env:DD_SELF)')
        )
        $swapOk = $true
        foreach ($sw in $swaps) {
            if (([regex]::Matches($lt, [regex]::Escape($sw[0]))).Count -ne 1) { $swapOk = $false }
            $lt = $lt.Replace($sw[0], $sw[1])
        }
        $lpath = Join-Path $ldir 'Run-Repair.cmd'
        [IO.File]::WriteAllText($lpath, $lt, (New-Object System.Text.ASCIIEncoding))
        $env:DD_OUT = Join-Path $ldir 'received.txt'
        $p = Start-Process -FilePath 'cmd.exe' -ArgumentList ('/d /s /c ""' + $lpath + '""') -Wait -PassThru -WindowStyle Hidden
        $got = if (Test-Path -LiteralPath $env:DD_OUT) { [IO.File]::ReadAllText($env:DD_OUT) } else { '<nothing>' }
        Test-That "elevation hands PowerShell the exact path, even with ' `$ & ( ) ; in the folder name (got: $got)" {
            $swapOk -and $p.ExitCode -eq 0 -and [string]::Equals($got, $lpath, 'OrdinalIgnoreCase')
        }
    }
    finally {
        Remove-Item Env:\DD_OUT -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ldir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

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
# SEC-006: console output must not carry escape sequences or control characters from snapshot strings.
$esc = [string][char]27; $bel = [string][char]7
$hasCtl = { param($x) [string]$x -match '[\p{Cc}\p{Cf}]' }
# Ordinal comparison: PowerShell's -eq is culture-aware and can ignore invisible format characters.
$same = { param($a, $b) [string]::Equals([string]$a, [string]$b, [System.StringComparison]::Ordinal) }
Test-That 'console text: CSI clear-screen, cursor move and color removed, text kept' { & $same (ConvertTo-DDConsoleText ("Intel" + $esc + "[2J" + $esc + "[1;1H" + $esc + "[31;1mGPU" + $esc + "[0m")) 'IntelGPU' }
Test-That 'console text: OSC window title (BEL and ST forms) removed' { (& $same (ConvertTo-DDConsoleText ("A" + $esc + "]0;pwned" + $bel + "B")) 'AB') -and (& $same (ConvertTo-DDConsoleText ("A" + $esc + "]2;pwned" + $esc + "\B")) 'AB') }
Test-That 'console text: 8-bit CSI, lone ESC, NUL, DEL and C1 removed' { $o = ConvertTo-DDConsoleText ("a" + [char]0x9B + "2Jb" + $esc + "c" + [char]0 + "d" + [char]0x7F + [char]0x85 + "e"); (& $same $o 'abde') -and -not (& $hasCtl $o) }
Test-That 'console text: carriage return and newline cannot overwrite or split a line' { & $same (ConvertTo-DDConsoleText ("Display OK`rFAKE: all good`nnext")) 'Display OK FAKE: all good next' }
Test-That 'console text: bidi overrides removed; plain and empty text unchanged' { (& $same (ConvertTo-DDConsoleText ("abc" + [char]0x202E + "fed" + [char]0x2066 + [char]0x200F)) 'abcfed') -and (& $same (ConvertTo-DDConsoleText 'Intel(R) Graphics - 32.0.101.6733') 'Intel(R) Graphics - 32.0.101.6733') -and (& $same (ConvertTo-DDConsoleText $null) '') }
$ca = Invoke-DDAnalysis -Snapshot (Get-Base)
$cf = @($ca.Findings | Where-Object { $_.Id -ne 'INTERNAL-PANEL' -and $_.Severity -ne 'Info' })[0]
$cf.Title = 'Evil' + $esc + '[2J' + $esc + ']0;owned' + $bel + "`rspoof"
$ca.Verdict.Summary = 'Sum' + $esc + '[31mmary'
$cs = @(Write-DDConsoleSummary -Analysis $ca 6>&1 | ForEach-Object { [string]$_ })
Test-That 'console summary prints no control characters, keeps the text' { $cs.Count -gt 3 -and @($cs | Where-Object { & $hasCtl $_ }).Count -eq 0 -and (($cs -join "`n") -match 'Evil spoof') -and (($cs -join "`n") -match 'Summary') }
$ca.Verdict.Severity = 'Bogus'; $cf.Severity = 'Bogus'
Test-That 'console summary survives an unknown severity (no null color)' { @(Write-DDConsoleSummary -Analysis $ca 6>&1).Count -gt 3 }
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
# NEW-6: the observation lines reach the console through Write-DCObservations, which cleans them.
$dcSt = [pscustomobject]@{
    Gpus           = @([pscustomobject]@{ Name = ('Intel' + $n6esc + '[2J' + $n6bel + 'GPU'); InstanceId = $gpuId; Present = $true; Status = 'OK'; Problem = 0; Inf = 'oem39.inf'; Version = '1'; Date = '2026-10-01' })
    Monitors       = @()
    ActiveMonitors = @()
    Firmware       = @()
    Bios           = [pscustomobject]@{ Version = 'F.10'; ReleaseDate = '2026-09-15' }
    Os             = [pscustomobject]@{ LastBoot = '2026-11-07 09:00:00' }
    FastStartup    = $false
    PnpRead        = $true
    Timeline       = @()
}
$dcOut = @(Write-DCObservations -State $dcSt 6>&1 | ForEach-Object { [string]$_ })
Test-That 'NEW-6: observation lines are cleaned before they reach the console' { $dcOut.Count -ge 1 -and -not (& $n6ctl ($dcOut -join '')) -and (($dcOut -join "`n") -match "GPU 'IntelGPU': status OK") }
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
$e2e = Invoke-DDOffline
$out = $e2e.Dir
Test-That 'DriverDoctor.ps1 exits 0' { $e2e.Exit -eq 0 }
Test-That 'report.html and findings.json written' { $out -and (Test-Path (Join-Path $out 'report.html')) -and (Test-Path (Join-Path $out 'findings.json')) }
Test-That 'findings.json verdict round-trips' { $out -and (Get-Content -Raw (Join-Path $out 'findings.json') | ConvertFrom-Json).Verdict.State -eq 'NotDetected-GpuFault' }
Remove-DDOfflineOutput $e2e
$e2r = Invoke-DDOffline -ExtraArgs @('-Mode', 'Repair')
Test-That 'Repair refuses to run on a snapshot' { $e2r.Exit -ne 0 -and $e2r.ErrFlat -match 'cannot be combined with -SnapshotPath' }
Remove-DDOfflineOutput $e2r

Write-Host ''
$color = if ($script:failed.Count -eq 0) { 'Green' } else { 'Red' }
Write-Host "Passed: $script:passed  Failed: $($script:failed.Count)" -ForegroundColor $color
foreach ($n in $script:failed) { Write-Host "  - $n" -ForegroundColor Red }
exit $script:failed.Count
