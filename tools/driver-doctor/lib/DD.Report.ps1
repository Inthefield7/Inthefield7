# DD.Report.ps1 - renders analysis results as a self-contained HTML file and a console summary.
# Pure functions: no system access, so reports can be regenerated from a saved snapshot.

function ConvertTo-DDHtml {
    param($Text)
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function ConvertTo-DDHtmlList {
    param([object[]]$Items)
    $items = @($Items | Where-Object { $_ })
    if ($items.Count -eq 0) { return '' }
    return '<ul>' + (($items | ForEach-Object { '<li>' + (ConvertTo-DDHtml $_) + '</li>' }) -join '') + '</ul>'
}

function ConvertTo-DDHtmlReport {
    param(
        [Parameter(Mandatory = $true)] $Snapshot,
        [Parameter(Mandatory = $true)] $Analysis,
        [object[]]$Plan,
        [object[]]$RepairResults,
        $Comparison,
        [string]$Mode = 'Diagnose'
    )
    $m = $Snapshot.Meta
    $findings = @($Analysis.Findings)
    $v = $Analysis.Verdict
    $counts = @{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $counts[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.Append(@'
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Driver Doctor Report</title>
<style>
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#5f5f5a;--line:#e3e2dd;--crit:#b3261e;--high:#c2541b;--med:#9a6b00;--low:#2f6f9f;--info:#5f5f5a;--ok:#2e7d32}
@media (prefers-color-scheme: dark){:root{--bg:#161615;--card:#1f1f1e;--fg:#ecebe6;--muted:#a3a29b;--line:#34332f;--crit:#ff8a80;--high:#ffab70;--med:#e6c25a;--low:#8cc4ef;--info:#a3a29b;--ok:#81c784}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 64px;overflow-wrap:anywhere}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:32px 0 10px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.pills{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}.pill{border:1px solid var(--line);border-radius:999px;padding:3px 12px;background:var(--card)}
.sev{font-weight:600;font-size:12px;letter-spacing:.04em;text-transform:uppercase}
.sev.Critical,.newp{color:var(--crit)}.sev.High{color:var(--high)}.sev.Medium{color:var(--med)}.sev.Low{color:var(--low)}.sev.Info{color:var(--info)}
.card.Critical{border-left:5px solid var(--crit)}.card.High{border-left:5px solid var(--high)}.card.Medium{border-left:5px solid var(--med)}.card.Low{border-left:5px solid var(--low)}.card.Info{border-left:5px solid var(--line)}
h3{font-size:16px;margin:4px 0 6px}ul{margin:6px 0 6px 18px;padding:0}li{margin:2px 0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
.tbl{overflow-x:auto}.tag{font-size:11px;border:1px solid var(--line);border-radius:4px;padding:1px 6px;margin-left:6px;color:var(--muted)}
.ok{color:var(--ok)}code{font-family:Consolas,ui-monospace,monospace;font-size:12.5px}
</style></head><body><main>
'@)
    $null = $sb.Append('<h1>Driver Doctor report</h1>')
    $machine = if ([string]$m.Model -like "$($m.Manufacturer)*") { [string]$m.Model } else { "$($m.Manufacturer) $($m.Model)" }
    $null = $sb.Append('<div class="muted">' + (ConvertTo-DDHtml "$machine | BIOS $($m.BiosVersion) ($($m.BiosDate)) | $($m.OsCaption) build $($m.OsBuild) | Last full boot $(Format-DDDate $m.LastBoot) | Collected $(Format-DDDate $m.CollectedAt) | Mode: $Mode") + '</div>')
    $null = $sb.Append('<div class="pills">')
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') { $null = $sb.Append("<span class=""pill""><span class=""sev $s"">$s</span> $($counts[$s])</span>") }
    $null = $sb.Append('</div>')

    # Built-in display verdict first: it is the reason this tool exists.
    $null = $sb.Append('<h2>Built-in display</h2>')
    $null = $sb.Append("<div class=""card $($v.Severity)""><div class=""sev $($v.Severity)"">$($v.Severity) <span class=""tag"">$(ConvertTo-DDHtml $v.Confidence)</span></div>")
    $null = $sb.Append('<h3>' + (ConvertTo-DDHtml "State: $($v.State)") + '</h3><p>' + (ConvertTo-DDHtml $v.Summary) + '</p>')
    $null = $sb.Append('<p><b>Next:</b> ' + (ConvertTo-DDHtml $v.NextStep) + '</p>')
    $null = $sb.Append('<details><summary>Evidence (' + @($v.Evidence).Count + ')</summary>' + (ConvertTo-DDHtmlList $v.Evidence) + '</details></div>')
    $null = $sb.Append('<div class="card"><b>Manual check no software can do:</b> power the laptop on with the external monitor unplugged and watch the built-in screen. ')
    $null = $sb.Append('HP logo visible = panel and cable work, the problem is in Windows/driver. Nothing at all (even with a flashlight on the screen) = run HP PC Hardware Diagnostics: press F2 repeatedly at power-on &gt; Component Tests &gt; Video.</div>')

    if ($Comparison) {
        $null = $sb.Append('<h2>Before / after repair</h2><div class="card">')
        $null = $sb.Append('<p class="ok"><b>Fixed (' + @($Comparison.Fixed).Count + '):</b></p>' + (ConvertTo-DDHtmlList @($Comparison.Fixed | ForEach-Object { $_.Title })))
        $null = $sb.Append('<p><b>Still present (' + @($Comparison.Remaining).Count + '):</b></p>' + (ConvertTo-DDHtmlList @($Comparison.Remaining | ForEach-Object { $_.Title })))
        $null = $sb.Append('<p class="newp"><b>New since repair (' + @($Comparison.New).Count + '):</b></p>' + (ConvertTo-DDHtmlList @($Comparison.New | ForEach-Object { $_.Title })))
        $null = $sb.Append('</div>')
    }

    $null = $sb.Append('<h2>Findings</h2>')
    foreach ($f in $findings) {
        if ($f.Id -eq 'INTERNAL-PANEL') { continue }
        $null = $sb.Append("<div class=""card $($f.Severity)""><div class=""sev $($f.Severity)"">$($f.Severity)<span class=""tag"">$(ConvertTo-DDHtml $f.Confidence)</span><span class=""tag"">$(ConvertTo-DDHtml $f.Category)</span></div>")
        $null = $sb.Append('<h3>' + (ConvertTo-DDHtml $f.Title) + '</h3>')
        $null = $sb.Append('<p>' + (ConvertTo-DDHtml $f.Interpretation) + '</p>')
        $null = $sb.Append((ConvertTo-DDHtmlList $f.Evidence))
        if ($f.Recommendation) { $null = $sb.Append('<p><b>Recommendation:</b> ' + (ConvertTo-DDHtml $f.Recommendation) + '</p>') }
        $null = $sb.Append('</div>')
    }

    if ($Plan -and @($Plan).Count -gt 0) {
        $null = $sb.Append('<h2>Repair plan</h2><div class="card tbl"><table><tr><th>#</th><th>Action</th><th>Target</th><th>What it does</th><th>Because of</th></tr>')
        $i = 0
        foreach ($p in $Plan) {
            $i++
            $null = $sb.Append("<tr><td>$i</td><td>$(ConvertTo-DDHtml $p.Type)</td><td><code>$(ConvertTo-DDHtml $p.Target)</code></td><td>$(ConvertTo-DDHtml $p.Detail)</td><td>$(ConvertTo-DDHtml (@($p.Reasons) -join ', '))</td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }

    if ($RepairResults -and @($RepairResults).Count -gt 0) {
        $null = $sb.Append('<h2>Repair log</h2><div class="card tbl"><table><tr><th>Action</th><th>Target</th><th>Result</th><th>Detail</th></tr>')
        foreach ($r in $RepairResults) {
            $null = $sb.Append("<tr><td>$(ConvertTo-DDHtml $r.Type)</td><td><code>$(ConvertTo-DDHtml $r.Target)</code></td><td>$(ConvertTo-DDHtml $r.Result)</td><td>$(ConvertTo-DDHtml $r.Detail)</td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }

    $devices = @(Get-DDArray $Snapshot.Devices | Where-Object { ($_.Present -ne $false -and [int64](ConvertTo-DDInt $_.ProblemCode) -ne 0) -or (Test-DDClass $_ 'Display') -or (Test-DDClass $_ 'Monitor') -or (Test-DDClass $_ 'Firmware') })
    if ($devices.Count -gt 0) {
        $null = $sb.Append('<h2>Display, monitor, firmware and problem devices</h2><div class="card tbl"><table><tr><th>Device</th><th>Class</th><th>Present</th><th>Code</th><th>Problem status</th><th>Driver</th></tr>')
        foreach ($d in ($devices | Sort-Object Class, Name)) {
            $null = $sb.Append("<tr><td>$(ConvertTo-DDHtml $d.Name)<br><code>$(ConvertTo-DDHtml $d.InstanceId)</code></td><td>$(ConvertTo-DDHtml $d.Class)</td><td>$(ConvertTo-DDHtml $d.Present)</td><td>$(ConvertTo-DDHtml (ConvertTo-DDInt $d.ProblemCode))</td><td>$(ConvertTo-DDHtml (Format-DDStatusText $d.ProblemStatus))</td><td>$(ConvertTo-DDHtml "$($d.DriverProvider) $($d.DriverVersion) $($d.DriverDate) $($d.DriverInf)")</td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }

    $targets = @(Get-DDArray $Snapshot.DisplayTargets | Where-Object { $_.Available -or $_.Active -or (Test-DDInternalOutputTechnology $_.OutputTechnology) })
    if ($targets.Count -gt 0) {
        $null = $sb.Append('<h2>Display outputs (QueryDisplayConfig)</h2><div class="card tbl"><table><tr><th>Name</th><th>Output</th><th>Internal</th><th>Available</th><th>Active</th><th>Device path</th></tr>')
        foreach ($t in $targets) {
            $null = $sb.Append("<tr><td>$(ConvertTo-DDHtml $t.FriendlyName)</td><td>$(ConvertTo-DDHtml (Format-DDHex $t.OutputTechnology))</td><td>$(Test-DDInternalOutputTechnology $t.OutputTechnology)</td><td>$(ConvertTo-DDHtml $t.Available)</td><td>$(ConvertTo-DDHtml $t.Active)</td><td><code>$(ConvertTo-DDHtml $t.DevicePath)</code></td></tr>")
        }
        $null = $sb.Append('</table></div>')
    }

    $errors = @(Get-DDArray $Snapshot.CollectionErrors)
    $null = $sb.Append('<h2>Collection coverage</h2><div class="card">')
    if ($errors.Count -eq 0) { $null = $sb.Append('<p class="ok">All collectors ran.</p>') }
    else {
        $null = $sb.Append('<p>These collectors failed, so conclusions that depend on them are marked unknown rather than assumed:</p>')
        $null = $sb.Append((ConvertTo-DDHtmlList @($errors | ForEach-Object { "$($_.Collector): $($_.Error)" })))
    }
    $wu = $Snapshot.WindowsUpdate
    $wuState = if ($null -eq $wu -or -not $wu.Searched) { 'skipped' } elseif ($wu.Error) { 'failed' } else { "searched, $(@(Get-DDArray $wu.Updates).Count) driver update(s) offered" }
    $hpState = if ($null -eq $Snapshot.HPIA) { 'skipped' } elseif (-not $Snapshot.HPIA.Present) { 'not installed' } elseif ($Snapshot.HPIA.Error) { 'failed' } else { "ran, $(@(Get-DDArray $Snapshot.HPIA.Recommendations).Count) recommendation(s)" }
    $null = $sb.Append('<p class="muted">' + (ConvertTo-DDHtml "Windows Update driver search: $wuState. HP Image Assistant: $hpState. Events counted as current since: $(Format-DDDate $Analysis.Since).") + '</p></div>')
    $null = $sb.Append('<p class="muted">VERIFIED = Windows reports it directly. INFERRED = connects separate facts (same device id, same driver, same time window); timing alone is labeled as timing, not cause.</p>')
    $null = $sb.Append('</main></body></html>')
    return $sb.ToString()
}

function Write-DDConsoleSummary {
    param($Analysis, $Comparison)
    $colors = @{ Critical = 'Red'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
    $v = $Analysis.Verdict
    Write-Host ''
    Write-Host "Built-in display: $($v.State) [$($v.Confidence)]" -ForegroundColor $colors[$v.Severity]
    Write-Host "  $($v.Summary)"
    Write-Host "  Next: $($v.NextStep)"
    Write-Host ''
    foreach ($f in $Analysis.Findings) {
        if ($f.Id -eq 'INTERNAL-PANEL' -or $f.Severity -eq 'Info') { continue }
        Write-Host ("[{0,-8}] {1}" -f $f.Severity, $f.Title) -ForegroundColor $colors[$f.Severity]
    }
    $info = @($Analysis.Findings | Where-Object { $_.Severity -eq 'Info' }).Count
    if ($info -gt 0) { Write-Host "($info informational item(s) in the HTML report)" -ForegroundColor Gray }
    if ($Comparison) {
        Write-Host ''
        Write-Host "Repair result: fixed $(@($Comparison.Fixed).Count), still present $(@($Comparison.Remaining).Count), new $(@($Comparison.New).Count)" -ForegroundColor Cyan
        foreach ($n in $Comparison.New) { Write-Host "  NEW: $($n.Title)" -ForegroundColor Red }
    }
}
