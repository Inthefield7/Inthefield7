<#
.SYNOPSIS
    Read-only root-cause check for the dialog
    "This module is blocked from loading into the Local Security Authority ... \Bonjour\mdnsNSP.dll".

.DESCRIPTION
    Verifies each link of the suspected chain and prints a verdict:
      1. Bonjour's mdnsNSP.dll exists and who signed it
      2. It is registered as a Winsock namespace provider (so Winsock loads it into processes that resolve names, lsass included)
      3. LSA protection (RunAsPPL) is on, so lsass only accepts DLLs at Microsoft's signing level
      4. Code Integrity logged lsass being refused mdnsNSP.dll
      5. What installed Bonjour (same install date = connection)
      6. Whether the blocks started after the last Windows install/upgrade
    Changes nothing. Run in an elevated PowerShell for full event-log access.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-BonjourLsa.ps1
#>
# NEW-6: ConvertTo-DDConsoleText strips escape sequences and control characters from text that comes
# from the registry, certificates and event logs before it reaches the console.
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib\DD.Report.ps1')

# NEW-6: machine-wide uninstall keys only (administrators write them). HKCU is the user's own hive, so a
# fake "Bonjour" entry there could change this verdict; it is not read.
$script:BLUninstallRoots = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

function Write-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail)
    $tag = if ($Ok) { '[YES]' } else { '[NO] ' }
    $color = if ($Ok) { 'Green' } else { 'Yellow' }
    Write-Host ("{0} {1}" -f $tag, $Name) -ForegroundColor $color
    if ($Detail) { Write-Host "      $(ConvertTo-DDConsoleText $Detail)" }
}

function Get-BLInstallerLines {
    # Pure: the "Installed by" lines for the installed-programs list, cleaned for the console (NEW-6).
    param([object[]]$Apps)
    $all = @($Apps)
    $bonjour = $all | Where-Object { [string]$_.Name -match '(?i)^Bonjour' } | Select-Object -First 1
    if (-not $bonjour) { 'No "Bonjour" entry in installed programs.'; return }
    ConvertTo-DDConsoleText "Bonjour $($bonjour.Version) ($($bonjour.Publisher)), installed $($bonjour.InstallDate)"
    $sameDay = @($all | Where-Object { $_.InstallDate -and $_.InstallDate -eq $bonjour.InstallDate -and [string]$_.Name -notmatch '(?i)^Bonjour' })
    foreach ($a in $sameDay) { ConvertTo-DDConsoleText "same install date: $($a.Name) $($a.Version) ($($a.Publisher))  <- likely brought Bonjour" }
    $knownHosts = @($all | Where-Object { [string]$_.Name -match '(?i)iTunes|iCloud|Apple Software Update|Apple Mobile Device|Creative Cloud|Photoshop|Autodesk|AirPrint' })
    foreach ($a in $knownHosts) { ConvertTo-DDConsoleText "known Bonjour user: $($a.Name) $($a.Version)" }
    if ($sameDay.Count -eq 0 -and $knownHosts.Count -eq 0) { 'No installed app is connected to Bonjour by install date or by known use.' }
}

# Dot-sourced (tests): stop here, functions only.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Continue'
$links = [ordered]@{}

# 1. The DLL and its signer
$dll = Join-Path $env:ProgramFiles 'Bonjour\mdnsNSP.dll'
$present = Test-Path -LiteralPath $dll
$sigText = ''
if ($present) {
    $sig = Get-AuthenticodeSignature -LiteralPath $dll
    $ver = (Get-Item -LiteralPath $dll).VersionInfo.FileVersion
    $sigText = "version $ver; signature $($sig.Status); signer: $($sig.SignerCertificate.Subject)"
}
$links['dll'] = $present
Write-Check '1. Bonjour mdnsNSP.dll is installed' $present $(if ($present) { "$dll - $sigText" } else { "Not found at $dll" })

# 2. Registered in the Winsock namespace catalog
$nsp = @()
foreach ($cat in 'Catalog_Entries64', 'Catalog_Entries') {
    $root = "HKLM:\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\$cat"
    foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
        if ([string]$p.LibraryPath -match '(?i)mdnsNSP\.dll') {
            $nsp += "$cat\$($k.PSChildName): '$($p.DisplayString)' -> $($p.LibraryPath) (Enabled=$($p.Enabled))"
        }
    }
}
$links['winsock'] = ($nsp.Count -gt 0)
Write-Check '2. Registered as a Winsock namespace provider (loaded into every process that resolves names)' $links['winsock'] ($nsp -join '; ')

# 3. LSA protection
$lsa = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$ppl = $lsa.RunAsPPL
$pplEvent = $null
try { $pplEvent = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Wininit'; Id = 12 } -MaxEvents 1 -ErrorAction Stop } catch { Write-Verbose "Wininit event 12 not found." }
$links['lsa'] = ($ppl -in 1, 2) -or ($null -ne $pplEvent)
$lsaDetail = "RunAsPPL=$ppl RunAsPPLBoot=$($lsa.RunAsPPLBoot)"
if ($pplEvent) { $lsaDetail += "; Wininit 12 at $($pplEvent.TimeCreated): $(($pplEvent.Message -split "`r?`n")[0])" }
Write-Check '3. LSA protection is ON (lsass runs as a protected process)' $links['lsa'] $lsaDetail

# 4. Code Integrity blocks naming mdnsNSP.dll
$ci = @()
try {
    $ci = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = 3033, 3063, 3065, 3066 } -MaxEvents 2000 -ErrorAction Stop |
            Where-Object { $_.Message -match '(?i)mdnsNSP\.dll' })
}
catch { Write-Verbose "No matching Code Integrity events." }
$links['ci'] = ($ci.Count -gt 0)
$ciDetail = ''
if ($ci.Count -gt 0) {
    $sorted = @($ci | Sort-Object TimeCreated)
    $ids = ($ci | ForEach-Object { $_.Id } | Sort-Object -Unique) -join ', '
    $proc = if ($sorted[-1].Message -match 'process \(([^)]+)\)') { $Matches[1] } else { '?' }
    $ciDetail = "$($ci.Count) event(s), ids $ids, first $($sorted[0].TimeCreated), last $($sorted[-1].TimeCreated), process $proc"
}
Write-Check '4. Code Integrity logged the block' $links['ci'] $ciDetail

# 5. What installed Bonjour (NEW-6: machine-wide keys only, see $script:BLUninstallRoots; console text cleaned)
$apps = @()
foreach ($r in $script:BLUninstallRoots) {
    foreach ($k in (Get-ChildItem -LiteralPath $r -ErrorAction SilentlyContinue)) {
        $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
        if ($p.DisplayName) { $apps += [pscustomobject]@{ Name = $p.DisplayName; Version = $p.DisplayVersion; Publisher = $p.Publisher; InstallDate = $p.InstallDate } }
    }
}
Write-Host ''
Write-Host '5. Installed by:' -ForegroundColor Cyan
foreach ($l in @(Get-BLInstallerLines -Apps $apps)) { Write-Host "      $l" }
$svc = Get-Service -Name 'Bonjour Service' -ErrorAction SilentlyContinue
if ($svc) { Write-Host "      Bonjour Service: $($svc.Status), start type $($svc.StartType)" }

# 6. Timeline against the last Windows install/upgrade
$osInstall = (Get-CimInstance Win32_OperatingSystem).InstallDate
Write-Host ''
Write-Host "6. Windows installed/upgraded: $osInstall" -ForegroundColor Cyan
if ($ci.Count -gt 0) {
    $first = ($ci | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
    if ($first -ge $osInstall) { Write-Host '      First block is AFTER that install: consistent with LSA protection arriving with the new install (Code Integrity log may not reach further back).' }
    else { Write-Host '      Blocks predate that install: LSA protection was already on before it.' }
}

# Verdict
Write-Host ''
if ($links['dll'] -and $links['winsock'] -and $links['lsa'] -and $links['ci']) {
    Write-Host 'ROOT CAUSE CONFIRMED (all four links present):' -ForegroundColor Green
    Write-Host '  Bonjour registered mdnsNSP.dll as a Winsock name provider -> Winsock loads it into lsass when lsass resolves a name ->'
    Write-Host '  LSA protection only accepts DLLs at Microsoft''s signing level -> Code Integrity refuses the Apple-signed DLL -> Windows shows the dialog.'
    Write-Host '  Impact: lsass alone cannot use Bonjour name lookups. Bonjour still works for other apps. LSA protection is doing its job.'
}
else {
    $missing = ($links.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object { $_.Key }) -join ', '
    Write-Host "NOT CONFIRMED - missing link(s): $missing. Send this output back for analysis." -ForegroundColor Yellow
}
