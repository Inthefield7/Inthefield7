# CLAUDE.md - envy-driver-doctor handoff

Context for a local Claude Code session on the affected laptop. Read this before touching code.

## Goal

Get the **built-in display** of an HP ENVY x360 2-in-1 16-ac0xxx (2024, Intel Core Ultra, Meteor Lake-P) working again. Do it without making anything worse. Driver Doctor is the vehicle: a read-only diagnosis by default, and a repair mode that asks before every step.

Done = the built-in panel shows the desktop after a normal boot. The proof is `report.html` showing the verdict `Active` plus the user confirming it by eye.

## Status (2026-10-03; restored 2026-11-04; updated 2026-11-07)

| Item | Status |
|---|---|
| **Built-in panel works again (no repair was run by this tool)** | FOUNDER-STATED 2026-11-07; cause UNKNOWN until `Get-DisplayChange.ps1` output is read |
| Tool built: collect -> analyze -> (repair -> re-verify) -> report | DONE |
| `tests/Run-Tests.ps1`: 84/84 pass on Windows PowerShell 5.1.26100 and pwsh 7.6 (the laptop, 2026-11-06) | VERIFIED |
| PSScriptAnalyzer: 0 findings against Windows PowerShell 5.1 and 7.0 profiles | VERIFIED |
| `lib/DisplayConfig.cs` compiles; marshaled sizes 72/64/420 match Win32 | VERIFIED |
| Restored to git on 2026-11-04 from the session record after a container reset; the replay reproduced the original 57/2 and 63/63 checkpoints and the final 66/66 | VERIFIED |
| Tests under **Windows PowerShell 5.1** | VERIFIED 2026-11-06 (fixed: Repair-refusal test threw NativeCommandError under 'Stop') |
| Live collectors and repair actions on real Windows | NOT RUN - never executed on hardware |
| HP logo / F2 hardware check | NOT DONE - user must do it |

## Evidence so far (Event Viewer screenshots, 2026-08-26, local time)

1. **7:49:44 PM, event 411:** `PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C&REV_08\3&11583659&0&10` (Intel Graphics), `oem39.inf`, service `igfxn`, problem status `0xC00000E5` STATUS_INTERNAL_ERROR. VERIFIED.
2. **Same second, event 442:** settings for `DISPLAY\Default_Monitor\1&8713bca&0&UID0` were not migrated. The last instance was `DISPLAY\CMN163B\4&5423816&0&UID0` (the built-in panel), `Present: false`. VERIFIED. The event marks the first boot after an OS upgrade or reinstall. INFERRED.
3. **Hypothesis, not proven:** an OS change, then the GPU driver failed to start, then the panel was not enumerated. The live run decides whether the GPU is still failing (verdict `NotDetected-GpuFault`), failed only then (`NotDetected-GpuHistory`), or shows no fault (`NotDetected`, which points to hardware).
4. **Event 412 for `UEFI\RES_{f9a422c9-7892-42c3-a237-218610bfd215}\0`:** `oem32.inf`, code 14, status `0xC00002D2`, logged 3/19 and 8/26. A staged UEFI capsule is waiting for a full Restart. No link to the display has been found.
5. **Bonjour `mdnsNSP.dll` blocked from LSA:** LSA protection is working as designed. It is unrelated to the display. Keep LSA protection on. `diagnostics/Test-BonjourLsa.ps1` confirms each link of that chain on the machine.

## Next actions, in order

0. **The panel came back on 2026-11-07.** First, while it still works, the user runs `diagnostics\Get-DisplayChange.ps1` (read-only, elevated). Read the `DisplayChange-*.txt` on the Desktop: collection errors first, then OBSERVATIONS, then the timeline between the last 411/442 and now. Decide the cause only from connected facts: a different GPU INF than `oem39.inf` = new driver; firmware `APPLIED` + BIOS date = capsule applied; neither = no software change found (transient start failure or intermittent hardware, which this data cannot separate). Do not run Repair while the panel works.
1. Run the tests in **Windows PowerShell 5.1**: `powershell -ExecutionPolicy Bypass -File tests\Run-Tests.ps1`. Expect 84/84. Fix anything that fails only on 5.1.
2. The user runs `Run-Diagnose.cmd` (elevated, read-only). Read `Desktop\DriverDoctor\<ts>\report.html` and `snapshot.json`.
3. Check `snapshot.json` -> `CollectionErrors` first. Any failed collector is a bug from the first real-hardware run. Fix it before trusting conclusions.
4. Confirm the real data against the assumptions below; adjust the parsers where they differ.
5. The user does the hardware check: external monitor unplugged, power on. If the HP logo shows on the panel, the problem is software. If the screen is black, use F2 > Component Tests > Video.
6. `DriverDoctor.ps1 -Mode Repair -WhatIf`, then review the plan with the user. Only then `Run-Repair.cmd`. The user answers every prompt.
7. Save the real `snapshot.json` as `tests/fixtures/envy-live.snapshot.json`. Replace the computer name first. Add regression tests for its verdict.

## Unverified assumptions (check against the first live snapshot)

- The Kernel-PnP configuration channel is found via `Get-WinEvent -ListLog 'Microsoft-Windows-Kernel-PnP/*'` matching `Configuration`.
- Kernel-PnP EventData field names (`DeviceInstanceId`, `Problem`, `Status`...). The parser falls back to the English message text.
- `HKLM\SYSTEM\CurrentControlSet\Control\FirmwareResources\{GUID}` holds `Version`, `LastAttemptVersion`, and `LastAttemptStatus` (NTSTATUS).
- `Get-PnpDevice` `ConfigManagerErrorCode` typing. It is normalized by `ConvertTo-DDProblemCode`.
- `pnputil /enum-drivers` output is English. Localized output yields an empty driver-store list, not an error.
- HP Image Assistant: CLI flags and exit codes come from search snippets, not the official PDF (HP docs were egress-blocked). The JSON report schema is unknown; it is parsed generically.
- Code Integrity IDs: 3033/3063 = enforced block, 3065/3066 = LSA audit, 3077 = policy block.

## Architecture

```text
DriverDoctor.ps1      entry point; -SnapshotPath re-analyzes offline (no system access)
lib/DD.Collect.ps1    read-only Windows collectors; each isolated, failures go to CollectionErrors
lib/DD.Analysis.ps1   PURE: decoders, parsers, correlation, findings, verdict, repair plan, diff
lib/DD.Repair.ps1     actions with ShouldProcess (ConfirmImpact High); restore point + driver backup first
lib/DD.Report.ps1     HTML report + console summary (pure)
lib/DisplayConfig.cs  QueryDisplayConfig / SetDisplayConfig(SDC_TOPOLOGY_EXTEND)
diagnostics/          standalone read-only checks (Test-BonjourLsa.ps1, Get-DisplayChange.ps1)
tests/Run-Tests.ps1   dependency-free tests; fixture = screenshots + labeled ASSUMED values
```

Keep reasoning in `DD.Analysis.ps1`, pure and tested. Collectors only gather data.

## Invariants (do not break)

- **Evidence:** every finding lists evidence lines. Use `VERIFIED` when Windows states the fact directly. Use `INFERRED` when separate facts are connected by the same device ID, the same driver, or the same boot window. Timing alone is labeled as timing. Never fill a gap with a plausible story.
- **Safety:** Diagnose never changes state. Repair never uninstalls drivers, deletes driver-store packages, disables devices, changes BIOS settings, turns off security features (LSA protection, Memory integrity), or installs unsigned code. It never switches to "PC screen only"; it only uses Extend. Firmware/BIOS updates only run with `-IncludeFirmware`, AC power, and battery >= 50%. It never restarts the PC without `-AllowRestart` plus a confirmation.
- **Human authority:** do not run Repair, install drivers, or restart on your own. Propose, show `-WhatIf`, and let the user approve.

## PowerShell traps already hit (keep these fixed)

- Scripts must be **ASCII only**. Windows PowerShell 5.1 misreads non-ASCII in BOM-less files.
- Hex literals like `0xC0000001` parse as **negative Int32**. Compare through `ConvertTo-DDInt`.
- Functions emit items; callers wrap with `@(...)`. `return , $array` plus `@()` nests arrays.
- In 5.1, `$ErrorActionPreference = 'Stop'` plus native `2>&1` throws on the first stderr line. Set it to `Continue` locally around native tools (see `Invoke-DDNative`).
- `Start-Process` has no `-WhatIf` in 5.1. Scope `$WhatIfPreference = $false` locally instead.
- Report files are written with `-WhatIf:$false`, so a `-WhatIf` run still produces a report.
- Add-Type C# must stay at C# 5: no `$""`, no `?.`, no `out var`.

## Checks before every commit

```powershell
powershell -ExecutionPolicy Bypass -File tests\Run-Tests.ps1     # 5.1: must be 0 failures
pwsh -File tests/Run-Tests.ps1                                   # 7.x if installed
```

Optional: `Invoke-ScriptAnalyzer -Path . -Recurse` with the compatibility rules. Keep commits small and keep the README in sync.

## Kickoff prompt for the local session

> Read CLAUDE.md. Run the test suite in Windows PowerShell 5.1 and fix any 5.1-only failures. Then wait while I run Run-Diagnose.cmd, and analyze the newest Desktop\DriverDoctor\*\snapshot.json and report.html: collection errors first, then the built-in display verdict and its evidence. Do not run Repair or change system state without my approval.
