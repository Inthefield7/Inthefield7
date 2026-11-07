# Driver Doctor

Windows driver and firmware health tool. It was built for an HP ENVY x360 16 (2024, Intel Core Ultra) whose built-in screen stays dark while external monitors work, but it sweeps every device.

- **Diagnose** (the default) only reads. It writes an HTML report, `findings.json` and `snapshot.json`.
- **Repair** makes a restore point and backs up drivers first. It asks before every change, then checks the machine again and lists what was fixed, what is still there and what is new.

## Quick start

1. Download this repo as a ZIP, extract it, and open `tools\driver-doctor`.
2. Double-click **`Run-Diagnose.cmd`** and accept the UAC prompt. The report opens from `Desktop\DriverDoctor\<timestamp>\report.html`.
3. Read the **Built-in display** section first. When you are ready, double-click **`Run-Repair.cmd`**. To see the plan without changing anything, run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\DriverDoctor.ps1 -Mode Repair -WhatIf
   ```

Optional, recommended on HP machines: extract [HP Image Assistant](https://ftp.ext.hp.com/pub/caps-softpaq/cmit/HPIA.html) to `%ProgramFiles%\HP\HPIA\bin` (or pass `-HPIAPath` to another folder under Program Files). The tool runs as administrator, so it runs HP Image Assistant only from Program Files and only with a valid HP Inc. signature; folders other users can write to, such as `C:\HPIA` or `C:\SWSetup`, are not searched, and a refused copy is reported as `HPIA-REJECTED`. The tool then compares your drivers against HP's certified set for this exact model.

## What the screenshots already show (2026-08-26)

| # | Evidence | Meaning | Status |
|---|---|---|---|
| 1 | Event 411, `PCI\VEN_8086&DEV_7D45&SUBSYS_8C66103C`, `oem39.inf`, service `igfxn`, status `0xC00000E5`, 7:49:44 PM | The Intel Meteor Lake-P GPU driver (HP subsystem) hit `STATUS_INTERNAL_ERROR` while starting | VERIFIED (screenshot) |
| 2 | Event 442 in the same second: last instance `DISPLAY\CMN163B\...`, `Present: false`, replaced by `DISPLAY\Default_Monitor` | Windows lost the built-in panel's identity (CMN = Innolux panel vendor code) and now sees only a generic monitor with no EDID | VERIFIED event / INFERRED vendor |
| 3 | Event 442 itself | Logged on the first boot after a Windows upgrade or reinstall | INFERRED (event meaning) |
| 4 | 1 + 2 + 3 together | The panel disappeared in the same boot the GPU driver failed, right after an OS change. The panel can only be detected through that GPU driver. | INFERRED (same boot + dependency), **not yet proven**. The live run checks whether the GPU is still failing. |
| 5 | Event 412 for `UEFI\RES_{f9a422c9-...}\0`, `oem32.inf`, code `0xE` (14), status `0xC00002D2`, on 3/19 and 8/26 | A UEFI firmware capsule is staged and waiting for a full restart. Whether it ever applied is in `FirmwareResources`, which the tool reads. | VERIFIED event |
| 6 | Bonjour `mdnsNSP.dll` blocked from LSA | LSA protection, a Windows security feature, refusing Apple's name-service DLL. No shared device or driver with the display problem. | VERIFIED / **unrelated** |

Nothing is joined into a cause unless something connects it: the same device ID, the same driver, or the same boot window. Timing alone is labeled as timing.

**Manual check that no software can do:** unplug the external monitor and power on. If the HP logo appears on the built-in screen, the panel and cable work and the fault is in Windows or the driver. If the screen stays black (shine a flashlight on it to check), press **F2** repeatedly at power-on and run *HP PC Hardware Diagnostics > Component Tests > Video*.

## The screen came back on its own? Find out why

Run this before you restart or install anything. It only reads, and finishes in about a minute:

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnostics\Get-DisplayChange.ps1
```

It writes `Desktop\DisplayChange-<timestamp>.txt`. The file compares the current state with the 2026-08-26 evidence: which GPU driver is installed now, whether the staged firmware capsule was applied, the BIOS version, whether the built-in panel is present and active, and a timeline of driver installs, Windows Updates, boots (full boot vs. Fast Startup) and recent sleep/resume. It lists facts only; the cause is decided from what connects.

## What it checks

- Every present device with a Device Manager problem code, decoded (`CM_PROB_*` plus NTSTATUS).
- The Kernel-PnP device configuration log (400/410/411/412/430/441/442): start failures, pending restarts, migration losses, driver installs. Events from different devices that fall in the same window are grouped as **timeline connections**.
- The display path, via `QueryDisplayConfig`. For each GPU output it reports whether it is internal (eDP/LVDS), whether a monitor is available, and whether it is active. Panel brightness, disabled monitor devices, and whether the GPU is on the *Microsoft Basic Display* fallback driver.
- Firmware update results from `HKLM\SYSTEM\CurrentControlSet\Control\FirmwareResources` (power-deferred vs rejected), pending-restart flags, and Fast Startup.
- Driver binaries named by each service's `ImagePath` actually exist.
- System log: display TDRs (4101), driver load failures (Kernel-PnP 219, SCM 7026), WHEA hardware errors.
- Code Integrity / LSA protection blocks (3033/3063/3065/3066/3077), with the owning installed product.
- Windows Update: driver installs that failed, plus drivers offered now (Windows Update Agent API). An offer is matched to a faulty device by hardware ID.
- Policy that blocks Windows Update drivers, and HP Image Assistant recommendations (analyze-only in Diagnose).

## Safety model

| Repair does | Repair never does |
|---|---|
| System restore point first. `pnputil /export-driver` backup of every affected driver package. | Uninstall drivers or delete driver-store packages |
| Restart a failed device (`pnputil /restart-device`). This does not persist, so a reboot undoes it. | Restart storage, CPU or platform devices |
| Rescan PnP (`pnputil /scan-devices`) | Install unsigned drivers or bypass signature checks |
| Re-enable a disabled **monitor or display** device | Re-enable other disabled devices (they may be disabled on purpose) |
| Switch the layout to **Extend** (same as Win+P) | Switch to "PC screen only", which could blank your only working screen |
| Raise panel brightness if it is 0% | Turn off LSA protection, Memory integrity or any security feature |
| Install Windows Update drivers you confirm one by one | Flash BIOS/firmware unless you pass `-IncludeFirmware`. Even then it requires AC power, battery at 50% or more, and a BitLocker key warning. |
| HP Image Assistant driver install (HP's own tool) | Restart the PC unless you pass `-AllowRestart` and confirm |

After the repair it collects again and diffs the **state-based** findings. History, such as old event-log entries, is never counted as "fixed". If anything new appears, it prints the rollback paths: Roll Back Driver, the exported package, or System Restore.

If the screen stays black after a GPU restart: wait 30 seconds, then hold the power button and boot again. A device restart is not persistent.

## Options

```text
-Mode Diagnose|Repair   default Diagnose
-Days 180               event-log lookback
-SkipWindowsUpdate      skip the online driver search (faster)
-SkipHPIA               skip HP Image Assistant
-HPIAPath <path>        folder or exe of HP Image Assistant; must be under Program Files (others are refused)
-IncludeFirmware        allow BIOS/firmware installs in Repair (AC + >= 50% battery)
-AllowRestart           allow Repair to schedule a restart (still asks)
-WhatIf                 show the plan, change nothing
-SnapshotPath <json>    re-analyze a saved snapshot offline (any OS, PowerShell 7)
-OutputPath <dir>       report folder
```

## Sharing results

Send `snapshot.json` (and `report.html`) for a second opinion. They hold the computer name, device and driver IDs, and event text from driver/firmware logs. They hold no personal files, serial numbers or credentials. Read them before you share.

## Development

```text
DriverDoctor.ps1        entry point: collect -> analyze -> (repair -> re-verify) -> report
lib/DD.Collect.ps1      read-only Windows collectors (each isolated; failures are reported, not guessed)
lib/DD.Analysis.ps1     pure analysis: decoders, parsers, correlation, findings, repair plan
lib/DD.Repair.ps1       confirm-each-step actions (ShouldProcess, ConfirmImpact High)
lib/DD.Report.ps1       HTML report and console summary
lib/DisplayConfig.cs    QueryDisplayConfig / SetDisplayConfig interop (C# 5, compiles under 5.1)
diagnostics/            standalone read-only checks (Test-BonjourLsa.ps1: Bonjour/LSA dialog root cause;
                        Get-DisplayChange.ps1: what changed since 2026-08-26 when the panel works again)
tests/Run-Tests.ps1     dependency-free tests; fixtures: the 2026-08-26 screenshots and the real
                        2026-11-06 snapshot (envy-live.snapshot.json, computer name redacted)
```

Run the tests with `pwsh -File tests/Run-Tests.ps1` or `powershell -File tests\Run-Tests.ps1`. The exit code is the number of failures.
