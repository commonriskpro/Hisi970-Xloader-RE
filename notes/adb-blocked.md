# Blocked: ADB on the Windows host (2026-11-15)

Status: **parked**. Not blocking P2. Recorded so nobody repeats the dead ends.

## Symptom

`adb devices` lists nothing while the phone is booted in Android with USB debugging enabled.
The device is present in Windows as:

    Android Composite ADB Interface   USB\VID_12D1&SUBCLASS_42&PROT_01\...
    service = WinUSB   inf = oem103.inf (Huawei)   version 2.0.3.0

## What was measured

- adb 37.0.1 (platform-tools) enumerates the interface path with the ADB interface GUID
  {f72fe0d4-cbcb-407d-8814-9ed673d0dd6b}, then fails at open:
  `windows.cpp:599 Failed to open device handle`.
- Direct P/Invoke `CreateFileW` on that interface path returns **error 5, Access denied**
  (not busy, not missing). So the device node rejects the open, it is not a plumbing issue.
- Reproduced from a normal cmd window and from an elevated cmd window.
- HiSuite processes and the HuaweiHiSuiteService64 service were stopped; no change.
- Kirin-Tool was closed; no change.
- Zadig was downloaded and run, but the driver was NOT actually replaced (the interface still
  reports oem103.inf/WinUSB 2.0.3.0 afterwards), so the WinUSB-with-permissive-SDDL path was
  never tested to completion.

## Working hypotheses (in order)

1. The Huawei INF installs WinUSB with a restrictive security descriptor; only some contexts
   can open it. The elevated test was inconclusive because a non-elevated adb daemon was
   already listening on 5037 and the elevated client attached to it instead of starting its own.
2. Huawei's ADB function requires the vendor stack (HDB) and a matching client.

## Next attempt, when it matters

- Kill every adb daemon first (`adb kill-server`), then start the daemon from an elevated
  shell so the USB work happens with admin rights, and only then attach clients.
- Or complete the Zadig replacement with target = WinUSB (not libusbK) and verify that
  DEVPKEY_Device_DriverInfPath changes away from oem103.inf.

## Why this is not blocking

Flashing is done by the vendor fastboot inside the service tool (Ultraflash), which works.
For runtime logs during kernel bring-up, alternatives exist: read pstore/ramoops data from a
later boot, or enable adbd over TCP from a modified ramdisk once we control it.
