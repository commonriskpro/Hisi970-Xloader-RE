# P2 — AOSP build done, boot blocked by AVB (2026-11-15)

## What was built

AOSP Pie (`android-9.0.0_r61`), target `aosp_arm64-eng`, on the Ryzen box (WSL2 Ubuntu 22.04).
Build host quirks that had to be fixed: locale (`en_US.UTF-8`), prebuilt clang needs
`libtinfo5`/`libncurses5`, the two `platform/developers/*` projects removed from the
manifest, and the prebuilt `flex-2.5.39` wrapped to run with `LC_ALL=C` (the binary crashes
on modern locales) while still being 2.5.39 (2.6.4 breaks `mclinker`'s C++ scanner).

Final artifact: `out/target/product/generic_arm64/system.img` (1.5 GB, no dexpreopt).
`WITH_DEXPREOPT=false` was required because ART's 2018 `patchoat`/`dex2oat` cannot mmap the
boot image at its fixed address on the WSL 6.6 kernel (`Failed to mmap at expected address`).

## What was proven on hardware

- `system.img` written to `system_a` with the vendor Ultraflash fastboot: OKAY in 35 s.
- Boot attempt fails in the bootloader with:
      hisi_avb: avb_slot_verify_result_error_invalid_metadata
      hisi_avb: verified slot_data NULL
      load_kernel: avb verify failed: 3
- Root cause chain, from the bootloader log (`rrecord` partition):
      huawei_fblock: cannot get oeminfo rdlock type info
      huawei_fblock: hwdog_certify->lock_state.fb_lock_stat = 0
      load_hhee: FB Locked on this device.
  i.e. because oeminfo item 0x82 is absent the bootloader treats the unit as locked and
  therefore *enforces* AVB. This is the same gate identified in STATUS.md, now confirmed to
  also gate AVB enforcement, not just the fastboot unlock UI.
- `oem check-image` reports `secure image verify fail` for the same reason.
- DM-verity/AVB has no 'unlocked skip' on this firmware: replacing a *kernel* boots (G1),
  replacing *system* does not, because only system is in the slot's AVB descriptor chain.

## Toolchain we now own (the important part)

The service tool (Kirin-Tool v2.4.2) loads its bootloader from
`<cwd>/loaders/<cpu>/fastboot.ktl` (see Services/FirmwareUnlocker.cs). The shortcut
`Kirin-Tool LockDiag.lnk` runs the build under
`default-workspace/Kirin-Tool-LockDiag/bin/Release/net8.0-windows/`, so that is the loader
directory that actually matters (there are three copies on disk; patching the wrong one
silently does nothing, which cost a cycle).

`build/ktl.py` (in the Windows copy of this repo) unwraps/wraps those containers with the
tool's own key material (`Kirin-Tool/Security/Constants.cs`): RSA-OAEP(SHA-256) wrapping an
AES-CBC payload. Round-trip is byte-identical, so we can hand the tool any patched
bootloader and it will upload it:

    python build/ktl.py --wrap patched.bin patched.ktl   # then overwrite loaders/hisi970/fastboot.ktl

`hisi970/fastboot.ktl` decrypts to exactly `artifacts/hisi970_fastboot_ram.bin`
(sha256 A41C25A3...), the image analysed in notes/b2a-decrypt-function.md.

## Patches built so far (validated in RAM)

1. **AVB verdict patch** — `0x168ADC0C`: `bl 0x168AC2F8` -> `mov w0,#0`. Forces the AVB
   status translator to report success. Verified live: after loading the patched image the
   word at `0x168ADC0C` reads `00 00 80 52` via `oem memupload`.
2. **Handler hook** — `0x16816488` (`oem check-image` handler entry) -> `b 0x168011D0`, with a
   stub in the zero cave at `0x168011D0` that calls internal routines and then answers OKAY
   through `0x1680AC6C`. The hook itself works (the command stops printing the old failure
   string), so the injection mechanism is proven end to end.

## What does NOT work (and why)

Calling the boot path from the fastboot loop crashes or resets the device:
- calling the boot orchestrator `0x168AE5CC` leaves USB enumerated but the protocol dead;
- calling its sub-checks (`0x168AE0EC`, `0x168AE254`, `0x168AE36C`, `0x168AE408`) reboots the
  phone after the first one.
So those routines depend on state that only the normal cold-boot flow establishes.

## Next approach (do this next)

Patch the **mode decision** instead of calling into the boot path: make the loaded bootloader
take its own normal-boot branch instead of entering the fastboot loop. The preboot modes are
visible in the log and in the strings: `check_boot_mode`, `check_image_state`,
`check_power_state`, `check_unlock_misc_info`. With the AVB patch already in place, that
branch should complete the boot in place, without a reset.

Fallbacks, in order: instrument the mode dispatcher to report its decision codes; or call
`load_kernel` (`0x168AE018`, the AVB wrapper's only caller is `0x168AE640`, orchestrator
`0x168AE5CC`) plus the kernel handoff directly.

## Operational notes

- Every attempt lives in RAM: power cycle returns the phone to the untouched 9.1.
- `system_a` currently holds our AOSP build (1.5 GB). The stock image is in the full dump
  (`Documents/crashdump/.../system_a.img`, 2.43 GB) if a rollback is ever wanted.
- Dumping is possible only while the fastboot loop is alive: `oem memupload <addr> <len> <file>`.
  `fastboot fetch` is broken on this firmware (`couldn't parse max-fetch-size '0.5'`); the
  tool's partition dump works instead.
- `oem check-image` is not an AVB check; it reports a different state and reads `fail` even
  with the AVB verdict patched. Do not use it to validate the AVB patch.
