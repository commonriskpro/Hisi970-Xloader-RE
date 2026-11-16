# Session log — 2026-11-15 — EMUI 12 → 9.1 → AOSP build → AVB

This is the consolidated record of a long hardware session on the Huawei P20 (EML-L09,
Kirin 970). It supersedes nothing: it ties together the per-topic notes written during the
day (`g1-milestone.md`, `b2a-live-decrypt-validation.md`, `phase1-boot-path.md`,
`rdlock-donor-research.md`, `adb-blocked.md`, `p2-aosp-boot-avb.md`) and adds what only
became clear at the end.

---

## 1. Executive summary

**Achieved**

1. Decrypted the stock EMUI 12 fastboot container **on the device** and extracted the
   plaintext (3,590,336 bytes) — the image the project needed.
2. Proved arbitrary AArch64/EL3 code execution inside the factory bootloader by patching
   handler entry points; found the correct response-dispatch ABI along the way.
3. Passed gate G1: the EMUI 9.1 bootloader boots a **modified kernel** (17 bytes changed in
   the cmdline), with the orange unlocked warning.
4. Built **AOSP Pie from source** (`android-9.0.0_r61`, `aosp_arm64-eng`) on a second PC and
   flashed the resulting `system.img` (1.5 GB) to `system_a` over Ultraflash.
5. Identified, from the bootloader's own log, **why a custom `system` cannot boot**: the
   oeminfo item `0x82` gate decides `fb_lock_stat = 0`, and that forces AVB enforcement.
6. Located the exact AVB verdict site and patched it (`0x168ADC0C`), verified live in RAM.
7. Discovered we can hand the service tool **any patched bootloader**: its `.ktl` containers
   are RSA-OAEP + AES-CBC with a key the tool itself ships, and `build/ktl.py` wraps and
   unwraps them with byte-identical round-trip.

**Not yet achieved**

Booting the custom system. The bootloader still ends in fastboot. The last section lists
exactly what is ruled out and the next experiment (a trace build).

---

## 2. Device and partition facts (measured)

- Model EML-L09, Kirin 970 / hi3660, serial BPN0218808000359.
- There is **no `boot` partition**: the boot payload is split into `kernel_a` (a standard
  Android boot image v1, `ANDROID!`, ramdisk_size = 0, page 0x800, header v1, cmdline at
  offset 64) plus `ramdisk_a`, `dts_a`, `vector_a` and `vbmeta_a`.
- `vbmeta_a` is `AVB0`, algorithm SHA256_RSA2048, with an embedded public key.
- `ramdisk_a` carries an `AVB0` header at +0x1000.
- `vrl.img` (512 KB) carries a real VRL blob, byte-identical to `vrl_backup.img`.
- `veritykey.img` (1 MB) is entirely zero on this unit.
- Sizes: system_a 2.43 GB, vendor 998 MB, product 1.73 GB, odm 150 MB, cust 201 MB,
  oeminfo 67 MB, nvme 5 MB, fastboot 12.5 MB, xloader 256 KB.
- The tool's full dump of all 66 partitions is the recovery baseline.

---

## 3. Boot chain as measured on this hardware

    BootROM (mask ROM, eFuse-rooted)  ->  xloader  ->  UCE  ->  fastboot image (EL3)

- The `fastboot` partition image is the **whole bootloader** (logo, keys, kernel load, and
  the fastboot protocol). It runs at EL3.
- The xloader verifies the next image through SEB/VRL without conditions; the 139 KB xloader
  contains no oeminfo/NV strings at all, so it cannot be consulting boot flags.
- The 9.1 and 12 bootloaders share the same `huawei_fblock` gate.

---

## 4. Why a custom system does not boot (root cause, from the log)

Taken from the `rrecord` partition after the failed attempt:

    huawei_fblock: cannot get oeminfo rdlock type info
    huawei_fblock: hwdog_certify->lock_state.fb_lock_stat = 0
    ... user_lock_stat = 0, check_root_stat = 0, check_sign_stat = 0
    load_hhee: FB Locked on this device.
    hisi_avb: avb_slot_verify_result_error_invalid_metadata
    hisi_avb: verified slot_data NULL
    load_kernel: avb verify failed: 3

Interpretation:

- The NV item table has **no item 0x82** (RDLOCK). Its absence makes `fb_lock_stat = 0`.
- With `fb_lock_stat = 0` the bootloader treats the unit as locked and **enforces AVB**; the
  unlocked state (`userlock = 0`, `fblock = 1`) is not consulted for this decision.
- Our `system.img` has no AVB hashtree metadata, so slot verification returns
  `error_invalid_metadata` and the boot aborts.
- Replacing only the *kernel* works (G1) because the kernel is not in the slot's AVB
  descriptor chain; replacing *system* is what trips it.
- `oem check-image` reports `secure image verify fail` but that is a **different** check; do
  not use it to validate the AVB patch.

---

## 5. The tool, and how we inject our own bootloader

- The tool loads `<cwd>/loaders/<cpu>/fastboot.ktl` (or `fastbootf.ktl` when the fast-flash
  switch is on **and** cpu is hisi980).
- The desktop shortcut `Kirin-Tool LockDiag` runs the build under
  `default-workspace/Kirin-Tool-LockDiag/bin/Release/net8.0-windows/`, so **that** is the
  loader directory that matters. There are three copies on disk; patching the wrong one is
  silent and cost one cycle.
- `hisi970/fastboot.ktl` decrypts to exactly `artifacts/hisi970_fastboot_ram.bin`
  (sha256 A41C25A3...).
- Container format: BE16 length + RSA-OAEP(SHA-256) wrapped AES key + 16-byte IV + AES-CBC
  payload. The tool ships the private key in `Kirin-Tool/Security/Constants.cs` (FBK, four
  base64 layers), which `build/ktl.py` consumes:

      python build/ktl.py --wrap patched.bin patched.ktl
      # then overwrite loaders/hisi970/fastboot.ktl (keep a .orig backup)

- Round-trip verified byte-identical, and the tool accepts the re-wrapped file without
  complaint (confirmed by reading the patched words back out of RAM).

---

## 6. Patch inventory

All offsets are into `artifacts/hisi970_fastboot_ram.bin` (base VA 0x16800000).

| purpose | address | original | patched | verified |
|---|---|---|---|---|
| AVB verdict forced to success | 0x168ADC0C | `bl 0x168AC2F8` | `mov w0,#0` | yes, reads back `00 00 80 52` in RAM |
| `check_boot_mode` -> next mode | 0x16806E44 | `cbz w0,0x16806E84` | `b 0x16806E84` | yes, `10 00 00 14` in RAM |
| `check_power_state` -> next mode | 0x16808098 | prologue | `mov w0,#0; ret` | yes |
| `oem check-image` handler hook | 0x16816488 | prologue | `b 0x168011D0` (stub) | yes, command stops printing the old string |

Stub cave: `0x168011D0`, 1584 zero bytes available. Scratch cells used: `0x16801600`.

Response dispatcher ABI (needed by every stub): `0x1680AC6C(msg, type)` with `type 0 = OKAY`,
`type 1 = FAIL`, **any other value sends nothing** and desynchronises the session. The OKAY
path requires the stock string `"OKAY"` at `0x169B7E40` (a NULL msg crashes: `0x1680AA54`
initialises the response buffer and is only reached when msg != NULL).

---

## 7. What was tried and ruled out

| attempt | result | why |
|---|---|---|
| Flash stock `system_a` back and re-check | not done | user chose to keep the AOSP image |
| `fastboot reboot` with AVB patched | orange "booting now" then fastboot | a reset discards the RAM image; the flash bootloader re-runs unpatched |
| Call the boot orchestrator `0x168AE5CC` from a hooked command | USB enumerated, protocol dead | needs state that only the normal cold-boot flow establishes |
| Call its sub-checks `0x168AE0EC/254/36C/408` | phone rebooted after the first | same reason |
| Force `check_boot_mode` and `check_power_state` to "next" | still fastboot | the fastboot decision is made after these |
| `fastboot fetch` | fails | `couldn't parse max-fetch-size '0.5'`; use the tool's partition dump or `oem memupload` |
| Stock fastboot (`platform-tools`) for writing | blocked | whitelist: `Writing 'x' FAILED (remote: 'Command not allowed')` |
| ADB on the Windows host | blocked | interface is present but `CreateFile` returns error 5; Huawei INF SDDL |

Useful instruments that DO work: `oem memupload <addr> <len> <file>` (RAM read), the tool's
partition dump, and the Ultraflash `flash <partition> <file>` for writes.

---

## 8. Readings taken during this session

- Bootloader mode struct: pointer at `0x16B89E30` -> `0x16BAE480` -> real struct at
  `0x16B0F030`. After a chain load it reads `[0] = 6`, `[4] = 4`, which is exactly what
  `check_boot_mode` writes on its "no usbdownload, go on next mode" path.
- Mode table (name, function, stride 0x18) at `0x16B12B30`:

      check_boot_mode         0x16806E14
      check_image_state       0x168097DC
      check_power_state       0x16808098
      check_smpl_state        0x168073C8
      check_unlock_misc_info  0x1680624C
      check_powerkey_misc_info 0x1680662C
      check_volumekey_state   0x16805EF8
      check_misc_info         0x16808BF4
      check_poweronkey_state  0x16807970
      check_last_reboot_flag  0x16806094

- Load path in the factory image: `load_kernel`-style function at `0x168AE018` (its only
  caller is `0x168AE640`), the AVB wrapper at `0x168ADB68`, the status translator at
  `0x168AC2F8`, the boot orchestrator at `0x168AE5CC`.

---

## 9. Next experiment (trace build)

The open question is *how far the boot flow gets*. Instrument instead of guessing: patch
2-3 points so each writes a marker into `0x16801600`, load the chain, let it settle in
fastboot, then read the cells with `oem memupload`.

    marker 1 -> entered load_kernel (0x168AE018)
    marker 2 -> the AVB call returned (0x168ADC10)
    marker 3 -> entered normal_boot

Relevant strings for stage 3: `normalboot_init` (0x16992918), `normal_boot: normal mode!`
(0x169B3E90), `normal_boot: %s can not get loadkernel_ops!` (0x169B3EB8). A very plausible
outcome is that `normalboot` runs and fails on `loadkernel_ops`, falling back to fastboot.

---

## 10. Operational notes

- Everything tried lives in RAM: a power cycle returns the unit to the untouched 9.1 state
  except for `system_a`, which currently holds our AOSP build.
- Stock `system_a.img` (2.43 GB) is in the tool's full dump if a rollback is ever wanted.
- The tool's `.ktl` backups: `fastboot.ktl.orig` next to each patched copy.
- One experiment per chain load; the RAM image is lost on reset.
- No account, key or service was created or purchased; nothing left the local network.

## 11. Addendum — superseded

See the CORRECTION section below; the claim that the mode patches caused the boot attempt was
wrong.

## 11. Addendum — mode patches make it attempt to boot, then it resets

After patching both `check_boot_mode` (0x16806E44 -> `b 0x16806E84`) and
`check_power_state` (0x16808098 -> `mov w0,#0; ret`), a chain load no longer sits in the
fastboot menu: the screen shows the orange unlocked banner and "your device is booting now".
Then the unit resets; the flash bootloader takes over (`FB LockState: LOCKED`, `oem memupload`
fails) and it ends in fastboot again because AVB rejects our `system`.

So the mode patches changed the flow from "enter fastboot" to "attempt boot, then reset".
The markers written in RAM cannot be read afterwards because the reset wipes them; the only
surviving record is the `rrecord` partition, which has to be dumped *before* the reset (i.e.
while the bootloader is still alive) or read afterwards with the tool if the stock fastboot
allows a partition dump.

### Next experiments, in order

1. **Control**: restore the stock `system_a` (2.43 GB dump) and load the same patched chain.
   If the stock system also resets, the problem is the in-RAM kernel handoff, not AVB; if it
   boots, our system image is what fails after the verdict.
2. **Persist the trace**: have the marker stub write to a partition-in-RAM the bootloader
   itself flushes (or write the markers into `bootfail_info`'s record) so they survive a reset.
3. **Read the log**: dump `rrecord` right after an attempt and look for the last lines of the
   RAM bootloader — they say whether `load_kernel` ran and why the handoff failed.
4. If the handoff is the blocker, revisit `boot_kernel`/BL31 mailbox semantics (the Phase-1
   note flagged 60% confidence there).

## 11. CORRECTION — the boot attempt was NOT caused by the mode patches

This section replaces an earlier, wrong reading of the same events.

Observed sequence across three builds:

| build | contents | outcome |
|---|---|---|
| `powpatch` | AVB patch + `check_boot_mode` -> next + `check_power_state` -> next | lands in the fastboot menu |
| `trace` | AVB patch + markers at `load_kernel` and after the AVB call | lands in fastboot; both markers read back as 0 |
| `modetrace` | AVB patch + 8 markers on the mode functions (**no behavioural change**) | orange banner, "booting your device", then a reset and the flash bootloader |

An earlier version of this document claimed the mode patches caused the boot attempt. That is
**wrong**: the build that attempted to boot is the one that only instruments, and the build
with the behavioural patches did not attempt it. Two honest possibilities remain, and they
must be separated by experiment, not by inference:

1. The boot attempt is timing-dependent (USB enumeration race around the chain load).
2. The marker stubs disturbed a mode function: they clobber `x9`/`x10` without saving them,
   and `check_boot_mode`/`check_power_state`/`check_misc_info` may carry live values in those
   registers at entry. A marker stub that saves and restores `x9`/`x10` (as the later ones do)
   removes this variable.

### What is still established

- Before `load_kernel` is reached, the RAM bootloader decides its mode; with the stock
  decisions it ends in the fastboot menu, and `load_kernel` is never entered (both markers 0).
- When a boot attempt does happen, it ends in a reset, which wipes RAM and with it every
  marker; the flash bootloader then runs unpatched and AVB rejects our `system`.
- So the trace must survive a reset, or the control experiment must remove the boot attempt
  from the equation.

### Next experiments, in order

1. **Control**: restore the stock `system_a` (2.43 GB dump) and load the same patched chain.
   Stock system + AVB patch + stock decisions: if it boots, our system image is the problem; if
   it resets, the in-RAM kernel handoff is.
2. **Reproducibility**: run the same `modetrace` chain twice. A boot attempt that appears only
   sometimes is a race, not a decision.
3. **Persist the trace**: write markers to `bootfail_info` (the record the bootloader flushes)
   so they survive a reset.
