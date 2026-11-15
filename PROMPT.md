# Work order — Kirin 970 xloader decrypted-fastboot extraction

You are the lead reverse engineer for this project. Use the DeepSeek Harness
agent team (subagents/workflows) to split static analysis, tooling, and
verification. Plan first and save all findings to `notes/`.

## Objective

Produce a decrypted copy of the stock EMUI 12 `fastboot` image for the Huawei
P20 (Kirin 970) from the already-decrypted xloader path, without relying on
Huawei RSA keys.

The deliverable is a reproducible pipeline:

1. A patched xloader that (a) reads the on-disk `fastboot` partition,
   (b) decrypts it with the xloader's normal-boot crypto path, (c) leaves the
   plaintext in a known RAM buffer, and (d) exposes that buffer through a read
   primitive usable from the host.
2. A host-side extractor that reads the buffer and reconstructs the image.
3. A verification step: the extracted plaintext must contain the expected
   fastboot structures (`BOOTMAGICNUMBER!`, vector table, strings such as
   `INFO FB LockState`, `oem unlock`, `oeminfo_lock_stat_write`).
4. If successful, analyze the plaintext lock-state initialization and prepare
   a patch that forces FBLOCK=1 and USERLOCK=unlocked (the 710A
   `fastboot_710a_dec_patched3.img` is the reference pattern).

## Known facts

- Device: P20 EML-L09, Kirin 970, EMUI 12.0.0.226, Android 10/API 29, locked.
- Persistent USERLOCK is unlocked (factory loader reads/decrypts oeminfo 0x5d).
- oeminfo 0x82 RDLOCK is absent; NVME FBLOCK=1. The stock 12 loader therefore
  reports locked after reboot.
- On-disk fastboot is the stock EMUI 12 payload (encrypted), SHA256
  `9D82C1CE...` over the unwrapped payload.
- The factory loader `artifacts/hisi970_fastboot_ram.bin` is already decrypted
  and is the source of the RAM unlock; it is not the stock 12 loader.
- The 2022 xloader rejected the 2020 factory image on disk. Do not flash it
  again without a verified patch and recovery plan.

## Files

- `artifacts/hisi970_xloader.bin` — decrypted 970 xloader, 139,264 B, Thumb-2,
  stripped. Main RE target.
- `artifacts/hisi970_fastboot_ram.bin` — decrypted factory fastboot (RAM),
  5,986,304 B. Reference for fastboot structures.
- `artifacts/hisi970_uce.bin`, `artifacts/hisi970_null.bin` — other VCOM stage
  artifacts.
- `artifacts/fastboot.stock.payload.img` — stock EMUI 12 fastboot payload,
  3,590,336 B, SHA256 `9D82C1CE...`.
- `artifacts/fastboot.dump.img` — 12 MiB raw partition dump (stock payload at
  offset 0, encrypted).
- `artifacts/oeminfo.dump.img`, `artifacts/nvme.dump.img` — raw dumps.
- Tool repo: `/Users/saturno/Developer/ROM/tools/Exploit` (Kirin-Tool fork).
  `Security/Constants.cs` holds the DTL key used to decrypt the `.ktl` loaders;
  `tools/=` has local helper scripts.

## Static-analysis starting points

- Architecture: Thumb-2 ARM; file offset `0x1a00` is valid code (memcpy/strcmp
  helpers), strings begin around `0x1a900`.
- Partition table around file `0x1e600`: `fastboot_a`, `nvme`, `vector_a`, ...
- Strings: `normalboot`, `fastboot`, `BOOTMAGICNUMBER!`, `sec verify err`,
  `vrl_check error`, `Rdsect%dErr`, `xloader main download mode to get
  fastboot!`, `LdFs failed`, `loadFsFail`.
- VCOM download mode accepts a plaintext fastboot from the host; the normal
  boot path is the one that reads/decrypts the on-disk `fastboot_a`.
- `SendInquiryPatched` exists in `KirinTool.ImageFlasher` and in the 710A
  `studentpad-hack` patches. Porting that read primitive to the 970 xloader is
  a likely route; find the USB command dispatcher and the normal-boot load
  function first.

## Milestones

1. **Map** — boot-mode dispatch, `fastboot_a` read, decrypt/verify call chain,
   output buffer address/size, jump target. Save addresses and evidence in
   `notes/xloader-map.md`.
2. **Read primitive** — identify the USB command handler and how to add/port an
   inquiry command. Save a patch plan.
3. **POC** — patch xloader, load via VCOM, dump the plaintext, verify markers.
4. **Stock patch** — locate lock-state init in the decrypted stock fastboot and
   prepare the force-unlock patch; verify on a copy first.
5. **Persist** — only after explicit approval and a testpoint baseline, flash
   the patched stock fastboot and verify post-reboot.

## Constraints

- No device writes in milestones 1–3. Use offline analysis and, if needed, a
  read-only VCOM session with explicit approval.
- Keep all Huawei binaries/keys local; nothing from `artifacts/` goes to a
  public repo.
- Every claim needs reproducible evidence (offset, instruction, hash, or test
  output). Never guess addresses; mark hypotheses as such.

