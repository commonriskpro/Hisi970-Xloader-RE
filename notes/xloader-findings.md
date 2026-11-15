# Xloader findings — initial pass

## File

- `artifacts/hisi970_xloader.bin`
- Size: 139,264 bytes
- SHA256: compute locally (`shasum -a 256`)
- Source: `loaders/hisi970/xloader.ktl` decrypted with `CryptoUtil.DTL`

## Architecture / layout

- Thumb-2 ARM, stripped.
- File `0x0..0x1000`: zero padding/header.
- File `0x1a00` onward: valid Thumb code (memcpy/strcmp helpers visible).
- Strings around `0x1a900` (normalboot/fastboot/BOOTMAGICNUMBER!/sec verify).
- Partition name table around `0x1e600`: `fastboot_a`, `nvme`, `vector_a`, ...

## Relevant strings

- `fastboot`, `download`, `xloader`, `normalboot`, `uce`
- `BOOTMAGICNUMBER!`
- `sec verify err(0x%x)`, `sec verify end`, `vrl_check error`
- `Rdsect%dErr`, `LdFs lasted:%dms`, `loadFsFail`
- `xloader main download mode to get fastboot!`
- `Flash boot mode to read uce!`

## Hypotheses (to verify)

1. Download mode receives the fastboot plaintext from the host and does not use
   the on-disk `fastboot_a` decrypt path.
2. Normal boot reads `fastboot_a`, decrypts/verifies it, and jumps to the
   resulting address (likely `0x16800000` per the loader manifest).
3. A patch can call the normal-boot load/decrypt routine from download mode,
   leave the plaintext in the load buffer, and expose it via the USB inquiry
   read primitive.
4. `BOOTMAGICNUMBER!` is the post-decrypt validation marker; finding its xref
   should lead to the load/decrypt routine.

## Open questions

- Exact load address/size of the decrypted fastboot.
- Is decryption done in-place, or into a separate buffer?
- Does the xloader verify before or after decrypting?
- Where is the USB command dispatcher, and can an inquiry command be added
  without breaking the VCOM handshake?
- Which xloader build is this (EMUI 8/9 board package, 2020-01-14)? The
  factory fastboot build string is `Chipset-boston8.0.1.001(028E)_FASTBOOT`.

