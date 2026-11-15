Milestone 1 is complete. No device was touched, nothing was flashed, and no artifact was modified.

## Files written
- `notes/xloader-map.md` — detailed map with file offsets, VAs, instructions, strings, partition entries, and evidence.
- `notes/plan.md` — step-by-step read-primitive/POC plan, including exact next step and patch bytes.
- `notes/subagent-crosscheck.md` — independent cross-check results and corrections.

## Key findings

- **Address mapping:** file `0x1000` is an ELF header; for code/data `VA = file_offset + 0x22000`. Entry stub at `0x23154`, main at `0x2316c`.
- **Boot dispatch:** `0x2326c` reads `[0x60053000]`. This is a **SATE-aging gate**, written at `0x24154` inside `0x2410c` when the `"patch"` partition starts with `"sate_aging_start"`. If set, `0x232e8` runs the reserved5/trampoline path and main skips `0x2391c`. If clear, `0x2391c` chooses between:
  - **normal storage load** (`0x23f1c()==1`): `0x237e0` → read/verify fastboot;
  - **USB download wait** (`0x2f8c0(0)==0x16800000`).
- **`0x23f1c`** compares masked `[0x4020ae00]` with `0x3670e000`/`0x3670a000`; otherwise returns bit 0 of `0x4020a40c`. **`0x23f5c`** returns eMMC/UFS (1/2) from `0x4020a3a0` bit 15.
- **fastboot_a read:** `0x235f4` reads the `"fastboot"` partition to **`0x16800000`**, max **`0x5fe000`**, via `0x24e14`. UFS table entry at file `0x1ea78`/VA `0x40a78`: start sector `0x5f800`, size `0x3000` sectors (6 MiB).
- **VRL header:** `0x237e0` reads `"vrl"`/`"vrl_backup"` at **offset `0x22000`**, size `0x1000`, to **`0x16dfe000`**. It then calls `0x311c8(src=0x16dfe000, dst=0x16800000, ..., "normalboot","fastboot")`.
- **Verify/decrypt chain:** `0x311c8` → `0x31074` → `0x36dcc` (SEB/HISEE). The visible code verifies VRL certificates/hashes and rewrites VRL store addresses to `0x16800000`; **it contains no software AES/SHA/RSA or write-back decrypt loop**. The SEB scratch `0x60035000` is zeroed after use.
- **Final handoff:** `0x2329a: blx r4`, with `r4 = 0xb3` from `0x23f70`, i.e. boot-ROM VA **`0xb2`**. There is **no direct branch to `0x16800000`**; the xloader is Thumb-2 and the image is AArch64, so the ROM/secure firmware must perform the transition. The decrypted factory image header at `0x16800020` contains `0x16800000` and `0x16800024` contains `"BOOTMAGICNUMBER!"`.
- **`0x23374` is dead/unreferenced** in this build. Its first `memcpy` saves the header from `0x16800000` to `0x16dfe000`; the second shifts the payload from `0x16801000` down to `0x16800000`.
- **USB read surface:** parser `0x2f918`; frame = type/seq/~seq/payload/CRC-16 big-endian (CCITT poly `0x1021`, init 0, table `0x3e2a4`). Inquiry `0xcd` sends one byte via `0x305bc(ctx, data, len)`. Preferred read primitive: unused head file type 3 + 248-byte zero cave at **`0x3efe8`**, patches at `0x2fa50` and `0x2fa58`.

## Remains uncertain

1. **Where decryption actually happens:** SEB/HISEE hardware behind `0x36dcc`, or the ROM handoff at `0xb2`. Static analysis cannot prove which, or whether the storage read already returns plaintext.
2. **Whether `0x16800000` contains plaintext before the handoff.** The first POC experiment must read it before `0x2329a`; if it is ciphertext, the current xloader-only read primitive is insufficient.
3. **Exact ROM API `0xb2` ABI/semantics** and the args `(0x8e200000, 0, 0xfff50000, 0, 0x2e000, 5)`.
4. **Host CRC convention:** the xloader CRC is CRC-16/CCITT; the host tool’s `CrcHqx` may differ and must be validated on the first frame.
5. **Cave/bounce safety:** the `ctx+0x3d8` bounce limit (0x400) and multi-packet `0x305bc` behavior are not dynamically verified.

The exact next action is in `notes/plan.md` §10: apply only the read primitive to a copy, validate a benign 16-byte read of the xloader’s own `0x23154`, and only then add the normal-load/stop-before-handoff patches.
