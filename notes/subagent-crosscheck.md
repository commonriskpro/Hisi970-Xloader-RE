# Independent cross-check notes (milestone 1)

Three read-only subagents were launched (USB dispatcher, SEB/decrypt, boot/final
handoff). Their closing summaries were used to correct the map; none of them
touched the device or artifacts. This file records what was accepted, what was
corrected, and what remained uncertain.

## USB / VCOM (accepted)

- Frame parser `0x2f918`, registered as a Thumb callback by `0x2f588` via
  `0x2f8c0`; download control block `0x60053878`, status at `+4`.
- RX buffer `ctx+0x3d8`; `+0 = cmd`, `+1 = seq`, `+2 = ~seq`, `+3.. = payload`,
  last two bytes CRC-16 big-endian.
- CRC-16/CCITT poly `0x1021`, init 0; table at `0x3e2a4`.
- `0xCD` inquiry: one status byte from `0x60053d48`, sent with
  `0x305bc(ctx, ctx+0x3d8, 1)`.
- `0xFE` head: file type at `+3`, size BE32 at `+4`, address BE32 at `+8`.
- `0xDA` data frames copy to `[ctx+0x9dc] + seq*0x400`; `0xED` EOT.
- Preferred read-primitive cave: **0x3efe8** (file `0x1cfe8`), 248 zero bytes;
  patch `0x2fa50` and `0x2fa58` as described in `notes/plan.md`.
- The agent's initial direct-arbitrary-address idea was replaced by the
  bounce-copy design (`ctx+0x3d8`, max 0x400) for DMA/cache safety; the direct
  `0x305bc` approach remains the fallback.

## SEB / decrypt (accepted with one correction)

- VRL header read offset is **0x22000** (`0x30ef4`: `0x22 << 12`), not offset 0.
- The active path reads the header from `vrl`/`vrl_backup` and the payload from
  `fastboot`; the fastboot partition itself starts with the payload.
- `0x31074` calls `0x36ea0` (`changeStoreAddr`), which rewrites the VRL
  store-address entries to `0x16800000`; `0x36dcc` submits to SEB.
- `0x60035000` is zeroed after use; it is not the plaintext output.
- No software AES/SHA/RSA; decryption is not visible in the CPU graph. SEB/HISEE
  hardware or the ROM handoff at 0xb2 are the candidates.
- **Correction:** the first `memcpy` in `0x23374` is
  `memcpy(dst=0x16dfe000, src=0x16800000, len=0x1000)` (save the header), not the
  reverse. The second is `memcpy(dst=0x16800000, src=0x16801000, 0x5fe000)`
  (shift payload). This was fixed in the map.

## Boot / final handoff (accepted with two corrections)

- Final handoff is `0x2329a: blx r4` with `r4=0xb3` (ROM VA 0xb2); no direct
  branch to 0x16800000 anywhere in the image. The xloader is Thumb-2, the image
  is AArch64, so the ROM/secure firmware must perform the state switch.
- `[0x60053000]` is **written** at `0x24154` inside `0x2410c`: it reads 0x40
  bytes of the `"patch"` partition and checks for `"sate_aging_start"`; on match
  it sets the flag to 1. `0x232e8` is therefore the SATE-aging/reserved5 path,
  not the normal USB-download path.
- `0x242a8` reads `[0x4020ae00]`, not the PC. The `0x3670e000`/`0x3670a000`
  compare in `0x23f1c`/`0x235f4` is a core/strap identity check.
- **Correction:** the agent reported no reference to `"normalboot"`; the
  PC-relative pair at `0x238ae`/`0x238b2` does resolve to `0x3c9b2`
  `"normalboot"`, and `0x238b6`/`0x238bc` resolves to `0x3c979` `"fastboot"`.
  These are the two `%s` tags passed to `0x311c8`. `"download"` (0x3c982) still
  has no verified code reference.
- The exact ROM API 0xb2 ABI, and whether it decrypts, remains unproven.

## Net effect

- The address-level map is unchanged in its main conclusions.
- The SATE-aging path, VRL offset 0x22000, the `"normalboot"` xref, and the
  `0x23374` copy direction were corrected.
- The one architectural unknown remains: **plaintext before or during the final
  ROM handoff**. The POC must read 0x16800000 before the handoff to decide.
