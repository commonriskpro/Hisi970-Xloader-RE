# Project status — 2026-11-15

## Short version

- The type-3 **RAM read primitive works on hardware** (verified many times).
- The **DRAM window containing the fastboot image is not readable from the
  32-bit loader**, even though it is writable and executable after the ROM
  handoff. This is a scope finding, not a patch bug.
- Nothing has been written to flash. The stock xloader is restored in
  Kirin-Tool. The phone may need a power cycle to leave the wedged VCOM session.
- **Offline SEB/HISEE static analysis is complete (notes/seb-analysis.md).**
  **Verdict: NO.** The SEB/HISEE interface in this loader is verify/hash-only;
  no read/decrypt/export command path exists.

## What is proven on hardware

| Claim | Evidence |
|---|---|
| Type-3 read primitive works | `0x23154` read 16/16 and 1024/1024 bytes, byte-identical, in multiple sessions |
| Read stub/cave/CRC/USB send are correct | returned entry stub `b.w 0x23164` x2 + ASCII `XLOADER!` |
| CRC is CRC-16/XMODEM only | parser inline code + `CrcHqx` identical over 2000 random buffers |
| VCOM upload path works | 6029 ACKs / 0 NAK for null + xloader + uce + 5.9 MB fastboot |
| DRAM is written correctly | factory fastboot uploaded to `0x16800000` boots; `fastboot devices` shows the device |
| Hold loop keeps loader alive | after a forced storage load, `0x23154` still reads while the loader polls |
| DTL `.ktl` container is understood | decrypt/re-encrypt round-trip byte-identical |
| Handler entry-point patch executes at EL3 | `oem ufs_test` stub wrote magic `0xB2A0C0DE` to `0x16B8F1F8`, read back byte-identical via `oem memupload` |
| Stock fastboot decrypted on device | `out_len 0x36C8C0`, plaintext at `0x18ECC6A0`, saved as `artifacts/fastboot.stock.decrypted.img` (sha256 `4BB40A92...`) |

## What is disproven / do not revisit

| Hypothesis | Why it is dead |
|---|---|
| SATE gate skipped the load | `[0x60053000]` reads 0 |
| CPU has no MMU translation for `0x16800000` | the `0xda` handler memcpy's there with the CPU |
| Two CRC conventions | one: CRC-16/XMODEM; the start frame `1D0F` is a handshake constant |
| Cave compares file type at `0x3dd` | file type is `0x3db`; `0x3dd` is the size byte |
| `b .` at `0x2329a` keeps USB alive | USB is polled, not interrupt-driven |
| `b 0x23988` keeps the loader alive | it jumps into the middle of `0x2391c`, skips `push`, corrupts the stack |
| Large reads corrupt the bounce buffer | `0x23154:0x400` reads 1024/1024 bytes MATCH |
| The address is fine, only length was wrong | `0x23154:0x400` works; `0x16800000:0x10` fails |

## The finding

`0x23154` (loader SRAM) and `0x60053000` (loader BSS) are readable at every
tested size. `0x16800000` and `0x16dfe000` (DRAM window) are not readable by
byte copy, word copy, or USB DMA; every read wedges the loader. Writes to the
same window succeed and the image boots after the ROM handoff.

Most likely cause: a TZASC-protected/privileged-only DRAM view or an
interconnect read path not decoded for this non-secure 32-bit master. The exact
mechanism does not change the practical conclusion: **a pure xloader read
primitive cannot recover the fastboot buffer.**

## Next step

Static analysis of 0x36DCC, 0x31074, 0x36EA0, and the ROM API 0xB2 handoff is complete (documented in notes/seb-analysis.md):
- **Verdict: NO.** No read/decrypt-only SEB command exists in this loader.
- 0x36DCC has a single caller (0x31116 in 0x31074), takes no command ID, and dispatches solely on status from 0xbdf0fad4.
- SEB operations are SHA-256 hash programming (H0 at 0x3F820, opcodes 0x82/0x41/0x42) and certificate verification; no software or hardware AES export path exists.
- 0x60035000 is a 4KB input staging scratch zeroed on return; changeStoreAddr (0x37008) updates a source-range {address, 0, length} descriptor, not a plaintext destination.
- The remaining route is **post-handoff AArch64 code execution (EL3)** after the ROM 0xB2 handoff.

## B2 live validation (2026-11-15)

The factory fastboot's built-in `oem memupload` command was validated on
hardware. `oem memupload 0x16800000 0x1000` returned exactly
`artifacts/hisi970_fastboot_ram.bin[0:0x1000]` (SHA256 `B7AFCAF0...DCD155`),
proving the AArch64/EL3 context can read the DRAM window that the 32-bit
xloader cannot. `0x16dfe000`, `0x16000000`, and `0x10000000` are also readable.
See `notes/b2-live-test.md`.

## B2a live validation (2026-11-15, second boot)

Four handler entry points were patched in one image and exercised in one boot:

- `oem memcpy_count` -> respond-only stub: OKAY. Response path is sound.
- `oem chipid` -> `FAILED (remote: invalid command)`: the internal dispatch
  table names are not the host-visible verb list.
- `oem ufs_test` -> OKAY and magic `0xB2A0C0DE` read back from `0x16B8F1F8`:
  entry-point patching works and that scratch is writable.
- `oem onchiprom_download` -> OKAY in 0.074 s: the stock container was
  decrypted and the plaintext published.

Decrypt result: `hisi_secboot_decrypt_encrypted_xloader(0x16000000, "fastboot",
&len)` returned `0x18ECB6A0` with `len = 0x36C8C0`. That address holds the
container header (`"fastboot"` at +0x1C); the plaintext starts at +0x1000
(`0x18ECC6A0`) with the AArch64 vector table and `BOOTMAGICNUMBER!`. The
3,590,336 bytes are saved as `artifacts/fastboot.stock.decrypted.img`
(sha256 `4BB40A92...`), which is plaintext: it matches the encrypted
`fastboot.stock.payload.img` in only ~14k of 3.59M bytes.

Two protection facts were established by crashing the SoC on purpose:
stores into the code page (`0x16801400`) reset the device, so text is mapped
read-only; `0x16B8F1F8` (data/bss) is writable and is the scratch to use.

See `notes/b2a-live-decrypt-validation.md`.

## Next open question

Whether the boot chain signature-verifies the `fastboot` partition on load. If
it does, flashing the patched stock image (or the patched NVMe `FBLOCK` block)
is gated by secure boot and the unlock path has to run from the RAM/EL3 context
instead of from flash.

## Operational notes

- One experiment per VCOM entry: the pwn replaces the bootrom, so a second
  upload in the same session gets 0/N ACKs.
- Never send the bootrom start frame into a running xloader.
- Trust `--list`/PnP, not "the port opened": Windows keeps a ghost COM handle.
- Kirin-Tool holds COM8 while running; close it before using the host tool.
- The stock xloader is restored (`2DA98C56...`); patched containers remain in
  the Windows agent's `build/` folder.
- Nothing here has written to flash.

See `notes/FINDINGS.md` for the full evidence, `notes/poc-status.md` for the
chronological log, and `notes/patch-report.md` for the verified patch/CRC
details.

