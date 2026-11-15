# Project status — 2026-11-15

## Short version

- The type-3 **RAM read primitive works on hardware** (verified many times).
- The **DRAM window containing the fastboot image is not readable from the
  32-bit loader**, even though it is writable and executable after the ROM
  handoff. This is a scope finding, not a patch bug.
- Nothing has been written to flash. The stock xloader is restored in
  Kirin-Tool. The phone may need a power cycle to leave the wedged VCOM session.
- The next work is **offline SEB/HISEE static analysis**, not another loader
  patch. Do not repeat the DRAM reads.

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

**Offline SEB/HISEE analysis** (no phone, no VCOM, no risk):

1. Map `0x36dcc` (SEB/HISEE submit), `0x31074`, `0x36ea0` (changeStoreAddr) and
   the SEB command IDs/structures.
2. Determine whether SEB exposes a read/decrypt-only command that can return
   image bytes, or whether the data is only reachable after the ROM handoff.
3. If SEB can read it, design a host-side request; if not, the remaining route
   is AArch64 code after the handoff (a much larger project).

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

