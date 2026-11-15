# Kirin 970 decrypted-fastboot extraction — current state of knowledge

A one-page summary. The chronological log is `poc-status.md`; the static map is
`xloader-map.md`; the original plan is `plan.md`.

## Where this stands

The **read primitive works and is fully verified**: 8, 16 and 1024-byte reads,
byte-wise and word-wise, all byte-identical to the artifact.

The **stock fastboot cannot be extracted this way, and that is now a result.**
Milestone 1's central open question — *is `0x16800000` plaintext before the
handoff?* — is answered: the buffer cannot be read from the loader at all. Not
through the byte copy, not through 32-bit accesses, not through the storage DMA.
Writes there succeed and the image boots after the ROM handoff, but every read
wedges the device — and so does reading `0x16dfe000`, a different address in the
same DRAM window.

So this is a scope finding, not a bug: the remaining work needs a secure-side path
(SEB/HISEE, or code that runs after the handoff), not a better loader patch.

## Proven on hardware

| Claim | Evidence |
|---|---|
| Type-3 read primitive works | `0x23154` read as 16/16 B, byte-identical to the artifact, in **5 separate sessions**; and 1024/1024 B MATCH at the full cap. Archived in `notes/poc/` |
| The read stub, cave, CRC and USB send are correct | same; returned `b.w 0x23164` ×2 + ASCII `XLOADER!` (the entry stub at file `0x1154`) |
| CRC-16/XMODEM is the single wire convention | derived from the parser's inline code `0x2f950..0x2f9c6`; `CrcHqx` proved identical over 2000 random buffers |
| The VCOM upload path is correct | 6029 ACKs / 0 NAK for the full unlock sequence (null, xloader, uce, 5.9 MB fastboot) |
| `0x16800000` is written correctly by the download path | the factory fastboot uploaded there **boots**; `fastboot devices` shows `<device-serial>` |
| The hold loop keeps the loader alive | after a forced storage load, `0x23154` still reads while the loader polls |
| The DTL `.ktl` container is understood | `build/ktl.py --verify`: decrypts the real loader to `2BB2329D...`, round-trip byte-identical |

## Disproven — do not revisit

| Hypothesis | Why it is dead |
|---|---|
| SATE gate was skipping the load | `[0x60053000]` reads `0` |
| CPU has no MMU translation for `0x16800000` | the `0xda` handler memcpy's there **with the CPU** (`0x2fb6c`) |
| Two different CRC conventions (bootrom vs xloader) | `CrcHqx` **is** XMODEM; one convention |
| The cave compared file type at `0x3dd` | file type is at `0x3db`; plan's pseudocode was wrong |
| `b .` at `0x2329a` would suffice | USB is polled (`0x2f8c0` → `0x2f8b4`), not interrupt driven |
| `b 0x23988` keeps the loader alive | `0x23988` is inside `0x2391c`; skips its `push`, corrupts the stack |
| Large reads corrupt the bounce buffer | `0x23154:0x400` reads 1024/1024 B MATCH — the full cap is safe |

## Resolved: the length confounder is dead, the address is real

The control ran on hardware:

```
[0x00023154 len 0x400] 1024/1024 B  MATCH      <- large read on a good address: fine
[0x16800000 len 0x10]  FAILED: no response     <- small read on the target: fails
```

Left half: a 1024-byte read works and matches the artifact byte for byte
(`notes/poc/read-00023154-400.bin`), so the `ctx+0x3d8` bounce copy and multi-packet
USB send are sound at the full `0x400` cap.

Right half: `0x16800000` fails with the smallest useful length. **The length was a
confounder and is now eliminated; the address is genuinely the problem.**

## The finding: the whole DRAM window is unreadable from the loader

Final experiment: a stub that copies with **32-bit `ldr`/`str`** instead of the
byte-wise `0x23a2a`, so access size is controlled, plus a second DRAM address.

```
[0x00023154 len 0x10] 16/16 B MATCH    <- word stub works on a good address
[0x16dfe000] FAILED: no response       <- a DIFFERENT DRAM address: also hangs
[0x16800000] FAILED                    <- (device already wedged by the previous)
```

Evidence across two addresses, two access sizes and two masters:

| target | region | byte copy | word copy | USB DMA | result |
|---|---|---|---|---|---|
| `0x23154` | SRAM (loader image) | 8, 16, 1024 B OK | 16 B OK | 16 B OK | **readable** |
| `0x60053000` | SRAM (BSS) | 8 B OK | — | — | **readable** |
| `0x16800000` | DRAM window | 0x10 / 0x20 / 0x400 FAIL | 0x10 FAIL | 0x20 FAIL | **wedges** |
| `0x16dfe000` | DRAM window | — | 0x10 FAIL | — | **wedges** |

Writes to the same window succeed: the `0xda` handler memcpy's 5.9 MB there with
6029 ACKs, and the image **boots** after the ROM handoff.

### Conclusion

`0x23154` and `0x60053000` are readable at every access size and length tested.
The `0x16xxxxxx` window is not readable at all — not by `ldrb`, not by `ldr`, not
by USB DMA — while remaining writable and executable after the handoff. Access
size is ruled out. The mechanism is most likely a TZASC-protected DRAM region or
an interconnect read path not decoded for this non-secure 32-bit master; it does
not need to be proven for the project, because the practical consequence is the
same either way.

**A pure xloader read primitive cannot recover the fastboot buffer.** This is the
answer to milestone 1's central open question, and it is a scope finding, exactly
as `plan.md` §6.B anticipated.

The read primitive itself is sound and verified: 8, 16 and 1024-byte reads,
byte-wise and word-wise, all byte-identical to the artifact.

## Next: why can't the CPU read DRAM?

"If the hardware reads that buffer, the question is *who* reads it, not whether it
can be read." The loader's own storage engine writes the buffer, and the AArch64
side reads and executes it. So the 32-bit loader's inability is a property of
*its* view of memory, and that is diagnosable.

The likely cause is that the loader never maps the `0x16xxxxxx` window in its MMU,
because it only touches it through DMA — and an untranslated CPU access is a data
abort, which with no handler is an infinite loop. That is exactly the silence
observed.

`build/hisi970_xloader_regs.bin` answers it by returning CP15 instead of memory
(file type 4, 32 bytes):

| offset | register | why it matters |
|---|---|---|
| `+0x00` | MIDR | core id |
| `+0x04` | SCTLR | bit 0 = MMU enabled |
| `+0x08` | TTBR0 | translation table base |
| `+0x0c` | TTBR1 | high-half table base |
| `+0x10` | TTBCR | split / walk type |
| `+0x14` | DACR | domain permissions |
| `+0x18` | DFSR | last data fault status |
| `+0x1c` | VBAR | exception vector base (is there a handler?) |

```
python host\vcom_read.py --port COMx --execute --settle 8 ^
    --xloader build\hisi970_xloader_regs.bin --regs
```

Then:

- **SCTLR.M = 0** → the MMU is off, so the hang is a *physical* access problem, not a
  missing translation. Different route.
- **SCTLR.M = 1** → TTBR0 should point into SRAM (readable!). Dump the first-level
  table and read the descriptor covering `0x16800000`. If it is not present or has
  no access permission, that is the confirmed diagnosis — and the fix is to give
  the loader a translation, which is the "same hardware reads it" answer.

## CP15 introspection: blocked

`build/hisi970_xloader_regs.bin` (file type 4, returns MIDR/SCTLR/TTBR0/TTBR1/TTBCR/
DACR/DFSR/VBAR) was loaded and queried:

```
reading CP15 (file type 4) ...
short CP15 reply: 1/32 bytes: aa          <- that is a stale ACK, not a reply
[0x00023154] FAILED: SerialTimeoutException: Write timeout
```

The lone `0xAA` is the leftover ACK the upload always leaves (earlier runs logged
`drained 1 stale byte(s): aa`). So the stub never sent its 32 bytes and the device
wedged instead — the `mrc p15` instructions almost certainly raise an undefined
instruction exception, which with no handler is an infinite loop.

That is consistent with the loader running at a privilege level where CP15 is not
accessible. It is also consistent with the DRAM behaviour: if the loader runs
unprivileged, the bootrom's page tables can mark the DRAM window
privileged-only, so a user-mode access faults. It does not explain why writes
appear to succeed (a posted write to a privileged-only page should also fault),
so the theory is not complete.

Effectively: **the loader cannot be introspected this way**, and the MMU question
can no longer be answered from inside it.

## Remaining routes

All cheap, in-loader options are now exhausted. What is left is different work,
not a patch:

1. **SEB/HISEE (`0x36dcc`)** — the hardware that decrypts and verifies the image
   can obviously reach the buffer. If a command exists that returns image data,
   the hardware itself becomes the reader. This is **fully offline static work**:
   no phone, no VCOM entries, no risk. This is the recommended next step.
2. **AArch64 code after the ROM handoff** — the only context that provably reads
   the buffer, since the image executes from it. But exfiltrating the data needs
   a USB (or other) driver written from scratch in AArch64, and the handoff
   replaces the loader. Very large.

## Images

| file | sha256 | purpose |
|---|---|---|
| `hisi970_xloader_read.bin` | `34CB9AD3...` | read primitive only, stays in the download path |
| `hisi970_xloader_hold.bin` | `9A1F04A6...` | read primitive + hold loop at the handoff site |
| `hisi970_xloader_store.bin` | `C0DDBE7A...` | hold + forced storage load (`0x2394c` nop) |
| `hisi970_xloader_direct.bin` | `55CB4A02...` | direct-DMA stub (no bounce copy) |
| `hisi970_xloader_diag.bin` | `A5B126D6...` | raised read bound, for reading SRAM globals |
| `hisi970_xloader_loop.bin` | `B266B540...` | **superseded** — stack-corrupting patch |
| `hisi970_xloader_read_bootpath.bin` | `72EF6374...` | **superseded** — same bad patch |

All are rebuilt from `artifacts/hisi970_xloader.bin` by `build/patch_*.py`, each
of which asserts its own diff.

## Operational notes

- One experiment per VCOM entry: the pwn replaces the bootrom, so a second upload
  in the same session gets `0/N` ACKs.
- Never send the bootrom start frame into a loader that is already running.
- Trust `--list`/PnP, not "the port opened" — Windows keeps a ghost COM handle.
- Kirin-Tool holds COM8 while running; close it before using the host tool.
- Kirin-Tool's `loaders/hisi970/xloader.ktl` is back to stock (`2DA98C56...`).
- The factory loader returns `0.5` for every `getvar`, so it is useless for
  reading the lock state.
- Nothing here has ever written to flash.
