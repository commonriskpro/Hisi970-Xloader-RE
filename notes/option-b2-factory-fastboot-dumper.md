# Option B2 — factory fastboot as post-handoff execution context (offline feasibility)

Status: **offline static analysis + plan. No device, no VCOM, no flash, no partition writes.**
Nothing here was validated on hardware. Every claim carries a VA/offset and the instructions it
rests on.

Addressing convention:

- Factory fastboot: VA = file_offset + 0x16800000
  (`artifacts/hisi970_fastboot_ram.bin`, 5,986,304 B = 0x5b5800, sha256 `a41c25a3…cf3c03c`).
- Xloader: VA = file_offset + 0x22000 (`artifacts/hisi970_xloader.bin`, 139,264 B,
  sha256 `2BB2329D…ACB1691`), per `notes/xloader-map.md` §0.

---

## 0. Executive feasibility

| Sub-goal | Verdict | Basis |
|---|---|---|
| **A. A memory-dump command exists in the factory fastboot** | **YES — already present, no patch required** | `upload_memory:` is entry #1 of the live command table (0x16b13580); its handler is a direct address/length to USB bulk-IN pump (0x1680b738 → `tx_data` 0x1680ab1c). It is not in the locked-state deny list. |
| **B. A patched factory fastboot is accepted by the boot chain** | **LIKELY YES (uncertain only at the ROM step)** | The VCOM download path contains no image verification; the only integrity check is the per-frame CRC-16/XMODEM. The SEB verification entry point is statically unreachable from that path. The residual checker, if any, is the opaque ROM service 0xb2 at the handoff. |
| **C. Stock-plaintext orchestration** (stock image into a second DRAM buffer, factory fastboot at 0x16800000 dumps it) | **UNCERTAIN — leaning feasible** | Requires two small xloader patches (4 + 12 bytes) plus a free DRAM buffer. The blocking unknown is whether the verify step decrypts/decompresses in place. |
| **D. "Proof of context" first** | **YES, zero-patch** | The same `upload_memory:` primitive dumps the fastboot's own image at 0x16800000, proving the AArch64/EL3 context reads DRAM. Cheapest hardware test; do it first. |

**Bottom line:** option B2 is viable, and the "add a dump command" half of the brief is already
solved by the shipped image. Risk is concentrated in two places: ROM service 0xb2 acceptance of a
modified image, and where the on-disk image is decrypted.

**Single most important unknown to resolve first:** does the stock image become plaintext in the
destination buffer as part of the load+verify path (0x237e0 → 0x311c8 → 0x31074 → SEB 0x36dcc), or
only later inside the ROM handoff 0xb2? If the latter, no xloader-side orchestration can produce a
readable stock plaintext and sub-goal C is dead.

---

## 1. Evidence base

The decrypted factory fastboot carries the complete `readelf -s` symbol table of `fastboot.elf`
as text appended to the image:

| Item | Value |
|---|---|
| Symbol-table text start | VA 0x16b8b000 (file 0x38b000) |
| Size | 2,271,016 bytes, 24,326 parsed symbols, addresses 0x16800000–0x16bee000 |
| First line | `…/FASTBOOT_OBJ/fastboot/bootable/bootloader/hilegacy/bin/fastboot.elf: file format elf64-littleaarch64` |

Every handler name below is the vendor's own, taken from that table.

Image header (file 0x0–0x33):

   0x16800000  0d 00 00 14 …        ; 8 x "b #0x34" (AArch64 vector table)
   0x16800020  00 00 80 16          ; 0x16800000 (base / self address)
   0x16800024  "BOOTMAGICNUMBER!"   ; 16-byte handoff magic
   0x16800034  e0 03 1f aa          ; mov x0, xzr (entry, reached through the vectors)

Execution context: `hisi_configure_mmu` (0x1680044c) calls `enable_mmu_el3` (0x16800a34) at
0x168004c4 and builds its map from `hisi_mmap` (0x169926c0) via `mmap_add` (0x168008d8) →
`mmap_add_region` (0x16800750). **The factory fastboot runs at EL3 with its own translation
tables** — the most privileged AArch64 context on the device, and the reason it can read the DRAM
window that the 32-bit loader cannot.

---

## 2. Command dispatch map

### 2.1 Main fastboot command table — 0x16b13568, 12 entries, stride 0x18

Entry layout: { char *name; u64 len_plus_1; u64 handler; } (len includes the NUL; dispatch
compares len-1 bytes).

| # | VA | Name | len+1 | Handler | Purpose |
|---|---|---|---|---|---|
| 0 | 0x16b13568 | signature | 0xa | 0x1680b6d0 `usbcmd_sign_func` | signing/attest request |
| **1** | **0x16b13580** | **upload_memory:** (str @0x169baba8) | **0xf** | **0x1680b738 `usbcmd_upload_memory_func`** | **memory → host** |
| 2 | 0x16b13598 | upload_emmc: | 0xd | 0x1680b8c0 `usbcmd_upload_storage_func` | storage dump |
| 3 | 0x16b135b0 | upload_storage: | 0x10 | 0x1680b8c0 (same) | storage dump |
| 4 | 0x16b135c8 | dump: | 0x6 | 0x1680b398 `usbcmd_dump_func` | register/param dump, not memory |
| 5 | 0x16b135e0 | ultraflash: | 0xc | 0x16825b24 `usbloader_ultraflash_cmd_func` | factory flash path |
| 6 | 0x16b135f8 | "oem " | 0x5 | 0x16815534 `usbcmd_oem_func` | oem sub-dispatch |
| 7 | 0x16b13610 | getvar: | 0x8 | 0x168101dc `usbcmd_getvar_func` | getvar dispatch |
| 8 | 0x16b13628 | download: | 0xa | 0x16826100 `usbcmd_download_func` | host → device |
| 9 | 0x16b13640 | erase: | 0x7 | 0x1680d620 `usbcmd_erase_func` | erase |
| 10 | 0x16b13658 | flash: | 0x7 | 0x16826340 `usbcmd_flash_func` | flash |
| 11 | 0x16b13670 | reboot | 0x7 | 0x1680b1a8 `usbcmd_reboot_func` | reboot |

Walker: `usb_rx_cmd_complete` (0x1680bc18). Table walk 0x1680bd74–0x1680bddc
(`adrp 0x16b13000` + `add #0x568` → 0x16b13568; bound `add x21,x19,#0x120` at 0x1680bd8c).
Handler invocation 0x1680be84–0x1680be98:

   0x1680be84  ldr  w0,[x19,#8]     ; len+1
   0x1680be8c  sub  x0,x0,#1        ; len-1
   0x1680be90  add  x0,x2,x0        ; cmd + (len-1)  <-- argument pointer
   0x1680be94  blr  x1


### 2.2 Pre-dispatch gate (fastboot_ctrl)

   0x1680bcb0  adrp x0,#0x169b8000 ; 0x169b8918 = "fastboot_ctrl"
   0x1680bcb8  bl   get_operators            ; 0x16970e44
   0x1680bcc4  ldr  x1,[x21,#0x10]           ; ops->[0x10]
   0x1680bcc8  blr  x1                       ; fastboot_cmd_lock_state_chk
   0x1680bcd0  cbz  w0, <"Command not allowed">   ; 0x169b89a0
   0x1680bcdc  ldr  x4,[x21,#0x18]           ; ops->[0x18] fastboot_unlock_execute_func
   0x1680bcf8  blr  x4
   0x1680bcfc  cmp  w0,#0xff                 ; 0xff -> fall through to the table

Operator record: name 0x169b8918, vtable 0x16b141b0 — +0x00 `get_lock_state_string`,
+0x08 `get_lock_state_for_verifyboot`, +0x10 `fastboot_cmd_lock_state_chk` (0x16815f84),
+0x18 `fastboot_unlock_execute_func` (0x16816360).

`fastboot_cmd_lock_state_chk`:

- 0x16815f9c `ldr w2,[x1,#0x308]; cmp w2,#1` → lock state 1 ⇒ allow everything.
- 0x16815fac … → secondary list (59 entries at [0x16b8a6a8], +0x1d8) ⇒ deny on match.
- 0x16815fd8 `memcmp(cmd,"oem unlock",10)`, 0x16816000 `memcmp(cmd,"flashing unlock",15)`
  ⇒ `check_frp_state` (0x1681cae0).
- 0x16816008–0x1681603c: walk 47 entries at [0x16b8a730] (= 0x16b14018, +0x178) ⇒ deny.

The 47-entry locked-state deny list (0x16b14018) contains `oem lock-state info`,
`oem hwdog certify *`, `flash:slock`, `reboot`, `download:`, `oem get-bootinfo`,
`oem check-rootinfo`, `oem check-image`, `oem unlock`, `oem relock`,
`flashing unlock/lock`, the `rescue_*` getvars, `getvar:max-download-size`,
`oem emmc_diag`, `oem emmc-dump`, `oem get_key_version`, `oem frp-*`,
`oem device info`, `oem oeminforead`, …

**`upload_memory:` and `dump:` are not in it**, and lock state 1 short-circuits to allow before
the list is consulted.

### 2.3 oem sub-dispatcher — `usbcmd_oem_func` (0x16815534)

Two tables, evaluated in order, both {name, len+1 (u64), handler} stride 0x18:

- Hidden table 0x16b13990, 50 entries (bound `add x21,x19,#0x4b0` @ 0x1681556c):
  fastboot_watchdog, boot, read_bsn, read_die_id, read (→0x168112a0), write (→0x168112a8),
  onchiprom_download, wrefuse, rdefuse, efuse_, ufs_test, ufs_vcmd, rw, wr, memcpy_count,
  watchdog, ramdump, set_reserved_mem, ftrace, dmsspt, ddr_para, jtagtosd, djtagtosd,
  enable_kaslr, disable_kaslr, uart6tosd, coresight, led_vibrator_test, dmatest,
  get_current_slot, set_current_slot, set_hisee_dflag, hhee, get_noboot_reason, seccfg,
  format_rpmb, ddrtest, lowpower, ddrdump, dump_kimage, get_kimage_size, enter_recovery,
  erase_storage_all, get-build-number, hisee_mntn, get_socid, uart, battery_present_check,
  get_flash_count, get_nv_count.
- Public table 0x16b14908, 21 entries (count from `get_tbl_oem_pub_size` 0x1681ff5c, GOT
  0x16b896c8): sec_unlock, sec_relock, get-lockstate, get-product-model, get-psid,
  "device info", oeminforead/write/erase, getencryptsn, …

`oem read` / `oem write` / `oem rw` / `oem wr` are storage reads/writes through a
registered string operator (`get_operators` 0x169b6d38, callbacks at ops+0x18/+0x20), not
memory reads.

### 2.4 Getvar tables

Local 0x16b13780, 19 entries (version, product, serialno, memory:, memory_num, memory_info_,
storageid, ddrid, nve:, resize, call:, cmd, emmc:, storage:, ptable, max-download-size, chipid,
get_config_lock, set_config_lock). Public 0x16b14b00, 15 entries (count from `get_tbl_getvar_pub_size` 0x16821650 = 0xf: recovery, error_print, bfr:,
rescue_*, vendorcountry, devicemodel, device_validation, system_update_state, dongle_info).

`memory_num` / `memory_info_<0..6>` (`getvar_dump_mem_info` 0x1680ec8c,
`getvar_dump_mem_detail` 0x1680ed0c) enumerate the runtime memory map — the clean way to pick the
second buffer in §6.

### 2.5 Unlock-flow table — 0x16b141f0 (the table named in the brief)

15 entries, **stride 0x10**, { char *command; void *handler; }, consumed by
`fastboot_unlock_execute_func` (0x16816360) through `unlock_cmd_str_seek` (0x168162ec) and the
GOT slot 0x16b89548 (0x168163c4–0x168163d0; `sbfiz x2,x0,#4` confirms the 16-byte stride):

| # | VA | Command | Handler |
|---|---|---|---|
| 0 | 0x16b141f0 | oem lock-state info | 0x168226c8 |
| 1 | 0x16b14200 | oem hwdog certify begin | 0x168227b8 |
| 2 | 0x16b14210 | oem hwdog certify enc begin | 0x16822a28 |
| 3 | 0x16b14220 | flash:slock | 0x168231bc |
| 4 | 0x16b14230 | oem hwdog certify close | 0x168234dc |
| 5 | 0x16b14240 | oem get-bootinfo | 0x16816204 |
| 6 | 0x16b14250 | oem check-rootinfo | 0x16824228 |
| 7 | 0x16b14260 | oem check-image | 0x16816488 |
| 8 | 0x16b14270 | oem unlock | 0x16823884 |
| 9 | 0x16b14280 | oem relock | 0x16823ba8 |
| 10 | 0x16b14290 | flashing unlock | 0x16823884 |
| 11 | 0x16b142a0 | flashing lock | 0x16823ba8 |
| 12 | 0x16b142b0 | oem hwdog certify set | 0x168235f8 |
| 13 | 0x16b142c0 | oem frp-erase | 0x16823f20 |
| 14 | 0x16b142d0 | oem frp-unlock | 0x16824044 |

The table ends at 0x16b142e0, where the unrelated KTVendor/SYSTEM_VERSION descriptor table begins.
This is a command → special-flow override table, not the general command table: wrong insertion
point for a dump command.


---

## 3. The memory-dump primitive already in the image

`usbcmd_upload_memory_func` (0x1680b738, 392 B):

   0x1680b74c  bl  hex2unsignedlong      ; parse "<addr>[:...]" -> x20 = address
   0x1680b754  and x0,x0,#3
   0x1680b758  cbnz x0,<"address 0x%x is invalid">   ; 0x169b82e0 ; ALIGNMENT only
   0x1680b75c..0x1680b79c  scan to ':'  (error: 0x169b8358 "can't get length")
   0x1680b7a4  parse after ':'           ; x21 = length
   0x1680b7c0  usbcmd_common_ack("OKAY", 2)          ; tx_status only
   0x1680b7f0  log "usbloader: sending %d bytes to pc, start addr is 0x%lx"
   0x1680b7f4  mov w1,w21 ; mov x0,x20
   0x1680b7fc  bl  tx_data
   0x1680b828  usbcmd_common_ack("OKAY", 0)          ; second OKAY + rx_cmd

`tx_data` (0x1680ab1c):

   0x1680ab48  ldr  x20,[x0]            ; usb device struct
   0x1680ab64  sub  w2,w21,w19          ; remaining
   0x1680ab6c  cmp  w2,#8, lsl #12      ; chunk = min(remaining, 0x8000)
   0x1680ab78  str  x0,[x20,#8]         ; descriptor.address
   0x1680ab7c  str  w2,[x20,#0x10]      ; descriptor.length
   0x1680ab9c  blr  x2                  ; ops->tx(device, descriptor)

Wire form: `upload_memory:<hex addr>:<hex len>` on the bulk-OUT command endpoint; device answers
OKAY, then len raw bytes on bulk-IN, then OKAY. Constraints in code: address must be 4-byte
aligned (0x1680b754); **no upper bound, no range check, no whitelist, no lock-state dependency**;
transfers are chunked at 0x8000.

Caveat: the alignment test is applied to the parsed address, and `hex2unsignedlong` must accept
whatever prefix the host sends. Use a 16-byte read first to settle both details.

`dump:` (`usbcmd_dump_func` 0x1680b398) is not a memory dump: it parses two whitespace tokens,
calls `str2value` and formats a two-field register/parameter report.

---

## 4. Patch plan for a memory-dump command

### 4.1 P0 — no patch (recommended)

Use `upload_memory:` as shipped. Nothing to change, nothing to re-validate against the boot chain.

### 4.2 P1 — rename only (if a memdump name is required)

15-byte .data edit, identical length, no relocation, no code change:

| File offset | VA | Now | Proposed |
|---|---|---|---|
| 0x1baba8 | 0x169baba8 | upload_memory: + NUL | mem_dump_data: + NUL (14 chars + NUL) |

The dispatcher compares len-1 = 14 bytes; the visible command becomes
`mem_dump_data:<addr>:<len>`. Keep the length identical or also patch the len field at
0x16b13588 (currently 0xf).

### 4.3 P2 — a real new oem memdump subcommand (not recommended)

The hidden oem table has no free slot: it ends at 0x16b13e40, where an unrelated array of command-name pointers begins.
Adding an entry means moving that array, or extending the loop bound at 0x1681556c
(`add x21,x19,#0x4b0` → `#0x4c8`) and relocating data. The image does contain large zero runs
(first: 0x168011d0, 0x630 bytes) usable as a cave, but the new handler would be a copy of
0x1680b738 with no added capability.

Architectural conclusion: the smallest, deepest interface already exists. A parallel command would
be pure accidental complexity; if the name must change, P1 is the whole change.


---

## 5. Is a patched factory fastboot accepted? (pwn / ROM / xloader)

### 5.1 The VCOM download path performs no image verification

    main 0x2316c
     0x2326c  bl 0x24178            ; [0x60053000] SATE-aging gate
     0x23270  cbnz r0,0x23276
     0x23272  bl 0x2391c            ; boot-mode dispatch
     0x23276  bl 0x23fb4            ; status bit |= 0x20000000
     0x2327a  bl 0x2ef8c            ; staging finalize (no verification call inside)
     0x2327e  movs r0,#0x19 ; bl 0x35f5c     ; progress
     0x23284  bl 0x23fe4            ; clock/status cleanup (no verification call inside)
     0x23288..0x2329a               ; ROM handoff

    0x2391c:
     0x23926  bl 0x23f1c            ; boot-mode register -> r5
     0x2392e  bl 0x30f28            ; storage probe (&type_byte) -> 0 ok / -1
     0x2394a  cmp r5,#1
     0x2394c  bne 0x23988           ; <-- DOWNLOAD MODE (the pwn path)
     0x23956  bl 0x237e0            ; <-- NORMAL PATH: read VRL + fastboot + verify
     0x23988  poll 0x2f8c0(0) until it returns 0x16800000
     0x239ac  12 bytes of 00 46 NOPs (loop exit, free space)
     0x239b8  epilogue / return

Mode gate `0x23f1c`: reads a register via 0x242a8, masks ~0xfff, compares with 0x3670e000
(literal @0x23f50) and 0x3670a000 (literal @0x23f54) → 1 ("flash boot mode"); otherwise returns [0x4020a40c] & 1 (literal @0x23f58).

Download parser 0x2f918 — the path that receives the factory fastboot:

| Stage | VA | Behaviour |
|---|---|---|
| Frame CRC | 0x2f9c6 `cmp sl,lr` | CRC-16/XMODEM over the frame only (error string @0x3e306) |
| Head frame | 0x2fa3a–0x2fac8 | requires type in {1,2} (0x2fa48–0x2fa52, byte at ctx+0x3db), size BE @ctx+0x3dc, address BE @ctx+0x3e0; **no range check** |
| Data frame | 0x2fb5c–0x2fb6c | `memcpy(dest + n*0x400, ctx+0x3db, 0x400)` via 0x23a2a — destination taken verbatim from the head frame |
| Tail frame | 0x2fba2, 0x2fc3a | clears the download state, ACKs, returns 0 |

**Verification reachability proof** (static BL-target scan over the code region):

| Callee | Callers |
|---|---|
| 0x311c8 (verify wrapper) | 0x233c0, 0x2346c, 0x234ce, 0x238c4 |
| 0x31074 (`seb_img_verification`) | 0x311e6 (only) |
| 0x36dcc (SEB submit) | 0x31116 (only) |

0x238c4 is inside 0x237e0, whose only callers are 0x2395e and 0x2396e — the mode-1 branch. The
other three are in the storage-image helper cluster (0x23328–0x234ce) reached from the same path.
Therefore **no route exists from the download branch (0x23988) to any signature verification**, and
0x2ef8c / 0x23fb4 / 0x23fe4 contain none either.

Corollary: this bootloader's untrusted-input boundary is the frame CRC, not the image.

### 5.2 What is still unknown

   0x23288  mov.w r2,#0x2e000 ; movs r3,#5 ; stm sp,{r2,r3}
   0x23292  ldr  r0,=0x8e200000        (literal @0x232b0)
   0x23296  ldr  r2,=0xfff50000        (literal @0x232b4)
   0x23298  movs r3,#0
   0x2329a  blx  r4                    ; r4 = 0xb3  (0x23f70: movs r0,#0xb3)
   0x2329c  ldr  r0,="fst err" ; 0x232a4 b .

r0=0x8e200000, r2=0xfff50000, stack args 0x2e000 / 5. No entry pointer is passed, consistent with a
**fixed handoff address 0x16800000** (matching the 0x16800000 word at 0x16800020 and
BOOTMAGICNUMBER! at 0x16800024). Hypothesis, not proof: the ROM service at VA 0xb2 is not part of
any artifact we hold.

Hypothesis H1: 0xb2 validates only the magic and jumps. The test below decides it.

### 5.3 Harmless acceptance test (RAM only — no writes, no flash)

Patch: one byte in a string constant, same length, no relocation, no code-path change.

| Item | Value |
|---|---|
| File offset | 0x1baba8 |
| Before | 75 70 6c 6f 61 64 5f 6d 65 6d 6f 72 79 3a 00 (upload_memory:) |
| After | 75 70 6c 6f 61 64 5f 6d 65 6d 6f 72 78 3a 00 (upload_memorx:) |

Sequence (later, with explicit approval; VCOM/RAM only):

1. Copy `artifacts/hisi970_fastboot_ram.bin` → `reports/fastboot_patchtest.bin`; apply the
   one-byte change; record sha256; `cmp -l` the two files (expect exactly one differing byte).
2. Run the ordinary hisi970 Kirin-Tool sequence up to and including the FASTBOOT stage with the
   patched image (same head frame, address 0x16800000, type 1, same VCOM data frames; the DTL
   container is only an on-disk wrapper, the wire payload is plaintext).
3. `fastboot devices` must enumerate.
4. Send `upload_memory:16800000:10` → **expect FAIL / unknown command** (the name no longer
   exists).
5. Send `upload_memorx:16800000:100` → **expect OKAY, 256 bytes** starting
   0d 00 00 14 0c 00 00 14 …, with BOOTMAGICNUMBER! at offset 0x24, then OKAY.

| Observation | Conclusion |
|---|---|
| Boots, new name answers, old name fails | Patched image accepted and the patch provably executes. H1 confirmed. |
| Boots, both names answer | Host tool uploaded the unpatched image; fix the tool, not the theory. |
| Boots, neither answers | Patch not applied / wrong offset. |
| No enumeration | Either 0xb2 rejected the image or the upload failed; repeat unpatched to separate the two. |

Rollback: power-cycle; re-run the stock sequence. Nothing is written to storage.


---

## 6. Stock-plaintext orchestration (the buffer question)

### 6.1 Why a separate buffer is required

- The factory fastboot must occupy 0x16800000 because the ROM handoff address is fixed (§5.2).
- The stock image must therefore be materialised elsewhere and read afterwards by the fastboot.

### 6.2 The stock read path as it exists today (mode 1 only)

    0x237e0(backup=0, mode=2, size=0)      ; called from 0x23956 / 0x23966
     0x237ec  bl 0x30ef4(name,0x22)        ; VRL partition/offset 0x22000
     0x23838  ldr r3,=0x16dfe000           ; literal @0x238ec -> VRL buffer
     0x2384a  bl 0x24e14(name,?,...,dest=0x16dfe000,size=0x1000,0)
     0x23896  bl 0x235f4(size)             ; stock image read
                0x23648  mov.w r3,#0x16800000   ; 4 bytes: 4f f0 b4 53
                0x23650  str r3,[sp]            ; dest argument
                0x2365e  bl 0x24e14("fastboot",0,0,0,dest,size,0)
     0x238c4  bl 0x311c8(...,vrl,img)      ; -> 0x31074 -> SEB 0x36dcc

`0x235f4` semantics (verified): size==0 ⇒ read the maximum 0x5fe000 (literal 0x5fe000 at 0x2368c,
`cbz r5` at 0x23600); size rounded to 0x200 at 0x23612–0x2361a.

### 6.3 Proposed xloader patch (RAM image only; two sites)

**P-A — destination redirect (4 bytes at file 0x1648, VA 0x23648)**

    before: 4f f0 b4 53    mov.w r3, #0x16800000
    after : 4f f0 XX XX    mov.w r3, #<B>   ; B must be modified-immediate encodable, 4 KiB aligned

0x23648 is the only place the fastboot destination is materialised (no literal pool, no table).
This also redirects the normal boot path — acceptable for a RAM-only experiment, but it is a
deliberate trade: the patched loader loses the stock boot path.

**P-B — perform the stock read in the download branch (12 bytes at file 0x19ac, VA 0x239ac)**

The 12 bytes at 0x239ac–0x239b7 are 00 46 x 6 (`mov r0,r0`, i.e. NOPs) and sit only on the
success exit of the download-wait loop (0x239a2 `beq 0x239ac`). The whole call fits in place:

    0x239ac  00 20        movs r0, #0        ; backup selector = 0 ("vrl")
    0x239ae  02 21        movs r1, #2        ; same mode value as the normal path (0x23958)
    0x239b0  00 22        movs r2, #0        ; size 0 = use the 0x5fe000 maximum
    0x239b2  00 bf        nop                ; padding
    0x239b4  ff f7 14 ff  bl   0x237e0      ; read VRL + stock image to B, then verify
    0x239b8  <unchanged epilogue: add sp,#0xc ; pop {r4,r5,pc}>

The 12 free bytes are 0x239ac–0x239b7; the epilogue at 0x239b8 must not move. The encoding
ff f7 14 ff decodes (capstone, Thumb) as `bl #0x237e0` at 0x239b4 — target = 0x239b4 + 4 - 0x1d8.
Re-assemble and re-verify both the encoding and the byte budget before use.

Why 0x237e0 and not 0x235f4: 0x237e0 is the full read+verify sequence and the only candidate site
for an in-place decrypt. Its three arguments are exactly those the mode-1 path passes (0x23956–
0x2395e: r0 = storage probe result = 0, r1 = 2, r2 = 0).

### 6.4 Choosing B

| Candidate | Rationale | Risk |
|---|---|---|
| 0x16000000 (8 MiB below the factory image) | contiguous, no overlap with 0x16800000–0x16dfe000 | unproven that 0x24e14 and the EL3 map cover it |
| 0x16dfe000 (VRL buffer) | known to the loader | only 0x1000 B — too small, and destroyed by the VRL read |
| 0x16d80000–0x16dfe000 | inside the known window | about 0x7e000 B — too small |

Do not guess B. Two on-hardware sources of truth: `upload_memory:16800000:20` first (proves the
primitive), then `getvar memory_num` / `getvar memory_info_<0..6>` to enumerate the live map,
then confirm the chosen region with a 16-byte read before the orchestration run.

### 6.5 Handoff constraints to preserve

- 0x23270 (`cbnz r0`), 0x2394c (`bne`), 0x2329a (`blx r4`) stay as-is: the factory fastboot
  has to run.
- The AArch64 handoff is the ROM service 0xb2; r4 = 0xb3 (0x23f70), args as in §5.2.
- Do not patch 0x2329a to a spin (the earlier hold-loop line of work); this plan needs the handoff.

### 6.6 Decrypt-timing analysis (the decisive unknown)

| Fact | Evidence |
|---|---|
| The partition's first 0x36c8c0 (3,590,336) bytes are an 8.0 bit/byte blob | `artifacts/fastboot.stock.payload.img`, entropy over the first MiB |
| The partition dump begins with exactly that blob | `fastboot.dump.img[0:0x36c8c0] == fastboot.stock.payload.img` (byte-identical) |
| The loader reads from partition offset 0 up to 0x5fe000 | 0x2365c (r2=0), 0x2368c (0x5fe000) |
| The plaintext image is 0x5b5800 (5,986,304) — 1.67x larger than the blob | `artifacts/hisi970_fastboot_ram.bin` |
| The stock fastboot does boot through this path | STATUS.md / notes/FINDINGS.md hardware evidence |

A readable 5.98 MiB image cannot come out of a 3.59 MiB high-entropy blob by memcpy. Something
between 0x24e14 and the handoff must decrypt and decompress in place. The only candidate in the
visible path is the verify sequence 0x237e0 → 0x311c8 → 0x31074 → SEB, which hands the secure core
a store address (0x36ea0 called from 0x310da).

Hypothesis H2 (leaning yes): the SEB verify step materialises the plaintext at the destination
buffer. If H2 holds, P-A + P-B are sufficient. If H2 fails (decrypt happens only inside 0xb2),
sub-goal C is not achievable from the 32-bit loader and the option collapses to "dump the factory
fastboot itself" (sub-goal D).


---

## 7. Alternative first: prove the context (task 4)

Zero patch, one command:

    upload_memory:16800000:100
    expected: OKAY, 256 bytes, 0d 00 00 14 0c 00 00 14 ... at +0x00,
              "BOOTMAGICNUMBER!" at +0x24, OKAY

Checks in order:

1. Payload matches `artifacts/hisi970_fastboot_ram.bin[0:0x100]` exactly.
2. `upload_memory:16dfe000:10` (VRL window) returns rather than hanging — the read is not
   limited to the image's own region.
3. A second identical read is byte-identical (stability).

If this works, the "write an AArch64 USB driver" objection in notes/FINDINGS.md (remaining route 2)
is already solved by the shipped image: it is that driver.

---

## 8. Test sequence, risks, rollback

### 8.1 Offline (no device)

1. Recompute every byte quoted here against the artifacts; `cmp -l` each patched file and record
   sha256 of original and patched images.
2. Disassemble each patched region with capstone and assert the intended mnemonics.
3. Assert the xloader diff touches only 0x1648 (4 B) and 0x19ac (at most 12 B).

### 8.2 On-device (later, explicit approval, RAM only)

| Step | Action | Expected |
|---|---|---|
| T0 | Stock factory fastboot, no patch | `fastboot devices` |
| T1 | `upload_memory:16800000:100` | OKAY + 256 bytes matching the artifact + OKAY |
| T2 | `getvar memory_num`, `memory_info_<n>` | region list; choose B |
| T3 | `upload_memory:<B>:10` | not a hang (validates B) |
| T4 | 1-byte rename patch (§5.3) | old name fails, new name answers |
| T5 | xloader P-A + P-B, B from T2 | boot reaches fastboot |
| T6 | `upload_memory:<B>:100` | 0d 00 00 14 ... ⇒ plaintext (H2 true); high entropy ⇒ ciphertext (H2 false) |
| T7 | full dump in 0x10000 chunks | 5.9 MiB, hash, two-pass stability |

### 8.3 Risks

| Risk | Mitigation |
|---|---|
| ROM 0xb2 rejects the modified image, no USB | re-run stock sequence; RAM-only, no persistent change |
| A bad B traps the fastboot (data abort at EL3) | validate B with a 16-byte read (T3) before T5 |
| 0x237e0 behaves differently in download mode (clock/SEB state) | it only reads storage and calls SEB; keep an unpatched loader to A/B the failure |
| The 12-byte site is reached by another path | verified: 0x239ac reachable only from 0x239a2 `beq` |
| Second VCOM upload in one session gets 0 ACKs (STATUS.md) | one experiment per VCOM entry |
| 0x2ef8c runs after the download and may touch staging memory | it targets 0x109c0000 / 0x60053070, not B or 0x16800000 — verify with a read-back |

### 8.4 Rollback

Nothing here writes flash. Recovery = power-cycle, then restore the stock xloader in Kirin-Tool
(already the project state). Patched images live only in `reports/`.

---

## 9. Open questions, ranked

1. **H2 — does 0x237e0/SEB materialise plaintext in the destination buffer?** Decides sub-goal C.
   Cheapest test: T5 + T6.
2. **H1 — does ROM 0xb2 accept a modified image?** Decides whether any patch is usable.
   Cheapest test: T4 (T1 already de-risks the surrounding assumptions).
3. **Which DRAM ranges are mapped and free (choice of B)?** Answerable from the image in T2.
4. Exact byte encoding of the two xloader patches (assemble + verify; the 12-byte budget is tight
   but sufficient).
5. Whether the second OKAY from `usbcmd_upload_memory_func` (0x1680b828) must be drained before
   the next command — host-tool detail, observed in T1.

---

## 10. What this changes in the project plan

- notes/FINDINGS.md "remaining routes -> 2. AArch64 code after the ROM handoff ... very large" is
  no longer accurate for the read half: the factory fastboot already contains the driver and a
  memory upload command. The remaining large work is only the stock-plaintext orchestration.
- The xloader read primitive stays dead for DRAM; this option does not revive it.
- If H2 is false, the only remaining route to the stock plaintext is an AArch64 agent that performs
  the SEB decrypt itself from the fastboot context (the image exposes
  `hisi_secboot_decrypt_encrypted_xloader` 0x16989d30 and the SecBoot_* operators) — a
  substantially larger and riskier project than this plan.

*No vendor binaries or keys are reproduced here; only addresses, offsets and instruction encodings
from artifacts already in this repository.*

