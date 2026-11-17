# Option B2b — stock-xloader orchestration (offline patch design)

Status: **offline static analysis and patch design only.** No device was touched,
no VCOM session, no fastboot command, no flash, no partition write. Nothing in
this document is a live result; every claim carries a VA/file offset and the
instruction or artifact field it rests on.

Addressing convention (unchanged from notes/xloader-map.md):

- Xloader: VA = file_offset + 0x22000; artifact artifacts/hisi970_xloader.bin,
  139,264 B (0x22000), sha256 2BB2329D…ACB1691.
- Factory fastboot: VA = file_offset + 0x16800000; artifact
  artifacts/hisi970_fastboot_ram.bin, 5,986,304 B (0x5B5800).
- Stock fastboot partition body: artifacts/fastboot.stock.payload.img,
  3,590,336 B (0x36C8C0).
- Stock write image (plaintext VRL header + body):
  artifacts/FASTBOOT.from-update-app.img, 3,594,432 B (0x36D8C0).

---

## 1. Executive feasibility

| Sub-goal | Verdict | Basis |
|---|---|---|
| Put the stock image at a second DRAM buffer **B** | **YES (offline proven)** | 4-byte mov.w at 0x23648; B is modified-immediate encodable and mapped (§5, §6) |
| Make the stock read+verify run in the download branch | **YES (offline proven)** | 12-byte cave at 0x239ac, reachable only from the success edge 0x239a2 (§4.4) |
| Make verification look at B instead of 0x16800000 | **YES, and mandatory** | the verify image pointer is a separate hardcoded literal at 0x238b8 (§4.2) |
| Keep the factory fastboot at 0x16800000 intact | **YES, and mandatory** | 0x237e0 calls 0x23710 → 0x236a8, which DMAs 0x200 B to 0x16800000 on every call; must be disabled (0x23880, §4.3) |
| B receives **decrypted plaintext** | **UNCERTAIN — leaning yes** | the only candidate is the SEB secure path; no CPU write-back exists; EL3 contains a same-shape decrypt API (§6) |

**Bottom line.** The orchestration is implementable and fully verifiable
offline. The brief's two-site plan (P-A + P-B) is **not sufficient**: without
P-C the SEB still points at 0x16800000, and without P-D the patched download
path destroys the factory fastboot header before the handoff. Four sites are
required.

**Single most important unknown:** does the SEB image operation invoked by
0x36dcc (through 0x31074) **write decrypted plaintext back to the store
address** it is given (B after P-C), or does it only hash/verify it? If it is
verify-only, B keeps the ciphertext, and Option B2b cannot produce plaintext —
decryption would have to happen inside ROM 0xB2, which B2b cannot observe.

---

## 2. Evidence base used here

| Fact | Evidence |
|---|---|
| Download branch is taken when 0x23f1c() != 1 | 0x2394a cmp r5,#1; 0x2394c bne 0x23988 |
| The branch waits for 0x2f8c0()==0x16800000 | 0x23998 bl 0x2f8c0; 0x2399c cmp.w r0,#0x16800000; 0x239a2 beq 0x239ac |
| 0x239ac..0x239b7 is a 12-byte cave | six 00 46 (mov r0,r0) at file 0x19ac..0x19b7; epilogue at 0x239b8 |
| The cave has exactly one incoming edge | branch scan of the whole Thumb code region: only 0x239a2 beq 0x239ac |
| Fastboot read destination is materialized once | 0x23648 4ff0b453 mov.w r3,#0x16800000; 0x23650 str r3,[sp]; only 0x23896 bl 0x235f4 calls it |
| Verify image pointer is a second, independent literal | 0x238b8 4ff0b451 mov.w r1,#0x16800000; 0x238c4 bl 0x311c8 |
| 0x237e0 always calls the patch-partition handler | 0x23880 bl 0x23710 (both the boot-type==2 skip and the normal path reach 0x23880) |
| The patch handler DMAs into 0x16800000 before any check | 0x23714 bl 0x236a8; 0x236c4 mov.w r5,#0x16800000; 0x236cc str r5,[sp]; 0x236d6 bl 0x24e14 (dest = 0x16800000, size 0x200, offset 0x400000) |
| Its magic-matching bulk read also targets 0x16800000 | 0x2376c mov.w r3,#0x16800000; 0x23784 bl 0x24e14 (size 0x400000) |
| The generic read has no crypto context | 0x24e14: dest at [sp,#0x58] (0x24e1a), 4-byte alignment test (0x24e1e), raw driver call blx r8 with dest/size (0x24eae..0x24eb6) |
| Verify chain | 0x311c8 (0x311e2/0x311e6) → 0x31074; 0x31074 (0x310da bl 0x36ea0, 0x31116 bl 0x36dcc) |
| SEB submit has one caller | 0x31116 bl 0x36dcc only |

Exact caller sets (whole-code scan, 2-byte aligned Thumb):

~~~
0x237e0 <- 0x2395e, 0x2396e          (mode-1 path only)
0x23710 <- 0x23880                    (only)
0x236a8 <- 0x23714                    (only)
0x235f4 <- 0x23896                    (only)
0x311c8 <- 0x233c0, 0x2346c, 0x234ce, 0x238c4
0x36dcc <- 0x31116                    (only)
0x239ac <- 0x239a2 beq                (only)
~~~

Only 0x16800000 consumers in the whole image (immediate scan):

~~~
0x232fc  trampoline store (SATE/reserved5 path)      not taken: [0x60053000]==0
0x23380/94/a6/b0  dead legacy 0x23374               unreferenced
0x23648  fastboot read dest                          P-A
0x236c4  patch-probe read dest (0x236a8)             covered by P-D
0x2376c  patch bulk read dest                        covered by P-D
0x238b8  verify image pointer                        P-C
0x2399c  compare against the download sentinel       must not change
0x2410e  SATE patch check (0x2410c)                  not called: gate is 0
0x332aa  fastboot-update helper (0x332e4)            not reachable from 0x2391c
~~~

---

## 3. The flow this patch produces

~~~
main 0x2316c
 0x23260  bl 0x232e8          ; SATE trampoline; returns at 0x23350 because [0x60053000]==0
 0x2326c  bl 0x24178          ; reads [0x60053000] == 0
 0x23270  cbnz r0,0x23276     ; not taken
 0x23272  bl 0x2391c
   0x23926  bl 0x23f1c        ; 0 -> download
   0x2394c  bne 0x23988
   0x23998  bl 0x2f8c0        ; VCOM receiver; FASTBOOT staged at 0x16800000
   0x2399c  cmp r0,#0x16800000
   0x239a2  beq 0x239ac       ; success edge
     0x239ac  P-B stub        ; read VRL + stock image -> B, then verify at B
     0x239b4  bl 0x237e0
   0x239b8  epilogue
 0x23276  bl 0x23fb4          ; status bit only
 0x2327a  bl 0x2ef8c          ; staging finalize (0x109c0000 / 0x60053070)
 0x23284  bl 0x23fe4
 0x2329a  blx r4              ; ROM 0xB2, fixed handoff address 0x16800000
~~~

After P-A/P-C/P-D, the only writes the 0x237e0 subtree can make are:

| Write | Destination | Size | Source |
|---|---|---|---|
| VRL header read | 0x16dfe000 | 0x1000 | 0x23838, 0x2384a |
| Stock image read | **B** | up to 0x5FE000 | 0x23648 (P-A), 0x2365e |
| SEB materialization (if any) | **B** | 0x36C8C0 | descriptor from 0x36ea0 |
| Patch-partition probe/bulk read | disabled | — | 0x23880 (P-D) |

Nothing in the subtree writes 0x16800000 any more.

---

## 4. Patch sites and exact bytes

All four sites are inside the stock image; the base image is the **pristine
stock xloader**, not the read-primitive image (rationale in §10).

### 4.1 P-A — stock read destination → B

~~~
VA 0x23648   file 0x1648
before: 4f f0 b4 53    mov.w r3, #0x16800000
after : 4f f0 b0 53    mov.w r3, #0x16000000
                      (only file byte 0x164A changes)
~~~

Evidence: 0x23648 materializes the destination; 0x23650 str r3,[sp] passes it
as argument 0 to 0x24e14; 0x24e1a reads it back as r6 and 0x24eae str r6,[sp]
places it in the driver call. 0x23648 is the only site that feeds 0x235f4's
destination.

### 4.2 P-C — verify image pointer → B (missing from the brief)

~~~
VA 0x238b8   file 0x18B8
before: 4f f0 b4 51    mov.w r1, #0x16800000
after : 4f f0 b0 51    mov.w r1, #0x16000000
                      (only file byte 0x18BA changes)
~~~

Evidence: 0x238c4 bl 0x311c8 takes r0 = 0x16dfe000 (VRL) and r1 = image.
0x311c8 forwards r1 unchanged to 0x31074 (0x311e2 / 0x311e4 / 0x311e6);
0x31074 saves it in sb (0x3107c) and feeds it to 0x36ea0 as the store address
(0x310bc mov r6,sb; 0x310d4 mov r2,r6; 0x310da bl 0x36ea0). 0x36ea0 is a
4-byte trampoline (b.w 0x37008); 0x37008 writes the 8-byte pair into the
selected certificate entry (0x3700e strd r2,r3,[sp]; 0x3705e..0x37062 writes
8 bytes, preserving the 4-byte length at +8).

Without P-C the store address stays 0x16800000, so after P-B the SEB would
hash/verify the **factory fastboot** instead of the stock image. That is a
guaranteed verification failure (0x238cc movs r0,#0x93 → 0x36294 reboot) in
the best case.

### 4.3 P-D — disable the patch-partition handler (missing from the brief)

~~~
VA 0x23880   file 0x1880
before: ff f7 46 ff    bl #0x23710
after : 4f f0 ff 30    mov.w r0, #-1
~~~

Evidence and necessity:

- 0x237e0 calls 0x23710 unconditionally at 0x23880 (both the r6==2 shortcut at
  0x23866 and the normal path converge there).
- 0x23710 immediately calls 0x236a8 (0x23714).
- 0x236a8 **always** DMAs 0x200 bytes from partition offset 0x400000 to
  0x16800000 (0x236c4 dest, 0x236cc str r5,[sp], 0x236d6 bl 0x24e14) and only
  afterwards copies the block to its stack buffer (0x236e2/0x236e4) for the
  magic compare. The read itself is enough to overwrite the factory fastboot
  vector table and the BOOTMAGICNUMBER! word at +0x24.
- If the magic matched, it would additionally read 0x400000 bytes into
  0x16800000 (0x2376c, 0x23784).

Returning -1 makes 0x23884 cbnz r0,0x23894 take the "read the image" path
(0x23894 ldr r0,[sp,#0x14]; 0x23896 bl 0x235f4), which is exactly what B2b
needs. Trade-off: the stock normal-boot patch-partition step is disabled in
this RAM-only image. It is never reached in the download branch anyway.

### 4.4 P-B — run the stock read+verify from the download branch

~~~
VA 0x239ac   file 0x19AC   12 bytes, exactly the cave
before: 00 46 00 46 00 46 00 46 00 46 00 46   (6 x mov r0,r0)
after : 00 20              movs   r0, #0          ; backup selector: "vrl"
        9d f8 07 10        ldrb.w r1, [sp, #7]    ; same SEB config byte the mode-1 path uses
        00 22              movs   r2, #0          ; size 0 -> 0x5FE000 maximum
        ff f7 14 ff        bl     #0x237e0
~~~

Byte budget: 2 + 4 + 2 + 4 = **12 bytes**, ending at 0x239b7; 0x239b8 is the
untouched epilogue (add sp,#0xc; pop {r4,r5,pc}).

Why ldrb.w r1,[sp,#7] instead of the brief's movs r1,#2:

- 0x2391e..0x23922 seeds [sp+7] = 2 and passes r4 = sp+7 to 0x30f28.
- 0x30f28 rewrites it with the SEB configuration byte (0x30f2a default 2;
  0x30f42 error 3; 0x30f60 0; 0x30f82/0x30f84 2 or 1).
- The mode-1 path passes exactly [sp+7] as r1 to 0x237e0 (0x23958 ldrb.w
  r1,[sp,#7]; 0x2395e bl 0x237e0).
- Hardcoding 2 would silently change the boot-type argument if this unit
  reports a different SEB configuration. Both variants fit the 12 bytes; the
  faithful one is recommended.

Branch math: BL at 0x239b4 computes 0x239b4 + 4 + (-0x1D8) = 0x237E0. Two
independent encoders agree:

- clang/LLVM (armv7-none-eabi, Thumb-2) emits f7ff ff14 → bytes ff f7 14 ff
  for a resolved local label at 0x237e0;
- capstone decodes ff f7 14 ff at 0x239b4 as bl #0x237e0.

(Note: BL has four equivalent S/J1/J2 bit patterns for a given offset;
f023 fbf0 was an unrelocated assembly artifact and is **not** used.)

r0 = 0, r2 = 0 reproduce the mode-1 arguments exactly (0x23956 mov r0,r4 with
r4 = 0x30f28() = 0; 0x2395c mov r2,r4 = 0). The return value in r0 is the verify
result; 0 propagates through 0x239b8 back to main.

### 4.5 Offline verification receipt

Assembled with clang 21 (--target=armv7-none-eabi -mthumb), decoded with
capstone 5.0.7, applied to a copy of the stock image:

~~~
stock    sha256 2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691
patched  sha256 E2EE3796AD60D4D8771D5519454A834116FCEEFA15863C7B3D8E25745C18275D

VA 0x23648  file 0x1648  4ff0b453 -> 4ff0b053   mov.w r3, #0x16000000
VA 0x238b8  file 0x18B8  4ff0b451 -> 4ff0b051   mov.w r1, #0x16000000
VA 0x23880  file 0x1880  fff746ff -> 4ff0ff30   mov.w r0, #-1
VA 0x239ac  file 0x19AC  004600460046004600460046
                              -> 0020 9df80710 0022 fff714ff
                                 movs r0,#0 / ldrb.w r1,[sp,#7] / movs r2,#0 / bl #0x237e0

differing bytes: 16 of the 24 patched bytes, all inside the four ranges
0x1648..0x164B, 0x1880..0x1883, 0x18B8..0x18BB, 0x19AC..0x19B7
~~~

All assertions (original bytes, equal instruction lengths, branch target, diff
containment) passed. Nothing else in the image changes.

Alternates, same structure:

| Variant | Patched sha256 |
|---|---|
| B=0x10000000, faithful r1 | 45B888D25AC619E1152248D66E93F0DE60C3E9B90E51470BA9C0902F18E8345D |
| B=0x16000000, brief's movs r1,#2 + nop | C5839010D1E00E35FFFA504BEF7256C9DB3853AE812059704D2550B646D27539 |

---

## 5. Buffer B selection

### 5.1 Requirement

- capacity >= 0x5FE000 (the 0x235f4 maximum; literal at 0x2368c, cbz r5 at
  0x23600, rounding at 0x23612..0x2361a);
- 4-byte aligned for 0x24e14 (0x24e1e lsls r7,r6,#0x1e);
- modified-immediate encodable for mov.w r3/r1 (4-byte patch budget);
- no overlap with the factory fastboot, its stack/heaps, the VRL buffer, the
  SEB staging area or the download scratch.

### 5.2 What the factory fastboot owns (from its own symbol table)

The image carries the full readelf -s text of fastboot.elf starting at
0x16B8B000. Absolute symbols and section sizes give:

| Region | Address | Evidence |
|---|---|---|
| image body | 0x16800000 .. 0x16BEE200 | max symbol end 0x16BEE200 (xlat_tables 0x16BD6000+0x18000, l1_xlation_table 0x16BEE000+0x200); .bss ends 0x16BD5170 |
| boot stack | 0x16DC0000, 8 KiB | BOOTLOADER_STACK; CPU_STACK_SIZE = 0x2000 |
| heap cache | 0x16E00000 .. 0x187FFFFF | BOOTLOADER_HEAP_CACHE(_TOP) |
| heap | 0x18800000 .. 0x1A7FFFFF | BOOTLOADER_HEAP(_TOP) |
| lheap / boot heap | 0x40000000 .. 0x60000000 | BOOTLOADER_LHEAP, BOOTLOADER_HEAP_BOOT |
| VRL staging (xloader) | 0x16DFE000, 4 KiB | 0x23838, 0x2384c |

### 5.3 EL3 translation map

hisi_configure_mmu (0x1680044c) loads the table pointer from GOT 0x16B8A150 →
hisi_mmap = 0x169926C0 and calls mmap_add (0x168004ac). mmap_add (0x168008d8)
walks 0x20-byte entries {pa, va, size, attr}:

~~~
[0] 0x00000000 .. 0x04000000  attr 3
[1] 0x04000000 .. 0x16800000  attr 2     <- B = 0x16000000 lives here
[2] 0x16800000 .. 0x18800000  attr 3
[3] 0x18800000 .. 0x1A800000  attr 2
[4] 0x1A800000 .. 0x40000000  attr 2
[5] 0x40000000 .. 0x60000000  attr 3
[6] 0x60000000 .. 0x7E000000 (its 64-bit size field reads 0x1E0000001; the
    adjacent word contributes the 0x1; intended size is 0x1E000000 — anomalous, unused)
[7] terminator {0,0,0,0}
~~~

Entries [0]–[5] are unambiguous. B is inside entry [1], identity-mapped, so
the EL3 context can read it (already validated live: oem memupload
0x16000000 0x10 returned 16 x 0xFF).

### 5.4 Candidates

| Candidate | Capacity | Overlap | Encodable | Verdict |
|---|---|---|---|---|
| **0x16000000** | 8 MiB free, B+0x5FE000 = 0x165FE000, 2 MiB gap | none (§5.5) | 4f f0 b0 53 / 4f f0 b0 51 (imm8 0xB0, rot 3) | **chosen** |
| 0x10000000 | far below | none | 4f f0 80 53 / 4f f0 80 51 | fallback; farther from any proven loader write |
| 0x16E00000 | — | **collides with BOOTLOADER_HEAP_CACHE** | yes | reject |
| 0x16DFE000 | 0x1000 only | VRL staging | yes | reject (too small) |
| 0x16800000 | — | factory fastboot | yes | reject (occupied) |
| 0x16600000 | 0x5FE000 fits (0x16BFE000) | none | not obviously encodable as one modified immediate | not needed |

### 5.5 Overlap check (computed)

~~~
B = 0x16000000 .. 0x165FE000 (0x5FE000 bytes)
factory fastboot  0x16800000 .. 0x16BEE200   no
fastboot stack    0x16DBE000 .. 0x16DC0000   no
VRL buffer        0x16DFE000 .. 0x16DFF000   no
SEB staging       0x60035000 .. 0x60036000   no
VCOM bounce/dir   0x60053000 .. 0x60054000   no
download scratch  0x109C0000 .. 0x109C1000   no
~~~

### 5.6 Is B writable by the storage engine?

**Unproven, and the main non-crypto risk.**

What is proven:

- 0x24e14 programs the destination verbatim for the storage driver
  (0x24eae..0x24eb6); there is no address-range filter in the wrapper.
- The same engine writes 0x16DFE000 (VRL) and 0x16800000 (fastboot) in the
  stock normal boot; those addresses are in EL3 map entry [2] (attr 3).
- 0x16000000 is in a different EL3 map entry ([1], attr 2) and has no live
  DMA-write evidence.

Static analysis cannot answer bus/TZASC permission for a non-secure 32-bit DMA
master. The test in §8 is the discriminator: a rejected DMA makes 0x24e14
return non-zero, 0x235f4 returns -1, and 0x237e0 reboots with reason 0x92
(0x2389e..0x238aa) — a clean, observable failure, not a hang.

---

## 6. Where the stock image could become plaintext (critical unknown)

### 6.1 The read path is a raw DMA copy

0x237e0 → 0x23896 bl 0x235f4 → 0x23648 (dest) → 0x2365e bl 0x24e14 → driver
call at 0x24eb4..0x24eb6. 0x24e14 has:

- no key/IV/context argument (arguments are name, offset, dest, size);
- a bounce path through 0x60000000 for partial blocks (0x24ee6 mov.w
  r3,#0x60000000, copy at 0x24f0c, second bounce at 0x24f3e);
- no call into the SEB cluster.

So the read itself cannot decrypt: whatever lands at B is the on-disk bytes,
byte for byte.

### 6.2 The verify path hands the image address to SEB as a store descriptor

~~~
0x238b8  mov.w r1, #B              (P-C)
0x238c4  bl 0x311c8
0x311e2  mov r0, r8                ; VRL header 0x16dfe000
0x311e4  mov r1, r7                ; image = B
0x311e6  bl 0x31074
0x3107c  mov sb, r1
0x310bc  mov r6, sb
0x310d4  mov r2, r6                ; store address = B
0x310da  bl 0x36ea0                ; -> 0x37008: {B, 0} into the certificate entry
0x31116  bl 0x36dcc                ; SEB submit, staging 0x60035000 / 0x1000
~~~

0x37008 writes the 8-byte {address, 0} pair and preserves the 4-byte length at
+8 (0x37060 movs r2,#8). The entry shape is {address, 0, length} — one
address, one length, no separate destination. If the SEB writes plaintext, it
must write **in place at that address**.

### 6.3 The descriptor length matches the on-disk body exactly

The only plaintext VRL header artifact we hold (FASTBOOT.from-update-app.img[0:0x1000]) has at 0x874:
00 00 00 00 | 00 00 00 00 | 30 b2 0d 00, i.e. {0, 0, 0x0DB230}. 0x30fb8
copies the 16-byte size record (0x31000..0x3100e) from the VRL header read at
0x22000 (0x237ec) and converts it with
lsls r2,r2,#2 (0x31010..0x31014). Therefore:

~~~
0x0DB230 words x 4 = 0x36C8C0 = 3,590,336 = fastboot.stock.payload.img length
~~~

The descriptor covers the entire on-disk body, and a size-preserving
(non-compressing) decrypt is consistent with the numbers: the pre-symbol part
of the factory image is 0x38B000 (3,715,072) bytes — within 3.5 % of the blob —
while the remaining 2.27 MB of the factory image is the appended symbol text
at 0x16B8B000.

### 6.4 What the 32-bit loader does *not* contain

| Claim | Evidence |
|---|---|
| No CPU write-back loop in 0x237e0/0x311c8/0x31074 | no store to the image pointer appears in any of the three functions; only 0x36ea0 touches the descriptor |
| No AES/SHA constants in the xloader | full-artifact search (notes/seb-analysis.md §3): no S-box, no RCON, no SHA K tables |
| No image-sized staging buffer (4 KiB only) | 0x31110..0x31112 passes 0x60035000 and 0x1000; the buffer is zeroed on status-dispatched returns (0x36E14 per notes/seb-analysis.md) |
| No export/read command | 0x36dcc has one caller; its opcodes are 0x82/0x41/0x42 (hash phases) |

### 6.5 What the AArch64 side contains (the strongest positive evidence)

The factory fastboot's linked secboot library exposes the same recipe under a
decrypt name:

| Symbol | VA | Role |
|---|---|---|
| hisi_secboot_decrypt_encrypted_xloader | 0x16989D30 | allocate buffer → SecBoot_ChangeCompStoreAddr(buf+0x1000) → SecBoot_ImageVerification → return the buffer |
| SecBoot_ChangeCompStoreAddr | 0x169877A4 | rewrites the same 12-byte store entries |
| SecBoot_ImageVerification | 0x16986C0C | SEB verification entry (reads a halfword gate at ctx+0x8e, 0x16986C38) |
| SecBoot_Get_StoreLen | 0x16985B74 | length helper (used at 0x16989D98) |
| aes_decrypt / aes_cipher_decrypt | 0x16817E74 / 0x1698A570 | software AES exists **at EL3**, not in the xloader |
| SecBoot_Check_Storgeaddr | 0x1685E78 | store-address validation |

Note: 0x16989D30 is slot +0x80 of the secboot_ops vtable at 0x16B84940
(0x16B849C0 holds the pointer), so it is a first-class API, not dead code.

At 0x16989DA4..0x16989DE4 the function computes a length, allocates a buffer
(0x16971790), copies the header, sets the store address to allocated + 0x1000
(0x16989DD8), and runs SecBoot_ImageVerification. Returning that buffer only
makes sense if the verification operation materializes the plaintext at the
store address.

### 6.6 Conclusion, stated precisely

- **Proven:** the loader can place the stock bytes at B and make the SEB
  descriptor point at B (P-A + P-C + P-B + P-D).
- **Not proven:** whether that SEB operation writes plaintext back at B.
- **Evidence leans yes:** the EL3 library implements exactly this sequence as
  its "decrypt" primitive and uses a caller-visible output buffer.
- **If it is verify-only:** the ciphertext stays at B, and the only remaining
  decrypt site is ROM 0xB2 (the handoff call at 0x2329a, args r0=0x8e200000,
  r2=0xfff50000, r3=0, [sp]=0x2e000, [sp+4]=5). In that case **B2b cannot
  produce plaintext**, and the report of that outcome is a definitive negative
  for this option.
- **Verification success does not imply plaintext at B.** A hash computed over
  ciphertext, or a transient internal decrypt, can both return success while
  leaving B encrypted. The dump is the only discriminator.

---

## 7. Does the patch change anything else?

| Concern | Finding |
|---|---|
| Normal boot path | Broken on purpose: P-A/P-C redirect it to B, and P-D disables the patch-partition step. This image is RAM-only for the download experiment. |
| ROM handoff | Unchanged: 0x23270, 0x2394c, 0x2329a and the arg setup 0x23288..0x23298 are untouched. |
| SATE gate | Untouched; [0x60053000] == 0 is a verified hardware fact, so 0x232e8 returns at 0x23350 and 0x2410c never runs. |
| Download parser | Untouched; only the success edge is reused. |
| USB state | 0x237e0 runs synchronously between the last ACK and the handoff; USB is not polled during the storage/SEB work (seconds). |
| 0x2ef8c staging finalize | Touches 0x109C0000 / 0x60053070, not B or 0x16800000 (per notes/option-b2-factory-fastboot-dumper.md §8.3 and the 0x2ef8c body). |

---

## 8. Proposed test sequence (RAM only — not executed)

Preconditions: explicit approval; one experiment per VCOM entry; nothing is
written to storage.

| Step | Action | Expected | Interpretation |
|---|---|---|---|
| T0 | Build the patched image from the stock hisi970_xloader.bin; assert the four sites, the 16 changed bytes and sha256 E2EE3796… (§4.5) | all assertions pass | build is correct |
| T1 | Re-wrap the patched image in the Kirin-Tool .ktl container (the VCOM flow uploads xloader.ktl and decrypts it with CryptoUtil.DTL, per tool-reference/FirmwareUnlocker.cs) | container loads | delivery path intact |
| T2 | One VCOM entry: null → patched XLOADER (0x22000, pwn flag) → UCE (0x60049000) → factory FASTBOOT (0x16800000), per tool-reference/VcomFlasher.cs | upload ACKs; no second upload attempt | pwn + download path |
| T3 | fastboot devices | device enumerates | P-B returned success **and** the factory fastboot survived P-D; ROM 0xB2 accepted it |
| T4 | fastboot oem memupload 0x16000000 0x100 b2b_head.bin | 256 bytes | first look at B |
| T5 | Compare with hisi970_fastboot_ram.bin[0:0x100] | match or not | see T4 table |
| T6 | fastboot oem memupload 0x16000000 0x5FE000 b2b_full.bin in 0x10000-byte chunks (the shipped command chunks at 0x8000 internally, 0x1680ab6c) | 6,283,264 bytes, two passes identical | full materialization |
| T7 | Offline: entropy + structure check | see below | verdict |

T4/T5 decision table:

| Head of B | Meaning |
|---|---|
| 0d 00 00 14 0c 00 00 14 …, BOOTMAGICNUMBER! at +0x24 | SEB materialized plaintext at B — **B2b works** |
| high-entropy, no AArch64 vector pattern | SEB is verify-only (or decrypt happens in ROM 0xB2) — **B2b cannot produce plaintext** |
| all 00 / all FF | the read never wrote B (DMA refused or read skipped); check the failure reason (T3 would have failed with a 0x92 reboot) |
| partial/garbage | wrong slot/partition or a partially failed read |

Negative outcomes are still informative and cost one VCOM session:

- device reboots instead of enumerating → verification rejected the redirected
  buffer (0x238cc reason 0x93), which points at the descriptor/B, not at the
  patch plumbing;
- device hangs → not expected from this patch set (no spin, no new loop).

---

## 9. Risks, failure modes, rollback

| Risk | Likelihood | Effect | Mitigation |
|---|---|---|---|
| SEB is verify-only | medium | B holds ciphertext; no plaintext | T4/T5 decides; fall back to B2a |
| SEB rejects the redirected store address | low-medium | reboot at 0x238cc (reason 0x93) | RAM only; re-run stock flow |
| Storage DMA cannot write 0x16000000 | low | 0x24e14 error → 0x235f4 -1 → reboot reason 0x92 | one VCOM session; B is in the same 296 MiB app region as proven writes |
| B overlapped something | very low | fastboot corruption or wrong dump | symbol-table footprint + overlap table (§5.2, §5.5) |
| P-D changes normal boot | certain | stock boot from storage would lose the patch-partition step | RAM-only experiment; stock loader remains installed |
| USB host timeout during the extra storage/SEB work | low | host aborts, device still proceeds | wait for fastboot devices; do not resend frames |
| Second upload in the same VCOM session gets 0 ACKs | known | session wedged | one experiment per VCOM entry (STATUS.md) |

Rollback: power-cycle. Nothing is written to storage; the stock xloader is
already restored in Kirin-Tool. Patched images live only under reports/.

---

## 10. Base image and comparison with B2a

**Base image: pristine stock xloader.** Reasons:

1. The read-primitive images carry unrelated patches (cave at 0x23154, hold
   loop, forced storage load) built for a different purpose; B2b needs the
   normal read+verify path intact, not a read stub.
2. All four sites are in code the read-primitive images also contain; applying
   both patch families would multiply the diff and the failure surface.
3. build/patch_*.py (Windows agent) already targets
   artifacts/hisi970_xloader.bin; the 4-site diff is exactly reproducible.

**B2b vs B2a**

| | B2b (this design) | B2a (EL3 decrypt call) |
|---|---|---|
| Change size | 4 sites / 24 bytes | a new AArch64 command or stub in the 5.9 MB factory image |
| Depends on | SEB materializing plaintext at the store address | hisi_secboot_decrypt_encrypted_xloader (0x16989D30) semantics |
| Runtime context | 32-bit loader, before handoff | AArch64 EL3, full secboot library |
| Failure cost | one VCOM session, reboot | larger build/debug loop |
| Settles the open question | **yes** (the dump is the answer either way) | only after the call is wired |

**Recommendation:** run B2b first. It is the cheapest experiment that either
finishes the extraction or definitively locates the decrypt boundary (ROM 0xB2
vs SEB). If T4 shows ciphertext, B2a is the only remaining route and the
report of that negative result is the input it needs.

---

## 11. Open questions, ranked

1. **Does 0x36dcc's SEB operation write plaintext at the store address?**
   Decides the option. Cheapest test: T4/T5.
2. **Can the storage DMA write 0x16000000?** Low risk, same experiment.
3. **Does the SEB configuration byte ([sp+7]) on this unit equal 2?** The stub
   copies it, so behaviour matches the mode-1 path either way; a different
   value changes the read size (parse vs 0x5FE000) only.
4. **Does 0x235f4's strap check skip the read in a pwn session?** 0x23624..
   0x23646 skips only when the strap is 0x3670e000/0x3670a000; that is exactly
   the value that would have made 0x23f1c() return 1 and prevented the download
   branch. Self-consistent, but worth confirming from the boot log.
5. **Is the active slot fastboot_a or fastboot_b?** 0x3c188 appends _a/_b from
   0x252d0; both are read through the same path, so the patch is slot-agnostic.

---

## Appendix A — apply/verify (reproducible, offline)

~~~python
import hashlib, capstone
BASE = 0x22000
D = open("artifacts/hisi970_xloader.bin", "rb").read()
assert hashlib.sha256(D).hexdigest().upper() == "2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691"

SITES = [
    (0x23648, bytes.fromhex("4ff0b453"), bytes.fromhex("4ff0b053")),  # P-A
    (0x238b8, bytes.fromhex("4ff0b451"), bytes.fromhex("4ff0b051")),  # P-C
    (0x23880, bytes.fromhex("fff746ff"), bytes.fromhex("4ff0ff30")),  # P-D
    (0x239ac, bytes.fromhex("004600460046004600460046"),
              bytes.fromhex("00209df807100022fff714ff")),               # P-B
]

img = bytearray(D)
for va, old, new in SITES:
    o = va - BASE
    assert D[o:o+len(old)] == old
    assert len(old) == len(new)
    img[o:o+len(new)] = new

assert hashlib.sha256(bytes(img)).hexdigest().upper() == "E2EE3796AD60D4D8771D5519454A834116FCEEFA15863C7B3D8E25745C18275D"

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
bl = next(md.disasm(bytes(img)[0x239b4-BASE:0x239b8-BASE], 0x239b4))
assert bl.mnemonic == "bl" and int(bl.op_str.strip("#"), 16) == 0x237E0
open("reports/hisi970_xloader_b2b.bin", "wb").write(img)
~~~

## Appendix B — values used in this note

~~~
stock xloader      0x22000 B   139,264    sha256 2BB2329D…ACB1691
patched (B=0x16000000)                    sha256 E2EE3796…C18275D
factory fastboot   0x5B5800 B  5,986,304  VA 0x16800000
stock body         0x36C8C0 B  3,590,336
VRL store length   0x0DB230 words = 0x36C8C0 bytes
B                  0x16000000 .. 0x165FE000
VRL buffer         0x16DFE000 (4 KiB)
fastboot .bss end  0x16BD5170
xlat tables        0x16BD6000 .. 0x16BEE200
fastboot stack     0x16DC0000 (8 KiB)
fastboot heap cache 0x16E00000 .. 0x187FFFFF
SEB staging        0x60035000 (4 KiB)
download scratch   0x109C0000
~~~

*No vendor binaries or keys are reproduced here; only addresses, offsets and
instruction encodings from artifacts already in this repository.*

