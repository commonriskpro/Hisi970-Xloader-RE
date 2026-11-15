# SEB/HISEE Offline Static Analysis — Kirin 970 xloader

**Artifact:** `artifacts/hisi970_xloader.bin`
**SHA-256:** `2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691`
**Size:** 139,264 bytes (`0x22000`)
**Architecture:** Thumb-2 / ARMv7, stripped
**Addressing:** `VA = file_offset + 0x22000`; `file_offset = VA - 0x22000`
**Scope:** offline, read-only analysis. No device, VCOM, upload, or flash operation was performed.

---

## 1. Executive Summary & Verdict

### Verdict: **NO** — no read/decrypt-only SEB/HISEE command path exists in this artifact.

The xloader's SEB/HISEE interface is a **verification state machine**, not a command interface. It is reached only from the VRL verification wrapper, and every CPU-visible data-bearing operation in that graph is certificate-chain checking or SHA-256 hash-engine programming. There is no caller-supplied command ID, no arbitrary read request, no plaintext write-back, and no buffer large enough to hold the fastboot image.

The decisive facts are:

1. **Single-entry call graph.** `0x36DCC` has exactly one caller (`0x31116` inside `0x31074`). `0x31074` has exactly one caller (`0x311E6` inside `0x311C8`, the `sec verify` wrapper). `0x36EA0` has exactly one caller (`0x310DA` inside `0x31074`). A scan of every 2-byte-aligned Thumb `BL`/`BLX` in the code range and every 32-bit literal found no other callers or function-pointer references.
2. **No command selector.** `0x36DCC` reads the SEB status byte at `0xbdf0fad4` and dispatches on values `0/1/3/5/7`. The caller cannot choose an operation; it supplies three certificate-chain addresses and a 4KB staging buffer.
3. **Verification-only payloads.** The only data-bearing SEB descriptor block is the six-word command at `0xbdf0fe80..0xbdf0fe94` written by `0x39604`. The observed opcode field values are `0x82`, `0x41`, and `0x42`; the same path loads the SHA-256 initial hash constants (H0) from `0x3F820`, identifying a SHA-256 engine. A full-artifact search found no AES S-box and no AES RCON.
4. **The only caller-supplied buffer is input staging, not an output.** `0x31074` passes `r1 = 0x60035000`, `r2 = 0x1000` to `0x36DCC`. `0x36CF4`/`0x36F80`/`0x3718C` copy the terminal VRL block (including its 12-byte store descriptor) into that buffer, and `0x36DCC` zeroes the whole `0x1000` on every status-dispatched return (`0x36E14`). It is a 4KB input/staging scratch; the fastboot image is up to `0x5FE000` bytes (6,283,264), ~1,534 times larger.
5. **`changeStoreAddr` rewrites a source-range address, not data.** `0x36EA0` branches to `0x37008`, which copies the 8-byte pair `{image_address, 0}` into the selected 12-byte certificate store-table entry (`0x3700E`, `0x3705E..0x37062`), preserving the entry's 4-byte length at `+8`. In the real update header the entry is `{0, 0, 0xDB230}` at `0x874`; after the write it is `{0x16800000, 0, 0xDB230}`. This is an `{address, 0, length}` source descriptor, not a plaintext destination. The error string calls the value `store_addr` (`0x3E769`).
6. **The image is read to DRAM and handed off.** The normal path reads fastboot to `0x16800000`, reads the VRL header to `0x16DFE000`, verifies via `0x311C8 -> 0x31074 -> 0x36DCC`, and calls ROM API `0xB2` at `0x2329A`. The post-handoff image is AArch64 and executes from `0x16800000`.

**Bounded caveat.** The SEB/HISEE firmware itself may contain undocumented commands that this xloader never uses. Such commands cannot be enumerated or invoked from this artifact alone. The verdict is about the implemented interface and the code paths present in `hisi970_xloader.bin`: **no read/decrypt/export command path is implemented here.**

**Corollary.** For exportable plaintext, the only context that can both read the `0x16800000` window and exfiltrate it is AArch64 code executing after the ROM `0xB2` handoff. The SEB hash engine can read the image internally for verification, but its only outputs in this graph are status and digest values.

---

## 2. Artifact and Method

### 2.1 Artifact and mapping

| Item | Value | Evidence |
|---|---|---|
| File | `artifacts/hisi970_xloader.bin` | file size `0x22000` |
| SHA-256 | `2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691` | `shasum -a 256` |
| ELF image start | file `0x1000`; entry `0x23154` | ELF header at file `0x1000` |
| Code/data mapping | `VA = file_offset + 0x22000` | first `PT_LOAD`: `p_offset=0x154`, `p_vaddr=0x23154` |
| Code range scanned | `0x23154..0x3C938` | `.text`; string pool starts at `0x3C938` |

The target functions map to file offsets:

| VA | File offset | Function |
|---|---|---|
| `0x36DCC` | `0x14DCC` | SEB status/verify dispatcher |
| `0x31074` | `0x0F074` | `seb_img_verification` wrapper |
| `0x36EA0` | `0x14EA0` | `changeStoreAddr` trampoline (`b.w 0x37008`) |
| `0x37008` | `0x15008` | real `changeStoreAddr` body |
| `0x39604` | `0x17604` | SEB six-word descriptor submit |
| `0x39634` | `0x17634` | SEB hash context init / opcode sequence |
| `0x3F820` | `0x1D820` | SHA-256 H0 constants |
| `0x2329A` | `0x129A` | `blx r4` ROM API `0xB2` handoff |

### 2.2 Tools and conventions

- Capstone 5.0.7 (`CS_ARCH_ARM`, `CS_MODE_THUMB`) and radare2 6.1.6 were used for independent disassembly.
- Listings show VA, raw little-endian instruction bytes, mnemonic, and operands. Capstone prints branch targets with `#`; comments and labels are the author's.
- `[OBS]` marks a direct instruction/data observation; `[INF]` marks an inference. Every inference is tied to an observation.
- The artifact is read-only; no file was modified except this report.

---

## 3. Call Graph and Subroutine Analysis

### 3.1 Verified call graph

```
0x237E0  read VRL header / fastboot image
  |
  +--> 0x235F4  read "fastboot" -> 0x16800000 (max 0x5FE000)
  |
  +--> 0x311C8  sec verify wrapper
         |
         +--> 0x31074  seb_img_verification (VRL, image)
                |
                +--> 0x3102C  optional seb_derive_rndvector
                |      +--> 0x36F2C -> 0x38380  (block engine, 0x1000-byte vector)
                |
                +--> 0x36BFC  FillCert(VRL) -> 0x37124 (TLV parser)
                |
                +--> 0x30D58  seb_vrl_format_check -> 0x36EA4 -> 0x3721C
                |
                +--> 0x36EA0  changeStoreAddr
                |      +--> 0x37008 -> 0x370F0 (header check)
                |                 -> 0x373F0 (8-byte memcpy)
                |
                +--> 0x36DCC  SEB verify dispatcher
                       |
                       +--> 0x37A4C  read status at 0xbdf0fad4
                       +--> 0x37D28  status acknowledge / continue
                       +--> 0x36CF4  3-segment certificate verification
                       |      +--> 0x36F80 -> 0x3718C / 0x3721C
                       |                 -> 0x37304 -> 0x377B8 / 0x37514 / 0x37540
                       |                       -> 0x38DE0  certificate/signature check
                       |                 -> 0x3706C -> 0x375E4  hash loop
                       |                       -> 0x36B58  memcpy callback
                       |                       -> 0x37810 -> 0x39634 (SHA-256 init)
                       |                                  -> 0x378BC / 0x379F0
                       +--> 0x36B6C  single-segment verification
                              +--> 0x3718C / 0x3721C -> 0x3706C -> 0x375E4
```

The important property is the **funnel**: both `0x31074` and `0x36DCC` are single-entry functions in this image. There is no alternate caller, no exported table entry, and no literal function pointer to either.

### 3.2 Cross-reference proof

A scan of all 2-byte-aligned Thumb instructions in `0x23154..0x3C938` for `BL`/`BLX` targets, plus a full-file search for 32-bit literal pointers (with and without the Thumb bit), produced:

| Target | Callers | Literal/pointer xrefs |
|---|---|---|
| `0x36DCC` | `0x31116` (`bl 0x36DCC`) | none |
| `0x31074` | `0x311E6` (`bl 0x31074`) | none |
| `0x36EA0` | `0x310DA` (`bl 0x36EA0`) | none |
| `0x37008` | only via the `0x36EA0` trampoline | none |
| `0x39604` | `0x37EC8`, `0x37EFC`, `0x37F26`, `0x37F4A`, `0x37FC8`, `0x38014`, `0x38036`, `0x3805E`, `0x38080`, `0x396CA`, `0x396EE`, `0x39716`, `0x39738`, `0x397BC`, `0x39832`, `0x3987E`, `0x398E2` | none |

The `0x39604` callers are all hash/certificate helpers; none is reachable from a host-controlled command dispatcher.

### 3.3 `0x36DCC` — SEB status/verify dispatcher

**Signature (observed):**
```
r0 = pointer to a 0x18-byte structure containing three 64-bit segment addresses
r1 = input/staging buffer (0x60035000 from the only caller)
r2 = buffer length (0x1000 from the only caller)
returns r0 = 0 or an SEB error (0xB000xxxx / 0xF100xxxx)
```

**Full disassembly:**

```
00036dcc: 2de9f043  push.w   {r4, r5, r6, r7, r8, sb, lr}
00036dd0: 0825      movs     r5, #8
00036dd2: 87b0      sub      sp, #0x1c
00036dd4: 8146      mov      sb, r0
00036dd6: 4ff47040  mov.w    r0, #0xf000
00036dda: 0e46      mov      r6, r1
00036ddc: 0024      movs     r4, #0
00036dde: cbf6f050  movt     r0, #0xbdf0
00036de2: 0deb0501  add.w    r1, sp, r5
00036de6: 1746      mov      r7, r2
00036de8: 0295      str      r5, [sp, #8]
00036dea: 0394      str      r4, [sp, #0xc]
00036dec: 00f02efe  bl       #0x37a4c
00036df0: b0b9      cbnz     r0, #0x36e20
00036df2: 029c      ldr      r4, [sp, #8]
00036df4: 052c      cmp      r4, #5
00036df6: 3bd0      beq      #0x36e70
00036df8: acb1      cbz      r4, #0x36e26
00036dfa: 012c      cmp      r4, #1
00036dfc: 13d0      beq      #0x36e26
00036dfe: 032c      cmp      r4, #3
00036e00: 42d0      beq      #0x36e88
00036e02: 072c      cmp      r4, #7
00036e04: 08bf      it       eq
00036e06: 0294      streq    r4, [sp, #8]
00036e08: 32d0      beq      #0x36e70
00036e0a: 4ff01b08  mov.w    r8, #0x1b
00036e0e: 0295      str      r5, [sp, #8]
00036e10: cff20018  movt     r8, #0xf100
00036e14: 3046      mov      r0, r6
00036e16: 3a46      mov      r2, r7
00036e18: 0021      movs     r1, #0
00036e1a: 00f0fffa  bl       #0x3741c          ; memset(staging, 0, len)
00036e1e: 4046      mov      r0, r8
00036e20: 07b0      add      sp, #0x1c
00036e22: bde8f083  pop.w    {r4, r5, r6, r7, r8, sb, pc}
00036e26: 0294      str      r4, [sp, #8]
00036e28: 0023      movs     r3, #0
00036e2a: 06aa      add      r2, sp, #0x18
00036e2c: 4ff47040  mov.w    r0, #0xf000
00036e30: 42f8043d  str      r3, [r2, #-0x4]!
00036e34: cbf6f050  movt     r0, #0xbdf0
00036e38: 3321      movs     r1, #0x33
00036e3a: 0493      str      r3, [sp, #0x10]
00036e3c: d9e90445  ldrd     r4, r5, [sb, #0x10]
00036e40: 00f0d2ff  bl       #0x37de8          ; read SEB register 0x33
00036e44: 8046      mov      r8, r0
00036e46: 0028      cmp      r0, #0
00036e48: e4d1      bne      #0x36e14
00036e4a: 059b      ldr      r3, [sp, #0x14]
00036e4c: 03f40003  and      r3, r3, #0x800000
00036e50: 0593      str      r3, [sp, #0x14]
00036e52: 002b      cmp      r3, #0
00036e54: ded0      beq      #0x36e14
00036e56: 46f65930  movw     r0, #0x6b59
00036e5a: 8de8c000  stm.w    sp, {r6, r7}
00036e5e: 2246      mov      r2, r4
00036e60: 2b46      mov      r3, r5
00036e62: c0f20300  movt     r0, #3
00036e66: 04a9      add      r1, sp, #0x10
00036e68: fff780fe  bl       #0x36b6c
00036e6c: 8046      mov      r8, r0
00036e6e: d1e7      b        #0x36e14
00036e70: 46f65930  movw     r0, #0x6b59
00036e74: 0097      str      r7, [sp]
00036e76: 4946      mov      r1, sb
00036e78: c0f20300  movt     r0, #3
00036e7c: 03aa      add      r2, sp, #0xc
00036e7e: 3346      mov      r3, r6
00036e80: fff738ff  bl       #0x36cf4
00036e84: 8046      mov      r8, r0
00036e86: c5e7      b        #0x36e14
00036e88: 4ff47040  mov.w    r0, #0xf000
00036e8c: cbf6f050  movt     r0, #0xbdf0
00036e90: 0294      str      r4, [sp, #8]
00036e92: 00f049ff  bl       #0x37d28
00036e96: 8046      mov      r8, r0
00036e98: 0028      cmp      r0, #0
00036e9a: bbd1      bne      #0x36e14
00036e9c: c4e7      b        #0x36e28
00036e9e: 00bf      nop
```

**Observed behavior:**

1. `0x36DCC` first calls `0x37A4C(0xBDF0F000, &status)`. `0x37A4C` polls the ready bit at `0xBDF0FABC` bit 0, then reads the status byte at `0xBDF0FAD4` and stores it in the caller's word (`0x36DEC`, `0x37A5A..0x37A6C`).
2. The status value drives the entire function:
   - `0` or `1`: `0x36E26` — read SEB register `0x33`; test bit `0x800000`; if set, call `0x36B6C` with `[sb+0x10]`; if clear, return `0xF100001B` after zeroing the staging buffer.
   - `3`: `0x36E88` — call `0x37D28` (status acknowledge); if successful, re-enter the register-`0x33` path.
   - `5` or `7`: `0x36E70` — call `0x36CF4` with the three 64-bit segment addresses from `sb`, the staging buffer `r6`, and length `r7`.
   - anything else: `0x36E0A` — zero the staging buffer and return `0xF100001B`.
3. There is no command-ID argument. The only caller-controlled values are the 24-byte `sb` structure and the staging buffer/length.
4. On every status-dispatched return path, the staging buffer is explicitly zeroed by `memset(r6, 0, r7)` at `0x36E1A` (`0x3741C`); the early `0x37A4C`-error return at `0x36E20` skips it. The verifier does not write a multi-megabyte image; the buffer is input staging for the terminal VRL block.

**Why this is not a read/decrypt command:**

- The `0x36CF4` path treats each 64-bit value in `sb` as a certificate-chain segment address, not an arbitrary read address: `0x36F80` calls `0x3718C`, which checks the VRL magic `0xE291F358` at `segment+0x80` (`0x37124..0x37140`). An arbitrary image buffer does not begin with that magic.
- The `0x36B6C` path does the same for the third segment (`[sb+0x10]`).
- The buffer is an input-staging context for the terminal VRL block; the only size passed is the 4KB staging length. It is zeroed on status-dispatched returns.

### 3.4 `0x31074` — `seb_img_verification` wrapper

**Signature (observed):**
```
r0 = VRL header pointer (0x16DFE000 in the fastboot path)
r1 = image pointer (0x16800000 in the fastboot path)
returns 0 on success, negative/0xF100xxxx on failure
```

**Full disassembly:**

```
00031074: 2de9f04f  push.w   {r4, r5, r6, r7, r8, sb, sl, fp, lr}
00031078: 91b0      sub      sp, #0x44
0003107a: 0546      mov      r5, r0
0003107c: 8946      mov      sb, r1
0003107e: fff7d5ff  bl       #0x3102c
00031082: 0028      cmp      r0, #0
00031084: 54d1      bne      #0x31130
00031086: 0021      movs     r1, #0
00031088: 2846      mov      r0, r5
0003108a: 0aaa      add      r2, sp, #0x28
0003108c: 05f0b6fd  bl       #0x36bfc
00031090: 0146      mov      r1, r0
00031092: 30b1      cbz      r0, #0x310a2
00031094: 2948      ldr      r0, [pc, #0xa4]
00031096: 2a46      mov      r2, r5
00031098: fdf75eff  bl       #0x2ef58
0003109c: 4ff0ff34  mov.w    r4, #-1
000310a0: 47e0      b        #0x31132
000310a2: ddf838a0  ldr.w    sl, [sp, #0x38]
000310a6: 05a9      add      r1, sp, #0x14
000310a8: 5046      mov      r0, sl
000310aa: fff755fe  bl       #0x30d58
000310ae: 30bb      cbnz     r0, #0x310fe
000310b0: 0999      ldr      r1, [sp, #0x24]
000310b2: 8046      mov      r8, r0
000310b4: 01f59471  add.w    r1, r1, #0x128
000310b8: 0024      movs     r4, #0
000310ba: 0025      movs     r5, #0
000310bc: 4e46      mov      r6, sb
000310be: 0027      movs     r7, #0
000310c0: 059b      ldr      r3, [sp, #0x14]
000310c2: 9845      cmp      r8, r3
000310c4: 19d2      bhs      #0x310fa
000310c6: 01eb0813  add.w    r3, r1, r8, lsl #4
000310ca: c3e90045  strd     r4, r5, [r3]
000310ce: 5046      mov      r0, sl
000310d0: cdf80080  str.w    r8, [sp]
000310d4: 3246      mov      r2, r6
000310d6: 3b46      mov      r3, r7
000310d8: 0391      str      r1, [sp, #0xc]
000310da: 05f0e1fe  bl       #0x36ea0
000310de: 0399      ldr      r1, [sp, #0xc]
000310e0: 8346      mov      fp, r0
000310e2: 38b1      cbz      r0, #0x310f4
000310e4: 1648      ldr      r0, [pc, #0x58]
000310e6: 5946      mov      r1, fp
000310e8: 5246      mov      r2, sl
000310ea: 4b46      mov      r3, sb
000310ec: fdf734ff  bl       #0x2ef58
000310f0: 5c46      mov      r4, fp
000310f2: 05e0      b        #0x31100
000310f4: 08f10108  add.w    r8, r8, #1
000310f8: e2e7      b        #0x310c0
000310fa: 0024      movs     r4, #0
000310fc: 07e0      b        #0x3110e
000310fe: 0446      mov      r4, r0
00031100: 2cb1      cbz      r4, #0x3110e
00031102: 1048      ldr      r0, [pc, #0x40]
00031104: 2146      mov      r1, r4
00031106: 4a46      mov      r2, sb
00031108: fdf726ff  bl       #0x2ef58
0003110c: 11e0      b        #0x31132
0003110e: 0aa8      add      r0, sp, #0x28
00031110: 0d49      ldr      r1, [pc, #0x34]        ; 0x60035000
00031112: 4ff48052  mov.w    r2, #0x1000
00031116: 05f059fe  bl       #0x36dcc
0003111a: 0546      mov      r5, r0
0003111c: 48b1      cbz      r0, #0x31132
0003111e: 0b48      ldr      r0, [pc, #0x2c]
00031120: 0b49      ldr      r1, [pc, #0x2c]
00031122: 4ff4b272  mov.w    r2, #0x164
00031126: 2b46      mov      r3, r5
00031128: fdf716ff  bl       #0x2ef58
0003112c: 2c46      mov      r4, r5
0003112e: 00e0      b        #0x31132
00031130: 0446      mov      r4, r0
00031132: 2046      mov      r0, r4
00031134: 11b0      add      sp, #0x44
00031136: bde8f08f  pop.w    {r4, r5, r6, r7, r8, sb, sl, fp, pc}
0003113a: 00bf      nop
```

**Stack/register conventions observed:**

| Location | Meaning | Evidence |
|---|---|---|
| `sp+0x28..0x3F` | 24-byte output of `0x36BFC`: three 64-bit segment addresses | `0x3108A`, `0x3108C`; `0x36BFC` stores at `r6+0`, `r6+8`, `r6+0x10` |
| `sp+0x38` | third segment address (`sl`); passed to `0x30D58` as the certificate header | `0x310A2`, `0x310A8` |
| `sp+0x14` | entry count returned by `0x30D58` | `0x310C0` |
| `sp+0x24` | `K[4] = terminal base + 0x1B4`; entry base is this `+0x128` (`T+0x2DC`) | `0x310B0`, `0x310B4` |
| `r8` | loop index over certificate entries | `0x310B0..0x310F8` |
| `sp+0x28` | `r0` for `0x36DCC` | `0x3110E` |
| `0x60035000` | input/staging scratch buffer (terminal VRL block) | `0x31110`; `0x3718C` copies the block in; `0x36E14` zeroes it on return |
| `0x1000` | staging length | `0x31112` |

**Observed control flow:**

1. `0x3102C` optionally derives a random vector if `[0x4020A008] & 0x4000` is set. It calls `0x36F2C(0x60035000, 0x1000, sp)` -> `0x38380`; this is a separate block-engine operation, not part of image verification. The log string is `"seb_derive_rndvector fail (0x%x)!"` at `0x3E746`.
2. `0x36BFC(VRL, 0, sp+0x28)` parses the VRL header into three segment addresses. `0x37124` validates the VRL magic `0xE291F358` at `VRL+0x80` and computes each segment length.
3. `0x30D58(segment2, sp+0x14)` runs `seb_vrl_format_check`; through `0x36EA4` it supplies a five-word result `K`: `K[0]` = entry count at `sp+0x14`, `K[4]` = `T+0x1B4` at `sp+0x24`. The code adds `0x128` to `K[4]` to get the entry base (`T+0x2DC`).
4. For each entry, `0x310C6` clears 8 bytes (`strd`) at `(K[4]+0x128) + index*16`, then `0x36EA0` writes the image address into the corresponding certificate store-table entry. The caller's 16-byte zero stride and the descriptor's 12-byte stride differ; for the real header `count=1`, so only index 0 is used.
5. `0x36DCC(sp+0x28, 0x60035000, 0x1000)` submits the three segment addresses to SEB.
6. On any error, the function logs through `0x2EF58` and returns the error. On success, it returns 0; the caller logs `"sec verify end, lasted %dms."` (`0x3E853`).

**The 4KB buffer is input staging, not an image output.** `0x31074` passes `0x1000` as the staging buffer length. `0x36CF4`/`0x36F80`/`0x3718C` copy the terminal VRL block into `0x60035000`; `0x36DCC` then zeroes the whole `0x1000` on every status-dispatched return (`0x36E14`). The fastboot image size is `0x5FE000` at most (`0x235F4`, `0x23648`), so the buffer is far too small for a full-image read/export, and it is erased before the caller sees it.

### 3.5 `0x36EA0` — `changeStoreAddr`

`0x36EA0` is a 4-byte trampoline, not the function body:

```
00036ea0: 00f0b2b8  b.w  #0x37008
```

The body at `0x37008` is:

```
00037008: 70b5      push     {r4, r5, r6, lr}
0003700a: 84b0      sub      sp, #0x10
0003700c: 0446      mov      r4, r0
0003700e: cde90023  strd     r2, r3, [sp]
00037012: b8b1      cbz      r0, #0x37044
00037014: 00f18006  add.w    r6, r0, #0x80
00037018: 3046      mov      r0, r6
0003701a: 03a9      add      r1, sp, #0xc
0003701c: 00f068f8  bl       #0x370f0
00037020: 0546      mov      r5, r0
00037022: 35b9      cbnz     r5, #0x37032
00037024: 039b      ldr      r3, [sp, #0xc]
00037026: 022b      cmp      r3, #2
00037028: 1cbf      itt      ne
0003702a: 1820      movne    r0, #0x18
0003702c: cff20010  movtne   r0, #0xf100
00037030: 01d0      beq      #0x37036
00037032: 04b0      add      sp, #0x10
00037034: 70bd      pop      {r4, r5, r6, pc}
00037036: d4f88830  ldr.w    r3, [r4, #0x88]
0003703a: 0899      ldr      r1, [sp, #0x20]
0003703c: 1a0c      lsrs     r2, r3, #0x10
0003703e: 013a      subs     r2, #1
00037040: 8a42      cmp      r2, r1
00037042: 04d2      bhs      #0x3704e
00037044: 0120      movs     r0, #1
00037046: cff20010  movt     r0, #0xf100
0003704a: 04b0      add      sp, #0x10
0003704c: 70bd      pop      {r4, r5, r6, pc}
0003704e: 9bb2      uxth     r3, r3
00037050: 2033      adds     r3, #0x20
00037052: 06eb8306  add.w    r6, r6, r3, lsl #2
00037056: 01eb4100  add.w    r0, r1, r1, lsl #1
0003705a: 06eb8000  add.w    r0, r6, r0, lsl #2
0003705e: 6946      mov      r1, sp
00037060: 0822      movs     r2, #8
00037062: 00f0c5f9  bl       #0x373f0
00037066: 2846      mov      r0, r5
00037068: e3e7      b        #0x37032
```

**Arguments (observed):**

| Register/stack | Value at the only call site | Evidence |
|---|---|---|
| `r0` | `sl` = terminal type-2 block base `T` (third segment) | `0x310CE` |
| `r1` | entry base (`K[4] + 0x128`, i.e. `T + 0x2DC`) | `0x310B0`, `0x310B4` |
| `r2` | `sb` = image address `0x16800000` | `0x310D4` |
| `r3` | `0` | `0x310D6` |
| `[sp]` | loop index `r8` | `0x310D0` |

**The store-table arithmetic (observed):**

1. `0x3700E` stores `{r2, r3}` = `{image_address, 0}` at `[sp]`.
2. `0x37014` sets `r6 = r0 + 0x80`; `0x3701C` calls `0x370F0(r6, &mode)`.
3. `0x370F0` checks the magic `0xE291F358` at `r6[0]`, the version `0x00010000` at `r6[4]`, extracts `mode = (r6[0xC] >> 17) & 3`, and returns 0 only if the header is valid. The caller requires `mode == 2` (`0x37024..0x37030`).
4. `0x37036` loads `r3 = [r4+0x88]`; `0x3703C..0x37040` computes `last_index = (r3 >> 16) - 1`; the requested index must be `<= last_index`.
5. `0x3704E..0x37052` computes the entry base:
   ```
   base = (T + 0x80) + (((u16)[T+0x88] + 0x20) << 2)
   ```
6. `0x37056..0x3705A` computes the entry address:
   ```
   entry = base + index * 12
   ```
7. `0x3705E..0x37062` calls `0x373F0(entry, sp, 8)`, an 8-byte copy. The two words copied are `{image_address, 0}`.

**Interpretation [OBS/INF]:** the 12-byte stride consists of an 8-byte `{address, 0}` pair plus a 4-byte field at `+8` that `changeStoreAddr` does not touch. The error string at `0x3E769` is `"Store Addr err(0x%x) vrladdr(0x%x) store_addr(0x%x)!"`; the caller passes `r3 = sb = image_address` as `store_addr` (`0x310EA`). This is a **source/store address** used by SEB to locate the image; the 4-byte field at `+8` is the range length. The function writes an address and zero; it does not copy image data.

**Worked example from the real update header.** `artifacts/FASTBOOT.from-update-app.img[0:0x1000]` contains a three-block VRL chain:
- root base `0x000`, second base `0x2CC`, terminal base `0x598`;
- terminal `[T+0x88] = 0x00010077` -> `count=1`, `off=0x77`;
- terminal `[T+0x8C] = 0x000501FF` -> type bits 17..18 = 2;
- `base = 0x598 + 0x80 + ((0x77 + 0x20) << 2) = 0x874`;
- `entry(0) = 0x874`; on disk the entry is `{0x00000000, 0x00000000, 0x000DB230}`;
- after `0x37008` with image `0x16800000`, the entry becomes `{0x16800000, 0x00000000, 0x000DB230}`, preserving the length.

The runtime VRL/certificate bytes are read from the `vrl` partition into `0x16DFE000`; the update header is a concrete example of the same structure, not necessarily byte-identical to the runtime `vrl` partition.

---

## 4. SEB Command Catalog & Protocol

### 4.1 Register/mailbox map at `0xBDF0F000`

| Offset | Access | Meaning | Evidence |
|---|---|---|---|
| `+0xAA4` | write | register-index command word: `0x00010000 \| (index << 2)` | `0x37DF8..0x37DFC` |
| `+0xAAC` | read | register data returned for the index | `0x37E0A..0x37E14` |
| `+0xAB4` | read | ready/busy bit 0 for the register transaction | `0x37E00..0x37E08` |
| `+0xABC` | read | ready/busy bit 0 for the status/register interface | `0x37A5A..0x37A62`, `0x37DF2..0x37DF6` |
| `+0xAC0` | write | status word for state 7 | `0x37D46` |
| `+0xAC4` | write | status mirror | `0x37D50` |
| `+0xAC8` | write | status mirror | `0x37D54` |
| `+0xACC` | write | status mirror | `0x37D58` |
| `+0xAD4` | read | SEB state/status byte | `0x37A64..0x37A6C` |
| `+0xAD8` | write | state-7 acknowledge flag | `0x37D5C` |
| `+0xE80..+0xE94` | write | six-word SEB command descriptor | `0x3960E..0x3962E` |
| `+0xE9C` | read | descriptor-ready low nibble | `0x39604..0x3960C` |
| `+0xA00` | read | block-engine status | `0x3842A..0x3844A` |
| `+0xA08` | write | block-engine control (`4`) | `0x3988C`, `0x39894` |

**Ready-bit correction.** The code uses `lsls rX, rX, #0x1F` followed by `bpl` (`0x37A60`, `0x37DF4`, `0x37E06`). The N flag after a 31-bit left shift is the original **bit 0**, not bit 31. Therefore the poll loops wait for **bit 0 = 1**, and the table above records bit 0. The `0x39604` loop uses `lsls r3, r3, #0x1C` and waits for the **low nibble** of `+0xE9C` to be nonzero.

### 4.2 Transport primitives

**`0x37A4C` — read SEB status.**
```
37a5a: 00f6bc22  addw  r2, r0, #0xabc
37a5e: 1368      ldr   r3, [r2]
37a60: d807      lsls  r0, r3, #0x1f
37a62: fcd5      bpl   #0x37a5e
37a64: d4f8d43a  ldr.w r3, [r4, #0xad4]
37a68: dbb2      uxtb  r3, r3
37a6a: 012b      cmp   r3, #1
37a6c: 0b60      str   r3, [r1]
```
Polls `+0xABC` bit 0, then returns the byte at `+0xAD4` to `*r1`. It additionally checks state 1 against `[+0xAD4]` bit 9 (`0xB0000004` if set), and state 5 against bit 8 (`0xB0000002` if set; otherwise it reads register `0xA` and returns `0xB0000010` unless the low nibble is 3) (`0x37A6E..0x37AAE`).

**`0x37DE8` — read one SEB register.**
```
37df2: 2368      ldr   r3, [r4]
37df4: db07      lsls  r3, r3, #0x1f
37df6: fcd5      bpl   #0x37df2
37df8: 41f48031  orr   r1, r1, #0x10000
37dfc: c0f8a41a  str.w r1, [r0, #0xaa4]
37e00: 00f6b421  addw  r1, r0, #0xab4
37e04: 0b68      ldr   r3, [r1]
37e06: db07      lsls  r3, r3, #0x1f
37e08: fcd5      bpl   #0x37e04
37e0a: d0f8ac3a  ldr.w r3, [r0, #0xaac]
37e12: 0020      movs  r0, #0
37e14: 1360      str   r3, [r2]
```
This is a **register-file read**, not a memory read: `r1` is an index, shifted left by 2 and ORed with `0x10000`. There is no address argument.

**`0x37AD0` — small mailbox transaction.** It reads status via `0x37A4C`, rejects state 3 with `0xB0000100`, writes 4 or 8 bytes into register indices `0x10..`, reads index `0xB`, and returns `0` or `0xB0000008`. It is used for control/status words, not image data.

**`0x39604` — six-word SEB descriptor submit.**
```
39604: 00f69c62  addw  r2, r0, #0xe9c
39608: 1368      ldr   r3, [r2]
3960a: 1b07      lsls  r3, r3, #0x1c
3960c: fcd0      beq   #0x39608
3960e: 0b68      ldr   r3, [r1]
39610: c0f8803e  str.w r3, [r0, #0xe80]
39614: 4b68      ldr   r3, [r1, #4]
39616: c0f8843e  str.w r3, [r0, #0xe84]
3961a: 8b68      ldr   r3, [r1, #8]
3961c: c0f8883e  str.w r3, [r0, #0xe88]
39620: cb68      ldr   r3, [r1, #0xc]
39622: c0f88c3e  str.w r3, [r0, #0xe8c]
39626: 0b69      ldr   r3, [r1, #0x10]
39628: c0f8903e  str.w r3, [r0, #0xe90]
3962c: 4b69      ldr   r3, [r1, #0x14]
3962e: c0f8943e  str.w r3, [r0, #0xe94]
39632: 7047      bx    lr
```
The descriptor layout is six 32-bit words. The callers fill a stack structure and pass its address in `r1`.

**`0x39634` — hash-engine context init and opcode sequence.**
```
39638: 4ff62004  movw  r4, #0xf820
3963c: 92b0      sub   sp, #0x48
3963e: c0f20304  movt  r4, #3          ; r4 = 0x3F820
...
3964a: 0fcc      ldm   r4!, {r0, r1, r2, r3}
3964c: 0fc5      stm   r5!, {r0, r1, r2, r3}
3964e: 94e80f00  ldm.w r4, {r0, r1, r2, r3}
39656: 85e80f00  stm.w r5, {r0, r1, r2, r3}
```
`0x3F820` contains the SHA-256 initial hash values in little-endian word order:
```
19cd e05b  abd9 831f  8c68 059b  7f52 0e51
3af5 4fa5  72f3 6e3c  85ae 67bb  67e6 096a
```
This is the H0 table `{6a09e667, bb67ae85, 3c6ef372, a54ff53a, 510e527f, 9b05688c, 1f83d9ab, 5be0cd19}`. The same function writes the observed opcode field values:

| Opcode | Where written | Descriptor control word | Inferred phase |
|---|---|---|---|
| `0x82` | `0x396B8` (`movs r3,#0x82`), `0x39870` | `0x10000825`, `0x80C0082B` | SHA-256 init / context setup |
| `0x41` | `0x396D2` (`movs r3,#0x41`) | `0x80000041` | SHA-256 update / block feed |
| `0x42` | `0x39706` (`movs r6,#0x42`), `0x3970A` | `0x20000820` | SHA-256 final / digest |

The phase labels are **inferences** from the constant H0 table and the init/update/final sequence; the exact SEB opcode names are not present in the artifact. The same hash helpers also use length/flag-packed descriptor words `0x08000011`, `0x08000012`, `0x02000820`, `0x04000820`, `0x01000825`, `0x04000825`, `0x0908082B`, `0x080C082B`, `0x04000C20`, `0x08000C26`, `0x01001C20`, and `0x08001C26` (`0x37E78..0x38080`); these are variants of the same hash/DMA engine, not read/export commands.

### 4.3 Command/status catalog

| Layer | Name/value | Direction | Meaning | Evidence |
|---|---|---|---|---|
| Status | `0` | SEB -> CPU | verification path / register 0x33 | `0x36DF8..0x36DFC` |
| Status | `1` | SEB -> CPU | same as 0 | `0x36DFA..0x36DFC` |
| Status | `3` | SEB -> CPU | acknowledge/continue via `0x37D28` | `0x36DFE..0x36E00` |
| Status | `5` | SEB -> CPU | three-segment verification | `0x36DF4..0x36DF6` |
| Status | `7` | SEB -> CPU | same as 5 | `0x36E02..0x36E08` |
| Register | `0x33` | SEB -> CPU | capability/status; bit 23 gates verification | `0x36E38..0x36E54` |
| Register | `0x0A` | SEB -> CPU | status extension | `0x37A8E..0x37A92` |
| Register | `0x0B` | SEB -> CPU | mailbox result | `0x37B86..0x37B8A` |
| Register | `0x0C..0x0F` | SEB -> CPU | four-word status block | `0x37BFE..0x37C48` |
| Register | `0x18..0x1E` | SEB -> CPU | seven-word status block | `0x37D9C` loop |
| Descriptor opcode | `0x82` | CPU -> SEB | SHA context init | `0x396B8`, `0x39870` |
| Descriptor opcode | `0x41` | CPU -> SEB | SHA update | `0x396D2` |
| Descriptor opcode | `0x42` | CPU -> SEB | SHA final | `0x39706` |
| Descriptor opcode | `0x840` / `0x574` | CPU -> SEB | secure-debug image verify mode | `0x36EE0..0x36F04`, `0x38BE6..0x38BEC` |
| Error | `0xF1000001` | CPU | null/bad argument, store-entry range | `0x37044`, `0x36F08` |
| Error | `0xF1000003` | CPU | bad VRL magic | `0x370FE` |
| Error | `0xF1000004` | CPU | bad VRL version | `0x37116` |
| Error | `0xF1000018` | CPU | bad store-header mode | `0x3702A` |
| Error | `0xF100001B` | CPU | verification capability bit clear | `0x36E0A` |
| Error | `0xB0000002`, `0xB0000010`, `0xB0000100`, `0xB0000008` | CPU | SEB transport/status errors | `0x37A80`, `0x37AA6`, `0x37B16`, `0x37BAA` |
| Error | `0xF7000001` | CPU | certificate/signature verification failure | `0x38E0A` |
| Error | `0xF0000002..7` | CPU | FillCert/TLV errors | `0x36C3C..0x36CB4` |

**Security-class mapping [OBS]:** `0x30F28` maps the same SEB status to a config byte using the string table at `0x3EA68`: status `5/7` -> config `0` (`SEB_SECCFG_SECURE` at `0x3EA1D`); status `0/1/3` -> register `0x33` bit 23 selects between config `1` (`SEB_SECCFG_INTEGRITY` at `0x3EA2F`) and config `2` (`SEB_SECCFG_NONE` at `0x3EA44`); otherwise config `3` (`SEB_SECCFG_ERROR` at `0x3EA54`). `0x36DCC` sends `5/7` to `0x36CF4` (secure class) and `0/1/3` to `0x36B6C` (integrity/none class). The secure-class path is the one that handles the certificate/store descriptors.

**Data direction on the CPU side [OBS]:** `0x36CF4`/`0x36F80`/`0x3718C` copy the terminal VRL block (including its 12-byte store descriptor) into `0x60035000`. The only CPU copy primitive on the hash path, `0x36B58`, is `memcpy(dst=r2, src=r0, len=r3)`; in `0x375E4` the source and destination both come from the descriptor, so it is a self-copy/no-op in the normal path. The SEB hash engine consumes the descriptor range; no CPU instruction writes plaintext to the descriptor address.

**There is no command ID field that the caller can set to `read`, `decrypt`, or `export`.** The only numeric "opcodes" are the descriptor words above, and they are written by the hash/certificate helpers, not selected by the host.

### 4.4 Other SEB consumers in the artifact

For completeness, the artifact contains a second SEB path for **secure-debug images**, not fastboot:

- `0x31274` (`secdbg`) reads a secure-debug image to `0x22000` via `0x25304`, checks the LCS/DCU state, and calls `0x36EE0(0x22000, r5)`.
- `0x36EE0` calls `0x38B70(0xBDF0F000, image, cmd, len)` with `cmd = 0x840` if `r5 == 0`, otherwise `cmd = 0x574` (`0x36EE8..0x36F04`).
- `0x38B70` checks the secure-debug image magic/fields, calls `0x38A40`/`0x38DE0`, and writes the SEB register at `0xBDF0FA64` on exit (`0x31392`).

This path still returns only status. It does not read the fastboot partition and does not write image bytes to a caller buffer.

The partition table also contains `hisee_fs_a` and `hisee_img_a` entries (`0x40718`/`0x407D8` in the eMMC table, `0x40B38`/`0x40BF8` in the UFS table), but no code in this artifact references those names. The xloader talks to the already-running SEB/HISEE block through `0xBDF0F000`; it does not load or command a HISEE firmware image.

---

## 5. Data Flow and Buffer Mechanics

### 5.1 Buffer map

| Address | Size | Role | Evidence |
|---|---|---|---|
| `0x16800000` | up to `0x5FE000` | fastboot image / verified image buffer | `0x235F4`, `0x23648`, `0x238B8` |
| `0x16DFE000` | `0x1000` | VRL header scratch | `0x23838`, `0x23840` |
| `0x60035000` | `0x1000` | SEB input staging/scratch (terminal VRL block); zeroed on status-dispatched return | `0x31110`, `0x3718C`, `0x36E14` |
| `0x60053000` | word | SATE-aging gate | `0x24178`, `0x24154` |
| `0x109C0000` | header | VCOM download header/scratch | `0x2EF8C..0x2F058` |
| `0x60053074` | `0x800` | VCOM download bounce/header | `0x2F054`, `0x2F0A4` |

### 5.2 Normal fastboot path

1. `0x237E0` reads the VRL header from `vrl`/`vrl_backup` at offset `0x22000` to `0x16DFE000`, size `0x1000` (`0x23830..0x23846`).
2. It reads the fastboot payload to `0x16800000`, size from the VRL header, capped at `0x5FE000` (`0x235F4`, `0x23648..0x2365E`).
3. It calls `0x311C8(VRL=0x16DFE000, image=0x16800000, boot_type, 0xB, "normalboot", "fastboot")` (`0x238AE..0x238C4`).
4. `0x311C8` calls `0x31074` when the boot type is `<= 1` (`0x311DC..0x311E6`); boot type `2` skips verification (`0x3121C..0x31232`).
5. `0x31074` verifies the certificate chain and calls `0x36DCC`.
6. Main proceeds to `0x2329A` and calls ROM `0xB2`.

**No xloader instruction writes plaintext to `0x16800000` after the storage read.** The only code that targets the address is:
- `0x235F4` / `0x23648`: destination argument for the storage read.
- `0x238B8`: image argument for verification.
- `0x2399C`: comparison against the USB download result.
- `0x232FC`, `0x23380`, `0x23394`, `0x233A6`, `0x233B0`: legacy/trampoline or fastboot dispatch, not a decrypt loop.
- `0x236C4`, `0x2376C`, `0x2410E`, `0x332AA`: other data-path references.

### 5.3 `0x60035000` is a 4KB input-staging scratch, not an image dump

`0x31074` passes `0x60035000` and `0x1000` to the SEB dispatcher. `0x36CF4`/`0x36F80`/`0x3718C` copy the terminal VRL block (including its 12-byte store descriptor at `0x600352DC`) into this buffer; the copy is at `0x37208..0x3720E`:
```
37208: 0998      ldr   r0, [sp, #0x24]   ; staging destination (0x60035000)
3720a: 2146      mov   r1, r4             ; terminal block
3720c: 2a46      mov   r2, r5             ; size
3720e: 00f0eff8  bl    #0x373f0          ; memcpy(dst, src, size)
```

`0x37304`/`0x3706C` then parse it. On every status-dispatched return, success or error, `0x36DCC` zeroes the whole `0x1000` at `0x36E14`; the early `0x37A4C`-error return at `0x36E20` skips the memset. The buffer is therefore an input/staging area, not a result channel. It has only two literal references in the whole artifact (`0x31068`, `0x31148`), and no USB code reads or forwards it. The fastboot image is `0x5FE000` bytes at most; `0x1000` cannot hold it, and any plaintext staged there would be erased before the caller could read it. (`0x3102C` also passes this buffer to `0x36F2C`/`0x38380` on the optional random-vector path; that is a separate block-engine operation, not image data.)

### 5.4 `changeStoreAddr` is a source-address update

The function writes `{0x16800000, 0}` into the certificate's store-table entry. The error string calls the value `store_addr` (`0x3E769`), and the caller passes the image pointer as that argument (`0x310EA`). This is the address at which the image is stored for verification. It is not a destination for decrypted output:
- the write is 8 bytes (`0x3705E..0x37062`), not an image-sized copy;
- the value written is the same `0x16800000` image pointer passed to `0x31074` (`0x3107C`, `0x310D4`);
- the 4-byte length at `entry+8` is preserved (real header: `0xDB230`);
- no code follows the write with a data transfer or a second-stage copy to the CPU.

**Residual hardware-store hypothesis [INF]:** the status `5/7` path is `SEB_SECCFG_SECURE` (`0x30F28`), and the descriptor has the shape `{address, 0, length}`. If the SEB secure operation also performs a decrypt-and-store, the address field is the redirection knob. The visible CPU graph does not establish this: it is verification/hash plus mailbox submission, the only copy callback is a self-copy, and the staging buffer is zeroed after the call. A redirect to `0x60035000` or `0x23154` would also be limited to a small object: the real descriptor length is `0xDB230` (~897 KB), far larger than the 4KB staging buffer or the loader's spare SRAM, and `0x36E14` would erase a small write. Treat “SEB writes plaintext” as unproven and hardware-dependent; it is not an implemented read/export command.

### 5.5 Where is decryption performed?

The on-disk fastboot payload is high-entropy, while the RAM image is plaintext AArch64:

| Image | First 16 bytes | Interpretation |
|---|---|---|
| `artifacts/fastboot.dump.img` | `bf695fc11e7c943f66a2eabf17f28b51` | high-entropy stored payload |
| `artifacts/fastboot.stock.payload.img` | `bf695fc11e7c943f66a2eabf17f28b51` | same stored payload |
| `artifacts/hisi970_fastboot_ram.bin` | `0d0000140c0000140b0000140a000014` | AArch64 exception vectors (plaintext) |

Therefore decryption occurs between storage and execution. The xloader contains:
- **no software AES S-box / RCON** (full-artifact pattern search: 0 hits for `637c777bf26b6fc53001672bfed7ab76` and `01020408102040801b36`);
- **no software decrypt loop** in the read/verify graph;
- **a SHA-256 engine interface** (`0x39604`, H0 at `0x3F820`);
- a storage read path (`0x24E14`) that writes the read result to the caller's destination and may configure the storage engine's crypto path.

**Storage-read plaintext clue [OBS/INF]:** the patch/legacy read path at `0x2376C` reads `0x400000` bytes to `0x16800000` via `0x24E14`, then compares the 16 bytes at `0x16800024` with `"BOOTMAGICNUMBER!"` (`0x236F0`/`0x236EC`, string `0x3CA67`). That path expects plaintext at the destination, which implies the storage read path decrypts inline for that partition. The fastboot path itself does not perform this magic check before `0x311C8`, so the conclusion is not automatically transferable to fastboot.

The exact decryption boundary (storage engine inline vs SEB internal vs ROM `0xB2`) is **not resolved by this artifact**. The bounded conclusion is: no xloader instruction writes plaintext to `0x16800000`; the CPU-visible SEB interface only verifies; the plaintext is either produced by the storage engine into DRAM or by SEB/ROM internally, and in either case the 32-bit loader's read primitive cannot export it.

---

## 6. ROM API `0xB2` Handoff

### 6.1 Call site and exact register state

The final call in main is at `0x2329A`:

```
00023284: 00f0aefe  bl       #0x23fe4          ; boot-reason / LCS handling
00023288: 4ff43832  mov.w    r2, #0x2e000
0002328c: 0523      movs     r3, #5
0002328e: 8de80c00  stm.w    sp, {r2, r3}      ; [sp]=0x2E000, [sp+4]=5
00023292: 0748      ldr      r0, [pc, #0x1c]    ; 0x8E200000
00023294: 0021      movs     r1, #0
00023296: 074a      ldr      r2, [pc, #0x1c]    ; 0xFFF50000
00023298: 0023      movs     r3, #0
0002329a: a047      blx      r4                 ; r4 = 0xB3 -> target 0xB2
0002329c: 0748      ldr      r0, [pc, #0x1c]    ; "fst err"
0002329e: 7844      add      r0, pc
000232a0: 0bf05afe  bl       #0x2ef58
000232a4: fee7      b        #0x232a4           ; hang
```

**Register state at `0x2329A` [OBS]:**

| Register | Value | Provenance |
|---|---|---|
| `r0` | `0x8E200000` | literal at `0x232B0`, loaded by `0x23292` |
| `r1` | `0` | `movs r1, #0` at `0x23294` |
| `r2` | `0xFFF50000` | literal at `0x232B4`, loaded by `0x23296` |
| `r3` | `0` | `movs r3, #0` at `0x23298` |
| `[sp]` | `0x0002E000` | `mov.w r2,#0x2E000` + `stm.w sp,{r2,r3}` at `0x23288..0x2328E` |
| `[sp+4]` | `5` | `movs r3,#5` + `stm.w` |
| `r4` | `0xB3` | `bl 0x23F70` at `0x23174`; `0x23F70` is `movs r0,#0xB3; bx lr`; `mov r4,r0` at `0x23178` |
| `lr` | `0x2329D` | `blx` return address (Thumb bit set) |
| CPSR.T | `1` | Thumb mode; `blx r4` with bit 0 set selects Thumb at `0xB2` |

**Note on prior notes.** Some earlier project notes said `r1` was "whatever `0x23FE4` left." That is incorrect: `0x23294` explicitly executes `movs r1, #0` immediately before the call. `r0`, `r1`, `r2`, and `r3` are all explicitly set at `0x23292..0x23298`.

### 6.2 Parameter interpretation

| Parameter | Value | Interpretation [INF] |
|---|---|---|
| `r0` | `0x8E200000` | a DRAM/secure-world address for the ROM handoff/parameter block; `0x8E200000 = 0x16800000 + 0x77800000`, and the value appears in the AArch64 image's data tables at file offsets `0x310830`/`0x310848`, suggesting a secure alias of the image base [INF] |
| `r1` | `0` | reserved/zero |
| `r2` | `0xFFF50000` | a secure/ROM configuration or vector constant |
| `r3` | `0` | reserved/zero |
| `[sp]` | `0x2E000` | size-like: 188,416 bytes; it matches the span of the `[0x20000,0x4E000)` SRAM window used by `0x240A4`, and is far smaller than the 5.9MB image |
| `[sp+4]` | `5` | boot/handoff mode |

The xloader does **not** pass the fastboot image size (`0x5FE000`) or a decryption output buffer. `0x2E000` is smaller than the fastboot image by more than an order of magnitude. A bulk decrypt of the 5.9MB image is therefore not parameterized by this call. The call is a **handoff/entry** invocation, not an explicit decrypt request.

### 6.3 AArch64 transition

The xloader is Thumb-2 and cannot execute AArch64 directly. The handoff is the only transition point:

- `0x2329A` calls ROM `0xB2`; the xloader has no `bx`/`blx` to `0x16800000`, no `eret`, no `rfe`, and no literal `0x16800000` branch target.
- The fallback trampoline at `0x232E8` writes AArch64 instructions to `0x16800000`:
  ```
  0x232FC: mov.w r3, #0x16800000
  0x23300: str   r2, [r3]         ; r2 = 0xAA1F03E0  -> mov  x0, xzr
  0x23306: str   r2, [r3, #4]     ; r2 = 0xF2A80000  -> movk x0, #0x4000, lsl #16
  0x2330A: str   r2, [r3, #8]     ; r2 = 0xD61F0000  -> br   x0
  ```
  This is direct evidence that the xloader expects the post-handoff context at `0x16800000` to be AArch64.
- The real fastboot image at `0x16800000` starts with AArch64 exception vectors:
  ```
  16800000: 0d000014  b #0x16800034
  ...
  1680001c: 06000014  b #0x16800034
  16800020: 00008016  .word 0x16800000
  16800024: "BOOTMAGICNUMBER!"
  16800034: e0031faa  mov x0, xzr
  ...
  ```
  The vectors branch to `+0x34`; `+0x20` holds the load address; `+0x24` is the boot magic. The entry stub at `+0x34` sets `VBAR_EL3`, `SCR_EL3`, and `SCTLR_EL3`, checks `CurrentEL`, and builds a per-core stack; the real vector table is at `+0x1800`. The post-handoff context is AArch64 **EL3**, not a generic AArch64 EL1 context. This is the code that runs after the ROM handoff and can read the image.

### 6.4 Does the handoff decrypt?

**Not proven either way from this artifact.** The call parameters do not include an image size or a decrypt buffer, and the xloader has no software decrypt routine. The three possibilities remain:
1. the storage read path (`0x24E14`) decrypts inline into `0x16800000`;
2. SEB decrypts internally while hashing the image, leaving `0x16800000` ciphertext until the ROM;
3. the ROM `0xB2` path decrypts/loads the image during the transition.

The artifact supports the following bounded statements:
- No xloader instruction writes plaintext to `0x16800000` after the read.
- The CPU-visible SEB interface performs verification/hash operations only; it does not export plaintext.
- The ROM call has no image-sized buffer/size argument; if it decrypts, the operation is implicit in ROM/secure firmware, not in the xloader ABI.
- The post-handoff AArch64 image is the only context that provably reads, executes, and can exfiltrate the window through the CPU.

### 6.5 Why the 32-bit read primitive fails but AArch64 succeeds

The project's hardware experiments show the 32-bit patched read primitive cannot read `0x16800000`/`0x16DFE000`, while the image is writable and boots after handoff. The likely mechanism is a TZASC/privilege-gated DRAM view for the non-secure 32-bit master, or an interconnect read path not decoded for that master. The AArch64 image executes from the same window, so the post-handoff master has a readable/executable view. This is an architectural property of the master/security state, not a property of the address.

**Storage-read plaintext clue [OBS/INF]:** the patch/legacy read path at `0x2376C` reads `0x400000` bytes to `0x16800000` via `0x24E14` and then compares the 16 bytes at `0x16800024` with `"BOOTMAGICNUMBER!"` (`0x236F0`/`0x236EC`, string `0x3CA67`). This path expects plaintext at the destination, which implies the storage read path decrypts inline for that partition. The same conclusion cannot be extended to the fastboot partition without testing; the fastboot path itself does not perform this magic check before `0x311C8`.

The SEB hash engine can also read the image (it verifies it), but its output is a digest/status, not the image. A privileged reader is not the same as an exporter.

---

## 7. Architectural Recommendation

### 7.1 If a read/decrypt SEB command existed (it does not)

If the xloader had a command such as `seb_read(addr, len, dst)`, the request block would be the six-word descriptor at `0xBDF0FE80` and the output would be a caller-supplied buffer. The artifact contains no such command:
- the descriptor opcodes are `0x82/0x41/0x42` (SHA-256) and the secure-debug `0x840/0x574`;
- the only caller-supplied buffer is the 4KB `0x60035000` input-staging scratch, which is zeroed on status-dispatched return;
- `0x36DCC` has no command argument;
- the store-table write is a source `{address, 0, length}` update, not a data transfer.

A host-side request cannot be constructed from this interface because there is no request opcode for it. A hardware-side decrypt-and-store on the `SEB_SECCFG_SECURE` path would not be a read/export command: it would write to the descriptor address, and this artifact provides no output channel, no suitably sized SRAM destination, and no way to prevent `0x36DCC` from zeroing the staging buffer. That hypothesis remains unproven and does not constitute a usable read/decrypt-only path.

### 7.2 Required architecture for post-handoff AArch64 retrieval

To export the plaintext, code must run **after** the ROM `0xB2` handoff in AArch64 and read the `0x16800000` window. The minimum architectural requirements are:

1. **AArch64 execution at the image entry.** The ROM handoff transfers control to `0x16800000` (or to the fallback trampoline there). The code must be resident at that address or reachable from it.
2. **A readable mapping of `0x16800000`.** The fastboot image itself proves the post-handoff master can read/execute the window. The AArch64 code must preserve or establish that mapping (MMU/cache configuration).
3. **An exfiltration channel.** The image already contains a USB device stack (it is the fastboot image). Reusing its USB controller initialization and bulk-IN endpoint is the lowest-cost channel; a minimal AArch64 USB driver is the fallback. UART is an alternative if exposed.
4. **A residency/injection mechanism.** Three options, in increasing cost:
   - **Patch-after-verify:** let the normal path read and verify the on-disk image to `0x16800000`, then write a small AArch64 stub over the image entry (CPU writes to the window succeed) before `0x2329A`. The stub reads the rest of the image and sends it over USB. This preserves the signed on-disk image and only modifies RAM. The open question is whether the ROM re-verifies the image after the patch; if it does, the stub will be rejected.
   - **Download-mode payload:** the USB download path (`0x23988`) accepts a host image at `0x16800000` and hands off without the `0x311C8` verification path. A custom AArch64 payload can run, but it replaces the on-disk image; to extract the on-disk fastboot, the payload must read the fastboot partition itself (AArch64 storage driver) or the loader must first place the on-disk image elsewhere.
   - **Signed-image modification:** patch the fastboot image itself to add a dump command. This breaks the signature and is not viable unless verification is bypassed.
5. **Memory/cache coherency.** The stub and the USB DMA engine must agree on cache maintenance and physical addresses. The image is at a fixed physical address; the AArch64 MMU mapping must be identity or the DMA must use the physical address.
6. **Recovery.** Any post-handoff stub can hang the device before USB enumeration. Keep a testpoint/recovery path and never write flash.

**Cost/risk:** high. The main cost is the AArch64 USB/storage code and the injection mechanism. The main risk is that the ROM or the EL3 boot flow re-verifies/authenticates the patched image, or that the image's USB/cache setup cannot be reused from the stub. The patch-after-verify route is the smallest experiment because it does not require an AArch64 storage driver; it only requires an AArch64 USB dump stub. The post-handoff context is EL3, so it has the privilege to read the window; the risk is integrity/re-verification, not a non-secure TZASC view.

### 7.3 Adjacent non-SEB observation (out of scope, unproven)

The storage read wrapper `0x24E14` takes the destination address as a parameter. `0x235F4` passes `0x16800000` (`0x23648`), but the wrapper forwards the destination to the storage driver at `[partition+0x38]` (eMMC `0x3B34D`, UFS `0x3564D`) and later copies from the `0x60000000` bounce buffer. Redirecting the destination to SRAM would make the storage engine write the read result to CPU-readable memory. Whether that result is plaintext depends on where decryption occurs (storage engine vs SEB/ROM); the patch/legacy path's `"BOOTMAGICNUMBER!"` check at `0x16800024` after a `0x400000`-byte storage read suggests the storage path can return plaintext for that partition, which makes this route more plausible. This is **not** a SEB command and is **not** proven by static analysis; it is noted only as a lower-cost read-only experiment to consider before committing to the AArch64 project. It is outside the requested SEB scope and was not tested.

---

## 8. Evidence Table

| Claim | VA / file | Evidence |
|---|---|---|
| `0x36DCC` has one caller | `0x31116` / `0x0F116` | `05f059fe bl #0x36dcc` |
| `0x31074` has one caller | `0x311E6` / `0x0F1E6` | `fff745ff bl #0x31074` |
| `0x36EA0` has one caller | `0x310DA` / `0x0F0DA` | `05f0e1fe bl #0x36ea0` |
| `0x36EA0` is a trampoline | `0x36EA0` / `0x14EA0` | `00f0b2b8 b.w #0x37008` |
| SEB status read | `0x37A5A..0x37A6C` / `0x15A5A` | poll `+0xABC` bit0, read byte `+0xAD4` |
| SEB register read | `0x37DF8..0x37E14` / `0x15DF8` | write `0x10000\|(index<<2)` to `+0xAA4`, read `+0xAAC` |
| Six-word descriptor | `0x39604..0x3962E` / `0x17604` | write `+0xE80..+0xE94`, poll `+0xE9C` low nibble |
| SHA-256 H0 | `0x3F820` / `0x1D820` | `19cde05b...67e6096a` |
| Hash opcode 0x82 | `0x396B8` / `0x176B8` | `8223 movs r3,#0x82` |
| Hash opcode 0x41 | `0x396D2` / `0x176D2` | `4123 movs r3,#0x41` |
| Hash opcode 0x42 | `0x39706` / `0x17706` | `4226 movs r6,#0x42` |
| No AES S-box | full file | 0 hits for `637c777bf26b6fc53001672bfed7ab76` |
| No AES RCON | full file | 0 hits for `01020408102040801b36` |
| Store-table write | `0x3700E`, `0x3705E..0x37062` / `0x1500E` | `strd r2,r3,[sp]`; `bl 0x373F0` with `r2=8` |
| Real store entry | `0x874` in `FASTBOOT.from-update-app.img[0:0x1000]` | before `{0,0,0xDB230}`; after `{0x16800000,0,0xDB230}`; length preserved |
| Security-class mapping | `0x30F28` / `0x0EF28` | status 5/7 -> `SEB_SECCFG_SECURE`; 0/1/3 -> INTEGRITY/NONE |
| Store address is image | `0x310D4`, `0x310EA` / `0x0F0D4` | `r2 = r6 = sb = 0x16800000`; error string `store_addr` |
| 4KB input staging | `0x31110..0x31116` / `0x0F110` | `r1 = 0x60035000`, `r2 = 0x1000`; `0x3718C` copies the block in; `0x36E14` zeroes it |
| Fastboot max size | `0x235F4`, `0x23648` / `0x15F4` | `ldr r4,=0x5FE000`, dest `0x16800000` |
| VRL header size | `0x23838..0x23846` / `0x1838` | dest `0x16DFE000`, size `0x1000` |
| Handoff call | `0x2329A` / `0x129A` | `a047 blx r4`, `r4=0xB3` |
| Handoff args | `0x23288..0x23298` / `0x1288` | `r0=0x8E200000`, `r1=0`, `r2=0xFFF50000`, `r3=0`, `[sp]=0x2E000`, `[sp+4]=5` |
| Fallback AArch64 trampoline | `0x232FC..0x2330A` / `0x12FC` | `AA1F03E0/F2A80000/D61F0000` at `0x16800000` |
| Fastboot AArch64 entry | `0x16800000` in `hisi970_fastboot_ram.bin` | vectors at 0, `0x16800000` at +0x20, `BOOTMAGICNUMBER!` at +0x24; EL3 stub at +0x34; VBAR_EL3 at +0x1800 |
| On-disk payload is high-entropy | `fastboot.dump.img` | first 16 bytes `bf695fc1...` |
| RAM image is plaintext | `hisi970_fastboot_ram.bin` | first 16 bytes `0d000014...` |
| Secure-debug SEB path | `0x31274`, `0x36EE0`, `0x38B70` | `cmd 0x840/0x574`; status only |
| HISEE partitions | `0x40718`, `0x407D8`, `0x40B38`, `0x40BF8` | names in partition tables; no code xrefs |

---

## 9. Unknowns and Bounded Negative Results

1. **Undocumented SEB firmware commands.** The xloader only exercises the commands above. The SEB/HISEE firmware may have a debug/export command that this artifact does not reference. It cannot be characterized or invoked from the xloader alone; the verdict is bounded to the implemented interface.
2. **Exact decryption boundary and hardware-store hypothesis.** The artifact does not resolve whether the storage engine decrypts inline, SEB decrypts internally for hashing, or the ROM decrypts at `0xB2`. The evidence supports "no xloader software decrypt" and "no SEB export," not a definitive attribution of the decrypt operation. The status `5/7` path is `SEB_SECCFG_SECURE`, and the store descriptor has an `{address, length}` shape; a hardware-side decrypt-and-store cannot be excluded. It is not proven by CPU instructions, the only CPU copy is a self-copy, and the 4KB staging buffer is zeroed after the call. A redirect of the store address to SRAM is therefore a hardware hypothesis, not an implemented command.
3. **ROM API `0xB2` ABI.** The target is boot-ROM code not present in the artifact. The parameter meanings in §6.2 are inferences from the values and the call context, not from ROM disassembly.
4. **Runtime VRL/certificate bytes.** The xloader reads the VRL header from the `vrl` partition at runtime; those bytes are not in the artifact. The store-table arithmetic in §3.5 is instruction-exact, but the runtime table contents (entry count, actual addresses) are not available offline.
5. **HISEE image loading.** The partition table defines `hisee_fs_a`/`hisee_img_a`, but no code path in this artifact references those names. Whether another component loads them is outside this image.
6. **AArch64 re-verification.** Whether the ROM re-verifies the image after a patch-after-verify injection is unknown. This is the main feasibility risk for the recommended route.
7. **TZASC behavior for the AArch64 master.** The project's hardware evidence is for the 32-bit master. The AArch64 image executes from the window, which proves read/execute for that master, but the exact TZASC/security-state configuration is not decoded here.

**Bounded negative result:** a full-file scan of all 2-byte-aligned Thumb `BL`/`BLX` instructions and all 32-bit literal pointers found no alternate entry to `0x36DCC`, `0x31074`, or `0x36EA0`. A full-file string search found no `decrypt`, `cipher`, `AES`, `plain`, or `export` command string. These are negative results over this artifact, not proofs about the silicon.

---

## 10. Reproduction Notes

All analysis was performed offline with read-only tools:

```bash
# artifact identity
shasum -a 256 artifacts/hisi970_xloader.bin

# key disassembly (radare2)
/opt/homebrew/bin/r2 -n -a arm -b 16 -m 0x22000 \
  -q -c 'e scr.color=0; s 0x36dcc; pd 60' artifacts/hisi970_xloader.bin

# capstone equivalent
python3 - <<'PY'
from capstone import *
from pathlib import Path
p = Path('artifacts/hisi970_xloader.bin').read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for ins in md.disasm(p[0x14dcc:0x14e9e], 0x36dcc):
    print(f'{ins.address:08x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')
PY
```

No device, VCOM port, upload, or flash operation was used. The only file created or modified is this report.

---

## 11. Bottom Line

**NO.** The SEB/HISEE interface in this xloader is a certificate/hash verification path, not a read/decrypt/export interface. `0x36DCC` is a status-driven verifier with a single caller; `0x31074` is the only entry to it; `0x36EA0` only rewrites the source-range address that tells SEB where to find the image. The CPU-visible SEB path stages the terminal VRL block in the 4KB `0x60035000` buffer, submits the store-range descriptor, and verifies the hash/signature; the buffer is zeroed on status-dispatched returns and cannot hold the 5.9MB image. The plaintext is not exportable through this interface. A hardware-side decrypt-and-store on the `SEB_SECCFG_SECURE` path remains a residual hypothesis, not an implemented or proven command.

The remaining route is post-handoff AArch64 code that reads `0x16800000` and exfiltrates it over USB or another channel. The smallest experiment is a patch-after-verify AArch64 dump stub; the safest alternative is a download-mode AArch64 payload, which bypasses the `0x311C8` verification but replaces the on-disk image. Both are substantially larger than a loader patch and must be treated as post-handoff systems-engineering work, not a SEB command.
