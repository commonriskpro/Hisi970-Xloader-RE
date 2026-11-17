# Option B2a - factory fastboot decryption path (offline analysis + patch design)

Status: **offline static analysis and plan.** No device, no VCOM, no fastboot, no flash,
no partition write was performed for this report. Nothing here is a live result.
Every claim carries a VA (or file offset) and the instructions it rests on.

Conventions:

- Factory fastboot: `VA = file_offset + 0x16800000`
  (`artifacts/hisi970_fastboot_ram.bin`, 5,986,304 B, sha256 `a41c25a3...cf3c03c`).
  Verified: this file is byte-identical to the plaintext of
  `tools/Exploit/bin/Release/net8.0-windows/loaders/hisi970/fastboot.ktl` (sha256 match).
- The image's **own** code+data ends at 0x16B8B000 (file 0x38B000). Everything after that in
  the artifact is the appended `readelf -s` symbol text, used below as the authority for
  names and function sizes. Any address >= 0x16B8B000 read from the file is symbol text, not
  data - this matters for every .bss constant named below.
- `[OBS]` = read directly from the artifact. `[INF]` = inference, tied to an observation.

---

## 0. Executive feasibility

| Question | Answer | Basis |
|---|---|---|
| Does the factory fastboot contain a decryption routine? | **YES** | `hisi_secboot_decrypt_encrypted_xloader` @ 0x16989D30, 0x1AC B, exported in the `secboot` operator table at **+0x80** (0x16B849C0). |
| Does that routine match the stock fastboot container? | **YES, on format** | It parses exactly the `E291F358` header chain present in `ROM/work/fastboot.img`, and its size arithmetic matches the file (`store_len + 0x1000`). |
| Is it reachable from any existing command? | **NO** | Zero direct callers; the only reference in the whole image is the vtable slot. No code reads `ops+0x80`. |
| Can a command be patched to call it? | **YES, minimally** | 8-byte handler repoint + an 88-byte AArch64 stub in an existing zero cave. Targets verified by re-decoding. |
| Will the SEB emit plaintext? | **UNCERTAIN** | Depends on whether the verify command used here decrypts in place at the comp-store address or only hashes. This is the decisive unknown. |

**Overall: UNCERTAIN, leaning feasible.** The engineering is small and safe; the physics is
unproven. One experiment decides it.

**Single most important unknown:** does `SecBoot_ImageVerification` (0x16986C0C) with
`w2 = 0` - the `seb_imghash_verify` branch taken at 0x16986D70 - **write the decrypted image
to the comp-store address**, or does it only produce a status/digest, leaving the actual
decryption to the ROM service `0xB2`? If it only verifies, B2a is dead: the plaintext never
leaves the secure core from this context.

---

## 1. Function map - `hisi_secboot_decrypt_encrypted_xloader` @ 0x16989D30

File offset 0x189D30, size 0x1AC (ends at 0x16989EDC, where `aes_byte` 0x16989EDC begins).

### 1.1 ABI

```
void *hisi_secboot_decrypt_encrypted_xloader(const void *container,   /* x0 */
                                             const char *group_name, /* x1 */
                                             uint32_t   *out_len);   /* x2 */
```

| Aspect | Value | Evidence |
|---|---|---|
| x0 | encrypted container base (header chain + ciphertext) | `src` of `memcpy` at 0x16989DC4; `x0` of `seb_fillcertpkg` at 0x16989D60 |
| x1 | NUL-terminated image-group name (`"fastboot"`) | forwarded unchanged to `SecBoot_ImageVerification` (0x16989DF8) which passes it to `SecBoot_GetImgGrpID` (0x16986B34) |
| x2 | `uint32_t *` out length | `str w0,[x21]` at 0x16989DA0 |
| return | malloc'd buffer, or NULL | `mov x20,x24` at 0x16989E00, return at 0x16989D68; every error path sets `x20=0` |
| buffer layout | `[0x1000 container header copy][plaintext of *out_len bytes]` | allocation size and destination offset, see 1.2 |
| alignment | none imposed on x0 | no AND/rounding of the source argument |

### 1.2 Instruction walk (VAs absolute)

```
16989d30  stp  x29,x30,[sp,#-0x80]!        prologue, frame 0x80
16989d38  stp  x19,x20,[sp,#0x10]
16989d3c  add  x19,x29,#0x68              ; local cert-pkg struct (0x18 B)
16989d48  mov  x22,x1                      ; x22 = group name
16989d54  mov  x21,x2                      ; x21 = out_len
16989d58  mov  x23,x0                      ; x23 = container base
16989d5c  mov  x20,#0                      ; default return = NULL
16989d60  bl   0x16986308                 ; seb_fillcertpkg(src, &vrl)
16989d64  cbz  w0,#0x16989d84              ; non-zero -> return NULL
16989d84  ldr  x0,[x29,#0x78]              ; vrl.ptr2
16989d8c  bl   0x16985e80                 ; seb_get_compdata(vrl.ptr2, &comp[0x18])
16989d90  cbnz w0,#0x16989e50              ; error path
16989d94  ldr  x0,[x29,#0x60]              ; comp.field2
16989d98  bl   0x16985b74                 ; SecBoot_Get_StoreLen(comp.field2)
16989d9c  add  w25,w0,#0x1000              ; alloc size = store_len + 0x1000
16989da0  str  w0,[x21]                    ; *out_len = store_len
16989da8  bl   0x16971790                 ; malloc(w25)
16989db0  cbz  x0,#0x16989ecc              ; OOM path -> return NULL
16989dc4  bl   0x169780ac                 ; memcpy(buf, src, store_len+0x1000)
16989dd0  bl   0x16986308                 ; seb_fillcertpkg(buf, &vrl) again
16989ddc  add  x1,x24,#1,lsl#12           ; x1 = buf + 0x1000  <- destination
16989de4  bl   0x169877a4                 ; SecBoot_ChangeCompStoreAddr(vrl, buf+0x1000, -)
16989df0  mov  w2,#0                      ; w2 = 0  -> imghash branch
16989dfc  mov  w3,#1                      ; w3 = 1
16989e04  bl   0x16986c0c                 ; SecBoot_ImageVerification(vrl, name, 0, 1)
16989e08  cbz  w0,#0x16989d68              ; success -> return buf
16989e4c  b    0x16989d68                 ; error -> return NULL (buffer leaked)
```

Callee identities from the symbol table:

| VA | Symbol | Notes |
|---|---|---|
| 0x16986308 | `SecBoot_FillCertPkg` (4-byte thunk -> 0x168983B8 `seb_fillcertpkg`) | header-chain parser |
| 0x16985E80 | wrapper -> 0x16898740 `seb_get_compdata` | fills a 0x18-byte triple |
| 0x16985B74 | `SecBoot_Get_StoreLen` | `memcpy(0x138)` then `return *(u32*)(base+0x130) << 2` |
| 0x16971790 | bump allocator (`malloc`) | `size > 0x7FFFF` only logs, then continues (0x169717AC -> 0x16971804 -> 0x169717B0) |
| 0x169780AC | `memcpy(dst,size,src,n)` | argument-order checks at 0x169780B0-0x169780DC |
| 0x169877A4 | `SecBoot_ChangeCompStoreAddr` | loops comp segments calling `seb_change_compaddr(seg_i, addr, i)` (0x169877FC-0x1698782C) |
| 0x16986C0C | `SecBoot_ImageVerification` | dispatches to SEB submit wrappers |
| 0x16989D30 | *(this function)* | referenced only from `secboot_ops+0x80` |

### 1.3 What it expects (header chain)

`seb_fillcertpkg` (0x168983B8) memsets a 0x18-byte output to `0xff` and parses three headers
through 0x1689420C, which inspects header *i* at `base_i + 0x80` and sets
`base_(i+1) = base_i + ((0x40 + len) * 4)`.

Header layout, from 0x168941C0:

```
+0x00  u32 magic   == 0xE291F358                (0x168941C0-0x168941D0)
+0x04  u32         == 0x00010000                (0x168941E0-0x168941E8)
+0x08  u16 own_len (type 1) / lo,hi (type 2)    (0x1689425C)
+0x0C  u32 flags   type = bits[18:17]           (0x168941F8-0x16894204, ubfx #0x11,#2)
next   base += (0x40 + u16@+8) * 4              (0x16894264-0x16894274)
type2  base += (0x40 + lo + 3*hi) * 4           (0x1689427C-0x16894284)
```

`seb_fillcertpkg` requires types **1, 1, 2** in that order and stores
`out = {base0, base1, base2}` (0x16898454, 0x168984A0, 0x168984EC).

### 1.4 Preconditions

- Heap headroom of `store_len + 0x1000` bytes in the fastboot bump allocator
  (`[0x16b8a448]` = current pointer, `[0x16b8b810]` = limit; loaded at 0x169717B8/0x169717BC,
  compared at 0x169717D4, OOM path 0x16971830-0x16971868).
- SEB reachable at EL3 (0xBDF0F000 register block). **Already exercised at runtime** by
  ops +0x30 (`SecBoot_Check_EncImg`, called from 0x1680C100), +0x60
  (`hisi_secboot_bootup_verification`, from 0x16808744) and +0x78
  (`hisi_secboot_in_sec_partition`, from 0x1680A8E0). [OBS] call sites; [INF] that the same
  channel serves 0x16986C0C.
- No key material is passed in: all three arguments are buffers/strings, and every SEB submit
  in 0x16893E64/0x168940D0 takes handles and descriptors, not keys. [OBS]

---

## 2. Reachability - dead interface slot

| Check | Result |
|---|---|
| `B`/`BL` whose target is 0x16989D30, over every 4-byte-aligned word of the image | **0 call sites** |
| 64-bit literal equal to 0x16989D30 | **1**: VA 0x16B849C0 = `secboot_ops + 0x80` |
| `secboot_ops` (0x16B84940) | 17 slots, +0x80 is the last |
| `get_operators("secboot")` call sites (name 0x169B5BD0) | 15: 0x16808738, 0x1680A8D4, 0x1680C0C8, 0x1680C218, 0x1680C7D8, 0x1680E188, 0x168227E8, 0x16822A50, 0x168245BC, 0x16825AD8, 0x168265EC, 0x16830F98, 0x1684B0F0, 0x168A6F04, 0x168A9064 |
| Ops offsets actually used at those sites | +0x08, +0x20, +0x30, +0x38, +0x58, +0x60, +0x70, +0x78 - **never +0x80, never +0x68** |

**Conclusion:** the operator is linked and exported but has no in-image consumer. No fastboot
command reaches it; a code patch is mandatory. Note also that +0x68
(`hisi_secboot_download_verification`, the natural "verify a downloaded image" entry) is
likewise unused, so there is no hidden download-time decrypt path.

---

## 3. Stock image format and key analysis

### 3.1 Measurements

| Artifact | Size | `u32@+0x87C` x 4 | Size - 0x1000 | Header chain |
|---|---|---|---|---|
| `ROM/work/fastboot.img` | 0x36D8C0 | 0x36C8C0 | 0x36C8C0 | 0x80, 0x34C, 0x618 |
| `artifacts/option-e/v2/xloader.img` | 0x22000 | 0x21000 | 0x21000 | 0x80, 0x34C, 0x618 |
| `artifacts/option-e/v2/fastboot.img` | 0x4CE000 | 0x4CD000 | 0x4CD000 | 0x80, 0x34C, 0x618 |
| `artifacts/option-e/v2/uce.img` | 0xA000 | 0x9000 | 0x9000 | 0x80, 0x34C, 0x618 |

The relation `store_len = file_size - 0x1000` holds for all four. That is exactly the
function's arithmetic: allocate `store_len + 0x1000`, copy `store_len + 0x1000` from the
container, decrypt into `buf + 0x1000`.

### 3.2 Layout of the stock fastboot container

```
0x0000..0x00FF    packaging prefix: 00..., 01 00 00 00 01 00 00 00, "fastboot" at 0x1C
0x0080            header #0  magic E291F358, 0x00010000, len 0x73, type 1  -> next 0x2CC
0x034C            header #1  identical shape, type 1                      -> next 0x2CC
0x0618            header #2  len 0x77/0x01, flags 0x000501FF (type 2)     -> body 0x880
0x087C            store length 0x000DB230 words = 0x36C8C0 bytes
0x1000..0x36D8BF  ciphertext, 0x36C8C0 bytes
```

Cross-checks: `artifacts/fastboot.stock.payload.img` is byte-identical to
`work/fastboot.img[0x1000:]` **and** to `artifacts/fastboot.dump.img[0:0x36C8C0]`. The
on-flash partition therefore carries **only the ciphertext**; the 0x1000 header chain exists in
the OTA container and, on-device, in the VRL block the loader reads to 0x16DFE000 (the live
probe reported header `"fastbkj4"` there, per the task brief).

Entropy of the payload is ~8.0 bit/byte and the plaintext length equals the ciphertext length,
so this is a block cipher applied in place - **no compression**. [INF] Corroborated by the
xloader, whose plaintext (`artifacts/hisi970_xloader.bin`, 0x22000) is exactly 0x1000 zero
bytes followed by the ELF payload, i.e. the same length as its own container.

### 3.3 Key and state

No key material is in the image and none is passed to the function. [OBS]
`SecBoot_GetImgGrpID` (0x16986A58) matches the `x1` string against four 16-name tables at
0x16B89120 (stride 0x10, entries `{gid, names}`):

```
entry 0  gid 0x1  { fastboot }
entry 1  gid 0x2  { teeos, fw_lpm3, trustfirmware }
entry 2  gid 0x4  { kernel, erecovery_kernel, vbmeta, ... }
entry 3  gid 0x8  { xloader, fastboot }        <- second match for "fastboot"
...
```

`"fastboot"` therefore resolves to **0x1 | 0x8 = 0x9**, i.e. the same group class the stock
image belongs to. Whether the *version* counter accepts the stock image is separate:
`SecBoot_CheckVersion.constprop.6` (0x16986B18) reads OTP word 0x5CF (20 bytes, via 0x168E86C8)
and compares bit counts with the segment version at `seg+0x18`; it only *reports*
(`str w0,[x20]`) and returns 0 unless the OTP read itself fails. [OBS] 0x16986B38-0x16986C08.

---

## 4. Patch design

Two file-level edits, applied to the copy uploaded over VCOM. Nothing is written to flash.

### 4.1 P1 - repoint the `dump:` command (8 bytes, .data)

Main command table 0x16B13568, 12 entries, stride 0x18, bound `add x21,x19,#0x120` at
0x1680BD8C. Entry 4 is `dump:` (name 0x169BABD8, len+1 = 6, handler 0x1680B398).

| Item | Value |
|---|---|
| VA | 0x16B135D8 |
| File offset | **0x3135D8** |
| Before | `98 b3 80 16 00 00 00 00` (0x1680B398 `usbcmd_dump_func`) |
| After | `d0 11 80 16 00 00 00 00` (0x168011D0, the stub) |

`dump:` is benign (`usbcmd_dump_func` only formats two parsed integers) and is **not** in the
47-entry locked-state deny list at 0x16B14018 (B2 report, section 2.2). The command keeps its
name and length, so no table relocation, no dispatcher change, no new command surface.

### 4.2 P2 - stub in the existing zero cave (88 bytes, .text)

First zero run in the image: **0x168011D0, 0x630 bytes of 0x00** (file 0x11D0). The stub fits
with 0x5D8 bytes to spare and touches nothing else.

| VA | File | Bytes | Meaning |
|---|---|---|---|
| 0x168011D0 | 0x11D0 | `fd 7b be a9` | `stp x29,x30,[sp,#-0x20]!` |
| 0x168011D4 | 0x11D4 | `fd 03 00 91` | `mov x29,sp` |
| 0x168011D8 | 0x11D8 | `f3 53 01 a9` | `stp x19,x20,[sp,#0x10]` |
| 0x168011DC | 0x11DC | `f3 03 00 aa` | `mov x19,x0` |
| 0x168011E0 | 0x11E0 | `c2 c7 05 94` | `bl 0x169730E8` (hex2unsignedlong(arg)) |
| 0x168011E4 | 0x11E4 | `40 00 00 b5` | `cbnz x0,#0x168011EC` |
| 0x168011E8 | 0x11E8 | `00 c0 a2 d2` | `movz x0,#0x1600,lsl#16` (default src) |
| 0x168011EC | 0x11EC | `61 0d 00 f0` | `adrp x1,#0x169b0000` |
| 0x168011F0 | 0x11F0 | `21 e0 11 91` | `add x1,x1,#0x478` -> "fastboot" |
| 0x168011F4 | 0x11F4 | `62 1c 00 d0` | `adrp x2,#0x16b8f000` |
| 0x168011F8 | 0x11F8 | `42 e0 07 91` | `add x2,x2,#0x1F8` -> out_len slot |
| 0x168011FC | 0x11FC | `cd 22 06 94` | `bl 0x16989D30` |
| 0x16801200 | 0x1200 | `68 1c 00 d0` | `adrp x8,#0x16b8f000` |
| 0x16801204 | 0x1204 | `08 01 08 91` | `add x8,x8,#0x200` |
| 0x16801208 | 0x1208 | `00 01 00 f9` | `str x0,[x8]` (publish buffer pointer) |
| 0x1680120C | 0x120C | `a0 0d 00 d0` | `adrp x0,#0x169b7000` |
| 0x16801210 | 0x1210 | `00 00 39 91` | `add x0,x0,#0xE40` -> "OKAY" |
| 0x16801214 | 0x1214 | `41 00 80 52` | `mov w1,#2` |
| 0x16801218 | 0x1218 | `95 26 00 94` | `bl 0x1680AC6C` (`usbcmd_common_ack`) |
| 0x1680121C | 0x121C | `f3 53 41 a9` | `ldp x19,x20,[sp,#0x10]` |
| 0x16801220 | 0x1220 | `fd 7b c2 a8` | `ldp x29,x30,[sp],#0x20` |
| 0x16801224 | 0x1224 | `c0 03 5f d6` | `ret` |

Contiguous hex (88 bytes, file 0x11D0):

```
fd7bbea9 fd030091 f35301a9 f30300aa c2c70594 400000b5 00c0a2d2 610d00f0
21e01191 621c00d0 42e00791 cd220694 681c00d0 08010891 000100f9 a00d00d0
00003991 41008052 95260094 f35341a9 fd7bc2a8 c0035fd6
```

Every branch target above was re-decoded from the encoded words, in place, at the VAs shown.
Facts the stub relies on, all verified: 0x169B0478 is the NUL-terminated `"fastboot"` used by
`SecBoot_GetImgGrpID`; 0x169B7E40 is `"OKAY"`; 0x169730E8 is a tail branch into the
`hex2unsignedlong` parser at 0x1697305C; `usbcmd_common_ack` is `(char *msg, w1=2)`.

### 4.3 Output publication

| Item | VA | Contents |
|---|---|---|
| `*out_len` | 0x16B8F1F8 | u32 plaintext length (written by the callee at 0x16989DA0) |
| buffer pointer | 0x16B8F200 | u64 pointer to `[0x1000 hdr][plaintext]` |

Both live inside `emmc_diag_record` (0x16B8F1F8, 0x540 B, .bss), touched only by
`oem emmc_diag_*`, which this flow never calls. Read both with one command:
`upload_memory:16B8F1F8:10` -> `[len u32][pad u32][ptr u64]`.

### 4.4 Getting the container into DRAM (staging)

The stub deliberately does not solve this: it takes the source address from the command
argument, so any staging path works.

**S-A (preferred): the VCOM download parser, before the handoff.**
The 32-bit loader's download parser takes the destination from the head frame
(`ctx+0x3E0`, 0x2FA3A-0x2FAC8 - no range check) and `memcpy`s each 0x400-byte data frame to it
(0x2FB5C-0x2FB6C). Writes to the `0x16xxxxxx` window are proven on hardware: the factory
fastboot itself is uploaded there and boots. The same VCOM session that uploads the patched
factory fastboot to 0x16800000 can upload `work/fastboot.img` (0x36D8C0 B, padded to a 0x400
multiple) to **0x16000000**. The loader cannot *read* that window (STATUS.md) but does not need
to - the AArch64 side reads it.

Caveats: (a) 0x16000000 + 0x36D8C0 = 0x1636D8C0, clear of the image at 0x16800000-0x16DB8000;
(b) one experiment per VCOM entry still applies (STATUS.md); (c) the region must survive the
ROM 0xB2 handoff - the live probe already shows 0x16000000 readable (0xFF) from the fastboot,
so it is free, but that it *retains* the uploaded bytes is confirmed only by the T4 read-back.

**S-B (fallback): `download:` + the ultraflash descriptor.**
`usbcmd_download_func` (0x16826100) only records `{len, 0, cb}` at 0x16B8F798
(`str x0,[x19,#8]` 0x16826128, `str xzr,[x19,#0x10]` 0x16826138, `str x3,[x19,#0x18]`
0x16826144) and publishes `&download` at [0x16B14C78]. No RAM buffer is allocated there; the
destination is materialised only when the flash path calls
`g_ultraflash_ops->[0x30](len, &addr, &len2)` (0x168263AC-0x168263C4). Calling that accessor
from the stub is possible but is more moving parts than S-A.

---

## 5. Read-only test sequence (no flash, no partition write)

| Step | Action | Expected | Decides |
|---|---|---|---|
| T0 | Stock factory fastboot | `fastboot devices` | baseline |
| T1 | `upload_memory:16000000:10` | OKAY + 16 B | staging window readable |
| T2 | Pre-flight heap: read `[0x16B8A448]` and `[0x16B8B810]` (8 B each), then the two values they point at | `limit - cur >= 0x36D8C0` | enough RAM for the 3.59 MB allocation |
| T3 | Upload patched factory fastboot + container at 0x16000000 in one VCOM session | `fastboot devices` | patch survives the ROM 0xB2 handoff |
| T4 | `upload_memory:16000000:20` | `bf 69 5f c1 ...` (container[0:0x20]) | staging landed and survived |
| T5 | `dump:` (no argument -> src defaults to 0x16000000) | `OKAY`, no hang | call plumbing |
| T6 | `upload_memory:16B8F1F8:10` | `[len][pad][ptr]` | function returned non-NULL and reported a length |
| T7 | `upload_memory:<ptr+0x1000>:40` | structured plaintext, not ciphertext | **the decisive observation** |
| T8 | Full dump of `<ptr+0x1000>` in 0x10000 chunks, two passes | 3,590,336 B, identical hashes | output is stable |

Interpretation of T7:

- `0d 00 00 14 0c 00 00 14 ...` (AArch64 vectors) or any low-entropy structured header ->
  the SEB emitted plaintext, **B2a works**.
- `bf 69 5f c1 ...` (still the ciphertext prefix) -> the SEB verified but did not decrypt into
  the store address, **B2a is dead**, go to B2b.
- Neither -> the store-address semantics differ from the model here; check `*out_len` against
  0x36C8C0 before concluding.

Control experiment if T7 is ambiguous: repeat with the small `uce` container (0xA000 B, known
plaintext length 0x9000). 40 KB distinguishes the three cases and costs one VCOM entry.

---

## 6. Risks

| Risk | Severity | Mitigation |
|---|---|---|
| SEB only verifies; no plaintext emitted | fatal to B2a | T7 answers it in one run; nothing persistent is touched |
| Heap headroom < 0x36D8C0 | fatal | T2 measures it first; the allocator logs and returns 0 (0x16971830) rather than corrupting memory |
| 0x16000000 cleared by the handoff or by heap growth | workaround exists | T4 read-back; otherwise pick a higher free window from `getvar memory_info_<n>` |
| SEB version/rollback rejects the stock image | likely benign | `SecBoot_CheckVersion` only reports; a rejection surfaces as non-zero from 0x16989E08 |
| Stub corrupts a register the dispatcher needs | low | stub saves/restores x19/x29/x30; the dispatcher's own x19 (0x1680BD74) is preserved by the callee-saved convention |
| Patch breaks the boot chain | low | bytes live in an unreferenced zero cave plus one table pointer; T0 vs T3 separates the two failure modes |

Rollback: power-cycle and re-run the stock sequence. Nothing is written to storage; the only
persistent artifacts are files under `reports/`.

---

## 7. Recommendation

**Run B2a once, in the form above.** Rationale:

- The call surface is 88 bytes of code plus one 8-byte pointer: no new command, no table growth.
- All four failure modes are non-destructive and distinguishable from two memuploads.
- If it works it is the cheapest route to the stock plaintext, and it also validates the
  SEB-in-place-decryption model that B2b would have to rely on anyway.

**Fall back to B2b (xloader P-A/P-B + SEB in-place decrypt at 0x16800000) if T7 shows
ciphertext.** B2b needs the same SEB property, so a negative here is also evidence against the
cheap half of B2b; in that case the paid RDLOCK route is the only remaining option.

Do **not** run the repoint without T2: a 3.59 MB allocation on a bump allocator with an unknown
limit is the one way this read-only experiment can turn into a hang.

---

## 8. Open questions, ranked

1. **Does `seb_imghash_verify` (0x16898298, reached from 0x16986D70) write plaintext at the
   comp-store address?** Decides everything. One run.
2. **Does 0x16000000 retain the VCOM-uploaded container across the ROM 0xB2 handoff?** Decides
   the staging variant only; T4.
3. **Is the stock image's certificate version >= the OTP counter at 0x5CF?** Affects acceptance,
   not feasibility.
4. **Must the 0x1000 header chain be the stock one?** It carries certificates, so assume yes:
   this plan uploads `work/fastboot.img[0:0x1000]` unchanged as part of the container.

*No vendor binaries, keys, or key material are reproduced here; only addresses, offsets and
instruction encodings derived from artifacts already in this repository.*
