# Kirin 970 xloader — milestone 1 static map

Status: **static analysis only.** No device was touched, nothing was flashed, and no
artifact was modified.

## 0. Artifact and addressing

| Item | Value |
|---|---|
| File | `artifacts/hisi970_xloader.bin` |
| Size | 139,264 bytes = `0x22000` |
| SHA256 | `2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691` |
| Architecture | Thumb-2 / ARMv7, stripped |
| Source | decrypted `loaders/hisi970/xloader.ktl` |

The file is a **0x1000-byte zero prefix followed by an ELF image at file offset
`0x1000`**. The ELF header is at file `0x1000`; `e_entry = 0x23154`,
`e_phoff = 0x34`, `e_phnum = 9`, `e_machine = 0x28` (ARM), `e_flags = 0x05000002`.

For the present code/data, the mapping is:

```
VA = file_offset + 0x22000
file_offset = VA - 0x22000
```

Evidence: the first `PT_LOAD` says `p_offset=0x154, p_vaddr=0x23154`; the ELF image
starts at file `0x1000`, so file `0x1154` is VA `0x23154`. This also makes every
literal string pointer resolve correctly (e.g. file `0x1c2e4` -> VA `0x3e2e4`).

Program headers (file `0x1034` onward, 32 bytes each):

| # | Type | File offset | VA | File size | Mem size | Flags |
|---|---|---|---|---|---|---|
| 0 | PT_PHDR | 0x0 | 0x0 | 0x154 | 0x154 | 4 |
| 1 | PT_LOAD | 0x154 | 0x23154 | 0x1ddf0 | 0x1ddf0 | 5 |
| 2 | PT_LOAD | 0x1df44 | 0x3ff44 | 0x30bc | 0x30bc | 6 |
| 3 | PT_LOAD | 0x21000 | 0x60048000 | 0x1000 | 0x1000 | 6 |
| 4 | PT_LOAD | 0x22000 | 0x60049000 | 0x1000 | 0x1000 | 6 |
| 5 | PT_LOAD | 0x23000 | 0x6004a000 | 0x9000 | 0x9000 | 6 |
| 6 | PT_LOAD | 0x2c000 | 0x0 | 0x0 | 0x0 | 0 |
| 7 | PT_LOAD | 0x2c000 | 0x0 | 0x0 | 0x0 | 0 |
| 8 | PT_LOAD | 0x2c000 | 0x60053000 | 0x0 | 0xca5c | 6 |

`ph1` corresponds to file `0x1154..0x1df44` (VA `0x23154..0x3ff44`) and `ph2` to
file `0x1ef44..0x22000` (VA `0x3ff44..0x43000`). The `ph3..ph5` file ranges begin at
or beyond EOF in this artifact (the last `p_offset` is `0x2c000`); they are either
truncated or runtime-populated and are not needed for this map. `ph8` is BSS at
`0x60053000`.

Useful regions:

| File | VA | Contents |
|---|---|---|
| `0x1000` | `0x23000` | ELF header / entry stub |
| `0x1154` | `0x23154` | entry stub; main at `0x2316c` |
| `0x1a938` | `0x3c938` | start of literal string pool (code ends at `0x3c937`) |
| `0x1e598` | `0x40598` | partition table for storage type 1 (eMMC) |
| `0x1e9b8` | `0x409b8` | partition table for storage type 2 (UFS) |
| `0x1c2e4` | `0x3e2e4` | USB/VCOM strings |
| `0x1e658` | `0x40658` | `fastboot_a` entry, type-1 table |
| `0x1ea78` | `0x40a78` | `fastboot_a` entry, type-2 table |

## 1. Entry stub and main

File `0x1154` / VA `0x23154`:

```
0x23154  00f006b8   b.w 0x23164
0x23158  00f004b8   b.w 0x23164
0x2315c  "XLOADER!"        ; data embedded between the branches
0x23164  00f002f8   bl 0x2316c
0x23168  fee7       b 0x23168   ; hang if main returns
```

`main = VA 0x2316c` (file `0x116c`). It initialises clocks/storage/security and
calls, in order (selected calls relevant here):

```
0x23174  bl 0x23f70        ; returns r0 = 0xb3 -> r4 (used at 0x2329a)
0x2317a  bl 0x23f74        ; writes 0 to address 0x21e14
0x2317e  bl 0x24460        ; conditional low-ROM call (see §6)
...
0x23222  bl 0x234f4        ; storage/boot helper with r0 = 4
...
0x23236  bl 0x23f1c        ; boot strap / LCS helper
0x2323e  bl 0x338d8        ; only if 0x23f1c() == 1
...
0x23260  bl 0x232e8        ; trampoline / "reserved5" fallback
...
0x2326c  bl 0x24178        ; read [0x60053000]
0x23270  08b9  cbnz r0, 0x23276
0x23272  bl 0x2391c        ; normal-load or USB-download wait
0x23276  bl 0x23fb4
0x2327a  bl 0x2ef8c        ; VCOM download buffer/header check
0x2327e  bl 0x35f5c        ; progress 0x19
0x23284  bl 0x23fe4
0x23292  ldr r0, =0x8e200000
0x23296  ldr r2, =0xfff50000
0x23298  movs r3, 0
0x2329a  blx r4            ; r4 = 0xb3: boot-ROM API 0xb2
0x2329c  ldr r0, =0x196ce ; +PC -> 0x3c970 "fst err"
0x232a4  b 0x232a4        ; hang
```

The stack arguments for the `blx r4` are `[sp] = 0x2e000`, `[sp+4] = 5`
(`0x23288..0x2328e`). `0x23f70` is a two-instruction function:

```
0x23f70  b320   movs r0, 0xb3
0x23f72  7047   bx lr
```

So the final call is to **VA 0xb2** (Thumb bit set in `0xb3`). Low addresses
`0x6a8/0xb2` are boot-ROM APIs; see §6.

## 2. Boot-mode dispatch

### 2.1 Global `[0x60053000]`

`0x24178` (file `0x2178`) is exactly:

```
0x24178  014b        ldr r3, [pc, #4]      ; literal at 0x24180 = 0x60053000
0x2417a  1868        ldr r0, [r3]
0x2417c  7047        bx lr
```

Main calls it at `0x2326c`. The branch at `0x23270` is **`cbnz r0, 0x23276`**:
if `[0x60053000] != 0`, the xloader **skips** `0x2391c`; if it is zero, it calls
`0x2391c`. The only write to `0x60053000` in this image is at `0x24154` inside
`0x2410c`: that function reads 0x40 bytes of the `"patch"` partition to
0x16800000, compares the first 0x11 bytes with `"sate_aging_start"` (`0x3cc40`),
and on success sets `[0x60053000] = 1`. Thus `0x232e8` first calls `0x2410c`; if
the patch magic is present, the flag becomes 1, `0x232ee` sees it non-zero, and
the SATE-aging/reserved5 trampoline path runs. Main then reads the same flag at
`0x2326c` and skips `0x2391c`, so the normal fastboot load/USB wait never runs.
If the patch magic is absent, the flag stays 0, `0x232e8` returns -1, and main
calls `0x2391c` for the normal path. This is a **SATE-aging gate**, not the normal
boot dispatch. `0x23fe4` also reads `[0x60053000]` at `0x23ff8` and calls
`0x242d8(0xff)` when it equals 1, and otherwise compares `[0x60053004]` with
`0xdaf` at `0x2400a`; that is consistent with a boot-reason word, but the exact
encoding is not fully proven.

### 2.2 `0x2391c`: normal load vs USB download

`0x2391c` (file `0x191c`) first calls `0x23f1c` and stores the result in `r5`:

```
0x23926  bl 0x23f1c
0x2392a  mov r5, r0
0x2392c  mov r0, r4
0x2392e  bl 0x30f28        ; LCS/boot-type helper; returns byte in [sp+7]
0x23932  ldrb r2, [sp, 7]
...
0x2394a  cmp r5, 1
0x2394c  1cd1  bne 0x23988 ; not 1 -> USB download wait
0x2394e  ... "Flash boot mode to read fastboot!"
0x2395e  bl 0x237e0        ; normal load/verify attempt #1
0x23962  adds r0, 1
0x23964  bne 0x239b8       ; success -> return
0x23966  ... second attempt
0x23972  adds r0, 1
0x23974  bne 0x239b8
0x23976  ... "FsLdCk fail!"; reboot(0x92)
```

The download branch:

```
0x23988  ... "xloader main download mode to get fastboot!"
0x23990  log loop
0x23996  movs r0, 0
0x23998  bl 0x2f8c0        ; USB download state machine
0x2399c  cmp r0, 0x16800000
0x239a2  beq 0x239ac
0x239a4  log; b 0x23990
0x239ac  ... return
```

So the runtime choice is:

```
if ([0x60053000] == 0) {
    if (0x23f1c() == 1)  load_fastboot_from_storage();   // 0x237e0
    else                 wait_for_usb_download();        // 0x2f8c0 == 0x16800000
}
```

The strings are real PC-relative references, not literal words:

- `0x3cac3` / file `0x1aac3` = `"Flash boot mode to read fastboot!"`
  (literal `0x1916f` at VA `0x239c0`, `add r0,pc` at `0x23950`).
- `0x3caf4` / file `0x1aaf4` = `"xloader main download mode to get fastboot!"`
  (literal `0x19164` at VA `0x239c8`, `add r4,pc` at `0x2398c`).
- `0x3cae6` / file `0x1aae6` = `"FsLdCk fail!"` (literal `0x1916a` at VA `0x239c4`).

### 2.3 `0x23f1c`: strap / LCS decision

`0x23f1c` (file `0x1f1c`):

```
0x23f1e  bl 0x242a8       ; read [0x4020ae00], not the PC
0x23f22  ldr r3, =0x3670e000
0x23f24  bic r0, r0, #0xff0
0x23f28  bic r0, r0, #0xf
0x23f2c  cmp r0, r3
0x23f2e  bne 0x23f34
0x23f30  movs r0, 1
0x23f32  pop {r3, pc}
0x23f34  bl 0x242a8
0x23f38  ldr r3, =0x3670a000
...
0x23f44  beq 0x23f30
0x23f46  ldr r3, =0x4020a40c
0x23f48  ldr r0, [r3]
0x23f4a  and r0, r0, 1
0x23f4e  pop {r3, pc}
```

So it returns **1** when the masked hardware register `[0x4020ae00]` equals
`0x3670e000` or `0x3670a000`, otherwise returns **bit 0 of `0x4020a40c`**. This is a
boot-strap/secure-config bit, not a string dispatch.

### 2.4 `0x23f5c`: storage type (eMMC vs UFS)

`0x23f5c` (file `0x1f5c`):

```
0x23f5c  ldr r3, =0x4020a3a0
0x23f5e  ldr r3, [r3]
0x23f60  tst.w r3, 0x8000
0x23f64  ite ne
0x23f66  moveq r0, 2
0x23f68  movs r0, 1
0x23f6a  bx lr
```

This returns **1 = eMMC**, **2 = UFS** (confirmed by `0x25268` logging
`"StorType:%s."` with `"eMMC"`/`"UFS"` at `0x3d162`/`0x3d167`). The partition
table lookup uses this value.

### 2.5 The `0x232e8` trampoline / "reserved5" fallback

`0x232e8` (file `0x12e8`) is called from main at `0x23260`:

```
0x232e8  ...
0x232ee  bl 0x24178
0x232f2  cbz r0, 0x23350   ; only when [0x60053000] != 0
0x232fa  ldr r2, =0xaa1f03e0
0x232fc  mov.w r3, 0x16800000
0x23300  str r2, [r3]       ; AArch64: mov x0, xzr
0x23302  ldr r2, =0xf2a80000
0x23306  str r2, [r3, 4]    ; AArch64: movk x0, #0x4000, lsl #16
0x23308  ldr r2, =0xd61f0000
0x2330a  str r2, [r3, 8]    ; AArch64: br x0
...
0x23310  mov.w r3, 0x10000000
0x23314  ldr r0, =string "reserved5" (VA 0x3c938)
0x23328  bl 0x24e14         ; read "reserved5" -> 0x10000000
0x23346  ldr r3, =0x4020a40c
0x2334c  str 0x100, [r3]
```

The three stored words are `0xaa1f03e0`, `0xf2a80000`, `0xd61f0000`: AArch64
`mov x0, xzr; movk x0, #0x4000, lsl #16; br x0`, i.e. a jump to **0x40000000**.
This is a **fallback trampoline** at 0x16800000; it is overwritten if a real
fastboot image is later read there. It is not the normal fastboot entry.

### 2.6 Boot-mode/message strings and their references

`"normalboot"` at file `0x1a9b2` / VA `0x3c9b2` **is** referenced: `0x238ae`
loads literal `0x190fc` and `0x238b2 add r3,pc` gives `0x3c9b2`; it is passed as
the first `%s` tag to `0x311c8`. `"fastboot"` at `0x1a979` / `0x3c979` is the
second tag (`0x238b6` literal `0x190b9`, `0x238bc add r3,pc`). `"download"` at
`0x1a982` / `0x3c982` still has no exact literal or PC-relative reference found;
the active dispatch uses `[0x60053000]`, `0x4020ae00`, and `0x4020a3a0`, plus
the long messages above. Do not treat the short `"download"` string as the
dispatch key.

## 3. Partition table and `fastboot_a`

The type-2 (UFS) table base is VA `0x409b8` (file `0x1e9b8`), 15 entries of
`0x40` bytes. The relevant entries:

| Name | File | VA | Start sector (+0x28) | Size sectors (+0x30) | Type (+0x38) |
|---|---|---|---|---|---|
| `xloader_a` | `0x1e9b8` | `0x409b8` | 0 | 0x800 | 0 |
| `vrl` | `0x1e9f8` | `0x409f8` | 0x200 | 0x200 | 3 |
| `vrl_backup` | `0x1ea38` | `0x40a38` | 0x400 | 0x200 | 3 |
| `fastboot_a` | `0x1ea78` | `0x40a78` | 0x5f800 | 0x3000 | 3 |
| `nvme` | `0x1eab8` | `0x40ab8` | 0x2800 | 0x1800 | 3 |

`0x3000` sectors = 6 MiB; the xloader's fastboot read cap is `0x5fe000`
(6,283,264), just below 6 MiB. The type-1 (eMMC) table base is `0x40598`
(file `0x1e598`); its `fastboot_a` entry is at `0x40658` / `0x1e658`
(start sector `0x61800`, size `0x3000`).

The lookup function is `0x3c188` (file `0x1a188`):

```
0x3c18e  bl 0x23f5c           ; 1=eMMC, 2=UFS
0x3c198  ldr r2, =0x40598     ; eMMC table
0x3c1a0  ldr r2, =0x409b8     ; UFS table
0x3c1a4  ldr r4, =0x60053d80  ; current table pointer
0x3c1ac  bl 0x3c148           ; strcmp over 0x40-byte entries
0x3c1e8  ...
0x3c202  cmp r6, 1
0x3c208  ldr r2, ="_a"
0x3c20c  cmp r6, 2
0x3c210  ldr r2, ="_b"
```

`r6` is the A/B slot from `0x252d0` (file `0x152d0`), which returns 1 or 2 via the
eMMC/UFS slot helpers (`0x3b214` / `0x352e4`). Thus the name `"fastboot"` passed
by the loader becomes **`fastboot_a`** or **`fastboot_b`**.

## 4. Fastboot read path

### 4.1 `0x235f4` — read `fastboot` to `0x16800000`

File `0x15f4` / VA `0x235f4`:

```
0x235f4  push {r0,r1,r2,r3,r4,r5,r6,lr}
0x235f8  bl 0x24294           ; timer
0x235fc  ldr r4, =0x5fe000    ; default/max size
0x23600  cbz r5, 0x2361e
0x23602  cmp r5, r4
0x23604  bls 0x23612
0x23606  ... "FsImgBig" ; reboot(0xc)
0x23612  addw r4, r5, 0x1ff
0x23616  bic r4, r4, 0x1fe
0x2361a  bic r4, r4, 1
0x2361e  movs r0, 1
0x23620  bl 0x2407c
0x23624  bl 0x242a8
0x23628  ldr r2, =0x3670e000
...
0x23648  mov.w r3, 0x16800000
0x2364c  ldr r0, =0x1931d   ; +PC -> 0x3c979 "fastboot"
0x23650  str r3, [sp]       ; arg5 = destination
0x23654  strd r2, r3, [sp,8] ; size/offset
0x2365e  bl 0x24e14         ; read partition
0x23662  cbz r0, 0x23678
0x23664  ... "LdFs ended" / reboot(9)
0x23678  ... return 0
```

Observed arguments to the generic read `0x24e14`:
`name="fastboot"`, offset 0, size `r4` (default `0x5fe000`, or the requested
size rounded up to `0x200`), destination `0x16800000`.

The `0x242a8` calls at `0x23624`/`0x23636` are **not** PC reads: `0x242a8` is
`ldr r3,=0x4020ae00; ldr r0,[r3]; bx lr`, i.e. a core/strap identity read. The
`0x3670e000`/`0x3670a000` compare is therefore a "skip the storage read when
already running from X" check, not a position-independent-code check.

### 4.2 `0x237e0` — VRL header, patch partition, verify

File `0x17e0` / VA `0x237e0`:

```
0x237e0  push {r4,r5,r6,r7,lr}
0x237ea  add r0, sp, 0x18
0x237ec  movs r1, 0x22
0x237f2  bl 0x30ef4           ; seb_get_vrl_offset(&dst, 0x22)
0x237f6  cbz r0, 0x23802
0x237f8  ... "GetVrlErr"
0x23802  movs r0, 0x14
0x23804  bl 0x35f5c           ; progress
...
0x2382e  ldr r0, =0x19252
0x23830  add r0, pc           ; -> 0x3ca86 "vrl"
0x23834  ldr r0, =0x19250     ; (alternate)
0x23836  add r0, pc           ; -> 0x3ca8a "vrl_backup"
0x23838  ldr r3, =0x16dfe000
0x2383a  mov.w r4, 0x1000   ; offset comes from 0x30ef4: 0x22 << 12 = 0x22000
0x23840  str r3, [sp]         ; arg5 = destination 0x16dfe000
0x23842  strd r4, r5, [sp,8]  ; size 0x1000
0x23846  ldrd r2, r3, [sp,0x18]
0x2384a  bl 0x24e14           ; read VRL header
...
0x23864  cmp r6, 2
0x23866  beq 0x23880
0x23868  ldr r0, =0x16dfe000
0x2386a  add r1, sp, 0x14
0x2386c  ldr r2, =0x5a5a0101
0x2386e  bl 0x30fb8           ; parse VRL header, get fastboot size
0x23872  cbz r0, 0x23880
...
0x23880  bl 0x23710           ; "patch" partition handling
...
0x23894  ldr r0, [sp, 0x14]   ; size
0x23896  bl 0x235f4           ; read fastboot -> 0x16800000
0x2389a  adds r0, 1
0x2389c  bne 0x238ae
...
0x238ae  ldr r3, =0x190fc    ; +PC -> 0x3c9b2 "normalboot"
0x238b4  str r3, [sp]
0x238b6  ldr r3, =0x190b9    ; +PC -> 0x3c979 "fastboot"
0x238b8  mov.w r1, 0x16800000 ; image
0x238be  str r3, [sp, 4]
0x238c2  movs r3, 0xb
0x238c4  bl 0x311c8           ; verify(VRL=0x16dfe000, img=0x16800000, tags)
```

`r4` (first argument) selects `"vrl"` when zero and `"vrl_backup"` otherwise.
`r6` is the boot type/LCS byte passed in `r1`; `2` skips the VRL size parse.
The "patch" handler at `0x23710` (file `0x1710`) is a separate
`BOOTMAGICNUMBER!`-based patch-partition mechanism; it runs **before** the
fastboot read and uses the same 0x16800000 scratch area, so it does not clobber
the later fastboot image.

## 5. Verify / decrypt call chain

### 5.1 `0x31154` — VRL format and size

File `0xf154` / VA `0x31154`, called from the legacy `0x23374` and from the
xloader self-verify at `0x234b8`:

```
0x31154  push.w {r0,r1,r4,r5,r6,r7,r8,lr}
0x31158  mov r8, r3          ; boot type
0x3115c  mov r7, r0          ; image address
0x3115e  mov r6, r1          ; magic
0x31160  mov r5, r2          ; max size
0x31166  bl 0x30d78          ; VRL format check
0x3116a  cbnz r0, 0x31198
0x3116c  mov r0, r7
0x3116e  add r1, sp, 4
0x31170  mov r2, r6
0x31172  bl 0x30fb8          ; get size
0x31176  ...
0x31184  ldr r3, [sp, 4]
0x31188  cmp r3, r5
0x3118a  bls 0x311b6
0x3118c  ... "get %s size error"
0x311b6  return
```

`0x30d78` (file `0xed78`) maps magic to partition name:

| Magic | Name | Check |
|---|---|---|
| `0x5a5a0101` | `"fastboot"` (VA `0x3c979`) | `[hdr+0x80] == 0xe291f358`, `[hdr+8]==1`, `[hdr+0xc]==1`, cert names |
| `0x5a5a0102` | `"xloader"` (VA `0x3c98b`) | same |
| `0x5a5a0103` | `"vector"` (VA `0x3e5bc`) | same |

`0x30fb8` (file `0xefb8`) calls `0x30d58`, then reads a size/count pair from the
parsed certificate structure at `+0x128`/`+0x138` and stores `size << 2` at
`*r6` (VA `0x30ff4..0x31014`).

### 5.2 `0x311c8` — sec verify wrapper

File `0xf1c8` / VA `0x311c8`:

```
0x311c8  ...
0x311dc  cmp r6, 1
0x311e0  bhi 0x3121c        ; boot type > 1
0x311e2  mov r0, r8         ; VRL addr
0x311e4  mov r1, r7         ; image addr
0x311e6  bl 0x31074         ; verify
0x311ea  mov r6, r0
0x311ec  cbz r0, 0x31208
0x311ee  ... "sec verify err(...)"
0x31208  ... "sec verify end, lasted %dms"
0x3121c  cmp r6, 2
0x3121e  beq 0x31232
0x31220  ... "error lcs!"
```

### 5.3 `0x31074` — SEB image verification

File `0xf074` / VA `0x31074`:

```
0x31074  push.w {r4..fp,lr}
0x3107a  mov r5, r0          ; VRL header
0x3107c  mov sb, r1          ; image
0x3107e  bl 0x3102c          ; secure/soc status
0x31084  bne 0x31130
0x31086  ...
0x31088  mov r0, r5
0x3108a  add r2, sp, 0x28
0x3108c  bl 0x36bfc          ; FillCert(VRL header)
0x31092  cbz r0, 0x310a2
...
0x310a2  ldr.w sl, [sp, 0x38]
0x310a6  add r1, sp, 0x14
0x310a8  mov r0, sl
0x310aa  bl 0x30d58          ; VRL format check
0x310ae  cbnz r0, 0x310fe
...
0x310da  bl 0x36ea0          ; cert/store-address iteration
...
0x3110e  add r0, sp, 0x28
0x31110  ldr r1, =0x60035000
0x31112  mov.w r2, 0x1000
0x31116  bl 0x36dcc          ; SEB operation
0x3111a  mov r5, r0
0x3111c  cbz r0, 0x31132
0x3111e  ... "%s %d seb status %x"
```

### 5.4 `0x36dcc` — SEB hardware interface

File `0x14dcc` / VA `0x36dcc` is the closest visible "security" routine. It:

- builds a local request/response block on the stack,
- uses the magic/API value `0xbdf0f000` (`movw r0, 0xf000; movt r0, 0xbdf0`)
  and the error family `0xf100xxxx`,
- calls `0x37a4c`, `0x3741c`, `0x36b6c`, and the SEB verification helpers
  `0x3718c`/`0x3721c`/`0x3706c`/`0x37de8`/`0x38380`.

The binary contains **no software AES/SHA/MD5/RSA constant tables** (searched for
the standard AES S-box, AES RCON, SHA-1/SHA-256 K, MD5 T; none found). The
verification loop `0x375e4` reads the image through a callback and compares a
computed hash; it does **not** write plaintext back to the image buffer.

**Conclusion (important):** the visible xloader path is **read + VRL parse +
certificate/hash verification**. The actual **decryption primitive is not visible
as a software routine** in this image. It must be either (a) performed by the
SEB/HISEE hardware behind `0x36dcc`, or (b) performed later by the boot-ROM
handoff at `0xb2` (§6). Static analysis alone cannot distinguish these; this is
the main unresolved question for the POC.

## 6. Output buffer, load address, and final jump

### 6.1 Buffers

| Address | Size | Role | Evidence |
|---|---|---|---|
| `0x16800000` | up to `0x5fe000` | fastboot image / candidate plaintext buffer (not proven plaintext before handoff) | `0x23648`, `0x235f4`, `0x238b8`, `0x2399c` |
| `0x16dfe000` | `0x1000` | VRL header scratch (read from `vrl`/`vrl_backup`) | `0x23838`, `0x238b0` |
| `0x16801000` | `0x5fe000` | payload-after-header address used by the **legacy** `0x23374` path | `0x233a2` |
| `0x60035000` | `0x1000` | SEB context/verification buffer | `0x31110` |
| `0x60053000` | — | SATE-aging gate read by `0x24178`, set at `0x24154` | `0x24178`, `0x2410c` |
| `0x60053074` | `0x800` | VCOM download bounce/header buffer | `0x2f054`, `0x2f0a4` |
| `0x60053878` | — | USB download state object/status | `0x2f908` |
| `0x109c0000` | — | VCOM download header/scratch | `0x2ef8e`, `0x2f058` |

The **decrypted factory fastboot** `artifacts/hisi970_fastboot_ram.bin` starts
with AArch64 exception branches, then at offset `0x20` contains `0x16800000` and
at `0x24` `"BOOTMAGICNUMBER!"`. This confirms the intended runtime image address
and entry at `0x16800000`.

The stock wrapped image `artifacts/FASTBOOT.from-update-app.img` is 0x36d8c0
bytes. Its first 0x1000 bytes are the plaintext VRL header (magic `0xe291f358` at
offset 0x80, write/boot flags at +8/+0xc, name `"fastboot"` at +0x1c), and
`FASTBOOT.from-update-app.img[0x1000:]` has exactly the SHA256
`9D82C1CEEEC3C4E68929F7D9746D13E375129029CD91FDDB63C3C9379E51F2D6` of
`artifacts/fastboot.stock.payload.img`. That is the direct file-level evidence
that the wrapped update image is header+payload, while the extracted payload
(the stock fastboot partition content) starts at the encrypted payload. The
xloader reads the header separately from `vrl`/`vrl_backup`; the raw
`artifacts/fastboot.dump.img` starts with the same high-entropy payload and has
no VRL magic in its first 0x1000 bytes.

The plaintext VRL header fields verified directly in
`FASTBOOT.from-update-app.img[0:0x1000]` are: `+0x80 = 0xe291f358` (magic),
`+0x84 = 0x00010000`, `+0x88 = 0x00000073`, `+0x8c = 0x00020102`,
`+0x08 = 1` (write flag), `+0x0c = 1` (boot flag), and `+0x1c = "fastboot"`.
The active reader `0x237e0` does not read this header from the fastboot
partition; it reads it from `vrl`/`vrl_backup` at **offset 0x22000**, size
0x1000, because `0x30ef4` turns the argument `0x22` into `0x22 << 12`.
`0x31074` later calls `0x36ea0` (`changeStoreAddr`), which rewrites the in-memory
VRL store-address entries to `0x16800000`; `0x36dcc` then submits the header to
the SEB path. The SEB scratch at `0x60035000` is zeroed after use, so it is not
the plaintext output. (A second static pass reported SEB mailbox writes around
`0xbdf00e80..0xbdf00e94` via `0x39604`, status at `0xbdf00ad4`/`0xbdf00e9c`, and
the BCH engine at `0x38380`; these are a useful lead but were not re-verified
instruction-by-instruction here.) This is strong circumstantial evidence that the image is
meant to be decrypted/stored in place at 0x16800000, but it is not proof: no
CPU instruction in the verify graph writes the payload.

### 6.2 `0x23374` — unreferenced legacy relocation

File `0x1374` / VA `0x23374` is a complete-looking fastboot handler:

```
0x23374  push {r0,r1,r2,r4,r5,lr}
...
0x23380  mov.w r0, 0x16800000
0x23384  ldr r1, =0x5a5a0101
0x23386  ldr r2, =0x5fe000
0x23388  bl 0x31154          ; VRL format/size
...
0x2339c  ldr r0, =0x16dfe000
0x2339e  bl 0x23a2a          ; memcpy(dst=0x16dfe000, src=0x16800000, 0x1000)  ; save header
0x233a2  ldr r1, =0x16801000
0x233a4  ldr r2, =0x5fe000
0x233a6  mov.w r0, 0x16800000
0x233aa  bl 0x23a2a          ; memcpy(dst=0x16800000, src=0x16801000, 0x5fe000) ; shift payload down
0x233be  ldr r0, =0x16dfe000
0x233c0  bl 0x311c8          ; verify
```

No `BL`/`B`/`BLX` or literal function pointer targets `0x23374` in this build
(scanned all 2-byte-aligned Thumb instructions and all 32/16-bit pointer
patterns). It is **dead/legacy** in this artifact. It is still useful as a
description of the "header + payload in one buffer" layout: it saves the
header from 0x16800000 to 0x16dfe000, then shifts the payload from 0x16801000
down over the old 0x1000 header. The
active `0x237e0` path does **not** use this shift; it reads the payload directly
to `0x16800000` and the VRL header separately to `0x16dfe000`.

### 6.3 Final handoff

`main` ends with:

```
0x2328c  movs r3, 5
0x2328e  stm.w sp, {r2,r3}     ; stack args 0x2e000, 5
0x23292  ldr r0, =0x8e200000
0x23296  ldr r2, =0xfff50000
0x23298  movs r3, 0
0x2329a  blx r4                 ; r4 = 0xb3
0x2329c  ... "fst err"
0x232a4  b 0x232a4
```

`r4` was set at `0x23178` from `0x23f70` (`movs r0,#0xb3; bx lr`), and `0x24460`
does not clobber `r4`. This is a call to **boot-ROM VA 0xb2** with:

```
r0 = 0x8e200000
r1 = value left by 0x23fe4 (not explicitly set at 0x23292)
r2 = 0xfff50000
r3 = 0
[sp] = 0x2e000, [sp+4] = 5
```

The call is immediately after the storage-load / USB-download stage and is
followed by the failure log + infinite loop, so it is the **final boot/handoff
call** in this path. The xloader has **no direct `bx`/`blx` to `0x16800000`**
(the image is AArch64 and the xloader is Thumb-2; a 32-bit-to-AArch64 transition
must go through ROM/secure firmware). `0x16800000` is the image entry, and the
boot ROM is the component that can switch state and jump to it.

The alternate low-ROM call in `0x24460` is `bx r1` with `r1 = 0x6a9` after a
magic check on `0x4020ae1c` (`0x55aa5aa5`), i.e. another ROM entry, not the normal
fastboot image jump.

## 7. USB/VCOM read surface (input to milestone 2)

The VCOM frame parser is `0x2f918` (file `0xd918`). Frame layout observed in
`0x2f918..0x2fc5a`:

```
byte 0      type
byte 1      seq
byte 2      ~seq              ; seq + ~seq == 0xff (checked at 0x2f92c)
byte 3..    payload
last 2      CRC-16             ; big-endian, covers type..payload
```

The CRC is CRC-16/CCITT (poly `0x1021`, init 0); the 16-entry nibble table is at
VA `0x3e2a4` (file `0x1c2a4`): `0000,1021,2042,3063,4084,50a5,60c6,70e7,8108,
9129,a14a,b16b,c18c,d1ad,e1ce,f1ef`.

Observed types:

| Type | Meaning | Handler |
|---|---|---|
| `0xcd` | inquiry | `0x2f9e4` compare; `0x2f9e8` log; `0x2f9f8` `bl 0x3accc`; `0x2fa02` `0x305bc(dev, frame, 1)` |
| `0xfe` | file start (14 bytes) | `0x2fa12`; parses file type, total size, destination address |
| `0xda` | data frame | `0x2fa2e`; copies payload to `[ctx+0x9dc] + seq*0x400` |
| `0xed` | EOT | `0x2fa32` -> `0x2fba2` |
| `0xaa`/`0x55` | ACK/NAK sent by xloader | `0x2fbe6`/`0x2fc40` |

`0x3accc` (file `0x18ccc`) simply returns `[0x60053d48]`; `0x3acd8` writes it.
The actual bulk-IN send is `0x305bc` (file `0xe5bc`):

```
0x305bc  push {r4,lr}
0x305be  mov r3, r1
0x305c0  cbz r1, error
0x305c2  cbnz r0, 0x305d0
0x305d0  str.w r3, [r0, 0x114]   ; data pointer
0x305d4  ldrh.w r3, [r0, 0xd4]   ; max packet
0x305dc  udiv r4, r2, r3
0x305e0  str.w r2, [r0, 0x10c]   ; length
0x305fc  b.w 0x2fee4             ; USB state machine
```

It accepts a caller-supplied data pointer and length, which is exactly what a
read primitive needs.

## 8. Evidence table (key rows)

| Claim | File | VA | Evidence |
|---|---|---|---|
| ELF entry | `0x1018` | `0x23018` | `e_entry = 0x23154` |
| Entry stub | `0x1154` | `0x23154` | `b.w 0x23164` x2; `bl 0x2316c` |
| Main | `0x116c` | `0x2316c` | full call sequence §1 |
| `r4 = 0xb3` | `0x1f70` | `0x23f70` | `b320 7047` |
| Boot flag read | `0x2178` | `0x24178` | `ldr r3,=0x60053000; ldr r0,[r3]` |
| Main skip branch | `0x1270` | `0x23270` | `cbnz r0,0x23276` |
| Normal/download split | `0x194c` | `0x2394c` | `bne 0x23988` |
| Normal log string | `0x1aac3` | `0x3cac3` | `"Flash boot mode to read fastboot!"` |
| Download log string | `0x1aaf4` | `0x3caf4` | `"xloader main download mode to get fastboot!"` |
| `0x23f1c` strap | `0x1f1c` | `0x23f1c` | `[0x4020ae00]` compare + `0x4020a40c & 1` |
| `0x23f5c` storage | `0x1f5c` | `0x23f5c` | `0x4020a3a0 & 0x8000` -> 1/2 |
| UFS `fastboot_a` | `0x1ea78` | `0x40a78` | name, start `0x5f800`, size `0x3000` |
| Fastboot read | `0x15f4` | `0x235f4` | dst `0x16800000`, max `0x5fe000`, `"fastboot"` |
| VRL read | `0x17e0` | `0x237e0` | dst `0x16dfe000`, size `0x1000`, `"vrl"`/`"vrl_backup"` |
| Verify wrapper | `0xf1c8` | `0x311c8` | `bl 0x31074`; `"sec verify"` strings |
| SEB verify | `0xf074` | `0x31074` | `0x36bfc`, `0x30d58`, `0x36dcc`, `0x60035000` |
| SEB driver | `0x14dcc` | `0x36dcc` | `0xbdf0f000`; SEB error family |
| Legacy relocation | `0x1374` | `0x23374` | `0x16800000->0x16dfe000` (save header), `0x16801000->0x16800000` (shift payload); no callers |
| Trampoline | `0x12e8` | `0x232e8` | writes `aa1f03e0/f2a80000/d61f0000` at `0x16800000` |
| Final handoff | `0x129a` | `0x2329a` | `blx r4`, r4=`0xb3`; args §6.3 |
| USB parser | `0xd918` | `0x2f918` | frame layout/CRC/types |
| Inquiry | `0xd9e4` | `0x2f9e4` | `cmp r3,#0xcd` |
| Bulk-IN send | `0xe5bc` | `0x305bc` | pointer + length |

## 9. Open questions / uncertainties (after cross-checks)

1. **Where is decryption performed?** The visible xloader graph
   (`0x237e0 -> 0x235f4` read, `0x311c8 -> 0x31074 -> 0x36dcc` verify) contains
   no software AES/SHA/RSA and no write-back decrypt loop. `0x31074` rewrites VRL
   store addresses to 0x16800000 and `0x36dcc` submits to the SEB/HISEE path; the
   other candidate is the boot-ROM handoff at 0xb2. Static evidence cannot prove
   which one turns ciphertext into plaintext, or whether the storage read is
   already plaintext. **Open.**
2. **Is 0x16800000 plaintext after `0x311c8` returns?** The factory fastboot
   header at `+0x20` and the read destination strongly suggest it is the intended
   final address, but no instruction in the verify graph writes 0x16800000.
   **Open; first POC experiment.**
3. **SATE flag / `[0x60053000]`:** now closed as a SATE-aging gate: `0x2410c`
   sets it from the `"patch"` partition magic `"sate_aging_start"` at 0x24154;
   `0x232e8` runs the reserved5/trampoline path when it is set, and main skips
   `0x2391c`. **Closed (static).**
4. **Exact ROM API 0xb2 semantics.** The call is `0x2329a: blx r4`, `r4=0xb3`,
   with `r0=0x8e200000`, `r2=0xfff50000`, `r3=0`, stack `0x2e000,5`; `r1` is
   whatever `0x23fe4` left (an independent pass reports 0, not re-proven here).
   The low-ROM calls at 0x6a8/0xb2 are real, but their ABI is outside this image.
   **Open.**
5. **`0x23374` is dead/unreferenced** in this build: no BL/B/BLX, no literal
   dword 0x23374/0x23375, and `0x232e8` ends with `pop {r4,pc}` at 0x23358, so
   there is no fallthrough. Its two copies are `memcpy(0x16dfe000,
   0x16800000, 0x1000)` (save header) and `memcpy(0x16800000, 0x16801000,
   0x5fe000)` (shift payload). **Closed (dead/legacy).**
6. **Artifact truncation:** `ph3..ph5` point at/after EOF; the file contains the
   code/string/partition data needed here but not those runtime segments. The
   analysis does not depend on them. **Closed for milestone 1.**
7. **USB CRC/host convention:** the xloader uses CRC-16/CCITT (poly 0x1021,
   init 0) over type..payload, stored big-endian. The host tool's `CrcHqx`
   convention may differ; the POC must validate against the xloader, not assume
   the host's existing helper. **Open until first frame is accepted.**

## 10. Milestone 1 final status

| Question | Status | Evidence |
|---|---|---|
| Boot-mode dispatch | **Answered** | `[0x60053000]` SATE gate; `0x23f1c` strap; `0x2391c` normal vs USB; `0x23f5c` storage; §2 |
| `fastboot_a` read | **Answered** | `0x235f4` -> `0x24e14("fastboot", ..., 0x16800000)`; UFS `fastboot_a` entry at 0x40a78; §3–4 |
| VRL read | **Answered** | `0x237e0` -> `0x24e14("vrl"/"vrl_backup", offset 0x22000, 0x16dfe000, 0x1000)`; §4.2 |
| Decrypt/verify call chain | **Partially answered** | chain `0x237e0 -> 0x311c8 -> 0x31074 -> 0x36dcc`; verify verified; decrypt not visible (SEB/ROM) |
| Output buffer / load address | **Answered at the address level** | 0x16800000, max 0x5fe000; VRL 0x16dfe000; SEB 0x60035000; §6 |
| Final jump | **Partially answered** | `0x2329a blx r4` -> ROM 0xb2; no direct branch to 0x16800000; exact ROM ABI open |
| USB read surface | **Answered** | parser 0x2f918; frame/CRC/types; `0x305bc`; §7 and plan |

**Bottom line:** the address-level map is complete and evidence-backed. The one
architectural unknown is whether the on-disk fastboot is decrypted before or
during the final ROM handoff. The next milestone must settle that with a
read-only dump of 0x16800000; do not flash.
