# Phase 1 — direct kernel boot path in the fastboot/usbloader image

Target: `artifacts/fastboot.stock.decrypted.img` (3,590,336 B = 0x36C8C0),
flat image, VA = 0x16800000 + file offset, AArch64, EL3.
All addresses below are VAs. Everything was disassembled, not guessed;
uncertain items are marked **UNCERTAIN**.

Static facts reused throughout:

- Image range: `[0x16800000, 0x16B6C8C0)`; everything at/above 0x16B6C8C0 is `.bss`
  (not in file, zero at load).
- The in-image `memset` helper at 0x168002CC clears `[0x16B6C8C0, 0x16BB2748)`
  (bounds read from the literal pool 0x168003B0/0x168003B8).
- No `smc`/`hvc` instruction exists anywhere in the image (verified by full sweep
  of 0xD4000003 / 0xD4000002 patterns). Only 2 `eret` (0x16801EDC, 0x16801FA4),
  both in the EL3 panic/register-dump handler.

---

## 0. Module/ops framework (needed to reproduce anything below)

Operator registry (this is the `hisi_ops` mechanism):

- `.data` slot 0x16B6BC40 holds table **start** = 0x16B6C4F0.
- `.data` slot 0x16B6BA58 holds table **end** = 0x16B6C898.
- 117 entries, array of pointers to 0x20-byte records:

```
struct module_rec {           // 0x20 bytes
    const char *name;         // +0x00
    u8  priority;             // +0x08   (init order key; 0xA7 for "kernel")
    u32 registered;           // +0x0C   (set to 1 by the init loop on success)
    int (*init)(void *);      // +0x10   (arg = 0x16AF2780)
    void *ops;                // +0x18   (NULL for name-only modules)
};
```

- `0x1696DBD4(name)` = `get_ops()`: linear scan, `strcmp(rec->name, name)`; returns
  `rec->ops` only when `rec->registered != 0`, else NULL.
- **Top-level dispatcher** = `main()` at **0x1696E03C** (reached from the EL3 reset
  vector: 0x16800000 `b 0x16800034` -> 0x16800034 EL3 init -> 0x168001D4 `b 0x1696E03C`).
  It bubble-sorts the registry by `rec->priority` (0x1696E0B8..0x1696E138), then loops:
  `x21 = table[i]; x0 = 0x16AF2780; blr [x21,#0x10]` at **0x1696E1BC**, and on success
  writes `[x21,#0x0C] = 1` at 0x1696E1CC. Every module init runs, in priority order,
  with the **same** argument: 0x16AF2780.
- Boot-params object used as that argument is in `.data` and statically initialised:
  `0x16AF2780 = {u32 0, u32 mode=1, u32 0, u32 0}` (+0x08 is overwritten by main from
  0x16829154, +0x04 is the mode that every module tests).

Named modules used here (rec -> name / init / ops):

| module | record | init fn | ops struct |
|---|---|---|---|
| kernel | 0x16B63650 | 0x168A729C | 0x16B63670 (2 entries) |
| verify_boot | 0x16B69248 | 0x1690603C | 0x16B69268 (11 entries) |
| normalboot | 0x16AF6440 | **0x168033B0** | none |
| trustfirmware | 0x16B6ABE8 | 0x16964B44* | 0x16B6AC08 |
| hhee | 0x16B69BC0 | 0x16928CE4 | 0x16B69BE0 |
| storage | 0x16B60E20 | 0x1688CF1C | 0x16B60E40 |
| dts / fdt | 0x16B60AA8 / 0x16B60F50 | 0x168716B4 / 0x1688D3DC | 0x16B60AC8 / 0x16B60F70 |
| secboot | 0x16B69498 | 0x16908F48 | 0x16B694B8 |

\* 0x16964B44 is the record field; not needed below.

`kernel` ops = **{0x168A9534, 0x168AA0B0}** — only two methods:

- `+0x00` = **load_kernel** (0x168A9534)
- `+0x08` = **boot_kernel** (0x168AA0B0)

`verify_boot` ops (0x16B69268), mapped by call sites:

| off | fn | role (from call sites) |
|---|---|---|
| +0x00 | 0x169061B4 | select/enter verify mode |
| +0x08 | 0x16906474 | clear verify state |
| +0x10 | 0x16905DF0 | get state ptr |
| +0x18 | 0x16905E00 | `str w0,[0x16B79428]` |
| +0x20 | 0x16905E0C | `ldr w0,[0x16B79428]` |
| +0x28 | 0x16905E18 | **`*0x1FF01100 = w0` (ATF result mailbox)** |
| +0x30 | 0x16905E28 | VMODE read/update |
| +0x38 | **0x16908110** | **verify boot image (AVB)** |
| +0x40 | 0x16907B30 | — |
| +0x48 | 0x16908780 | — |
| +0x50 | **0x169063D4** | get lock state (`fastboot_ctrl` ops+8) |

---

## 1. The boot routine and its chain

**Boot routine (load+verify): `load_kernel` @ 0x168A9534.**
**Boot routine (dtb/cmdline + jump): `boot_kernel` @ 0x168AA0B0.**

Evidence that these are the right functions (log strings with their `adrp/add` xrefs,
all inside these two bodies):

- `load_kernel: load_and_verify_image fail!` — 0x16A01568, xref add @ 0x168A9588 (in 0x168A9534).
- `load_kernel: can not get sec_cfg_ops!` — 0x16A01328, xref @ 0x168A9504 / 0x168A9974.
- `load_kernel: do security prepare cfg failed` — 0x16A01388, xref @ 0x168A9498.
- `load_kernel: copy dts end, lasted %d ms` — 0x16A01F58, xref @ 0x168AA1CC (in 0x168AA0B0).
- `load_kernel: boot from bl31.` — 0x16A01BC0, xref @ 0x168A9F64.
- `load_kernel: boot from hhee.` — 0x16A01C10, xref @ 0x168AA008.
- `load_kernel: boot_from_flash: boot_linux_arm64` — 0x16A01C60, xref @ 0x168A9FB8.
- Name string `boot_kernel` (0x16998BE8) is passed as `%s` at 0x168AA39C..0x168AA3D0.
- Name string `load_kernel` (0x16998BA0) is passed as `%s` at 0x168A9798..0x168A97CC.
- Name string `load_and_verify_image` (0x16998B78) at 0x168A8F38.
- Name string `verify_image_locked` (0x16998B48) at 0x168A8CF8.
- Name string `add_device_tree` (0x16998C68) at 0x168AA378.

### Chain

```
0x16800000  b 0x16800034                  EL3 reset vector
0x16800034  ... EL3 init (SCTLR_EL3/VBAR_EL3/SCR_EL3, per-core stacks)
0x168001D4  b 0x1696E03C                  boot-core C entry = main()
0x1696E03C  main(): sort registry, for each rec: blr rec->init(0x16AF2780)
0x1696E1BC  blr [x21,#0x10]               <-- module init dispatch
   normalboot rec 0x16AF6440 -> init 0x168033B0
0x168033B0  ldr w0,[x19,#4] / cmp w0,#1   (x19 = 0x16AF2780, mode at +4)
0x168033D8  b.eq 0x168033F0               only mode==1 continues
0x168033C0  get_ops("kernel") -> x20
0x16803418  ldr x0,[x20]; blr x0          kernel_ops[0] = load_kernel
0x1680342C  ldr x0,[x20,#8]; blr x0       kernel_ops[1] = boot_kernel
```

`load_kernel` (0x168A9534) — structure:

```
0x168A9548  get_ops("blackbox")                      ; progress markers 0x22
0x168A9550  bl 0x168A8FB8   ; preboot state check, sets g_boot_mode
0x168A9558  bl 0x168A9110
0x168A955C  bl 0x168A9278
0x168A9560  bl 0x168A933C   ; teeos ops[0]() -> *[0x16B91768]
0x168A9574  bl 0x168A7770   ; load 0x800-byte boot-image header from partition
0x168A9578  cbz x0, 0x168A96B0   ; NULL -> "no image" / preboot-retry path
0x168A957C  bl 0x168A8E98   ; load_and_verify_image()
0x168A9580  cbz w0, 0x168A9604  ; 0 = success -> verify-boot lock gate
0x168A9584  log "load_kernel: load_and_verify_image fail!" -> return -1
0x168A9610..0x168A9644  verify_boot gate (see §2, site V4)
0x168A9648  bl 0x168A9464   ; sec_pre_cfg (seccfg ops[0])
0x168A96A0  mov w0,#0; ret
```

`0x168A7770` is the image loader: it picks the image name from the boot mode
(`0x168A734C`: mode 1/2 -> `"kernel"` 0x169FB790, mode 3 -> `"erecovery_kernel"`
0x169FB660, else `"INVALID_NAME"`), then `0x168A738C(name)` mallocs 0x800 bytes
(0x1696E904) and does `storage_ops[0](name, 0, buf, 0x800)`, checks `"ANDROID!"`
(0x169FFD30), and stores the buffer into `*[0x16B6B578]` = **[0x16B91760]**.
So **[0x16B91760] holds the 0x800-byte AOSP boot-image header**, and its fields map
directly to what `boot_kernel` uses:

| header + | meaning | used at |
|---|---|---|
| +0x04 | boot mode | 0x168A89C0, 0x168A96B8 |
| +0x08 | (second addr / used by ATF path) | 0x169676A0 |
| +0x0C | **kernel entry address** | 0x168A9FF0, 0x16967650 |
| +0x10 | ramdisk size | 0x168AA1E0 |
| +0x14 | ramdisk address | 0x168AA1DC |
| +0x20 | **tags/dtb address** | 0x168A9FEC, 0x16967678 |
| +0x40 | cmdline[] | 0x168A99DC |

`0x168A8E98` = `load_and_verify_image`: `0x168A89A0` (verify) then `0x168A87E0`
(load_image_to_imgaddr, decompress/relocate to header addresses); error strings
`load_kernel: verify_image fail!` (0x16A00E28) and
`load_kernel: load_image_to_imgaddr fail!` (0x16A00E98).

`boot_kernel` (0x168AA0B0) — structure:

```
0x168AA0E0  x21 = *[0x16B91760]                  ; boot-image header
0x168AA100  bl 0x168A99A4   ; build cmdline ("__get_cmdline") from header->cmdline (+0x40)
0x168AA124  battery ops[0x50]()                   ; battery/SMPL check before boot
0x168AA138  mntn   ops[0x40]()                   ; "mntnops_before_boot_kernel"
0x168AA19C  bl 0x16870DC4   ; dma/cache op over the dtb region (dtb = header+0x20, len 0x200000)
0x168AA240..  fdt/dts ops: copy dts, set initrd-start/end props, add_device_tree
0x168AA4E8  bl 0x168A9ECC   ; <-- final handoff (see below); never returns
0x168AA508  ret
```

Final handoff `0x168A9ECC` (no arguments; reads the header from [0x16B91760]):

```
0x168A9EFC  x21 = *[0x16B91760]              ; header
0x168A9F58  blr hhee_ops[8]()
0x168A9F60  if hhee_ops[8]()==0: log "boot from bl31"
0x168A9FA4    blr trustfirmware_ops[0x10](header, *[0x16B91768])
0x168AA004  else: log "boot from hhee"
0x168AA034    ldr x2,[x19,#0x18] -> blr x2 at 0x168A9FA4  (trustfirmware_ops[0x18])
0x168A9FB4  if trustfirmware ops absent: log "boot_from_flash: boot_linux_arm64"
0x168A9FE4    bl 0x16800C20 ; bl 0x16800D20      ; cache maintenance
0x168A9FEC    w0 = [header+0x20]                  ; dtb
0x168A9FF0    w1 = [header+0x0C]                  ; kernel entry
0x168A9FFC    b  0x168AA954
0x168AA954  mov x6,x0 ; mov x7,x1
0x168AA95C  bl  0x168002CC                        ; memset [0x16B6C8C0,0x16BB2748)
0x168AA960  mov x0,x6 ; mov x1,x7
0x168AA968  br  x1                                ; **the only in-place kernel jump**
```

**The single in-place jump instruction to a kernel is `br x1` @ 0x168AA968**
(original word `D61F0020`), with `x0 = tags/dtb`, `x1 = header->kernel_addr`.

`trustfirmware_ops[+0x10]` = 0x169675DC does **not** branch to the kernel: it writes
a handoff block into SRAM (`0x1FF00030` fields: entry=header+0x0C, dtb=header+0x20,
`[+0x10]=0x3C5`, `[+0x04]=1`; `0x1FF00058`, `0x1FF00088`, `0x1FF000A0`+0x18 also
filled), copies 0x40 bytes from `0x16B8DD80` (.bss; referenced read-only at 0x16967724,
0x169678D0, 0x169679D8, so another stage fills it), then
`b 0x16839D70`, which does `memset(0x209E1008,0,8)` and finally
`*0x209E1008 = (reboot_reason[0x4E]=='1')`.
Whether BL31 acts on that mailbox immediately or only after a warm reset is
UNCERTAIN - it needs a hardware experiment (see §4).

---

## 2. The verification call, the failure branch, and the exact words

Verify chain: `load_kernel` -> `0x168A8E98` -> `verify_image_locked` **0x168A89A0**
-> `handle_verify_result` **0x168A6C98** -> `verify_boot_ops[0x38]` = **0x16908110**
-> **0x16980830** (avb_slot_verify).

### Site V1 — lock-state gate (`verify_image_locked`, 0x168A89A0)

```
0x168A89BC  ldr x0,[x20,#0xb10]      ; x20=0x16B78000 -> x0 = *[0x16B78B10] = boot params
0x168A89C0  ldr w0,[x0,#4]           ; params->mode
0x168A89C4  cmp w0,#2
0x168A89C8  b.eq 0x168A8C38          ; mode 2: extra RAM-image probe, then verify anyway
0x168A89CC  adrp x0,#0x169b3000 / add x0,x0,#0x9c0   ; "verify_boot"
0x168A89D4  bl 0x1696DBD4            ; get_ops("verify_boot")   [word 94031480]
0x168A89DC  cbz x0,0x168A8E10        ; no ops -> log + return -1
0x168A89E4  blr [x19,#8]             ; ops[+0x08]()  clear verify state
0x168A89E8  ldr x1,[x19,#0x50]
0x168A89F0  blr x1                   ; ops[+0x50](&status)  get_lock_state
0x168A89F4  ldr w0,[x29,#0x4c]       ; status
0x168A89F8  cmp w0,#1                ; 7100041F
0x168A89FC  b.eq 0x168A8B98          ; 54000CE0  -> "unlocked / alternate" path
0x168A8A0C  bl 0x168A6C98            ; 97FFF8A3  <-- V2 call (locked path)
0x168A8BB8  bl 0x168A6C98            ; 97FFF838  <-- V2 call (status==1 path)
```

`ops[+0x50]` = 0x169063D4: `get_ops("fastboot_ctrl")` -> `fastboot_ctrl_ops[+8](buf,0x20)`
-> `*arg = w0`; returns 1/0 (or -1 when the ops are missing).

### Site V2 — status normaliser (`handle_verify_result`, 0x168A6C98)

```
0x168A6CA8  adrp x0,#0x169b3000 / add x0,x0,#0x9c0   ; "verify_boot"
0x168A6CB4  bl 0x1696DBD4                                   ; get_ops("verify_boot")   [94030F23]
0x168A6CC0  ldr x2,[x0,#0x38]                                ; x2 = ops[+0x38] = 0x16908110
0x168A6CC4  mov w0,w19                                      ; w0 = mode
0x168A6CC8  blr x2                                          ; D63F0040  <== THE VERIFY CALL
0x168A6CCC  cmp w0,#7                                       ; 71001C1F
0x168A6CD0  mov w3,w0                                       ; 2A0003E3
0x168A6CD4  b.ls 0x168A6D24                                 ; 54000289
0x168A6CD8.. log "hisi_avb: ret of avb_slot_verify illegal" -> return 2
0x168A6D24  ldrb w0,[0x16998998 + w0]                        ; 8-entry signed-byte jump table
0x168A6D38  br x0                                           ; D61F0000
```

Jump table bytes @ 0x16998998 = `33 20 20 20 10 43 20 20` (signed, x4, base 0x168A6D3C):

| avb result | target | message | returns |
|---|---|---|---|
| 0 OK | 0x168A6E08 | `load_kernel: avb verify success` (0x169FF5F8) | **0** |
| 1 OOM,2 IO,3 VERIFICATION,6 INVALID_METADATA,7 | 0x168A6DBC | `load_kernel: avb verify failed: %d` (0x169FF720) | 2 |
| 4 ROLLBACK_INDEX | 0x168A6D7C | `load_kernel: avb rollback index not match` (0x169FF6B0) | 2 |
| 5 PUBLIC_KEY_REJECTED | 0x168A6E48 | `load_kernel: avb public not match` (0x169FF650) | **1** |

Back in `verify_image_locked` the normalised value is consumed at:

```
0x168A8A10  cmp w0,#2   ; 7100081F
0x168A8A18  b.eq 0x168A8C98   ; 54001400 -> fail path (logs, returns -1)
0x168A8A1C  cmp w0,#1   ; 7100041F
0x168A8A20  b.eq 0x168A8AC4   ; 54000520 -> "public key mismatch" path
0x168A8A24  (fallthrough)      ; success path: ops[0x18](0); ops[0x28](0xA5A5A5A5); return 0
```

**So: verification is "valid" iff `0x168A6C98` returns 0**, and the only two consumers
that matter are the `cmp w0,#2 / b.eq 0x168A8C98` and `cmp w0,#1 / b.eq 0x168A8AC4`
pairs. Anything else falls into the success block at 0x168A8A24.

### Site V3 — the actual signature check (0x16908110)

```
0x16908144  bl 0x16907A14                 ; slot / avb init, returns handle
0x16908158  cmp w19,#1                    ; w19 = mode
0x16908344  (mode 1 branch)
0x169081C4  (mode 2/3 branch)
0x169081D8  get_ops("partition") 0x169B2240 (name string)
0x169081EC  get_ops("storage")   0x169B1B90
0x16908208  get_ops("rescue")    0x169B9D80
0x1690824C  bl 0x16980830                 ; 9401E179  <== avb_slot_verify(...)
0x16908250  cmp w0,#7                     ; 71001C1F
0x16908258  b.ls 0x16908388               ; 54000989
0x1690825C  log "hisi_avb: ret of avb_slot_verify illegal" (0x16A35B68) -> return 2
0x16908388  ... -> returns w0 unchanged
```

`0x16980830` is a large (0x1E0-byte frame) AVB routine; the `verify_boot` ops table is
immediately followed in `.data` by the `avb_slot_verify_result_*` string vector at
0x16B692C0.., which corroborates the semantics.

### Site V4 — the EL3 result mailbox

`verify_boot_ops[+0x28]` = **0x16905E18**: `mov x1,#0x110; movk x1,#0x1ff0,lsl#16;
str w0,[x1]; ret` -> writes **0x1FF01100**.

- success block 0x168A8A38/0x168A8A3C builds `0xA5A5A5A5` and calls it at 0x168A8A40;
- public-key-mismatch block 0x168A8AD8/0x168A8AE0 builds `0x5A5A5A5A` and calls it at 0x168A8AE4;
- the status==1 block does the same `0xA5A5A5A5` at 0x168A8BC8/0x168A8BCC.

Inference (not proven from this image alone): **0x1FF01100 is the AVB verdict register
consumed by BL31**; `0xA5A5A5A5` = passed, `0x5A5A5A5A` = failed. This should be the
first thing to check on hardware, because it decides whether any ATF-mediated
handoff is allowed.

---

## 3. Patch proposal

Image is not code-signed per-page and text is mapped read-only at runtime, so these
are *image* patches to be applied offline to the decrypted blob before upload.
All words verified by decoding them back with capstone.

### P0 — recommended, one instruction, kills the signature gate

| addr | file off | original | patched | meaning |
|---|---|---|---|---|
| **0x168A6CC8** | 0x8A6CC8 | `D63F0040` (`blr x2`) | **`52800000`** (`mov w0,#0`) | `handle_verify_result` always returns 0 = AVB OK |

Effect: `verify_boot_ops[+0x38]` (0x16908110) and therefore `avb_slot_verify`
(0x16980830) are never executed on any of the 5 call sites (0x168A781C, 0x168A7884,
0x168A7964, 0x168A8A0C, 0x168A8BB8). Flow then goes
`cmp w0,#7` (0<=7) -> jump table entry 0 -> 0x168A6E08 -> logs `avb verify success`
-> returns 0. The normal success machinery still runs (including
`ops[+0x18](0)` and `ops[+0x28](0xA5A5A5A5)` -> `*0x1FF01100 = 0xA5A5A5A5`), so the
rest of the boot path sees a consistent "verified" state.

### P1 — equivalent, per-path (two instructions, leaves 0x168A6C98 intact)

| addr | original | patched |
|---|---|---|
| 0x168A8A0C | `97FFF8A3` (`bl 0x168A6C98`) | `52800000` (`mov w0,#0`) |
| 0x168A8BB8 | `97FFF838` (`bl 0x168A6C98`) | `52800000` (`mov w0,#0`) |

### P2 — force the "unlocked" branch (does NOT skip verification on its own)

| addr | original | patched |
|---|---|---|
| 0x168A89FC | `54000CE0` (`b.eq 0x168A8B98`) | `14000067` (`b 0x168A8B98`) |

The `status==1` path still calls 0x168A6C98 at 0x168A8BB8, so P2 alone is not enough;
it only changes which side-effects run before the check. Use it together with P1/P0
if a specific lock-state side effect is wanted.

### Minimum viable = P0 (4 bytes at 0x168A6CC8).

Not recommended: patching `0x16908250 cmp w0,#7` — the following `b.ls` consumes the
flags set by that `cmp`, so replacing it with `mov w0,#0` would branch on stale flags.

---

## 4. Calling the boot chain from our stub — ABI and preconditions

### Kernel ops entry points

| | load_kernel | boot_kernel |
|---|---|---|
| address | 0x168A9534 | 0x168AA0B0 |
| args | none (`x0` unused) | none (`x0` unused) |
| returns | `w0` = 0 ok / -1 fail | never (jumps) |
| stack | own 0x40 frame + malloc | own 0x80 frame |

### Global state that must be valid (all of it lives in `.bss`, i.e. zero at image load)

| global | address | who sets it | needed for |
|---|---|---|---|
| boot params ptr | **[0x16B78B10]** | kernel module init 0x168A729C (`str x0,[0x16B78B10]`) | `load_kernel`, `verify_image_locked` deref `[+4]` |
| boot mode | [0x16B78B18] | 0x168A8FF4 copies params+4; 0x168A72DC | image-name selection, mode branches |
| boot-image header (0x800 B) | **[*0x16B91760]** = `*[0x16B6B578]` | 0x168A7770 -> 0x168A738C | `boot_kernel` field accesses |
| teeos ctx | [*0x16B91768] = `*[0x16B6BB80]` | 0x168A9388 (`teeos_ops[0]()`) | 2nd arg of the ATF handoff |
| system-verified flag | [*0x16B91770] = `*[0x16B6C3A8]` | 0x168A8BF0 (`str 1`) | downstream consumers |
| nvme "system verify" flag | [*0x16B78AD0] = `*[0x16B6C4D0]` | nvme module | the `w0==1` path |
| ATF AVB verdict | [0x1FF01100] | `verify_boot_ops[+0x28]` | BL31 handoff (inference) |

`[0x16B78B10]` is **already set** in a live fastboot session: `main()` calls every
module init with `x0 = 0x16AF2780`, and the `kernel` module init stores it. So a stub
can simply rely on it, but it can also (re)set it explicitly.

`0x16AF2780` is `.data` and statically `{0, 1, 0, 0}` -> **mode 1** (normal boot). If any
module has since rewritten `+4`, force it back before calling load_kernel.

### Preconditions a stub must satisfy

1. Ops must be registered (`rec->registered != 0`), which is true after `main()` has
   run — i.e. for every module actually initialised in fastboot mode. `get_ops()`
   returns NULL for modules whose init failed and `load_kernel` then logs
   `can not get verify_boot_ops!` / `can not get sec_cfg_ops!` and aborts.
2. `params->mode` (0x16AF2784) must be 1 (or 2) — mode 1 selects partition `"kernel"`.
3. Storage/partition/dts/fdt/nvme/battery/mntn/blackbox ops must be live (they are;
   storage I/O is used heavily).
4. A usable stack: both functions allocate <= 0xD0 bytes; the EL3 handler SP that the
   existing stub runs on is sufficient (the stock handlers already call deep code).
5. Watchdog: `load_kernel` does full partition reads + AVB + decompress; this takes
   hundreds of ms to seconds. The watchdog module is running; either accept the
   timeout risk or service it the same way the normal-boot path does.

### Suggested stub shape

```
; assumes EL3, MMU as left by the fastboot image, SP valid
    mov  w0,#1
    adrp x1,0x16af2000
    str  w0,[x1,#0x784]        ; params->mode = 1
    bl   0x168a9534            ; load_kernel -> w0 (0 = ok)
    cbnz w0, fail
    bl   0x168aa0b0            ; boot_kernel (never returns)
fail: ...
```

or, after a successful `load_kernel`, bypass the trustfirmware decision entirely:

```
    ldr  x9,[0x16b6b578]       ; adrp/ldr from 0x16B6B578
    ldr  x9,[x9]               ; boot-image header
    ldr  w1,[x9,#0x0c]         ; kernel entry
    ldr  w0,[x9,#0x20]         ; tags/dtb
    bl   0x168aa954            ; memset BSS + br x1
```

---

## 5. Judgement: is calling the boot routine realistic?

**load_kernel: yes.** It is a normal C function, reads flash through `storage_ops`,
verifies, decompresses to the addresses in the boot-image header, and returns a status.
Its dependencies are all ops tables plus one 16-byte params object. Nothing it needs is
produced by an "earlier boot stage" that we cannot reproduce; the only truly external
inputs are the flash contents and the seccfg/oeminfo/nvme state, which exist already.

**The jump: not directly.** The `br x1` fallback at 0x168AA968 hands the CPU to the
kernel from the current exception level with the current MMU state. This image
provably runs at EL3 (0x16800194 `msr vbar_el3`, 0x168001B0 `mrs/msr sctlr_el3`,
0x16801DD0 `mrs currentel`, three-way EL3/EL2/EL1 handling in the panic dumper), and
it has no `smc`/`hvc`/`eret` kernel-entry path. Branching to a Linux image from EL3 is
architecturally wrong: the kernel expects EL1 (or EL2 for KVM), with `SCR_EL3.NS` set
and MMU state it owns. So the direct `br` is a fallback for a build/SoC variant, not
the path this SoC uses in normal operation.

The production path this image uses is the **BL31 mailbox**: `trustfirmware_ops[+0x10]`
writes an entry/dtb descriptor to SRAM 0x1FF00030.., copies 0x40 bytes from the
`.bss` block 0x16B8DD80, and then pokes 0x209E1008 (derived from `reboot_reason[0x4E]`).
That block does **not** branch anywhere; the handoff completes inside ATF.

**Hidden state that only the full cold-boot path sets up, and that must be replicated:**

1. **0x1FF01100** — AVB verdict. `0xA5A5A5A5` = pass. If BL31 checks it (strongly
   implied by the name and by the fact that both success paths write it), any in-place
   boot must publish `0xA5A5A5A5` first. Patch P0 does this for free.
2. **0x1FF00030 block** + **0x16B8DD80 (0x40 B)** — the ATF boot descriptor. 0x16B8DD80
   is `.bss`; it is *not* initialised anywhere in this image (no `adrp`/store pair was
   found targeting it), so it is filled by an earlier stage (xloader/ATF).
   **UNCERTAIN** which fields matter; it is copied verbatim into SRAM.
3. **0x209E1008** — written only by 0x16839D70. Semantics **UNCERTAIN** (a mailbox
   doorbell vs. a warm-reset request are both consistent with the evidence).
4. **g_boot_mode / params->mode** and the nvme VMODE value (`hisi_write_vmode_nve`,
   `"VMODE"` at 0x169CD5F8, written during the verify path at 0x168A8A6C..0x168A8A94).
5. **seccfg / oeminfo / anti-rollback** — read by 0x168A9464 (`seccfg`) and 0x16908110.
   These are device state, already present; they are not "cold-boot-only" RAM state.

**Practical conclusion.** The realistic plan is:
(a) patch P0 so verification cannot fail;
(b) from the stub, set params->mode=1 and call `load_kernel` (0x168A9534) — this both
    loads and publishes the AVB verdict;
(c) then either call `boot_kernel` (0x168AA0B0) and let it use the trustfirmware
    mailbox, or call `0x168AA954` directly if the experiment shows the mailbox path
    only works on a cold boot.
The decisive hardware experiment is to watch whether the trustfirmware path returns
(i.e. whether 0x16839D70 simply `ret`s) — if control comes back to `boot_kernel`'s
caller, the mailbox is a reset/handoff request and only the direct `br` remains, which
then requires an EL2/EL1 setup of our own before the jump.

---

## 6. Where I stopped / open items

- Semantics of `0x209E1008` and whether BL31 boots from the 0x1FF00030 descriptor
  without a reset: needs hardware (single `oem`-stub experiment). Next anchor: the
  ATF entry that reads 0x1FF00030 is not in this image — dump BL31 from the device or
  trace the register with a stub that logs `[0x1FF00030]` after the call.
- Exact role of the `w0==1` (public-key-mismatch) path at 0x168A8AC4: it inspects
  `[*0x16B78AD0]` and logs `load_kernel: %s, the system verify is %d in nvme!`.
  Marked UNCERTAIN; it is not needed if P0 is applied.
- `verify_boot_ops[+0x40]` (0x16907B30) and `[+0x48]` (0x16908780) were located in the
  table but not traced.
- `load_image_to_imgaddr` (0x168A87E0) was identified by its error string and call site
  but its decompression/relocation internals were not disassembled in depth.

---

## 7. Anchors used (all verified in the file)

Symbol-name strings (no `adrp/add` xref anywhere — confirmed by full sweep; they are
name tables, not log messages):

| addr | string |
|---|---|
| 0x169989C0 | `load_kernel_init` |
| 0x169989D8 | `load_image_head` |
| 0x169989E8 | `adapt_ramdisk_addr` |
| 0x16998A00 | `warning_after_verify` |
| 0x16998A18 | `try_backup` |
| 0x16998A28 | `find_cpio_tail` |
| 0x16998A38 | `load_and_decompress_image` |
| 0x16998B18 | `get_ramdisk_ptn_size` |
| 0x16998B30 | `load_image_to_imgaddr` |
| 0x16998B48 | `verify_image_locked` |
| 0x16998B60 | `is_system_damaged` |
| 0x16998B78 | `load_and_verify_image` |
| 0x16998B90 | `__load_hhee` |
| 0x16998BA0 | `load_kernel` |
| 0x16998BC0 | `__get_cmdline` |
| 0x16998BE8 | `boot_kernel` |
| 0x16998C68 | `add_device_tree` |
| 0x169996A8 | `mntnops_before_boot_kernel` |

Note: 0x16998998 is **not** a string (`"3   "`); it is the 8-byte signed switch table of
0x168A6C98, adjacent to the `check_boot_addr_and_size` name string at 0x169989A0.

Module-name strings resolved from `adrp/add` at lookup sites:

| addr | string | ex. site |
|---|---|---|
| 0x169FB790 | `kernel` | 0x168033C4, 0x168A7384 |
| 0x169B39C0 | `verify_boot` | 0x168A6CAC, 0x168A89D0 |
| 0x169AFCE8 | `secboot` | 0x16807FF8 |
| 0x169B1B90 | `storage` | 0x168A73A8 |
| 0x169B1D40 | `dts` | 0x168AA1F0 region |
| 0x169C1198 | `fdt` | 0x168AA1F4 |
| 0x169CB960 | `cmdline` | 0x168A9A64 |
| 0x169B2240 | `partition` | 0x169081D8 |
| 0x169CD5F8 | `VMODE` | 0x168A8A80, 0x16905E3C |
| 0x16A01320 | `seccfg` | 0x168A947C |
| 0x169B9D80 | `rescue` | 0x16908204 |
| 0x169AE4C0 | `battery` | 0x168AA114 |
| 0x16A17A18 | `mntn` | 0x168AA12C |
| 0x169AE188 | `reboot_reason` | 0x16839D98 |

Log strings with real xrefs (address -> add-site):

| addr | string | xref |
|---|---|---|
| 0x169ADC50 | `normal_boot: %s can not get loadkernel_ops!` | 0x16803470 |
| 0x169B17D0 | `recovery: %s can not get loadkernel_ops!` | 0x1680A4A8 |
| 0x169B27F8 | `usbloader: reboot kernel` | 0x1680B684 |
| 0x169B39C0 | `verify_boot` | 5 sites (0x1680CDCC, 0x16821824, 0x16825808, 0x16898334, 0x168A6CAC) |
| 0x169B5618 | `oem check-image` | 0x1680F858 |
| 0x169B5688 | `INFOsecure image verify success` | 0x1680FA10 |
| 0x169B56A8 | `INFOsecure image verify fail` | 0x1680F9D4 |
| 0x16A00AF0 | `load_kernel: can not get verify_boot_ops!` | 0x168A9894 |
| 0x16A00E28 | `load_kernel: verify_image fail!` | 0x168A8FA0 |
| 0x16A00E98 | `load_kernel: load_image_to_imgaddr fail!` | 0x168A8F6C |
| 0x16A00ED0 | `load_kernel: %s end, lasted %d ms` | 0x168A8EEC, 0x168AA374 |
| 0x16A01328 | `load_kernel: can not get sec_cfg_ops!` | 0x168A9504, 0x168A9974 |
| 0x16A01388 | `load_kernel: do security prepare cfg failed` | 0x168A9498 |
| 0x16A01498 | `kernel image is damaged!` | 0x168A97F4 |
| 0x16A01568 | `load_kernel: load_and_verify_image fail!` | 0x168A9588 |
| 0x16A01BC0 | `load_kernel: boot from bl31.` | 0x168A9F64 |
| 0x16A01C10 | `load_kernel: boot from hhee.` | 0x168AA008 |
| 0x16A01C60 | `load_kernel: boot_from_flash: boot_linux_arm64` | 0x168A9FB8 |
| 0x16A01F58 | `load_kernel: copy dts end, lasted %d ms` | 0x168AA1CC |
| 0x169FF5F8 | `load_kernel: avb verify success` | 0x168A6E0C |
| 0x169FF650 | `load_kernel: avb public not match` | 0x168A6E4C |
| 0x169FF6B0 | `load_kernel: avb rollback index not match` | 0x168A6D80 |
| 0x169FF720 | `load_kernel: avb verify failed: %d` | 0x168A6DC4 |
| 0x16A35A58 | `hisi_avb: boot_mode error %d` | 0x16908178 |
| 0x16A35B68 | `hisi_avb: ret of avb_slot_verify illegal` | 0x16908264 |

Code addresses introduced by this note (all disassembled here):
0x1696E03C main, 0x1696E1BC init dispatch, 0x1696DBD4 get_ops, 0x168033B0 normalboot init,
0x168A729C kernel init, 0x168A734C image-name select, 0x168A738C image load,
0x168A7770 get-image, 0x168A8E98 load_and_verify_image, 0x168A89A0 verify_image_locked,
0x168A6C98 handle_verify_result, 0x16908110 verify_boot_image, 0x16980830 avb_slot_verify,
0x168A9534 load_kernel, 0x168AA0B0 boot_kernel, 0x168A9ECC handoff, 0x168AA954 jump stub,
0x169675DC trustfirmware boot_linux, 0x16839D70 0x209E1008 poke, 0x168002CC bss memset.
