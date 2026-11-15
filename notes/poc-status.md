# Milestone 2 — read primitive: WORKS on hardware

The type-3 RAM read primitive was built, verified offline, and then **executed on
the device**. The benign read succeeded and is reproducible.

## Live result (the milestone-2 goal)

Patched xloader `34CB9AD3373F99951585180F31801FD93BDCDFB487925E3B4C80FAE0D24CFD66`
was uploaded to RAM on the P20 (COM8, `HUAWEI USB COM 1.0`, VID_12D1 PID_3609)
via the hisi970 head-resend pwn, then read back.

```
start frame sent
null head         : ack 0xaa
null data seq 1/1 : ack 0xaa
xloader head      : ack 0xaa
xloader data 1..136: ack 0xaa   (all)
pwn head (0x22000): ack 0xaa
pwn: bootrom sent 07
pwn data (entry)  : ack 0xaa
        ACKs: 141 ok, 0 NAK, 0 no-ack
reopened COM8 (after 2.5s)
read 1/2: 16/16 bytes: 00 f0 06 b8 00 f0 04 b8 58 4c 4f 41 44 45 52 21
read 2/2: 16/16 bytes: 00 f0 06 b8 00 f0 04 b8 58 4c 4f 41 44 45 52 21
compare with hisi970_xloader_read.bin: MATCH
```

`0x23154`, 16 bytes, saved as `notes/poc/read-23154-16.bin`
(SHA256 `EAD99FEFE9480B06755BF0E8420F3E37B1E67F47EAC39FF094F13A47D413F74D`).

The returned bytes decode as the entry stub at file `0x1154`:

```
00 f0 06 b8   b.w 0x23164
00 f0 04 b8   b.w 0x23164
58 4c 4f 41 44 45 52 21   "XLOADER!"
```

`XLOADER!` coming back proves, in one shot: the 14-byte frame layout, the
file-type-3 dispatch, the CRC, the code cave, the memcpy, the USB bulk-IN send,
and that the patched xloader is the code actually running. Stable across two
reads.

The pwn also returned the expected single byte `0x07` — the reference
`VcomFlasher.ExploitBootrom` checks for exactly `0x07` on hisi970/hisi980.

## Bug found and fixed during the live run

**The CRC was wrong, and it cost a full run.** First live attempt: 137/137 frames
NAKed (`0x55`), nothing worked.

`tool-reference/Crc16.cs` `CrcHqx` has a non-standard main loop:

```
t = HqxTable[crc >> 8];
crc = (crc << 8) | b;
crc ^= t;
```

I first read its two trailing zero-byte iterations as *additional* augmentation
on top of a standard loop, and implemented `crc_hqx(data) = XMODEM(data + 0000)`
→ `0x39d0` for the head frame body. **Wrong.** The trailing loop *completes* the
non-standard main loop, so `CrcHqx` is exactly plain **CRC-16/XMODEM** →
`0x47e5`. Verified over 2000 random buffers, 0 mismatches.

So there is **one** CRC convention, not two: bootrom upload frames and xloader
read frames both use CRC-16/XMODEM (poly `0x1021`, init 0, non-reflected,
big-endian over `bytes[0..len-2)`). The read frame was already right; only the
upload frames were wrong. After the fix: 141/141 ACKs.

(An earlier version of this note claimed two conventions. That was an artefact of
misreading the C# helper; it is corrected here and in `notes/patch-report.md`.)

The canned start frame `fe 00 ff 01 00000004 00000201 1d0f` matches neither
convention for its body — it is a handshake constant accepted independently of
the frame CRC. Do not derive the CRC from it; it is misleading.

## Second correction: the cave compared the wrong byte

Still valid from the offline pass. `notes/plan.md` §2.0 says to load
`[r4,#0x3dd]` and compare it with 3 as the file type. It is not:

| offset | field |
|---|---|
| `0x3db` | **file type** (`0x2fa48: ldrb.w r1,[r4,#0x3db]`) |
| `0x3dc..0x3df` | size, big-endian |
| `0x3e0..0x3e3` | address, big-endian |

`0x3dd` is the second byte of the **size**. The shipped stub compares
`[r4,#0x3db]` and separately reproduces the overwritten `ldrb.w r3,[r4,#0x3dd]`
before rejoining at `0x2fa5c`, so file types 1/2 behave exactly as before.

## Incident after the success: the loader is now down

A follow-up `--skip-upload` run **re-sent the bootrom start frame into the
already-running xloader**. That frame parses as a 4-byte image to address
`0x201`, so the download state machine was left expecting `0xda` data frames;
subsequent type-3 frames got no answer at all, and the next write timed out.

Recovery attempts:
- reopen port and re-read benign address → no response;
- fresh full upload → `0 / 141 ACKs`, aborted after 8 frames by design.

**The bootrom is gone after the pwn**, so it cannot be re-uploaded from software.
The device still enumerates (`HUAWEI USB COM 1.0`, `CM_PROB_NONE`) but does not
answer. **It needs a power cycle / re-entry into VCOM** before anything else can
run. Nothing was written to flash at any point, so this is fully recoverable.

Fix shipped: the start frame is now sent **only** as part of an upload, never on
`--skip-upload`. And reads now default to a small length so an unmapped address
is isolated from a transfer-size problem.

Lesson for the next run: one session per experiment. Do not re-handshake a loader
that is already running.

## What is verified about the patch (offline, unchanged)

`build/verify_static.py`: **22 pass, 0 fail, 1 warn** (the warn is the start-frame
constant). Three patch sites, nothing else changed (asserted byte-by-byte):

| VA | file | old | new |
|---|---|---|---|
| `0x2fa50` | `0x0da50` | `01 2b` | `02 2b` |
| `0x2fa58` | `0x0da58` | `94 f8 dd 33` | `0f f0 c6 ba` → cave |
| `0x3efe8` | `0x1cfe8` | 248 zeros | 74-byte stub |

74-byte stub in the R+X cave, ends `0x3f032`, data at `0x3f0e0` untouched, no
literal-pool reference into the cave, every branch target valid, `0x305bc`
returns with `sp` balanced so the jump to the parser epilogue `0x2fc58` is legal.
Bounce copy goes to `ctx+0x3d8` — the same buffer the working `0xcd` inquiry
sends from — so cache/DMA behaviour matches known-good firmware.

Stub caps: `length <= 0x400`, non-zero, `address+length <= 0x20000000`; else NAK.

## Current blocker: the phone is in neither VCOM nor fastboot

Checked explicitly, not inferred:

```
adb devices     -> (empty)
fastboot devices-> (empty)
COM ports       -> COM3 (Intel AMT) and COM8, but only COM3 is a present PnP port
USB at the phone's port:
  Error  USB  Unknown USB Device (Device Descriptor Request Failed)
         USB\VID_0000&PID_0002\5&2B41B6C5&0&3
```

`5&2B41B6C5&0&3` is the exact port that used to host `VID_12D1&PID_3609`, so the
cable and port are fine. The phone is physically connected but does not complete
enumeration — it will not answer a descriptor request, so it is in **no** usable
mode (not testpoint/VCOM, not fastboot). Most likely the xloader is still wedged
from the `0x16800000` read and the USB peripheral cannot answer after the port
reset.

### Ghost COM ports are a trap (guard added)

`COM8` **opens successfully even with no device behind it** — Windows keeps a
ghost handle for a removed device and writes silently succeed. An earlier run in
this window opened that ghost, wrote frames into the void and reported `0/141`
ACKs, which says nothing whatsoever about the loader.

`host/vcom_read.py` now refuses to run unless the port is backed by a **present**
`VID_12D1` device:

```
REFUSING: COM8 is not backed by a present VID_12D1 device.
  present VID_12D1 ports: (none)
```

Override only with `--force`, and only when you know the port is real. The
dry-run path is unaffected.

**Action:** power-cycle and re-enter download mode via testpoint, then confirm
`python host\vcom_read.py --list` shows `HUAWEI USB COM 1.0` / `VID_12D1
PID_3609` before running anything.

## Boot-path variant is built and verified, not loaded

`build/hisi970_xloader_read_bootpath.bin`
(SHA256 `72EF63746F4B4017BC9A92957887CCF7152C3A7FFB044468C9FF41A3BA585DAA`),
built by `build/patch_bootpath.py` on top of the working read image. Two extra
sites, 4 changed bytes, nothing else:

| VA | file | old | new | purpose |
|---|---|---|---|---|
| `0x2394c` | `0x194c` | `1c d1` (`bne 0x23988`) | `00 bf` (nop) | force the normal storage-load path |
| `0x2329a` | `0x129a` | `a0 47` (`blx r4`) | `75 e3` (`b 0x23988`) | loop back into the USB poll instead of handing off to ROM |

### Why `b 0x23988` and not `b .`

The plan (§3.2) suggested `b .` at `0x2329a`. That would not work, and the
firmware shows why. The USB parser callback is registered **only** inside
`0x2f8c0`:

```
0x2f8ca  ldr  r0, =0x60053878     ; memset(0x60053878, 0, 0x454)  <- BSS, not 0x16800000
0x2f8d6  bl   0x2f588             ; registers callback 0x2f919 (== 0x2f918|1)
0x2f8de  bl   0x2f8b4             ; poll = 0x308b4(*(0x6005f8b4))
0x2f8ee  ldr  r3, [0x60053878+4]  ; spin until status != 0
0x2f8f2  beq  0x2f8de
```

USB is **polled**, not interrupt driven. A bare `b .` would leave the CPU
spinning with nothing servicing the USB, so a type-3 frame would never reach the
parser. Branching to `0x23988` re-enters the download loop, which calls
`0x2f8c0`, which polls — keeping the read primitive alive while the loaded image
stays at `0x16800000`.

`b 0x23988` was chosen over `b.w 0x23988` because it encodes in 2 bytes and
therefore does not clobber the instruction at `0x2329c`; verified.

### Risks

- `0x237e0` verifies the loaded fastboot and on two failures calls `reboot(0x92)`
  at `0x23976` — a verify failure resets the device instead of letting us read.
  Recoverable by re-entering VCOM.
- Forcing `0x2394c` takes the storage branch even when `0x23f1c() != 1`. If the
  SATE gate `[0x60053000]` is set, main skips `0x2391c` before reaching this
  code, so that gate should be checked first.
- `0x23fb4 / 0x2ef8c / 0x35f5c / 0x23fe4` still run between the load and the
  divergence.

## Round 2: boot-path image loads, but 0x16800000 hangs the loader

`build/hisi970_xloader_read_bootpath.bin` was loaded on real hardware:

```
ACKs: 141 ok, 0 NAK
reopened COM8 (after 10.0s)
[0x00023154] read 1/1: 16/16 B: 00 f0 06 b8 00 f0 04 b8 58 4c 4f 41 44 45 52 21  MATCH
[0x16800000] FAILED: no response at all ... then SerialTimeoutException: Write timeout
```

So:

- the boot-path patches load cleanly and the loader stays **alive and polling**
  (the `0x23154` read works, which also proves the branch to `0x23988` did not
  stop USB servicing);
- reading **`0x16800000` wedges the CPU** — silence, then the write blocks on
  flow control. A follow-up benign read also fails, so the hang is real and not
  a host-side artefact. The USB device still enumerates (`Status OK`) because
  there was no electrical disconnect; enumeration is not evidence of a live CPU.

### Most likely cause: the SATE gate skipped the load

If `[0x60053000] != 0`, main does `cbnz r0, 0x23276` at `0x23270` and skips
`0x2391c` **entirely**, so `0x237e0` never reads the fastboot and `0x16800000` is
never populated. A read of an unimplemented address then locks the AXI bus,
which matches the observed silence exactly. `notes/plan.md` §3.1 already called
for the belt-and-braces patch for this case.

The TrustZone explanation (a secure DRAM region causing an unhandled external
abort) is the alternative and cannot be ruled out yet — it would be a scope
finding, not a bug.

### Diagnostic image built (not loaded)

`build/hisi970_xloader_diag.bin`
(SHA256 `A5B126D6D294B7DF8F18CCB6BCA6D945B4DC40EFA276BEA4AB6F7496EABAC608`),
via `build/patch_diag.py`. Adds, on top of the boot-path image:

| VA | old | new | purpose |
|---|---|---|---|
| `0x23270` | `08 b9` (`cbnz r0,0x23276`) | `00 bf` (nop) | run `0x2391c` even if the SATE gate is set |

and re-assembles the cave stub with the read bound raised `0x20000000 -> 0x80000000`
so BSS globals become readable. `0x60053000` is in `ph8` (a memsz-only
`0xca5c`-byte BSS segment at exactly that address) and `0x24178` reads it, so it
is definitely mapped.

Probe ladder (results are valid only up to the first hang):

```
--probe 0x23154:16,0x60053000:8,0x16800000:0x20
```

- `0x23154` = session sanity (`XLOADER!`).
- `0x60053000` = SATE gate + boot-reason word. It should be `0` once the forced
  load has run. If it is `1`, the previous round never loaded anything and the
  `0x23270` patch is the fix.
- `0x16800000` = the candidate plaintext buffer.

## Round 3-4: the MMU hypothesis was wrong

Round 3 (`hisi970_xloader_diag.bin`) settled two things:

```
[0x00023154] 16/16 B  MATCH
[0x60053000]  8/8 B  00 00 00 00 00 00 00 00   <- SATE gate is 0
[0x16800000] FAILED: no response
```

So the SATE gate is **0**: `0x2391c` did run, and the `0x23270` patch was
unnecessary. The gate was never the cause.

Round 4 (`hisi970_xloader_direct.bin`, no bounce memcpy, the requested address
passed straight to `0x305bc` as the bulk-IN data pointer) **also hung** on
`0x16800000` while `0x23154` read fine. So it is not the CPU memcpy either.

### Hard evidence against "0x16800000 is unmapped"

The `0xda` data-frame handler memcpy's to the head frame's destination **with
the CPU**:

```
0x2fb5c  ldr.w r3, [r4, #0x9dc]      ; destination address from the head frame
0x2fb60  ldr.w r0, [r4, #0x9e8]      ; sequence index
0x2fb64  addw  r1, r4, #0x3db        ; source = frame payload
0x2fb68  add.w r0, r3, r0, lsl #10   ; dest = address + seq*0x400
0x2fb6c  bl    0x23a2a               ; memcpy(dst, src, len)  <- CPU, not DMA
```

That is exactly how the unlock flow loads FASTBOOT into `0x16800000`, so the CPU
**can** write that address. "No MMU translation" is therefore false.

The surviving asymmetry: a **write** can retire in the write buffer without
waiting for a response, while a **read** must wait for data. If nothing answers
reads for that range, writes appear to work and reads hang forever — which
matches every observation so far. That is a hypothesis, not yet proven.

### Also: the loader does not re-enumerate after the pwn

The `--usb-log` watcher shows the only USB transition happens early (0.21s ->
0.44s, during the `null` upload). There is **no** re-enumeration after the pwn,
so the `reopen` step was solving a problem that does not exist — and closing and
reopening toggles DTR, which can disturb the interface. This was spotted by the
operator ("se desconecta pero luego no escucho que se conecta").

`--reopen` is now **off by default**; the serial handle is kept end to end.

## Next experiment: pattern round-trip in the buffer

`--pattern-test` writes a known 0x400-byte pattern to `0x16800000` through the
**download path** — a `0xfe` head naming the address, one `0xda` data frame, EOT,
i.e. exactly the mechanism the unlock flow uses for FASTBOOT — then reads it back
with the type-3 primitive.

This separates the two remaining explanations:

| Outcome | Meaning |
|---|---|
| pattern reads back MATCH | the buffer is fully accessible; the earlier hang is state/timing, and the storage load simply never populated it |
| read hangs, write returned ACKs | the range accepts writes but not reads (the asymmetry above) |
| the write itself hangs | contradicts the unlock flow working; re-examine the head frame |

```
python host\vcom_read.py --list                       # expect VID_12D1 PID_3609
python host\vcom_read.py --port COMx --execute --usb-log --pattern-test ^
    --xloader build\hisi970_xloader_read_bootpath.bin ^
    --probe 0x23154:16,0x16800000:0x400
```

Note `--reopen` is no longer needed (off by default now).

## Round 5: the write to 0x16800000 is ACKed, then the device dies

`--pattern-test` with the boot-path image:

```
pattern head: 14 B sent, ack 0xaa
pattern data: 1029 B sent, ack 0xaa     <- accepted
error: SerialTimeoutException: Write timeout   (on the EOT)
```

This is a real datum. In the `0xda` handler the order is memcpy first, ACK
second:

```
0x2fb6c  bl 0x23a2a             ; memcpy(dst=0x16800000 + seq*0x400, ...)
0x2fb74  mov.w r8, #0          ; success
...
0x2fbde  blo 0x2fc3c           ; r8=0 -> ACK 0xaa
```

So the 1 KB CPU memcpy to `0x16800000` **retired** and the ACK was sent — then the
device stopped reading and never answered again (a follow-up read failed).

Conclusion so far: it is not the *read* that is special. **Any** access to
`0x16800000` ends the session — a read hangs immediately, a write appears to be
accepted (posted, no response needed) and the lockup surfaces right after.
"0x16800000 is not usable from this context" now fits every observation.

### A variable I introduced

The boot-path image forces the storage load (`0x2394c` nop), and that load is
itself an access to `0x16800000`. So the buffer may already have been poisoned
before the pattern test ran. The known-working flow on this device (the
Kirin-Tool unlock) does **not** force that: after the pwn it sits in the download
path and receives FASTBOOT from the host.

`build/hisi970_xloader_loop.bin`
(SHA256 `B266B540EE41530526B2115A45B51B915B3A605354B3BC3CBD1DAA3FCDCF4A1C`)
is that flow plus the read primitive and nothing else: only `0x2329a`
`blx r4` -> `b 0x23988` (stay in the download loop after a transfer).
`0x2394c` and `0x23270` are explicitly left untouched, and the build asserts it.

```
python host\vcom_read.py --port COMx --execute --usb-log --pattern-test ^
    --xloader build\hisi970_xloader_loop.bin ^
    --probe 0x23154:16,0x16800000:0x400 --settle 10
```

If the pattern round-trips here, the boot-path image was the problem. If the
device still dies on the write, then `0x16800000` is genuinely unusable from this
patched context, and the next control test is to write the same pattern to a
different DRAM address (e.g. `0x10000000`) to tell "this address" apart from "no
DRAM at all".

## Breakthrough: the DTL .ktl container is understood

Kirin-Tool decrypts every loader before uploading (`Kirin-Tool/Security/CryptoUtil.cs`,
`CryptoUtil.DTL`). The scheme, read out of the source and then verified against the
real loader:

```
eklen  = BE16
eaek   = next eklen bytes     RSA-2048, OAEP(SHA-256), MGF1-SHA256, no label
iv     = next 16 bytes
edta   = remainder            AES-256-CBC, PKCS#7
```

`build/ktl.py --verify` proves it: decrypting
`Kirin-Tool/bin/Release/net8.0-windows/loaders/hisi970/xloader.ktl` yields exactly
`artifacts/hisi970_xloader.bin` (`2BB2329D...`), and a rewrap/unwrap round-trip is
byte-identical. The private key `FBK` is in `Kirin-Tool/Security/Constants.cs`
(four nested base64 layers, RSA-2048).

This means a patched loader can be **wrapped as a .ktl and fed to the tool's
known-working upload path** instead of hand-rolling the VCOM protocol. The tool
already uploads `null`, `XLOADER`, `UCE` and `FASTBOOT` (to `0x16800000`) and it
works — confirmed on hardware: `fastboot devices` showed
`<device-serial> fastboot` afterwards.

### Prepared swap (tool loaders dir)

| | |
|---|---|
| backup | `loaders/hisi970/xloader.ktl.orig` — `2DA98C562DF2B83AC5020D9D4EFDCB189E963E0C24017380607D6667B20FE2FC` |
| in place | `loaders/hisi970/xloader.ktl` — `3601DD87065BB432C7E4E7DA388E491600BF4A2A288450A9CDAC265115FDCA34` |
| decrypts to | `build/hisi970_xloader_loop.bin` — `B266B540EE41530526B2115A45B51B915B3A605354B3BC3CBD1DAA3FCDCF4A1C` |

Restore with:
`Copy-Item loaders\hisi970\xloader.ktl.orig loaders\hisi970\xloader.ktl -Force`

### Why this is the right vehicle

`hisi970_xloader_loop.bin` has the read primitive plus `0x2329a` `blx r4` ->
`b 0x23988`, so when the tool finishes uploading FASTBOOT to `0x16800000` the
loader **loops back into the download poll instead of handing off to the ROM**.
The image stays in the buffer and the loader stays alive to serve type-3 reads.

Then, with the tool closed (it holds COM8 while running):

```
python host\vcom_read.py --port COM8 --execute --skip-upload --probe 0x16800000:0x400
```

## Round 6: the whole unlock replicated, and a real bug in my hold patch

Running the tool's exact sequence with the patched loader worked end to end:

```
null -> 0x22000, xloader -> 0x22000 (pwn), uce -> 0x60049000,
fastboot 5986304 B -> 0x16800000
ACKs: 6029 ok, 0 NAK, 0 no-ack
```

**So writing 5.9 MB to `0x16800000` is fine.** Every earlier "0x16800000 is not
usable" conclusion is dead: the pattern test was a bad test that proved nothing
about the address.

But the loader still handed off — the phone came back as `fastboot devices ->
<device-serial>`. The cause was a genuine bug in my hold patch:

```
0x2329a -> b 0x23988      ; WRONG
0x2391c  push {r0,r1,r2,r4,r5,lr}      ; prologue, 0x18 bytes
0x239b8  add sp,#0xc ; pop {r4,r5,pc}  ; matching epilogue
```

`0x23988` is **inside** `0x2391c`, past its prologue. Entering there skips the
`push`, so the epilogue pops 12 bytes that were never pushed — stack corruption
and a wild jump.

Fixed in `build/hisi970_xloader_hold.bin`
(SHA256 `9A1F04A6D909E67CA6F35D89C2DDD2C77F9128E8A2875602C4EAB004C1A531CB`),
`build/patch_hold.py`. The handoff site now branches to a loop in the cave that
uses only proper calls:

```
0x2329a  b.w 0x3f038
0x3f038  movs r0, #0
0x3f03a  bl   0x2f8c0      ; memset + register parser 0x2f918 + poll
0x3f03e  b    0x3f038
```

`0x2f8c0` is a real function (`push {r4,lr}` / `pop {r4,pc}`), so the stack stays
balanced, and calling it in a loop is exactly what the stock download loop does at
`0x23998`. After each completed transfer it re-initialises and polls again, so the
image stays at `0x16800000` and the loader keeps serving type-3 reads.

87 bytes changed vs the artifact; the build asserts every change is inside a
known site, that `0x2391c`'s prologue is untouched, and that the loop never
jumps into the middle of `0x2391c`.

Also wrapped into the tool as `loaders/hisi970/xloader.ktl`
(`CD467603A094920DFAD8AFF32BCE7903A30E01F90787D02CFC25F7507E971B7B`, decrypts to
`9A1F04A6...`); the original is still `xloader.ktl.orig`
(`2DA98C56...`).

## Round 7: a confounder in my own experiments

With the corrected hold loop the loader finally behaved: it survived the forced
storage load and kept polling.

```
ACKs: 141 ok, 0 NAK
drained 1 stale byte(s): aa
[0x00023154 len 0x10] 16/16 B MATCH      <- loader alive, hold loop works
[0x16800000] FAILED: no response
```

So the hold loop (`0x2329a -> b.w CAVE2`, CAVE2 calling `0x2f8c0` in a loop) is
correct, and the forced storage-load branch did **not** reboot the device
(`0x237e0` returned success). But `0x16800000` still fails.

### The confounder

Every failing read and every succeeding read differ in **two** ways, and I had
only been controlling one of them:

| reads that worked | length | | reads that failed | length |
|---|---|---|---|---|
| `0x23154` | `0x10` | | `0x16800000` | `0x20` |
| `0x23154` | `0x10` | | `0x16800000` | `0x400` |
| `0x23154` | `0x10` | | `0x16800000` | `0x400` |
| `0x60053000` | `0x8` | | | |

All successes used 8 or `0x10`; all failures used `0x20` or more. The stub
memcpy's the payload into `ctx+0x3d8`, so a large length writes up to
`ctx+0x7d8` and could corrupt the USB context — meaning the failures may have
nothing to do with the address at all. Five sessions went to the address theory
without this control.

The stub's cap is `cmp.w r2, #0x400`, so no firmware change is needed: the fix is
to sweep the length from the host.

### The control, in this order

```
python host\vcom_read.py --port COM8 --execute --settle 10 ^
    --xloader build\hisi970_xloader_read.bin ^
    --probe 0x23154:0x400,0x16800000:0x10
```

1. `0x23154:0x400` — good address, large length. If this fails, the length (bounce
   copy) is the problem and the whole address theory is wrong.
2. `0x16800000:0x10` — target address, small length (already known good).

Order matters: the first probe is the more informative, so if it fails we learn
the answer without spending the second.

### Housekeeping

The patched `.ktl` was removed from Kirin-Tool and the stock loader restored
(`xloader.ktl` = `2DA98C56...`, verified to decrypt to
`artifacts/hisi970_xloader.bin`). The tool is back to stock behaviour; the
patched containers stay in `build/` for when they are needed:

| file | sha256 |
|---|---|
| `hisi970_xloader_hold.ktl` | built from `9A1F04A6...` |
| `hisi970_xloader_hold.bin` | `9A1F04A6D909E67CA6F35D89C2DDD2C77F9128E8A2875602C4EAB004C1A531CB` |
| `hisi970_xloader_store.bin` | `C0DDBE7A7ABA99D928486116E6438E39FC56BC7AE6ABC488CE17B4727FEE167D` |

## Rules learned the hard way

- One experiment per VCOM entry: every upload consumes the bootrom (the pwn
  replaces it), so a second upload in the same session gets `0/N` ACKs.
- Never re-send the bootrom start frame into a loader that is already running.
- Trust `--list` / PnP, not "the port opened": Windows leaves a ghost COM handle
  for a removed device that opens and silently swallows writes.
- Do not launch a live command merely to test a guard — it may consume the
  session. Use `--dry-run`.
