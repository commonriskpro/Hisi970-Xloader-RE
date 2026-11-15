# Read primitive / POC plan (milestone 2–3)

Status: **plan only.** Milestone 1 was offline static analysis. Nothing here has
been run against a device. Do not flash anything and do not start a VCOM session
without the explicit approval gate described below.

The static map is in `notes/xloader-map.md`; addresses and file offsets below use
the same `VA = file_offset + 0x22000` mapping.

## 0. Objective and success criterion

Goal: make the already-decrypted xloader expose the RAM buffer at **0x16800000**
(the fastboot image / intended plaintext buffer) through the VCOM USB channel,
then dump up to **0x5fe000** bytes and check for the decrypted fastboot markers.

Success for the POC:

- dump contains the AArch64 exception-vector table at offset 0
  (first words `0x1400000d`, `0x1400000c`, ...),
- `0x16800024` contains ASCII `BOOTMAGICNUMBER!`,
- strings such as `INFO FB LockState`, `oem unlock`, `oeminfo_lock_stat_write`
  are present,
- the dump is stable across two reads and its size/hash are recorded.

If the dump is high-entropy ciphertext, the POC has **not** succeeded; use the
decision tree in §6.

## 1. What is already known (from milestone 1)

- Fastboot is read to **0x16800000**, max **0x5fe000**, by `0x235f4`
  (`0x23648` sets the destination; `0x2365e` calls `0x24e14` with name
  `"fastboot"`).
- The VRL header is read separately to **0x16dfe000**, size 0x1000, by `0x237e0`
  (paths `"vrl"` / `"vrl_backup"` at `0x23830` / `0x23836`, **offset 0x22000**
  from `0x30ef4`: `0x22 << 12`).
- Verification is `0x237e0 -> 0x311c8 -> 0x31074 -> 0x36dcc` (SEB/HISEE).
- The final handoff is `0x2329a: blx r4`, where `r4 = 0xb3` from `0x23f70`, i.e.
  boot-ROM VA 0xb2. The xloader has no direct branch to 0x16800000.
- **Open question:** the visible code verifies but does not contain a software
  AES/SHA decrypt routine. Decryption is either inside SEB/HISEE or inside the
  ROM handoff. The first POC must distinguish these.
- The VCOM parser is `0x2f918`; inquiry type `0xcd` responds with one byte via
  `0x305bc(dev, data, len)`, which accepts an arbitrary pointer and length.

## 2. Read primitive design

Two designs are viable. The **head-frame type-3** design below is preferred
because it uses a verified 248-byte zero cave at `0x3efe8` and does not disturb
the inquiry command. The **new command 0xce** design in §2.5 is the fallback.

### 2.0 Preferred: head frame file type 3 + cave at 0x3efe8

The file-start frame already carries a 32-bit size and a 32-bit destination
address. Repurpose an unused file type **3** as a read request:

```
type 0xFE, seq 0, ~seq 0xFF,
file type = 3,
size      = read length (big-endian, +0x3dc),
address   = read address (big-endian, +0x3e0),
CRC-16/CCITT big-endian.
```

The total frame is 14 bytes (`0x2fa40` checks length `0xe`). The parser's head
path currently accepts file type 1/2 at `0x2fa50`; the patch makes it accept 3
and diverts type 3 to the cave. The cave restores the overwritten
`ldrb.w r3,[r4,#0x3dd]` instruction for types 1/2 and branches back to the normal
head path at `0x2fa5c`.

| VA | File | Original | Proposed | Purpose |
|---|---|---|---|---|
| `0x2fa50` | `0xda50` | `01 2b` (`cmp r3,#1`) | `02 2b` (`cmp r3,#2`) | accept file type 3 |
| `0x2fa58` | `0xda58` | `94 f8 dd 33` (`ldrb.w r3,[r4,#0x3dd]`) | `0f f0 c6 ba` (`b.w 0x3efe8`) | divert to the cave |
| `0x3efe8` | `0x1cfe8` | 248 zero bytes | read stub | code cave in the first segment |

The cave is exactly `0x3efe8..0x3f0df` (248 zero bytes, ending before data at
`0x3f0e0`). Pseudocode:

```
; entry: r4 = USB context; ctx+0x3d8 = 14-byte frame buffer
    ldrb.w r3, [r4, #0x3dd]     ; restore the original instruction
    cmp    r3, #3
    bne    normal_head          ; b.w 0x2fa5c
    ; type 3: read request
    ; size is big-endian at ctx+0x3dc, address is big-endian at ctx+0x3e0
    ldr    r0, [r4, #0x3e0]     ; address (big-endian -> bswap)
    ldr    r2, [r4, #0x3dc]     ; length (big-endian -> bswap)
    rev    r0, r0
    rev    r2, r2
    cmp    r2, #0x400           ; keep the bounce copy inside ctx+0x3d8
    bhi    fail
    add    r1, r4, #0x3d8       ; bounce buffer
    ; memcpy(r1, r0, r2) -> use 0x23a2a with r0/r1 swapped
    ; 0x23a2a(dst=r1, src=r0, len=r2)
    ...
    mov    r1, r4
    add    r1, #0x3d8
    mov    r0, r4
    bl     0x305bc              ; usb_bulk_in_transfer(ctx, ctx+0x3d8, len)
    b      0x2fc58              ; clean return / r0=0
normal_head:
    b.w    0x2fa5c
fail:
    b      0x2fc40              ; NAK
```

Notes:

- The big-endian fields are the existing head-frame convention (`0x2fa58` reads
  bytes `0x3dc/0x3e0` big-endian). The host must send them big-endian; do not
  reuse the little-endian layout from the fallback design.
- The 0x400 limit keeps the bounce copy inside the frame/context area. The exact
  usable size of `ctx+0x3d8` must be confirmed against the USB context layout
  before increasing it. Start with 0x100 and then 0x400.
- Copying into `ctx+0x3d8` avoids handing an arbitrary address to the USB/DMA
  path (cache coherency/alignment safer), but it does overwrite the frame buffer;
  that is acceptable because the response is sent from that buffer and the parser
  returns immediately.
- This design does not change the inquiry command, so the existing VCOM
  handshake/status behavior is preserved.
- An independent static pass found that the host tool's `CrcHqx` convention may
  differ from the xloader's direct CRC-16/CCITT (poly 0x1021, init 0, big-endian
  stored). Validate the first frame against the device before assuming the host
  helper is correct.

### 2.5 Fallback design: new VCOM command 0xce (details below)

#### 2.5.1 Why this shape

The existing inquiry handler already has everything needed:

- the frame is copied into a contiguous buffer at `ctx+0x3d8`,
- the parser has already checked sequence and CRC,
- `0x305bc` can send an arbitrary pointer/length,
- the parser's return path at `0x2fc58` is a clean epilogue.

Add a new command type **0xce** with a 9-byte payload:

```
offset  size  field
0       1     type = 0xce
1       1     seq (host chooses; 0 is fine)
2       1     ~seq = 0xff - seq
3       1     pad = 0 (keeps the 32-bit loads aligned)
4       4     address, little-endian
8       4     length, little-endian
12      2     CRC-16/CCITT, big-endian, over bytes 0..11
```

The total frame is 14 bytes, the same size as the existing file-start frame, so
the parser's length handling is already comfortable with it.

#### 2.5.2 CRC

The parser's table at VA `0x3e2a4` (file `0x1c2a4`) is CRC-16/CCITT, polynomial
`0x1021`, init 0. The stored CRC is **big-endian** and covers the type, seq,
~seq, pad, address, and length bytes. The host must compute exactly this; a
mismatch takes the `[USBE]crc err` path at `0x2f9c6` and sends NAK.

#### 2.5.3 Patch points

| VA | File | Original | Proposed | Purpose |
|---|---|---|---|---|
| `0x2f9e4` | `0xd9e4` | `cd 2b` (`cmp r3,#0xcd`) | `ce 2b` (`cmp r3,#0xce`) | route type 0xce into the inquiry branch |
| `0x2f9f8` | `0xd9f8` | `00 f0 68 f9` (`bl 0x3accc`) | `f3 f7 bc fc` (`bl 0x23374`) | call the read stub |
| `0x23374` | `0x1374` | legacy fastboot handler | read stub (see below) | code cave; no callers in this build |

`0x23374` is chosen because it is **unreferenced** in this artifact (no `BL`,
`B`, `BLX`, or function-pointer literal targets it). Using it as a cave avoids
growing the image. If a later milestone needs the legacy handler, move the stub
to another unused cave or the end of the segment.

#### 2.5.4 Read stub (cave at 0x23374)

The parser enters the inquiry branch with `r4 = USB context` and `sb = r4+0x3d8`
(frame buffer). The payload is at `sb+3`; with the pad, address is at `sb+4` and
length at `sb+8`.

```
; r4 = ctx, sb = frame buffer, r7 = frame length
    mov   r1, sb
    ldr   r0, [r1, #4]       ; address
    ldr   r2, [r1, #8]       ; length
    cmp   r2, #0x10000       ; per-request cap; tune after first tests
    bhi   fail
    add   r3, r0, r2
    cmp   r3, #0x20000000    ; stay below the peripheral/secure window
    bhi   fail
    mov   r1, r0
    mov   r0, r4
    bl    0x305bc            ; usb_bulk_in_transfer(ctx, address, length)
    b     0x2fc58            ; parser's clean return (r0=0)

fail:
    b     0x2fc40            ; parser's NAK path (type byte 0x55)
```

Notes:

- The loads at `sb+4`/`sb+8` are 32-bit aligned because of the pad byte.
- `0x305bc` masks the length with `& 0x00ffffff` and chunks by the endpoint
  max-packet size (`[ctx+0xd4]`); a 0x10000 request is reasonable for a first
  test. Start with 0x1000 and increase.
- `0x305bc` expects `r0 != 0` and `r1 != 0`; the validation above rejects a null
  address only if `addr+len` wraps; add an explicit `cmp r0,#0` / `beq fail` if
  reading address 0 is not needed.
- The stub must not return to `0x2f9fc`; it jumps directly to the parser
  epilogue, so the old one-byte response code after the `bl` is bypassed.
- If the device's unaligned-access policy is uncertain, do not remove the pad;
  the aligned loads avoid the question.

### 2.5 Host-side request

1. Send the 14-byte frame over the VCOM bulk-OUT endpoint.
2. Read the raw bulk-IN response; it is exactly `length` bytes, not a framed
   response. The existing inquiry path also sends raw bytes (one byte), so this
   matches the stack's behavior.
3. For a full 0x5fe000 dump, issue chunks (e.g. 0x1000 or 0x10000). Save each
   chunk with its address and length; reassemble and hash.

A first safe request is `address = 0x16800000, length = 0x1000`. Check the
result before asking for the full buffer.

## 3. Boot-path patch to keep the image at 0x16800000

The read primitive alone is not enough: the xloader must actually reach the
normal fastboot-load path and then **not** hand off before we can read.

### 3.1 Force the normal path

Current logic (see map §2):

```
0x2326c  bl 0x24178          ; [0x60053000]
0x23270  cbnz r0, 0x23276    ; nonzero -> skip load/wait
0x23272  bl 0x2391c
...
0x2394a  cmp r5, 1
0x2394c  bne 0x23988         ; not 1 -> USB download wait
```

For a **normal storage load** POC:

- `[0x60053000]` is the SATE-aging gate: `0x2410c` sets it to 1 only if the
  `"patch"` partition starts with `"sate_aging_start"`. A stock/unpatched patch
  partition should leave it 0. Verify this first; if it is 1, do not rely on the
  normal path. As a belt-and-braces patch, change `0x23270` from `08 b9`
  (`cbnz r0,0x23276`) to `00 bf` (`nop`) so `0x2391c` always runs.
- Force `0x2391c` down the normal branch by patching `0x2394c` from `1c d1`
  (`bne 0x23988`) to `00 bf` (`nop`). It will then log the normal message and
  call `0x237e0` twice.

This is preferable to patching hardware registers and keeps the patch local.

### 3.2 Stop before the ROM handoff

After the normal load/verify returns, main continues to `0x2329a` and calls the
ROM API at 0xb2. To keep the xloader alive and service the USB read command,
patch the final call to a harmless loop:

- `0x2329a: 20 47` (`blx r4`) -> `fe e7` (`b .`) for a first test, **or**
- `0x2329a` -> `b 0x232a4` (the existing hang loop).

Risk: the USB stack may require the main loop to keep servicing it. If the read
command times out while main is in `b .`, use a loop that calls the USB poll
function instead of a bare spin. The first test should try `b .` and observe
whether the USB device still answers; if not, replace the hang with a call to the
USB state machine/poll function used by the parser.

**Do not patch the final call until the read primitive is independently tested**
on a benign read (e.g. read a known string in the xloader's own RAM). That
separates "read primitive works" from "boot path reaches plaintext".

### 3.3 Alternative: download mode

The xloader also supports a host-supplied image: `0x23988` waits until
`0x2f8c0(0) == 0x16800000`, and the file-start frame (`0xfe`) carries the
destination address. This path can put a host image at 0x16800000 without
storage. It is a useful fallback if the storage path is rejected, but it does not
exercise the on-disk fastboot decrypt path; use it only to validate the read
primitive and the final handoff separately.

## 4. Offline build and verification

1. Copy `artifacts/hisi970_xloader.bin` to a new file under `reports/` or
   `notes/` (do not overwrite the artifact).
2. Apply the two hot patches (`0x2f9e4`, `0x2f9f8`) and the cave stub.
3. Apply the boot-path patches (`0x23270` and/or `0x2394c`, final `0x2329a`).
4. If using the fallback design, disassemble the patched regions with capstone/r2
   and confirm:
   - `0x2f9e4` is `cmp r3,#0xce`,
   - `0x2f9f8` is `bl 0x23374`,
   - the cave decodes as intended and does not overlap `0x233e4`,
   - `0x23270`/`0x2394c`/`0x2329a` have the intended branches.
5. Recompute SHA256 of the patched image and record it. Keep the original hash
   `2BB2329D...` in the report.
6. If a `.ktl` wrapper is required by the VCOM loader, use the existing local
   tooling; do not copy keys into this project.

## 5. POC execution (requires explicit approval; RAM only)

Preconditions:

- A testpoint/recovery baseline exists and is documented.
- The device is known recoverable; the last factory-fastboot flash was rejected,
  so no flash is attempted here.
- The operator explicitly approves a **read-only VCOM session** and a **RAM
  load** of the patched xloader.

Steps:

1. Put the device into the VCOM/download mode used for xloader loading.
2. Load the patched xloader into RAM (no partition write).
3. Let it initialize; confirm USB enumeration.
4. Send a **benign** read request first (e.g. the address of a known string in
   the xloader image, or a small RAM region). Verify the returned bytes match the
   offline file. This proves the read primitive and CRC.
5. Force/allow the normal path (`[0x60053000]==0` or patched branch), let
   `0x237e0` read/verify fastboot, and stop before the final handoff (§3.2).
6. Read `0x16800000`, length `0x1000`; save and inspect.
7. If the first 0x1000 looks like the expected AArch64 vector table/magic, dump
   the full `0x5fe000` in chunks; reassemble and hash.
8. Repeat one chunk twice to check stability.
9. Power-cycle back to the stock loader if anything behaves unexpectedly; do not
   write flash.

## 6. Decision tree after the first dump

### A. Plaintext markers present

- The dump contains the AArch64 vectors at 0 and `BOOTMAGICNUMBER!` at +0x24.
- Save it as the candidate decrypted stock fastboot; hash it.
- Verify the expected strings (`INFO FB LockState`, `oem unlock`,
  `oeminfo_lock_stat_write`) and the vector table.
- Proceed to milestone 4: locate the lock-state initialization in the plaintext
  and prepare the force-unlock patch on a **copy** first. No flash yet.

### B. High-entropy data, no markers

The xloader did not decrypt the payload; the read primitive works but the
plaintext is not at 0x16800000 at this point.

Next experiments, in order:

1. Confirm the read is actually 0x16800000 (return a known pattern or read a
   known xloader string at a nearby address).
2. Test whether the **ROM handoff** performs decryption. This is harder because
   the xloader may no longer be able to service USB after the call. Options:
   - hook the final call to a small stub that saves the return/arguments and
     loops, if the ROM call returns;
   - use the ROM/SEB API directly from the xloader if a decrypt-only entry can be
     identified (this requires more RE; do not guess the API).
3. Do **not** flash an image or a patched fastboot to test this. A wrong
   fastboot image was already rejected once; recovery is not guaranteed.

### C. Wrong size / truncated read

- Check the read cap (`0x5fe000`) and the partition size (`0x3000` sectors =
  6 MiB). The last 0x2000 may be padding; dump in chunks and stop at the actual
  VRL-reported size.
- Check the USB endpoint max packet and the `0x305bc` chunking; a short read may
  be a host-side transfer-size issue, not a xloader issue.

## 7. Evidence to capture

For every POC run, save under `reports/` (not in a public repo):

- patched image SHA256 and the exact patch list,
- host request/response logs (address, length, CRC, bytes),
- first 0x1000 dump and full dump,
- entropy/marker checks,
- device state and recovery notes,
- any deviation from this plan.

## 8. Risks and rollback

- **RAM load only.** Do not write the xloader or fastboot partition in this POC.
- A bad patched xloader can hang before USB enumeration; keep a known-good
  loader and a testpoint recovery path.
- The USB read command can crash the stack if the address/length is invalid;
  validate in the stub and start with 0x1000.
- The final-handoff patch may leave the SoC in an unexpected state; power-cycle
  and re-enter VCOM rather than flashing.
- If the plaintext is only produced inside the ROM/SEB, a pure xloader read
  primitive will not recover it. That is a scope/architecture finding, not a
  reason to flash blindly.

## 9. Open questions carried into milestone 2

1. Does the first dump at 0x16800000 show plaintext or ciphertext? This single
   experiment decides whether the current architecture is sufficient.
2. Which component decrypts: SEB/HISEE (`0x36dcc`) or the ROM handoff (`0xb2`)?
3. Is the final ROM call safe to skip, or does it also initialize the USB/clock
   state needed by the read primitive?
4. Can the read command be serviced while main is in the post-load loop, or does
   it need a dedicated poll?
5. Is `0x23374` truly dead in the running build, or is it reached by a path not
   visible in this truncated artifact? The static scan says dead; dynamic
   testing can confirm.


## 10. Exact next step (do this before any other POC work)

1. Copy `artifacts/hisi970_xloader.bin` to `reports/xloader_readprim.bin`.
2. Apply **only** the preferred read primitive:
   - `0x2fa50`: `01 2b` -> `02 2b`
   - `0x2fa58`: `94 f8 dd 33` -> `0f f0 c6 ba`
   - write the cave at `0x3efe8` (file `0x1cfe8`), leaving `0x3f0e0` untouched.
3. Disassemble `0x3efe8..0x3f0e0` with capstone and verify the cave stays inside
   the 248 bytes and that `0x2fa5c` is reached for file types 1/2.
4. Diff the patched file against the original; confirm **only** the three regions
   changed and record the SHA256.
5. In a read-only VCOM session with explicit approval, load the patched xloader
   into RAM (no flash) and send one type-3 head frame reading a known address
   (for example 16 bytes at the xloader's own `0x23154` and compare with file
   offset `0x1154`). This validates the frame/CRC/read path without relying on
   the fastboot/decrypt path.
6. Only after that benign read succeeds, add the normal-path patch (`0x2394c`
   `bne` -> `nop`) and the stop-before-handoff patch (`0x2329a` -> `b .`), then
   dump `0x16800000` as described in §6.
7. If the benign read fails, do not touch the boot path; debug the frame length,
   CRC byte order, and the `ctx+0x3d8` bounce limit first.
