# Option B1 — bootrom-context feasibility analysis

Status: **offline analysis only.** No phone, VCOM port, UFS access, or flash
operation was used. This report adds one file; no existing document was changed.

## 1. Executive summary

**Feasibility of B1 as stated: NO.** The premise that the existing bootrom pwn
gives an "EL3 context" that can read `0x16800000` is a category error. The
head-resend sequence gives code execution on the **LPMCU**, a Cortex-M3, in the
BootROM's privileged (handler-mode) context. EL3 is the **ACPU** context that
runs the decrypted fastboot image *after* the xloader releases it. The two are
different cores, different execution states, and different memory views.

**Executive feasibility: NO.** The only plausible B1 variant was the SEB
store-address redirect, and the concurrent static analysis in
`notes/seb-analysis.md` closes it: the 12-byte VRL entry is
`{address, 0, length}`, a **source-range descriptor**, not a plaintext
destination. The implemented SEB interface is verification/hash only; the 4 KB
staging buffer at `0x60035000` is zeroed on return, and there is no
read/decrypt/export command in this artifact. The residual B1 possibility is an
undocumented SEB/HISEE hardware decrypt-and-store on the `SEB_SECCFG_SECURE`
status-5/7 path; that is a hardware hypothesis, not an implemented command and
not invocable from the xloader as a read path.

The bootrom context also runs **before DDR is initialised**: the xloader is the
component that brings DDR up. A stage image that replaces the xloader therefore
cannot read `0x16800000` simply because that DRAM does not exist yet. If it
initialises DDR itself, it is still the same LPMCU master whose CPU read path to
the `0x16xxxxxx` window is the one that already fails from the xloader.

**Single most important unknown:** does the SEB/HISEE hardware internally
perform a decrypt-and-store to the descriptor address on the
`SEB_SECCFG_SECURE` status-5/7 path, despite the CPU-visible interface being
verification-only? If yes, it would still be a hardware operation with a
`0xDB230`-byte (about 897 KB) source range, not a small-SRAM redirect, and the
4 KB staging buffer would be irrelevant. If no, B1 is closed and the only
remaining export path is AArch64 code after the ROM `0xB2` handoff (B2).

**Actionable next unknown (B2):** does the ROM re-verify the fastboot image
after the xloader rewrites the `+0x20` entry to a post-handoff AArch64 stub? A
negative answer allows the small patch-after-verify experiment; a positive
answer forces a dedicated AArch64 download-mode image.

## 2. What was inspected

Project artifacts (read-only):

| Artifact | Use |
|---|---|
| `tool-reference/VcomFlasher.cs` | exact head/data/tail frames and the head-resend sequence |
| `tool-reference/FirmwareUnlocker.cs` | load order and per-SoC addresses |
| `tool-reference/Crc16.cs` | wire CRC convention |
| `artifacts/hisi970_xloader.bin` | xloader map, `0x31074`/`0x36ea0`/`0x36dcc` |
| `artifacts/hisi970_fastboot_ram.bin` | decrypted-fastboot header layout (`+0x20`, `+0x24`) |
| `artifacts/FASTBOOT.from-update-app.img` | plaintext VRL header |
| `notes/FINDINGS.md`, `notes/xloader-map.md`, `notes/plan.md` | hardware results and prior static map |

External artifacts (read-only, not copied into this project):

| Artifact | Why it matters |
|---|---|
| TASZK Security Labs, *CVE-2021-22434: Huawei Arbitrary Write in BootROM USB Stack* | authoritative description of the head-resend state confusion and the `0x07` response |
| TASZK Security Labs, *How To Tame Your Unicorn* (Black Hat USA 2021 whitepaper) | boot-chain topology: LPMCU Cortex-M3 for BootROM/xloader, ACPU EL3 for fastboot |
| `SoC-BootROMs` (`code.chipmunk.land/max/SoC-BootROMs`, `hisilicon/`; the kasnria001-contributed set) | sibling Kirin bootrom dumps used for instruction-level cross-checks |

Sibling bootrom dumps used (SHA-256):

| File | Size | SHA-256 |
|---|---|---|
| `kirin810.bootrom.bin` | `0xd000` | `261de519402dad7d40ad0e8747b60f6eb0d82fec147ca1f5df8cf18dfeb96a0c` |
| `kirin820.bootrom.bin` | `0x10000` | `ccf29eb17b193c1cd963bbb9bcd5eaa1dc2df6d302457c072ed8d82eda1f6962` |
| `kirin710a.bootrom.bin` | `0x10000` | `198dfb8eb0d12ceb56e5fdb157bb9b1b2073766a207fc57923e6c418724ff3cd` |

**There is no Kirin 970 bootrom dump in this repository, in `work/loaders`, or in
the public `SoC-BootROMs` tree.** The sibling dumps are evidence for the
mechanism and the stack invariant, not for 970-specific ROM addresses.

## 3. The head-resend sequence, exactly

### 3.1 Host side (`VcomFlasher.cs`)

`UploadData` sends the normal transfer first:

1. head frame at `address`, length `data.Length` (`VcomFlasher.cs:120`);
2. data frames `seq = 1..N`, each up to `0x400` bytes (`:124-133`);
3. if `shouldHeadResend`, call `ExploitBootrom(xloaderStart, cpu)` (`:135-150`);
   otherwise send the tail frame (`:153`).

`ExploitBootrom` then does exactly this (`:158-196`):

| Step | Frame | Meaning |
|---|---|---|
| 1 | head `0x22000`, length `4`, ACK expected (`:160`) | valid head; resets BootROM XMODEM state, sets `next_seq = 1` |
| 2 | delay 100 ms (`:161`) | lets the BootROM commit the state |
| 3 | head `0x4DBC8`, length `4`, no ACK wait (`:175`) | invalid head; still commits the address |
| 4 | read one byte and compare with `0x07` (`:177-187`) | observes the BootROM address-error status |
| 5 | data frame `seq = 1`, 4 bytes = little-endian `xloaderStartAddr` (`:189-191`) | writes the value at the latched address |
| 6 | tail frame `seq = 2` (`:194`) | ends the transfer; the overwritten return slot is popped |

For `hisi970`, `xloaderStartAddr = 0x2316D` (`:141`) and
`returnAddr = 0x4DBC8` (`:164`). `0x2316D = 0x2316C | 1`, i.e. Thumb entry at
xloader `main` (the entry stub is `0x23154`, `main` is `0x2316C`; see
`notes/xloader-map.md` §1).

The frame builders are unambiguous:

- head: `0xFE, seq=0, ~seq=0xFF, file_type=1, length (BE32), address (BE32),
  CRC-16 (BE16)` (`:215-224`);
- data: `0xDA, seq, ~seq, data, CRC-16` (`:226-234`);
- tail: `0xED, seq, ~seq, CRC-16` (`:236-243`).

The CRC helper is CRC-16/XMODEM, verified on hardware (see `notes/poc-status.md`).

For `hisi970`, `FirmwareUnlocker.cs:103` lists `null` at `0x22000` before the
xloader. That 1-byte image is a state primer: it is a complete tiny transfer to
the valid address, after which the real xloader head resets the transfer state.
The head-resend sequence is attached to the xloader stage, not to `null`.

The initial `SendStartFrame` (`VcomFlasher.cs:111-116`) is
`FE 00 FF 01 00000004 00000201 1D0F`: a head-shaped frame to address `0x201`,
not a normal transfer. It is a wake-up/handshake constant; the host does not
wait for an ACK, and the following valid head at `0x22000` resets the state.

### 3.2 BootROM side: the state confusion

The public CVE-2021-22434 description gives the pseudo-code. The sibling
bootroms let us confirm it instruction-by-instruction. In `kirin810.bootrom.bin`
(the dump with the same `0x4DBC8` return slot as 970/980), the head parser is at
`0x4CD0`:

```
0x4CD0  ldrb.w r2, [r7, #0x3DB]    ; file type
0x4CD4  subs   r3, r2, #1
0x4CD6  uxtb   r3, r3
0x4CD8  cmp    r3, #1              ; accept types 1..2
0x4CDA  bhi    0x4C38              ; -> NACK path
0x4CDC  ...                          ; reconstruct length and address (BE)
0x4D14  cmp.w  r1, #0x22000        ; address check
0x4D18  str.w  r2, [r7, #0x9D8]    ; file type
0x4D1C  str.w  r3, [r7, #0x9E0]    ; length
0x4D20  str.w  r1, [r7, #0x9DC]    ; file_download_addr  <-- committed first
0x4D24  str.w  r1, [r7, #0x9F4]    ; last address
0x4D28  beq    0x4D3C              ; only now branch on the check
0x4D2A  ...                          ; "address err" log
0x4D36  mov.w  fp, #7              ; response code 0x07
0x4D3A  b      0x4BE0              ; common response dispatch
```

The stores at `0x4D18..0x4D24` happen **before** the conditional branch. That is
the missing state cleanup: a failed address check leaves `file_download_addr`
set to the attacker value while `next_seq` is still 1 from the previous valid
head. The response dispatch at `0x4BE0` selects `0x4C0C` for code 7:

```
0x4C0C  mov r0, r7
0x4C0E  movs r1, #7
0x4C10  bl 0x4774              ; send one byte (0x07)
```

The same sequence is present in the other sibling dumps:

| BootROM | `cmp #0x22000` | unconditional store | `fp = 7` |
|---|---|---|---|
| `kirin810` | `0x4D14` | `0x4D20` | `0x4D36` |
| `kirin820` | `0x3E94` | `0x3EA0` | `0x3EB6` |
| `kirin710a` | `0x34B0` | `0x34BC` | `0x34C6` |

The data path is equally explicit (`kirin810` at `0x4C98`):

```
0x4C98  ldr.w r3, [r7, #0x9DC]   ; file_download_addr
0x4C9C  ldr.w r0, [r7, #0x9E8]   ; latest_seen_seq
0x4CA0  addw  r1, r7, #0x3DB      ; data start in the frame buffer
0x4CA4  add.w r0, r3, r0, lsl #10 ; dst = addr + seq * 0x400
0x4CA8  bl    0x2C0C             ; memcpy(dst, src, 0x400)
```

Equivalent data paths: `kirin820` `0x3E18..0x3E28` (`memcpy` at `0x1BB4`),
`kirin710a` `0x34CC..0x34DC` (`memcpy` at `0x16E0`).

**Answer to "why 0x07":** `0x07` is the BootROM's *address error* response for
a head whose address is not `0x22000`. It is not a success code. It is the
fingerprint of the state-confusion step: the invalid head was parsed, its
address was committed, and the 4-byte data frame will therefore write to
`0x4DBC8`. The host check at `VcomFlasher.cs:184` is intentionally empty; a
missing or different byte does not abort the sequence.

### 3.3 What is at `0x4DBC8`?

The sibling dumps expose the stack invariant directly. Every dump starts with a
Cortex-M vector table:

```
word 0: initial MSP
word 1: reset vector (Thumb)
word 2..: NMI / HardFault / ... handlers (0xB5 = 0xB4|1)
```

| BootROM | initial MSP | head-resend slot | difference |
|---|---|---|---|
| `kirin810` | `0x0004DBFC` | `0x4DBC8` | `0x34` |
| `kirin820` | `0x000673FC` | `0x673C8` | `0x34` |
| `kirin710a` | `0x00049BFC` | `0x49BC8` | `0x34` |

The 970/980 host sequence uses `0x4DBC8`; for 970 this is exactly `kirin810`'s
MSP minus `0x34` (no 980 dump was available to check). This is a stack slot,
not a code address. In the 810 image, `download_xloader`
at `0x6AC` creates a `0x30`-byte frame (`push.w {r4-r8,sb,sl,lr}` = `0x20`,
`sub sp,#0x10`), leaving `SP = MSP-0x30 = 0x4DBCC`; a callee with a two-register
`push` stores its LR at `SP-4 = 0x4DBC8`. The slot is therefore the saved return
address of the BootROM's download path. The tail frame makes that function
return; the overwritten LR is popped and execution continues at `0x2316D`
instead of the BootROM caller.

The public description matches: "overwrite a pushed return address on the
stack" (TASZK CVE-2021-22434); the studentpad-hack analysis names it the return
address of `download_xloader`. The exact active function at the moment of the
tail can differ by call path, but the slot and its effect are invariant across
the three sibling SoCs.

The normal BootROM-to-xloader transition in the 810 image is visible at
`0x75C..0x786`: it validates `\x7fELF` at `0x23000`, loads `e_entry` from
`0x23018` (`0x23154` in the 970 xloader), adds the Thumb bit, and `blx r4` to
`0x23155`. The head-resend path deliberately uses `0x2316D` (xloader `main`)
instead of the entry stub. Both are valid instruction boundaries; the tool
chooses `main` for this SoC.

### 3.4 Execution context — the important correction

The TASZK whitepaper's boot-chain section is explicit:

> "This core is called the LPMCU which is a small Cortex-M3. The main CPU
> (ACPU) only comes online at the fastboot stage."

and the chain is:

```
LPMCU  BootROM  -> loads xloader (UFS or USB download)
LPMCU  xloader  -> initialises DDR and the main CPU
LPMCU  xloader  -> loads fastboot (and UCE/BL2)
ACPU   fastboot -> runs in EL3 (<990), loads kernel/TEE/modem
```

The sibling bootrom dumps independently confirm the M-class context: initial
MSP, reset vector, and fault vectors, not an AArch32/AArch64 EL3 vector base.
The xloader is Thumb-2 code on the same LPMCU. For 970 the fastboot image is
AArch64 (`artifacts/hisi970_fastboot_ram.bin` starts with AArch64 exception
branches), and it is the ACPU that executes it in EL3 after the handoff.

This also explains the failed CP15 introspection in `notes/FINDINGS.md`:
Cortex-M3 has **no CP15 and no MMU**. `mrc p15` is an undefined instruction
there, so the earlier "MMU translation" hypothesis was testing a mechanism the
core does not have. The 32-bit loader's DRAM read failure is a fabric/access
property, not a missing page table.

**Consequence:** a stage image loaded by the head-resend sequence runs at
LPMCU privileged level, not EL3. It cannot read EL3 registers, cannot execute
AArch64 EL3 instructions, and does not inherit the ACPU's view of DRAM.

### 3.5 Before or after the xloader upload? Can a custom image be substituted?

**After.** `UploadData` sends every xloader data frame first (`VcomFlasher.cs:124-133`),
then `ExploitBootrom` writes the return slot and sends the tail (`:135-195`).
The BootROM is still in its own download path when the tail is processed; the
stage image at `0x22000` is already resident.

**Yes, a custom stage image can be substituted.** The sequence needs only:

1. a valid head at `0x22000` to set `next_seq = 1`;
2. a stage image in SRAM at `0x22000` (or wherever the stage is linked);
3. a 4-byte value written to the saved-return slot that is a Thumb address in
   the stage image;
4. a tail frame to trigger the return.

The BootROM's certificate/SEB verification of the downloaded xloader is reached
by the code that called the interrupted download/receive routine. The return-slot
overwrite fires first: the overwritten LR returns to the stage instead of back
to that caller, so the verification path is skipped. This is exactly why the
sequence works with a patched (unsigned) xloader today.

The stage image runs with the BootROM's USB stack still live and with the
controller already initialised. That is useful for exfiltration, but it does
not change the LPMCU's DRAM read path.

It is not a post-BootROM jump. The redirection happens on the return path of
the BootROM's own download/receive code; that is why the BootROM's USB context
and controller state are still valid when the stage begins.

## 4. Can that context read `0x16800000` / `0x16dfe000`?

### 4.1 What the project proved on hardware

From `notes/FINDINGS.md` and `STATUS.md`:

| Target | Byte copy | Word copy | USB DMA | Result |
|---|---|---|---|---|
| `0x23154` (loader SRAM) | 8/16/1024 B OK | 16 B OK | 16 B OK | readable |
| `0x60053000` (loader BSS) | 8 B OK | — | — | readable |
| `0x16800000` (DRAM window) | 0x10/0x20/0x400 fail | 0x10 fail | 0x20 fail | wedges |
| `0x16dfe000` (DRAM window) | — | 0x10 fail | — | wedges |

Writes to the same window succeed: the `0xDA` path copies the 5.9 MB image to
`0x16800000` with 6029 ACKs, and the image boots after the ROM handoff. The
length confounder was eliminated (`0x23154:0x400` matches; `0x16800000:0x10`
fails). Access size is ruled out.

### 4.2 Why the bootrom context does not automatically fix it

Three independent reasons:

1. **DDR is not up at the point of the head-resend return.** The xloader is the
   component that initialises DDR (`notes/xloader-map.md` main sequence; TASZK
   boot chain). A stage image substituted for the xloader runs before that
   initialisation. Reading `0x16800000` then is a read of uninitialised or
   undecoded address space, not a read of the fastboot buffer.
2. **The failing master and the stage master are the same LPMCU.** The xloader
   already runs Thumb-2 on the Cortex-M3. The difference between the BootROM
   and the xloader is not a privilege boundary that would open the DRAM read
   path; both issue transactions from the same LPMCU master port.
3. **The proven reader is the ACPU.** The fastboot image executes from
   `0x16800000` on the ACPU; the ACPU is the master that demonstrably reads it.
   The LPMCU is the master that writes it and then hands off.

The exact gating mechanism (TZASC region, interconnect read decode, or a
secure/non-secure attribute mismatch) remains unproven, but the practical
consequence is independent of the mechanism: **a BootROM/LPMCU stage image is
not a proven reader of that window, and there is no evidence it would be.**

### 4.3 Missing artifact and how to obtain it

**Missing:** a Kirin 970 BootROM image (and, ideally, the LPMCU SRAM/DDR map and
the `0xb2` ROM API semantics).

Why it matters: the 970-specific SEB entry points, USB transmit routine, UFS
boot read routine, and the final `0xb2` handoff ABI are all ROM addresses. The
sibling dumps give the code shape but not the 970 addresses.

How to obtain it, in increasing cost:

1. **Public dump/release.** Check `SoC-BootROMs` and Kirin research archives for
   a `kirin970`/`hi3680`-class image. None was present at the time of this
   analysis.
2. **Self-dump with the existing pwn (RAM-only).** Upload a small stage image
   to `0x22000` and redirect the return slot to it. The stage reads the BootROM
   ROM range (the sibling vector tables start at `0x0`; a `0x10000`-byte read is
   the natural first attempt) and sends it over the live BootROM USB stack. The
   stage can preserve the BootROM XMODEM context pointer seen at the return
   (the parser uses `r7` as the context base) and reuse the BootROM's one-byte
   transmit routine (sibling `0x4774`, which calls the USB state machine at
   `0x3DDC`). This is the same class of work as B1 but strictly smaller: no
   storage, no SEB, no DDR.
3. **JTAG/testpoint read.** If the board exposes a debug port and the ACPU/LPMCU
   debug is not fused off, a debugger can read the ROM directly. This needs
   hardware access and explicit authorisation.

Related public work worth reading, but not a 970 artifact: TASZK's Kirin 990
blind port and Pangu's `checkm30` both describe dumping the BootROM and leaking
data through the memory-inquire path. They are 990-specific chains; they do not
provide a 970 bootrom image or 970 ROM addresses.

Evidence vs hypothesis:

| Claim | Status |
|---|---|
| BootROM pwn runs on LPMCU Cortex-M3, not ACPU EL3 | **evidence** (whitepaper + sibling vector tables) |
| `0x4DBC8` is MSP-`0x34` and a saved return slot | **evidence** for 810/820/710a; **strong inference** for 970 (same address as 810) |
| `0x07` is the address-error response and the address is committed before the check | **evidence** (three sibling bootroms + TASZK) |
| DDR is not initialised at the pwn point | **evidence** (boot-chain topology; xloader init sequence) |
| LPMCU cannot read `0x16800000` | **hardware evidence** from the xloader; the exact gate is **hypothesis** |
| BootROM stage could read the window after initialising DDR itself | **no evidence**; same master; not recommended |
| 970 SEB can write plaintext to an SRAM store address | **no evidence**; static analysis shows a source `{address, 0, length}` descriptor and a verification-only interface |

## 5. The two B1 sequences, evaluated

### 5.1 B1a — BootROM/stage image reads UFS and drives the crypto engine

Target shape: a stage image at `0x22000` uses the BootROM's UFS read and SEB
functions to load the stock fastboot, decrypt it to a known buffer, and send it
out over USB/serial.

Required knowledge:

- BootROM UFS initialisation and read API (the BootROM already loads xloader
  from UFS, so the capability exists);
- partition map: UFS `fastboot_a` at start sector `0x5F800`, size `0x3000`
  sectors (6 MiB), from the type-2 table at VA `0x40A78`;
- VRL header location: `vrl`/`vrl_backup` at offset `0x22000`, size `0x1000`,
  to `0x16DFE000` (`0x237E0`, `0x30EF4`);
- SEB command structures: `SEB_SecureInit`, `SEB_FillCertPkg`,
  `changeStoreAddr`, the `0xbdf0f000` register window, and the command/response
  descriptors behind `0x36DCC`;
- key availability: TASZK reports EFUSE-resident keys up to 970 and a crypto
  engine as a decryption oracle from 980 onward; the 970 fastboot is encrypted
  while the 970 xloader is plaintext;
- a destination buffer that the LPMCU can read (SRAM), and its size — the
  static analysis found no such output channel in the implemented SEB path;
- a transmit primitive (BootROM USB or UART).

Patch points: there are no ROM patch points. The stage image is the patch. If
the stage is a **patched xloader**, the known-good SEB code is already at
`0x31074`/`0x36DCC`/`0x36EA0`; that is far less work than reimplementing the
SEB protocol in a from-scratch Cortex-M3 image.

Exfiltration: the BootROM's one-byte/4-byte transmit path (`0x4774`/`0x47A0` →
`0x3DDC` in the sibling) or the xloader's proven type-3 read primitive if the
plaintext is in SRAM. The latter is the preferred channel: it already works on
hardware.

Risks:

- The fastboot partition window is 6 MiB (the stock encrypted payload file is
  about 3.4 MiB; the decrypted RAM artifact is about 5.7 MiB). That is larger
  than the LPMCU's likely SRAM window; a whole-image decrypt to SRAM would
  overrun. Chunking depends on the VRL certificate's store entries and on
  whether SEB can be invoked per segment.
- SEB may require the whole-image context/hash and may reject a partial or
  redirected operation.
- The UFS read may need power/clock initialisation that only the xloader
  performs.
- A bad SEB request returns an error (fail-closed) or hangs the LPMCU; RAM-only,
  power-cycle recovery. No flash writes.

The sibling BootROM's own SEB path has the same shape: `kirin810` `0x3AC`
builds a `0x400`-byte certificate package at `0x4DC00` (`0x5D98`) after
`SEB_SecureInit` (`0x5A94`/`0x5E58`) for the image at the download address. It
returns a status, not image bytes. There is no visible export path in that ROM
either.

**Verdict: NO for the implemented interface.** The xloader's SEB path is
verification/hash only. An undocumented SEB firmware command is outside this
artifact and is not a software-only project.

### 5.1b The SEB store-address redirect — static result closes it

This was the cheapest B1 candidate: use the xloader's own path and change the
argument at `0x238B8` (`mov.w r1,#0x16800000`, bytes `4F F0 B4 51`) to a small
SRAM address, hoping SEB would write plaintext there. The concurrent static
analysis in `notes/seb-analysis.md` (§3.5, §5.4) resolves the question against
that interpretation:

- the 12-byte certificate entry is `{address, 0, length}`; the in-place update
  at `0x3700E..0x37062` copies `{image_address, 0}` and preserves the length at
  `+8`;
- the real update header has one entry at `0x874`: `{0, 0, 0xDB230}`; after the
  normal rewrite it is `{0x16800000, 0, 0xDB230}`;
- the field is therefore the **source range** that SEB reads for verification,
  not a plaintext destination; the error string calls it `store_addr`
  (`0x3E769`), but its shape is `{address, length}`, not an output descriptor;
- the only caller-supplied buffer, `0x60035000`/`0x1000`, is a 4 KB input
  staging area; `0x36DCC` zeroes it on every return (`0x36E14`), and no USB code
  reads or forwards it;
- the visible SEB path is certificate/hash verification (SHA-256 engine), with
  no AES S-box and no read/decrypt/export command.

Consequences:

1. Changing `0x238B8` to an SRAM address would make SEB read the wrong source
   range, not redirect an output. The expected result is a verification error,
   not plaintext.
2. Even the residual hardware-store hypothesis is not a small-SRAM test: the
   descriptor length is `0xDB230` (about 897 KB) in the real header, far larger
   than the 4 KB staging buffer or the loader's spare SRAM. A destination would
   have to be DRAM-sized, which returns to the original read problem.
3. The `SEB_SECCFG_SECURE` status-5/7 path could still, in hardware, perform a
   decrypt-and-store to the descriptor address; the CPU graph does not prove
   it either way. That is a hardware hypothesis, not an implemented command,
   and it does not provide a small output channel.

Patch point (for completeness, not recommended as a first experiment):
`0x238B8` -> a cave that loads the chosen address into `r1` and returns to
`0x238BC`; a second cave is available after the existing read-primitive cave
(`0x3EFE8..0x3F032`) and before the data at `0x3F0E0`. A negative result is
expected from the static evidence; a positive would require the SEB hardware to
write plaintext to the descriptor address, and the destination would still need
to be about `0xDB230` bytes and readable by the LPMCU.

**Verdict: B1a' is not viable. Do not spend a VCOM session on it before B2.**

### 5.2 B1b — xloader decrypts to DRAM, then an EL3/AArch64 stage reads it

This is the architecturally correct version: the xloader already loads and
decrypts the stock fastboot into `0x16800000`, and the ACPU is the master that
reads/executes it. The task is to regain control at the ACPU/EL3 boundary.

Possible patch points:

1. **Fastboot header entry field.** `artifacts/hisi970_fastboot_ram.bin` has
   `0x16800000` at offset `+0x20` and `BOOTMAGICNUMBER!` at `+0x24`. If the ROM
   `0xb2` handoff reads the ACPU entry from that header, the xloader can rewrite
   `+0x20` after verification (it can write DRAM) to point at an AArch64 stage
   that the host uploaded to a second DRAM window. The xloader does not need to
   read DRAM for this; it only writes the entry word. This is a small xloader
   patch but depends on the `0xb2` ABI and the header semantics.
2. **Handoff arguments.** Main ends at `0x2329A: blx r4`, `r4 = 0xb3` (ROM
   `0xb2`), with `r0=0x8E200000`, `r2=0xFFF50000`, `r3=0`, stack `0x2E000,5`.
   If one of those arguments selects the ACPU entry or image descriptor, patch
   it to the stage. The exact ABI is **open** and needs the 970 BootROM image.
3. **Skip the handoff and keep the LPMCU alive.** Not sufficient by itself:
   the LPMCU still cannot read the DRAM window. It only helps if the ACPU stage
   can deposit chunks into an LPMCU-readable SRAM mailbox.
4. **JTAG/EL3 debug.** If the ACPU debug port is available, halt after the
   handoff and read DRAM directly. This avoids software entirely but needs
   hardware access and a non-fused debug configuration.

Exfiltration options for the EL3/AArch64 stage:

- **UART**: simplest software, but requires a physically accessible debug UART
  and the 970 UART register map. No VCOM involvement.
- **USB**: a new AArch64 USB stack, or reuse of the fastboot image's USB code;
  large and not recommended as a first step.
- **LPMCU SRAM mailbox**: the ACPU writes chunks into a region the LPMCU can
  read; the patched xloader sends them over the proven VCOM read primitive.
  This avoids an AArch64 USB driver but requires the ACPU→LPMCU SRAM path and
  an LPMCU that stays alive after the ACPU release. Both are unproven.
- **Patch decrypted fastboot in RAM**: the ACPU stage can read/write the
  plaintext and patch the stock fastboot's lock/dump behavior before jumping to
  it. This is powerful but needs the plaintext layout first (chicken-and-egg).

Required knowledge: the 970 `0xb2` handoff ABI, the ACPU boot/release registers,
the fastboot header entry semantics, the AArch64 stage's load address, and an
exfiltration channel. This is B2-sized work.

Risks: AArch64 stage development, handoff may not return, USB re-enumeration,
ACPU/LPMCU coherency, and a hang that requires power-cycle/testpoint recovery.
RAM-only; no flash writes.

**Verdict: correct architecture and now the primary route.** B1a' is not
viable; proceed to B2 rather than spending a VCOM session on it.

## 6. Can the existing head-resend/inquiry mechanism read memory?

**No, not as an arbitrary read.**

- The head-resend primitive is a **write**: it latches a destination and the
  data frame `memcpy`s up to `0x400` bytes there (`0x4C98..0x4CA8` in the 810
  BootROM). There is no response carrying the written bytes.
- The `0xCD` inquiry handler returns a **fixed status value**, not memory. In
  the 810 BootROM it dispatches at `0x4B1A` to `0x4B38`, reads a fixed word at
  `0x21E04` (`0x4D84`), and sends 4 bytes with `0x47A0`. It does not take a
  pointer or length from the host.
- The xloader's analogous `0xCD` inquiry returns one byte from its status
  object; the type-3 head frame is a project-added read path, not a BootROM
  feature.

Therefore a BootROM-context dumper needs a **new stage image**, but not
necessarily a new USB stack: the stage can reuse the BootROM's live USB context
and transmit routine. The sibling send path shows the shape:

```
0x4774  strb r1, [r0, #0x3D8]   ; 1-byte response
        str  r5, [r0, #0x10C]   ; length = 1
        str  r4, [r0, #0x114]   ; data pointer = ctx+0x3D8
        b    0x3DDC             ; USB state machine
```

`0x47A0` is the 4-byte variant. A stage that knows the context base can set
`ctx+0x10C`/`ctx+0x114` to an arbitrary pointer/length and call `0x3DDC`
directly. That is the cheapest exfiltration primitive for a BootROM dump, and
it is also the reason a BootROM dump is a practical first step toward the
missing 970 artifact.

## 7. Recommendation and ordering

1. **Do not pursue "bootrom/EL3 stage reads DRAM" as written.** It is not one
   context; the stage is LPMCU M3, DDR is down, and the LPMCU is the master that
   already fails to read the window. No amount of privilege in that stage
   changes the fabric read path.
2. **The SEB store-address question is settled offline against B1.**
   `notes/seb-analysis.md` §3.5/§5.4 shows the 12-byte entry is a source
   `{address, 0, length}` descriptor (`0x874`: `{0, 0, 0xDB230}`), the 4 KB
   staging buffer is zeroed on return, and the implemented interface is
   verification/hash only. Do not run the one-argument SRAM redirect as a B1
   experiment; the static evidence predicts a verification error.
3. **If the residual hardware-store hypothesis is pursued**, it is not a small
   SRAM test: the descriptor range is about `0xDB230` bytes, so the destination
   must be about 897 KB and readable by the LPMCU. The loader's spare SRAM is
   not that large; a DRAM destination returns to the original read problem.
   Treat this as a hardware-characterization question, not a B1 POC.
4. **Go to B2 now.** The ACPU EL3 stage is the only context that provably reads
   the plaintext. Start with the smallest experiment: let the normal path read
   and verify the stock image to `0x16800000`, then have the xloader write a
   small AArch64 stub over the image entry before `0x2329A`. The stub reads the
   rest of the image and sends it over USB. The open question is whether the
   ROM re-verifies the image after the patch; if it does, the stub is rejected
   and the next route is a dedicated AArch64 download-mode image.
5. **In parallel, obtain the 970 BootROM image** (public dump, self-dump via the
   pwn, or JTAG). It is the gating artifact for both the `0xb2` ABI and the
   970-specific SEB/USB addresses. A self-dump stage is a contained, RAM-only
   sub-project and reuses the live BootROM USB stack.

## 8. Test plan (offline first; hardware only with explicit approval)

### 8.1 Offline (no device)

1. Cross-check the sibling VRL result in `notes/seb-analysis.md` §3.5: the
   terminal block's entry is at `0x874`, `{0, 0, 0xDB230}`, count `1`; after
   `changeStoreAddr` it is `{0x16800000, 0, 0xDB230}`. Confirm the same layout
   on the runtime `vrl` partition bytes if they are available. Do not re-port
   the parser unless the runtime bytes disagree with the update header.
2. Build the LPMCU SRAM map from the xloader program headers, the BootROM stack
   top, the UCE/BSS layout, and any public 970 memory map. Record the largest
   CPU-readable SRAM range. It is not expected to hold `0xDB230` bytes.
3. B2 offline: map the `0xb2` call and the ACPU release; confirm whether the
   fastboot header `+0x20` entry is consumed by the handoff; identify the
   AArch64 stub entry and the USB/other exfiltration channel.
4. B2 static verification: build a patched xloader that writes the AArch64 stub
   over the decrypted image entry before `0x2329A`; assert the patch does not
   touch the VRL/verify path; record the SHA-256.
5. Confirm the chosen exfiltration channel is usable before committing to a
   hardware run (UART pinout/baud or USB stack reuse).

### 8.2 B1 hardware (not recommended)

Only if the residual hardware-store hypothesis becomes a priority:

1. The destination must be about `0xDB230` bytes and LPMCU-readable; the 4 KB
   staging buffer and the loader's spare SRAM are not sufficient. A DRAM
   destination is unreadable by the LPMCU, so this does not solve the export
   problem.
2. Do not run a small-SRAM redirect as a proxy: the static evidence predicts a
   source-range verification error, not a plaintext write.
3. If a large readable destination exists, the RAM-only test is the same
   `0x238B8` argument change with a cave; it is fail-closed on bad parameters.
   One experiment per VCOM entry; power-cycle; no flash.

### 8.3 B2 test plan (primary)

1. Build a minimal AArch64 stub that reads `0x16800000` and writes to the
   chosen exfiltration channel. Reuse the fastboot image's USB initialization
   and bulk-IN endpoint if possible; a UART stub is the simpler fallback.
2. Upload the stub to a second DRAM window through the host download path, and
   rewrite the image entry at `+0x20` to point to it after verification. The
   xloader only writes the entry word; it does not need to read DRAM. An
   alternative is to embed the stub in an xloader cave and write it over the
   entry, but that is a larger xloader change.
3. Patch the xloader to perform the entry rewrite immediately before `0x2329A`;
   do not disturb the VRL/verify path.
4. RAM-only run; expect a fastboot re-enumeration or a hang. Power-cycle
   recovery. If the ROM re-verifies the patched image, the stub is rejected;
   the fallback is a dedicated AArch64 download-mode image.

## 9. Risks and rollback

| Risk | Impact | Rollback |
|---|---|---|
| B1 hardware-store test needs a ~`0xDB230` destination | overrun/hang | power-cycle; re-enter VCOM; no flash changed |
| SEB reads the wrong source range | fail-closed verification error | power-cycle; revert patch |
| AArch64 stage faults before fastboot | no USB/hang | power-cycle; testpoint recovery |
| ROM re-verifies the patched image | B2 stub rejected | fallback to a download-mode AArch64 image |
| Handoff does not return to the LPMCU | no LPMCU-side exfiltration | use UART/JTAG or a different channel |
| Wrong VRL/segment assumption | no plaintext or corrupted buffer | revert to stock xloader; do not flash |

No step in this plan writes a partition or the bootloader. The stock xloader is
already restored per `STATUS.md`; keep a known-good loader and testpoint
recovery path for every session.

## 10. Evidence table (key rows)

| Claim | Evidence |
|---|---|
| Head-resend order: upload, then return-slot write, then tail | `VcomFlasher.cs:120-195` |
| Return address 0x4DBC8, value 0x2316D for 970 | `VcomFlasher.cs:141,164,189-191` |
| 0x07 is the address-error response | TASZK CVE-2021-22434; 810 `0x4D36`/`0x4C0C`; 820 `0x3EB6`; 710a `0x34C6` |
| Address committed before the check | 810 `0x4D20`; 820 `0x3EA0`; 710a `0x34BC` |
| Data write is `memcpy(addr + seq*0x400, frame+0x3DB, 0x400)` | 810 `0x4C98-0x4CA8`; 820 `0x3E18`; 710a `0x34CC` |
| 0x4DBC8 is MSP-0x34 | 810 SP `0x4DBFC`; 820 SP `0x673FC`; 710a SP `0x49BFC` |
| BootROM is LPMCU Cortex-M3 | TASZK whitepaper boot chain; sibling vector tables |
| Fastboot runs at ACPU EL3 | TASZK whitepaper; 970 fastboot AArch64 image |
| LPMCU cannot read the DRAM window | `notes/FINDINGS.md` hardware table |
| VRL store entry is a source `{address, 0, length}` descriptor | `notes/seb-analysis.md` §3.5; `0x3700E..0x37062`; real entry at `0x874`: `{0, 0, 0xDB230}` |
| SEB staging buffer is 4 KB input, zeroed on return | `0x31074` passes `0x60035000`/`0x1000`; `0x36E14` zeroes it |
| No read/decrypt/export command in this xloader | `notes/seb-analysis.md` §1/§7.1; no AES S-box; one SEB caller chain |
| B2 open question: ROM re-verification | `notes/seb-analysis.md` §7.2/§9.6 |
| Missing 970 BootROM image | no `kirin970` in `SoC-BootROMs` or local artifacts |

## 11. Open questions

1. Does the SEB/HISEE hardware perform a decrypt-and-store to the descriptor
   address on the `SEB_SECCFG_SECURE` status-5/7 path, despite the CPU-visible
   interface being verification-only? (Residual B1 hardware hypothesis.)
2. What is the Kirin 970 LPMCU SRAM map and the largest CPU-readable range?
   (Needed for any B1 hardware-store test and for a B2 SRAM mailbox.)
3. Does the runtime `vrl` partition table match the update header's one entry
   `{0, 0, 0xDB230}` at `0x874`, and can SEB operate per entry?
4. Is the 970 EFUSE firmware key directly readable (TASZK says keys up to 970;
   confirm for this device/firmware), or is only the crypto-engine oracle
   available?
5. Does the ROM re-verify the fastboot image after a patch-after-verify B2
   stub overwrites the entry? (The main B2 feasibility question.)
6. What are the 970 BootROM's `0xb2` handoff ABI, USB TX entry, and SEB entry
   addresses? (Needs the 970 BootROM image.)
7. Can the ACPU write to an LPMCU-readable SRAM mailbox after the handoff?
   (Would make B2's exfiltration much cheaper.)

---

**Bottom line:** B1 is not a route to "EL3 reads DRAM" — that context does not
exist in the head-resend sequence. The only LPMCU-side candidate, the SEB
store-address redirect, is a source-range descriptor in this artifact, and the
implemented SEB interface is verification/hash only. B1 is closed unless the
SEB hardware has an undocumented decrypt/store path, which is not a
software-only project. Proceed to B2: the smallest experiment is
patch-after-verify with an AArch64 stub at the image entry; the decisive
unknown is whether the ROM re-verifies the patched image.
