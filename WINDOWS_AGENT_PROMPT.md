# Windows agent work order — Kirin 970 read-only POC

You are the Windows-side execution agent. The phone is connected to **this** PC.
The Mac-side analysis is finished. Clone the private project repo:

```
git clone https://github.com/commonriskpro/Hisi970-Xloader-RE
cd Hisi970-Xloader-RE
```

If it is already cloned, update it (`git pull`) and use that folder.

## Read first

- `PROMPT.md`
- `notes/xloader-map.md`
- `notes/plan.md` (especially §2.0 and §10)
- `notes/subagent-crosscheck.md`
- `tool-reference/VcomFlasher.cs`, `tool-reference/FirmwareUnlocker.cs`,
  `tool-reference/Crc16.cs` (exact 970 head-resend/FEC reference)

## Objective

Execute **milestone 2 only**: build and validate the patched xloader read
primitive, then perform a **RAM-only** read of `0x23154` and, if that works,
`0x16800000` before the final ROM handoff. No partition writes.

## Non-negotiable safety rules

- Never run `fastboot flash`, `erase`, `oeminfo*`, `nve*`, or any partition
  write. No factory-fastboot flash. This is a read-only POC.
- The last factory-fastboot flash was rejected by the 2022 xloader and the
  device was recovered with `artifacts/fastboot.stock.payload.img`. A testpoint
  recovery baseline is required before loading anything into RAM.
- Ask the human before entering VCOM and before loading the patched xloader.
- If the phone does not enumerate, the read is unstable, or the result is not
  the expected plaintext, stop and report. Do not try random images.

## Environment

- Windows with the phone in VCOM (`HUAWEI USB COM 1.0`, VID_12D1 PID_3609).
- Prefer Python (`pip install pyserial capstone`) for the host runner and patch
  verifier. If Python is unavailable, use a .NET 8 console app.
- Use `tool-reference/VcomFlasher.cs` and `tool-reference/FirmwareUnlocker.cs`
  for the exact 970 head-resend sequence. The installed Kirin-Tool is optional.
- Keep every generated file under `build/`, `host/`, `notes/`, or `artifacts/`.
- The large raw dumps (`oeminfo.dump.img`, `nvme.dump.img`, `fastboot.dump.img`)
  are intentionally not in the repo. They are not needed for milestone 2;
  the xloader, stock payload, and notes are.

## Steps

1. Inventory: COM port, Python/.NET, project path, and
   `sha256(artifacts/hisi970_xloader.bin)` (must be
   `2BB2329D3EBFB362FB4F40970D5DF1BCF09642464BE205AE7810CC093ACB1691`).
2. Build `build/patch_xloader.py` for the preferred read primitive:
   - copy the original to `build/hisi970_xloader_read.bin`;
   - apply file patches `0xDA50: 01 2B -> 02 2B` and
     `0xDA58: 94 F8 DD 33 -> 0F F0 C6 BA`;
   - write the type-3 read stub into the zero cave at file `0x1CFE8`
     (VA `0x3EFE8`) using plan §2.0;
   - verify with capstone/radare2 that the cave decodes, the branches reach
     `0x2FA5C`/`0x2FC58`, and nothing overlaps past `0x3F0DF`;
   - write the patched SHA256 and a diff report to `notes/patch-report.md`.
3. Build `host/vcom_read.py` (or .NET):
   - open the COM port, send the start frame, upload `null` + the patched
     xloader with the 970 head-resend sequence (`null` at `0x22000`, xloader at
     `0x22000` with pwn, return address `0x4DBC8`);
   - send the 14-byte type-3 read head frame (size/address big-endian,
     CRC-16/CCITT) per plan §2.0;
   - read the bulk-IN response and save it to
     `notes/poc/read-<address>-<length>.bin`;
   - CLI: `--port`, `--xloader`, `--address`, `--length`, `--output`; default
     benign read `0x23154`, length 16;
   - validate the frame CRC offline before sending.
4. Ask the human to put the phone in VCOM. Load the patched xloader RAM-only.
   Send the benign read.
   - Success: the 16 bytes must equal the xloader file at VA `0x23154..0x23164`
     (file `0x1154..`). Save the evidence.
   - Failure: capture error/timeout, stop, report.
5. Only after the benign read works, apply the normal-load/stop-before-handoff
   patch from plan §3.1/§3.2. Ask for approval. Read `0x16800000`, length
   `0x1000`; save.
6. Inspect the first `0x1000`: AArch64 vectors at 0 and `BOOTMAGICNUMBER!` at
   `+0x24` mean plaintext. If present, dump the full `0x5FE000` in `0x400`
   chunks, reassemble, SHA256. If high-entropy/no markers, stop and report; do
   not flash anything.
7. Write `notes/windows-poc.md` with commands, outputs, hashes, what worked and
   what failed, and the exact next step. Leave all artifacts in the project.

## Report back

Phone state, COM port, patched xloader SHA256, benign-read result, dump SHA256,
and blockers. Do not publish vendor binaries or keys.

