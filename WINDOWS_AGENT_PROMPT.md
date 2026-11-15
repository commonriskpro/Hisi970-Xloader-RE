# Windows agent work order — SEB/HISEE offline analysis

**Status: milestone 2 is complete. Do not touch the phone, do not enter VCOM,
and do not repeat the DRAM reads.**

The type-3 read primitive works, but the 32-bit loader cannot read the DRAM
window that holds the fastboot image. `0x23154`/`0x60053000` read fine;
`0x16800000`/`0x16dfe000` wedge on every access size. Writes there succeed and
the image boots after the ROM handoff. This is documented in `notes/FINDINGS.md`
and `STATUS.md`.

## Read first

- `STATUS.md`
- `notes/FINDINGS.md`
- `notes/poc-status.md` (chronological evidence)
- `notes/patch-report.md` (verified read primitive/CRC)
- `notes/xloader-map.md` (static map)

## Objective

Determine, **offline**, whether the SEB/HISEE path can return the decrypted
fastboot image bytes (a read/decrypt-only command), or whether the data is only
reachable from AArch64 code after the ROM handoff. No device work is required
for this milestone.

## Targets

- `0x36dcc` — SEB/HISEE submit path (`0xbdf0f000`; SEB error family).
- `0x31074` — VRL verify wrapper.
- `0x36ea0` — `changeStoreAddr` (rewrites VRL store addresses to `0x16800000`).
- SEB command IDs/structures and any response/data channel.
- ROM API `0xb2` handoff semantics (`(0x8e200000, 0, 0xfff50000, 0, 0x2e000, 5)`).
- Whether the `0x36dcc` command set includes a read/decrypt/export operation.

## Deliverables

1. `notes/seb-analysis.md` — call graph, command IDs, structures, evidence
   offsets, and a clear yes/no on a read/decrypt-only path.
2. If a command exists: a minimal host-side request plan and the exact register/
   buffer layout, with a read-only POC proposal (no flash).
3. If not: document why, and outline the AArch64-post-handoff alternative with
   its cost and risks.
4. Update `STATUS.md` with the conclusion.

## Constraints

- No phone, no VCOM, no upload, no flash.
- Every claim needs an offset/instruction/evidence reference.
- Do not publish vendor binaries or keys.

