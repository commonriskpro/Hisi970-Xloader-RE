# DeepSeek Harness Work Order: SEB/HISEE Offline Static Analysis

## Context & Objective
Offline static analysis of the decrypted Kirin 970 xloader (`artifacts/hisi970_xloader.bin`).
The type-3 RAM read primitive functions on hardware, but the DRAM window containing the fastboot image (`0x16800000` / `0x16dfe000`) is not accessible from the 32-bit loader due to TZASC / privilege gating. Writes succeed and the image boots after the ROM handoff.

Determine, **offline**, whether the SEB/HISEE subsystem exposes a read/decrypt-only command that can return or export decrypted fastboot bytes to SRAM/USB, or whether the plaintext data is strictly reachable only from AArch64 code execution post-ROM-handoff.

## Mandatory Reading
Read and synthesize the following project documents first:
1. `STATUS.md`
2. `notes/FINDINGS.md`
3. `notes/xloader-map.md`
4. `notes/plan.md`
5. `WINDOWS_AGENT_PROMPT.md`

## Analysis Scope & Targets
Analyze `artifacts/hisi970_xloader.bin` (Thumb-2 / ARMv7, load base VA = file_offset + 0x22000):
- **`0x36DCC`**: SEB/HISEE submit path (`0xbdf0f000`; SEB status / error families).
- **`0x31074`**: VRL verification wrapper.
- **`0x36EA0`**: `changeStoreAddr` (rewrites VRL store destination addresses to `0x16800000`).
- **SEB command IDs & structures**: Identify command codes, message descriptors, response channels, and mailbox registers.
- **ROM API `0xB2`**: Handoff semantics (`(0x8e200000, 0, 0xfff50000, 0, 0x2e000, 5)`), entry conditions, register states, and whether decryption occurs during the transition.
- **Tools available**: Python 3 with `capstone` and `/opt/homebrew/bin/r2` (radare2) are available in the local environment for automated disassembly and AST inspection.

## Parallelization Strategy
Use harness subagents / workflow tools to parallelize work into 3 tracks:
1. **Track A (Call Graph & Command Codes)**: Disassemble `0x36DCC`, trace all callers and cross-references, catalog all SEB command IDs dispatched or accepted.
2. **Track B (Data Structures & Buffers)**: Map memory buffers, mailbox descriptors, parameters passed to `0x36DCC`, and `changeStoreAddr` (`0x36EA0`) buffer transformations.
3. **Track C (ROM Handoff Semantics)**: Trace the call site at `0x2329a` (`blx r4` calling ROM API `0xB2`), parameters, entry point transitions, and CPU mode switches to AArch64.

## Required Deliverable: `notes/seb-analysis.md`
Create `notes/seb-analysis.md` containing:
1. **Executive Summary & Verdict**: Explicit conclusion: does a read/decrypt-only SEB command path exist? (**YES** / **NO** / **UNCERTAIN**).
2. **Call Graph & Subroutine Analysis**: Full disassembly and disassembly evidence (exact VA offsets, hex instructions, register conventions) for `0x36DCC`, `0x31074`, `0x36EA0`.
3. **SEB Command Catalog & Protocol**: Table of command IDs, descriptors, and expected buffer layouts.
4. **Data Flow & Buffer Mechanics**: Destination buffer handling (`0x16800000` vs `0x16dfe000` vs `0x60035000`).
5. **ROM API `0xB2` Handoff Specifications**: Parameters, target architecture transition, execution flow.
6. **Architectural Recommendation**:
   - If YES: Exact parameter block / request structure to trigger the read/decrypt operation.
   - If NO: Technical explanation of why SEB is verify/boot-only, and architectural requirements for post-handoff AArch64 retrieval.

## Strict Invariants & Constraints
- Fully offline: **Do NOT touch any physical device, phone, VCOM port, or flash storage**.
- Read-only analysis of the firmware artifact.
- Do NOT modify any files other than creating `notes/seb-analysis.md`.
- All technical claims must be grounded in exact instruction disassembly, addresses, or file offsets.
- Adhere strictly to clean systems-engineering terminology.

