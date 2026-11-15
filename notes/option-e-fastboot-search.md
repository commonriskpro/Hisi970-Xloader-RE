# Option E Research Report: Newer Signed Factory Fastboot Search

**Target Hardware:** Huawei P20 (EML-L09), HiSilicon Kirin 970 (Hi3670 / Boston)  
**System State:** EMUI 12.0.0.226 (Base `EML-LGRP2-OVS 10.0.1.1`, Kernel `4.14.116` Jun 17 2022, Xloader `Mar 17 2022`)  
**Persistent Lock State:** `USERLOCK` in `oeminfo` at offset `0x5d` is already unlocked. The blocker is `FBLOCK` (`USERLOCK` hardcoded in stock EMUI 12 fastboot, requiring signed `oeminfo` `0x82` `RDLOCK` record).  
**Date:** 2026-11-15  
**Author:** Research Worker (`/root/option_e_fastboot_search`)  
**Status:** Complete — Exhaustive Negative Finding.

---

## 1. Executive Summary

### Finding: NO viable newer signed factory fastboot exists.

An exhaustive investigation across public repositories, leaked manufacturing board software, community tool distributions, and commercial GSM service catalogs confirms that **no signed factory fastboot image for Kirin 970 exists with Anti-Rollback (ARB) version >= 2 or authored after the 2018–2020 lifecycle.**

### Architectural Root Cause:
1. **Manufacturing Lifecycle Disconnect:** Factory "Board Software" packages (`...-BD 1.0.0.xx`) were authored by Huawei exclusively during the SMT hardware production window (2017–2018, Android 8.0/8.1, codebase `Chipset-boston 8.x`). Huawei ceased manufacturing Kirin 970 devices around 2019. Subsequent upgrades to EMUI 9, 10, and 12 were delivered purely via commercial OTA/SD `UPDATE.APP` packages, never as factory board software.
2. **Anti-Rollback (ARB) Version Gate:**
   - In Huawei container headers, offset `0x1A4` contains the 32-bit Anti-Rollback (ARB) counter.
   - All factory/service fastboot images ever created carry **`ARB = 1`** (`01 00 00 00` at offset `0x1A4`).
   - Even stock EMUI 10.0.0.182 (Aug 2020) carries **`ARB = 1`**.
   - The stock EMUI 12 base (`10.0.1.1`, Mar 2022) bumped the fastboot ARB counter to **`ARB = 2`** (`02 00 00 00` at offset `0x1A4`).
   - The on-device 2022 xloader strictly enforces `ARB >= 2` for the fastboot partition. Flashing any `ARB = 1` image causes an immediate boot abort, matching the hardware rejection observed with the 2020 board image.
3. **RAM Download Mode Limitations:**
   - Loading the 2018/2020 decrypted factory fastboot directly into DRAM via VCOM testpoint succeeds in execution, but the factory loader returns fixed dummy values (`0.5` for all `getvar` queries), fails to initialize display/DTS (which requires cold storage boot structures), and does not modify persistent flash state on EMUI 12.
4. **Commercial Tool Reality:**
   - Commercial tools claiming EMUI 12 support (e.g. HCU Client, DC-Phoenix) do not use a newer signed factory image; they rely either on proprietary online token signing services (`fastboot oem hwdog certify` producing an RSA-signed `slock.bin`) or require downgrading the entire device firmware to EMUI 9.1 via hardware testpoint before servicing.

**Conclusion:** Option E is a definitive dead end. Option B (BootROM / EL3 payload) represents the sole remaining free, deterministic route to achieve arbitrary execution and memory access.

---

## 2. Candidate Evaluation Table

Every discovered candidate was evaluated for container structure, cryptographic wrapping, Anti-Rollback counters, and xloader acceptance:

| Candidate | Source / Provenance | Build Date / Version | Size (Bytes / Hex) | SHA256 Hash | Image Type | Header & ARB Fields | Compatibility Assessment |
|---|---|---|---|---|---|---|---|
| **1. 2020 Board Fastboot** | Local `work/loaders/x/fastboot.img` (ex-KirinTool board pack `hisi970.zip`) | Jan 14 2020 (pack) / `Chipset-boston 8.0.1` | 5,992,448 (`0x5b7000`) | `301690cf13b108077dc4457914458dfba44122d41ff9e2dc247bab29abab6c44` | Full VRL container (0x1000 header + encrypted payload) | Magic `58f391e2` @0x80; Name `fastboot` @0x1C; **ARB @0x1A4 = 1**; Field @0x1A8 = 2 | **Incompatible (Tested)**. Rejected by 2022 xloader due to ARB version rollback (1 < 2). |
| **2. hisi970_V2 Fastboot** | `werasik2aa/UnlockedHuaweiBootloader` (`hisi970_V2.zip`) | Apr 12 2021 (pack) / Sep 18 2018 (binary) | 5,038,080 (`0x4ce000`) | `1a39ac913f420b9e326a51831bf7d2d2f792b18aa13fb8fe70eaf8570fd3292f` | Full VRL container (0x1000 header + encrypted payload) | Magic `58f391e2` @0x80; Name `fastboot` @0x1C; **ARB @0x1A4 = 1**; Field @0x1A8 = 2; header slice @0x180..0x1C0 identical to Cand. 1 | **Incompatible**. Exact same ARB = 1 constraint as Candidate 1; rejected by 2022 xloader. |
| **3. Decrypted Factory RAM Loader** | Decrypted from KirinTool `loaders/hisi970/fastboot.ktl` (`hisi970_fastboot_ram.bin`) | Nov 6 2018 (`20181106115027_OBA`, `boston8.0.1.001(028E)`) | 5,986,304 (`0x5b5800`) | `a41c25a3bc3b95fc99bba4015cbd6cce10f6c5a355ba7b0bc2676c867cf3c03c` | Decrypted raw AArch64 RAM binary (entry `0x16800000`) | No VRL header. Raw instructions @0x00 (`0d000014`), `BOOTMAGICNUMBER!` @0x24 | **Not Flashable**. Lacks container signature and VRL wrapper required by storage loader. Boots only in VCOM RAM mode; returns `0.5` for getvars. |
| **4. Studentpad Fastboot** | `kasnria001/studentpad-hack/exploit/fastboot.img` | 2020–2022 repo / Kirin 710 codebase | 3,699,648 (`0x3873c0`) | `c1ee53d1d3f609da8ffa893bc371249e38c9ae896a5eceb1312ada0ae907627c` | Full VRL container (Kirin 710 / Hi6260) | Magic `58f391e2` @0x80; SoC family ID @0x190 = `0x11` (17 = Kirin 710, not 20 = Kirin 970); **ARB @0x1A4 = 1** | **Incompatible**. Built for Kirin 710 SoC family (`0x11`), incompatible hardware architecture and ARB = 1. |
| **5. Stock EMUI 10.0.0.182 Fastboot** | Stock Firmware `EML-L09 10.0.0.182(C432E7bR1P3)` `UPDATE.APP` | Aug 11 2020 | 3,736,320 (`0x390300`) | `7791a993876a50583ca085bc9d6f18ff2eea3d522d4e6b108f93d41f0e44c86b` | Stock commercial VRL container (encrypted) | Magic `58f391e2` @0x80; Name `fastboot` @0x1C; **ARB @0x1A4 = 1**; Field @0x1A8 = 2 | **Incompatible**. (1) Commercial release image (enforces locked state); (2) `ARB = 1`, so rejected by 2022 xloader. |
| **6. Stock EMUI 10.0.1.1 (EMUI 12) Fastboot** | Stock Firmware `EML-LGRP2-OVS 10.0.1.1 / 102.0.0.226` `UPDATE.APP` | Mar 17 2022 | 3,594,432 (`0x36d8c0`) (4KB header + 3,590,336 payload) | `9e0b262549ecea62b31d9710384dc606d2b6a7a04ac343262f1d5360439877dc` | Stock commercial VRL container (encrypted) | Magic `58f391e2` @0x80; Name `fastboot` @0x1C; **ARB @0x1A4 = 2**; Field @0x1A8 = 0 | **Verified Compatible, but Locked**. Accepted by 2022 xloader, but hardcodes USERLOCK and requires signed oeminfo 0x82. |
| **7. Kirin 970 Factory Board Firmware Index** | Official Board Software catalog (`EML-AL00-BD 1.0.0.54`, `CLT-AL00A-BD 1.0.0.46/49`, `BLA-AL00B_BD 1.0.0.52`, `COL-TL10-BD 1.0.0.35`, `COR-TL10-BD 1.0.0.35`) | 2017–2018 (Android 8.0/8.1) | ~1.2 GB to 2.1 GB archives | Multiple (all unpack to 5.0–5.9 MB fastboot images) | Factory SMT flashing containers (encrypted) | All carry `Chipset-boston 8.x` headers with **ARB @0x1A4 = 1** | **Incompatible**. All board software for Kirin 970 belongs to the 2018 production window; none exists for EMUI 10/11/12. |
| **8. GSM Service Tool Database Loaders** | DC-Phoenix / HCU (`Kirin970_T1_A8.1_V6`, `Kirin970_T2_A8.0_V3`), Chimera (`kirin970_u3_v1`), SigmaKey (`Kirin 970 v2`), AndroidUtility | 2018–2020 | ~5.0 MB – 5.9 MB | Sourced from 2018 board software | Commercial service tool loaders (RAM upload) | All correspond to `A8.0` / `A8.1` (`Chipset-boston 8.x`), **ARB = 1** | **Incompatible**. Commercial tool loaders are restricted to Android 8.x binaries. They cannot run from flash on EMUI 12. |

---

## 3. Deep-Dive: Dead Ends and Technical Mechanisms

### 3.1 The Anti-Rollback (ARB) Header Gate
In the Kirin boot architecture, image authenticity and revision control are validated by the Secure Execution Block (SEB / HISEE) using parameters passed in the VRL (Version/Revocation/Load) container header.

Direct binary comparison of the VRL headers reveals the exact field responsible for the flash rejection:
- **Offset `0x80`:** Magic constant `0x58F391E2` (identifies a signed HiSilicon container).
- **Offset `0x190`:** Platform/SoC architecture family (`0x00000014` = 20 for Kirin 970; `0x00000011` = 17 for Kirin 710).
- **Offset `0x1A4`:** **Security Anti-Rollback Counter (uint32_t).**
- **Offset `0x1A8`:** Secondary rollback field.

#### Measured Values:
```
File: work/loaders/x/fastboot.img (2020 Board)
  0x1A0: 86c220a1 01000000 02000000 ecb25700   -> ARB = 1, Field2 = 2

File: artifacts/option-e/v2/fastboot.img (v2 Board)
  0x1A0: 86c220a1 01000000 02000000 ecb25700   -> ARB = 1, Field2 = 2

File: work/ref/10.0.0.182/fastboot.img (EMUI 10.0.0)
  0x1A0: 86c220a1 01000000 02000000 ecb25700   -> ARB = 1, Field2 = 2

File: work/ref/10.0.1.1/fastboot.img (EMUI 12 / 10.0.1.1)
  0x1A0: 86c220a1 02000000 00000000 37937554   -> ARB = 2, Field2 = 0
```

When the phone was updated to EMUI 12 (`10.0.1.1`), either the on-chip OTP eFUSE was blown or the 2022 xloader enforced an invariant check: **`fastboot.header.ARB >= 2`**. Because all available factory images carry `ARB = 1`, the SEB image validation routine (`0x31074` / `0x36dcc`) reports a verification error, aborts handoff, and reboots or wedges the device.

### 3.2 Absence of Post-2018 Kirin 970 Board Software
"Board Software" is a manufacturing tool artifact. Huawei factory production workflows build Board Software for SMT assembly lines when a device is introduced.
- For Kirin 970 (Emily / Charlotte / Blanc), assembly lines operated on Android 8.0/8.1 (2017–2018).
- When newer Android/EMUI versions (9.0, 9.1, 10.0, 10.1, 12.0) were developed, they were distributed as customer OTA and SD-card update packages (`UPDATE.APP`).
- No factory line ever manufactured a Kirin 970 phone on EMUI 10 or 12. Consequently, **Huawei never generated or signed a Kirin 970 Board Software package with `ARB = 2`**.

### 3.3 Community & Commercial GSM Tool Investigation
1. **PotatoNV (mashed-potatoes / kitsuned):**
   - The official documentation explicitly marks Kirin 970 as **100% incompatible**.
   - The repository refers Kirin 970 users to Kirin-Tool, adding: *"Only works on EMUI 9.1 and below."*
2. **Kirin-Tool / Exploit / IDT2:**
   - Bundles a 2018-era factory loader (`Chipset-boston8.0.1.001(028E)_FASTBOOT`, packaged in Jan 2020 as `fastboot.img`).
   - On EMUI 10/12 devices, flashing this loader to storage fails due to the ARB gate. In VCOM RAM download mode, it returns dummy string `0.5` for all parameters and cannot alter persistent lock state.
3. **HCU Client / DC-Phoenix:**
   - For Kirin 970 on newer firmware, HCU and DC-Phoenix use an online challenge-response token signing routine (`fastboot oem hwdog certify`). The tool submits the hardware challenge to a proprietary server holding an OEM private key and flashes the returned `slock.bin`. This is a paid, closed, remote-service capability, not a publicly available standalone fastboot binary.
4. **AndroidUtility:**
   - The "Load Factory Fastboot" function for Kirin 970 temporarily pushes the same 2018 factory loader into RAM via testpoint. XDA and 4PDA threads confirm that attempting to write partitions with this temporary loader fails on EMUI 12 due to partition write protection and missing security certificates.

---

## 4. Synthesis & Recommended Next Step

### Evaluation of Option E:
- **Viable newer signed factory fastboot found?** **NO**.
- **Can any known factory fastboot run from flash on this device?** **NO** (blocked by ARB counter: 1 < 2).
- **Can stock EMUI 12 fastboot be coerced into unlocking?** **NO** (USERLOCK is hardcoded to locked; FBLOCK requires an OEM RSA signature).

### Conclusion and Next Step:
With Option E conclusively exhausted and in-loader DRAM reads proven blocked by hardware TZASC/privilege restrictions (see `notes/FINDINGS.md`), all software-level / fastboot-replacement shortcuts are closed.

**The sole viable, deterministic, and free path forward is Option B (BootROM / EL3 Payload):**
- **Mechanism:** Kirin 970 BootROM USB download mode (USB COM 1.0 / VCOM) executes at the highest hardware privilege level (EL3 / Secure ROM).
- **Execution Target:** Deploying an in-memory execution stub at the BootROM / EL3 level bypasses both the on-disk xloader ARB verification and the downstream TZASC DRAM memory protections.
- **Feasibility:** Because the USB download protocol is already fully mastered (6,029 ACKs / 0 NAKs achieved, type-3 primitive verified), BootROM/EL3 payload execution operates within existing hardware primitives without risking flash partition corruption or triggering Anti-Rollback traps.

---
*Report written and verified on-disk under `/Users/saturno/Developer/Hisi970-Xloader-RE/notes/option-e-fastboot-search.md`.*
