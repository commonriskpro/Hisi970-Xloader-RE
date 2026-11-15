# B2a live validation — factory fastboot decryption & handler repoint

Date: 2026-11-15. Device: Huawei P20 (EML-L09), Kirin 970.
Factory fastboot loaded into DRAM via standard VCOM/RAM pipeline (`null` + stock xloader + UCE + patched factory fastboot).
Pure RAM execution. No flash write, no partition modification.

---

## 1. Overview & Test Objective

Option B2a tests whether the factory fastboot running at EL3 can be repurposed to decrypt the encrypted stock fastboot container using the internal `hisi_secboot_decrypt_encrypted_xloader` routine (0x16989D30).

Hardware probe image `build/patch_fastboot_b2a_probe.bin` combined four handler-entry patches into a single boot to answer all open architectural questions:

1. **Response path soundness**: `oem memcpy_count` -> respond-only stub (calling response dispatcher with OKAY string).
2. **Host-visible command dispatch**: `oem chipid` -> write test to DRAM candidate.
3. **BSS scratch writeability & session stability**: `oem ufs_test` -> store magic `0xB2A0C0DE` into BSS cell `0x16B8F1F8`.
4. **Hardware decryption**: `oem onchiprom_download` -> call `hisi_secboot_decrypt_encrypted_xloader` with stock container at `0x16000000`, group `"fastboot"`.

The test was driven from the host runner `host/b2a_probe_test.py`.

---

## 2. Hardware Probe Results

| Command | Fastboot Result | Timing | Hardware Outcome |
|---|---|---|---|
| `oem memcpy_count 0x16000000` | `OKAY` | <0.01 s | Respond-only stub executed cleanly. Confirms response dispatcher protocol is sound and isolates earlier session crashes. |
| `oem chipid` | `FAILED (remote: invalid command)` | 0.01 s | Handler never ran. Name rejected by OEM command dispatcher; dispatch table name list != host-visible allowed command list. |
| `oem ufs_test` | `OKAY` | 0.01 s | Magic `0xB2A0C0DE` successfully read back from `0x16B8F1F8` via `oem memupload`. Proves handler entry-point patching works, scratch memory is writable, and session stays alive. |
| `oem onchiprom_download 0x16000000` | `OKAY` | 0.074 s | Decryption stub executed to completion. Stock fastboot plaintext decrypted and published. |

---

## 3. Patch Mechanism & Dispatcher Invariants

Hardware execution established four decisive invariants regarding factory fastboot patching and IPC:

1. **File Table vs. Entry-Point Patching**:
   - The OEM dispatch table in decrypted factory fastboot starts at `0x16B13AE0` with entries formatted as `{char *name @ +0x00, void (*fn) @ +0x10}`. The `memcpy_count` slot sits at name `0x16B13AE0` / fn `0x16B13AF0 -> 0x16814BC8`.
   - Modifying this table slot directly in the file binary did NOT change dispatch behaviour at runtime. The active dispatch table is either relocated or shadowed in memory.
   - In contrast, patching handler *entry points* (overwriting the 4-byte function prologue with `b <stub_va>`) works reliably on hardware.

2. **Response Dispatcher Protocol (`0x1680AC6C`)**:
   - Signature: `0x1680AC6C(const char *msg, uint32_t type)`.
   - `type = 0`: sends `OKAY`.
   - `type = 1`: sends `FAIL`.
   - Any other value (e.g., `type = 2` used in an earlier experimental build): returns immediately without transmitting any packet, causing the host to see a stock response followed by complete fastboot session desynchronisation.

3. **Buffer Initialisation Invariant (`0x1680AA54`)**:
   - Function `0x1680AA54` is invoked only when `msg != NULL`. It initialises the internal response buffer dereferenced by the OKAY path at `0x1680A938`.
   - Passing `msg = NULL` causes an immediate null dereference crash.
   - All stubs must pass the existing stock `"OKAY"` string literal at `0x169B7E40`.

4. **Host Command Whitelist**:
   - Commands appearing in the internal dispatch table (e.g., `chipid`) are filtered before handler dispatch if not exposed in the host-visible command set. Entry-point hooks must target host-accepted OEM verbs (`memcpy_count`, `ufs_test`, `onchiprom_download`).

---

## 4. Memory Protection: Code Page RO vs. BSS Scratch RW

Hardware experiments mapped page permissions at EL3:

- **Code Page Read-Only Invariant**:
  - Attempting to store to `0x16801400` (inside code page `0x16801000`) triggers an immediate SoC reset/reboot.
  - Confirmed across two independent hardware boots. Fastboot text segments are mapped strictly read-only by the EL3 MMU.
- **BSS Scratch Read-Write**:
  - `0x16B8F1F8` resides in BSS/data space. Writing magic `0xB2A0C0DE` via `oem ufs_test` succeeded and was read back byte-identical via `oem memupload`, confirming safe scratch storage.

---

## 5. Live Decryption Evidence & Plaintext Analysis

### 5.1 Decryption Routine Invocation

The decryption stub at `0x168012C0` invoked:
```c
void *hisi_secboot_decrypt_encrypted_xloader(
    const void *container,  /* x0 = 0x16000000 */
    const char *group_name, /* x1 = 0x169B0478 ("fastboot") */
    uint32_t   *out_len     /* x2 = &out_len */
);
```

- Execution elapsed time: **0.074 seconds**.
- Output length (`out_len`): `0x36C8C0` (3,590,336 bytes).
- Returned pointer: `0x18ECB6A0`.
- Container header: Located at `0x18ECB6A0` (group name `"fastboot"` at `+0x1C`).
- Plaintext start: Returned pointer `+ 0x1000 = 0x18ECC6A0`.
  - Starts with AArch64 vector table.
  - Load address `0x16800000` at offset `+0x20`.
  - ASCII magic `BOOTMAGICNUMBER!` at offset `+0x24`.

### 5.2 Artifact Verification

The 3,590,336 bytes of decrypted memory were dumped and saved as `artifacts/fastboot.stock.decrypted.img`:

- **SHA-256**: `4BB40A9252419C064A210B1581A420CDE6AD615AA4D299AE11AD881591671FD4`
- **Plaintext vs. Ciphertext**:
  - `artifacts/fastboot.stock.payload.img` (same 3,590,336-byte size, encrypted container payload) shares only 14,058 matching bytes out of 3,590,336 (~0.39%, Poisson noise). The artifact is indisputably decrypted plaintext.
- **Stock Decrypted vs. Factory Fastboot**:
  - Differs from `artifacts/hisi970_fastboot_ram.bin` starting at offset `0x1D4` (branch targets and implementation specifics).
  - The initial `0x1D4` bytes are byte-identical (common Kirin 970 SoC boot header and vector prologue).
- **Statistical & Structural Sanity**:
  - Zero-byte ratio: 30.5% (typical code + BSS padding).
  - Entropy: 256 / 256 distinct byte values present.
  - Disassembly: Disassembles cleanly into valid AArch64 instruction sequences.
  - String inspection confirms critical stock fastboot symbols present:
    `memupload`, `FBLOCK`, `fblock`, `userlock`, `RDLOCK`, `OKAY`, `FAILED`.

---

## 6. Conclusions & Next Steps

### Hardware Conclusions
1. **Option B2a is fully proven on hardware**: Repointing handler entry points in factory fastboot allows arbitrary execution of internal routines at EL3.
2. **Stock fastboot plaintext is recovered**: The decrypted stock binary is extracted and preserved.

### Residual Unknown (The Flashing / Signature Gate)
- The outstanding architectural unknown is **whether the stock fastboot partition is signature-verified on load by the boot chain** (xloader / bootrom / SEB).
- If the xloader verifies the RSA/ECDSA signature of the fastboot partition before branching to it, flashing an unpacked/patched stock fastboot image directly to UFS will fail secure boot verification unless the signature check itself is bypassed.
- If the fastboot partition is not signature-verified, or if the verification authority can be satisfied, a patched stock image disabling `userlock` / `fblock` provides permanent device unlock.
