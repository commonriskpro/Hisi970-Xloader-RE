# RDLOCK / oeminfo item 0x82 — donor research

Scope: external evidence only (web) plus read-only inspection of artifacts already in this repo.
No device was touched, no VCOM/flash/fastboot command was run. Date: 2026-11-15.
Target: Huawei P20 (EML-L09), Kirin 970, EMUI 12.0.0.226, oeminfo item 0x82 ("RDLOCK type info") absent.

## Verdicts

### Q1 — Is the 0x82 blob device-bound or model-wide/portable?

**Verdict: UNKNOWN.** No public field report, teardown or RE writeup states either way.
Confidence: **low** (for both hypotheses). The structural evidence is real but only covers the *key*, not the *message*.

- The verifier is described as using a key baked into fastboot, not a per-device key: "Starting from Kirin 970, the
  fblock unlock status is stored in the oeminfo partition, signed with RSA, and the RSA public key is fixed in Fastboot"
  (postmarketOS/Nura wiki, HiSilicon Kirin section). A fixed public key is *necessary* for a portable blob, but says
  nothing about whether device identity is inside the signed payload.
- The same page notes the practical consequence of that design: "except for one NCK tool or HCU client that has a Kirin
  970 fblock certificate, which can permanently unlock the fblock" — i.e. the capability that is scarce is a *signing*
  capability, not a per-device secret.
- zenfyrdev/wall-of-shame describes the same thing operationally: RDLOCK "allows you to flash to any partition ... while
  the signature exists on the OEMINFO partition", and "HCU-client is the ONLY program capable of achieving FBunlock as
  they have the RSA keys". Wording is about the blob being present/valid, not about the unit.
- Counterweight (why I do not call it portable): on Kirin 970, oeminfo is documented to carry device identity — "oeminfo:
  contains device model and region, on newer phones (k970) also stuff from nvme and imeis" (A2L5E0X1 gist). And the
  *temporary* unlock path is unambiguously device-bound by construction: the phone emits a token
  (`fastboot oem hwdog certify begin`) which Huawei's private key must sign into `slock.bin` (hicode002 kirin-info.md).
  If Huawei signs a per-device token for the temporary path, a per-device binding in the permanent item is plausible but
  unproven.
- Local corroboration that this fastboot has identity machinery next to the oeminfo path: the decrypted stock image
  contains the strings `FlashProtect: %s:check cert-socid info ERROR.`, `compute_socid_entry`, `secboot_get_socid`,
  `no_module: %s:die_id is 0x%x%x`. Certificates in this bootloader can carry SOC ID; that does **not** prove item 0x82
  does.

### Q2 — Public dumps of oeminfo from unlocked P20 / Kirin 970 units?

**Verdict: NO usable public dump found.** Confidence: **medium-high** (indexed sources, EN/RU/ZH).

- Per-model oeminfo collections exist and are freely shared, but for region/rebrand/demo purposes, and nothing states
  that any of them carries a valid RDLOCK authorization:
  - XDA "OEMINFO collection" (2016→): users post raw `oeminfo.img` extracts per model; format is described as unknown.
  - GSM-Forum f719 "Huawei oem info collection": modern units too (e.g. LYA-L29 "Demo removed ... 100% Tested"), always
    for region/demo, never for unlock state.
  - File-vendor pages (e.g. firmware4mobile EML-L09 "OEMinfo file") exist but I did not download them and they claim
    only "restore IMEI / network settings"; nothing about unlock authorization. Treat as unverified.
- No GitHub repo, gist or forum attachment I opened contains an oeminfo record id 0x82 at all.

### Q3 — Documented case of copying oeminfo/unlock blob between units, accepted or rejected?

**Verdict: NO documented case for item 0x82.** Confidence: **medium** (absence of evidence, not evidence of absence).

- What *is* documented is that cross-unit oeminfo writes are routinely accepted on these SoCs for unsigned records:
  GSM-Forum threads instruct writing a donor `oeminfo.bin` from another unit (e.g. LYA-L29 demo removal via testpoint,
  "100% Tested"); XDA P20 rebrand guide flashes a donor oeminfo image; XDA 3518535 is a bulk dump-sharing thread.
  This proves the partition is writable and readable by the bootloader across units — it says nothing about a signed
  record being honoured.
- Nobody reports "I flashed an unlocked oeminfo on EMUI 10+ and the bootloader accepted RDLOCK". Equally, nobody reports
  an explicit rejection with a signature/certificate error for a transplanted 0x82. The decisive experiment appears
  simply not to have been published.

### Q4 — Format of "RDLOCK type info" / signed oeminfo blobs on EMUI 10+

**Verdict: container format documented; blob internals NOT publicly documented.** Confidence: **medium** (container),
**low** (internals: key version, identity fields).

- Container (solid, two independent parsers agree): 64 MiB partition, fixed 0x400-byte record slots; each slot starts
  with a 28-byte header `"OEM_INFO" + u32 version + u32 id + u32 type + u32 data_len + u32 age`; payload begins at slot
  +0x200 and is at most 0x200 bytes. (penn5/oeminfo-huawei, EtoTen fork, R0rt1z2 oeminfo.py.)
- Item ids are only partly mapped, for version 6 and 8 images: 0x43 "Root Type (info)", 0x67 "CN or CDMA info",
  0x76 "pos_delivery constant", 0x8b/0x8d/0x96 "Unknown SHA256 1/2/3", 0xa6 "Update Token". **0x82 appears in no
  public id map**, under any name.
- Local, read-only, this repo: `artifacts/oeminfo.dump.img` holds 94 valid `OEM_INFO` records, ids 0x08…0xd0, and 0x82
  is absent. 64-byte items (0x8b, 0x8d, 0x8f) look like digests; 0x8a and 0x14a are 256-byte blobs. Nothing here
  identifies which of these, if any, is a signed authorization.
- Local, read-only: the decrypted stock fastboot (`artifacts/fastboot.stock.decrypted.img`) carries a function-name
  table with `read_oeminfo_signed_data`, `analysis_oeminfo_for_tar_and_key_sign`,
  `verify_the_oeminfo_data_for_signed`, `get_lock_state_string`, and an oeminfo tag-name table that includes
  `rdlockstate`, `userlockstate`, `acclockstate`, `device_certificate1/2`, `key_attestation`, `udid`, `psid`.
  So the firmware has a dedicated "verify oeminfo record as signed, parse TLV + key/cert" path. That is all the symbol
  names prove; I did not disassemble it, and no key-version or identity field layout can be claimed from them.
- No public document describes the 0x82 payload as containing a key-version field, a serial/IMEI/die-id field, or a
  digest over such fields. Anything beyond "TLV + certificate/key material + 32-byte digest" would be a guess.

### Q5 — EMUI 9.1 vs 10+: does 10+ add the gate?

**Verdict: YES, with high confidence.** The unlock path changes at Android 10/EMUI 10, and every service and guide
requires Android 9 firmware for a permanent unlock.

- HCU's own unlock procedure: "**The phone should be running Android 9 otherwise bootloader will remain locked until
  downgraded**" (hcu-client.com/huawei-bootloader-unlock-via-testpoint).
- PotatoNV README, alternatives: Kirin-Tool "Only works on EMUI 9.1 and below."
- XDA P20 thread (2024, EMUI 12): "to unlock bootloader you have to downgrade to EMUI 9 as higher versions have the
  unlock command disabled".
- XDA Mate 20 Pro (2020, first EMUI 10 builds): "On EMUI10 ... it's normal behavior. It's seem that oem unlock's fastboot
  command was made invalid or was modified ... rolling back to emui9 B346 or B347 will open bootloader back".
- XDA Honor 8X (2026): after the testpoint unlock, "If you are using EMUI 10, this is only a temporary unlock ... If you
  are using EMUI 9.1 or below, this is a permanent unlock".
- 4pda unlock thread: "При обновлении на Android 10 загрузчик закрывается и открыть его становится невозможно, fastboot
  покажет 'invalid command'" (on the Android 10 update the bootloader closes and cannot be opened; fastboot prints
  `invalid command`).
- hicode002 kirin-info.md: "For EMUI10 and newer, the USERLOCK is written to be locked in fastboot images ... you cannot
  get bootloader unlocked permanently without replacing fastboot with factory unlocked one."
- postmarketOS/Nura wiki: "starting from EMUI10 ... Huawei has completely removed userlock unlocking ... almost
  impossible to permanently unlock BL unless you have an RSA private key."
- Consistent with our own binary: the 2022 (EMUI 12) fastboot has the 0x82 gate and hardcodes USERLOCK.
- Nuance: the community frames the change as "unlock command removed / userlock forced locked"; our RE frames it as
  "0x82 authorization required". These are the same architectural change seen from two sides, not a contradiction.
  I found no source that documents the 0x82 gate itself — that part is our own finding.

## Sources

| URL | What it is |
|---|---|
| https://wiki.postmarketos.org/wiki/Unlocking_Bootloaders | HiSilicon Kirin section: two locks (userlock/fblock), "from Kirin 970 fblock is in oeminfo, RSA-signed, public key fixed in fastboot"; EMUI 10 removed userlock unlocking |
| https://github.com/zenfyrdev/bootloader-unlock-wall-of-shame/blob/main/brands/huawei/README.md | RDLOCK definition, factory/ASC unlock semantics, HCU = holder of the RSA keys, per-SoC support matrix |
| https://github.com/hicode002/studentpad-hack/blob/main/docs/kirin-info.md | Kirin 960 vs 710/980 unlock mechanics, `rd_lock` in oeminfo (HMAC/RSA), `hwdog certify` token → `slock.bin`, EMUI 10 userlock hardcoded locked |
| https://www.bilibili.com/opus/1085346125611794454 | Chinese translation of the same kirin-info.md (same content; useful for ZH search terms) |
| http://hcu-client.com/huawei-bootloader-unlock-via-testpoint | Official HCU procedure; "phone should be running Android 9 otherwise bootloader will remain locked until downgraded"; logs write oeminfo + "unlock restrictions" |
| https://raw.githubusercontent.com/mashed-potatoes/PotatoNV/master/README.md | Kirin 970 explicitly unsupported by PotatoNV; Kirin-Tool "only works on EMUI 9.1 and below" |
| https://xdaforums.com/t/help-to-unlock-bootloader-for-huawei-p20-without-code-from-huawei-and-create-a-custom-android-12-or-13-rom.4668277/ | P20 on EMUI 12: must downgrade to EMUI 9, higher versions have the unlock command disabled |
| https://xdaforums.com/t/emui-10-bootloader-unlock-not-possible.4017851/ | Mate 20 Pro: EMUI 10 makes `fastboot oem unlock` invalid; rollback to 9.x restores it |
| https://xdaforums.com/t/honor-8x-jsn-l22-unlock-bootloader-and-root-with-magisk-lineageos-2026.4792198 | Testpoint unlock: temporary on EMUI 10, permanent on ≤9.1 |
| https://4pda.to/forum/index.php?showtopic=741037 | Big RU unlock thread; Android 10 closes the bootloader, `invalid command`; per-model caveats |
| https://github.com/penn5/oeminfo-huawei/blob/master/oeminfo_huawei.py | Reference oeminfo record layout (0x400 slot, 28-byte header, payload at +0x200) and the id map (no 0x82) |
| https://github.com/EtoTen/oeminfo-huawei | Maintained fork/rewrite of the same parser; same layout assumptions |
| https://github.com/R0rt1z2/huawei-playground | Independent oeminfo pack/unpack + fastboot image parser (no id naming for 0x82) |
| https://github.com/rabits/honor-tools | oeminfo contains `DEBUG_LOCK_POLICY`, `DEVICE_CERTIFICATE1`, `KEY_ATTESTATION` — device-bound material lives in this partition |
| https://gist.github.com/A2L5E0X1/1e6564ab4479a13e7e5362c7c9ddca5f | "oeminfo: ... on newer phones (k970) also stuff from nvme and imeis"; older fblock-in-nvme model |
| https://xdaforums.com/t/oeminfo-collection.3518535/ | Historic bulk oeminfo dump-sharing thread (region/rebrand, not unlock) |
| https://forum.gsmhosting.com/vbb/f719/huawei-oem-info-collection-2840715 | Service-tool oeminfo file collection incl. modern units (LYA-L29 demo removal, "100% Tested") — cross-unit writes are routine |
| https://xdaforums.com/t/guide-switching-oeminfo-versions.3882537/ | P20 Lite: flashing a donor oeminfo zip is an accepted, documented operation |
| https://xdaforums.com/t/rebrand-huawei-p20-eml-l29-eml-l09.3779283 | P20 rebrand via donor oeminfo image — confirms writes are accepted on this exact family |

## Local ground truth used (read-only)

- `artifacts/oeminfo.dump.img`: 94 `OEM_INFO` records, ids 0x08–0xd0, **no 0x82**; second region copy starting at
  +0x2000000 with independent `age` values.
- `artifacts/fastboot.stock.decrypted.img`: symbol-name strings for the signed-oeminfo path and an oeminfo tag-name
  table containing `rdlockstate`.

## If you want to test this

Ordered by cost, cheapest decisive test first. Nothing here has been executed.

1. **Two-blob diff, zero writes (the actual answer).** Obtain the same 0x82 record from **two different unlocked units**
   of the same model and key version (two customers/service shops, or the same shop for two devices). Byte-compare.
   - Identical in the non-digest region → the signed message carries no per-device data → portable.
   - Differs → find *where*. A 32-byte digest will always differ; look for a third differing field, ASCII/BCD digits, or
     a length that matches a serial/IMEI/die-id. Three blobs (not two) separate "random nonce per signature" from
     "device id", and nonce-randomness is exactly what a naive two-blob test would misread as binding.
2. **If you only have one blob:** write it and observe. Keep the 64 MiB dump; the state is recomputed at boot, so a
   restore or a plain reboot back to the old oeminfo is the rollback.
   - Write the item with the **same `age` semantics** the reader expects, and write it in the region that
     `get_valid_oeminfo_region` will select (our dump has two: +0x0 and +0x2000000). A naive single-region write can be
     shadowed by the newer record in the other copy.
   - Expect the id to be permission-checked (`check_oeminfo_id_permisson`, `write_reused_oeminfo_item`). If fastboot
     refuses the write, the raw-partition path we already have (RAM fastboot / EL3) bypasses that layer.
   - Read the result with the gate's own inputs, not the UI: `oem lock-state info` / `getvar` on the stock fastboot, then
     attempt an unsigned `fastboot flash boot`. Acceptance of the flash is the real signal.
3. **Cheapest negative control:** take a 0x82 from a *different model* (e.g. Kirin 980) — if that is rejected with a
   signature/cert error while same-model is accepted, the payload is at least model/SoC-scoped, which is a useful
   intermediate result between "portable" and "device-bound".

## What I could not find

- Any statement, in any language I searched (EN/RU/ZH: XDA, 4pda, GSM-Forum/GSMHosting, DC-Unlocker forum, GitHub,
  bilibili), that the RDLOCK/0x82 blob is or is not device-bound.
- Any public dump that is documented to contain a valid 0x82 record.
- Any report — success or explicit failure — of transplanting that record between units.
- Any description of the 0x82 payload's internal layout: key-version field, TLV tags, whether a serial/IMEI/die-id is
  inside the signed message, or which key/cert chain is embedded.

Caution: a Gemini "shared conversation" page surfaces high in search results for this topic and asserts specific details
(oeminfo record sizing, cross-version binding, donor-image behaviour) with citations that do not check out. It is
model-generated text, not a field report. I did not use it as evidence and neither should the rest of this project.
