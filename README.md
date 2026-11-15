# Hisi970 Xloader RE — decrypted fastboot extraction

Status: **setup + static analysis**
Owner: assistant-owned project (local)
Device: Huawei P20 EML-L09, Kirin 970, EMUI 12.0.0.226 (base 10.0.1.1,
build 102.0.0.226), Android 10 / API 29, locked.

Private repo: `https://github.com/commonriskpro/Hisi970-Xloader-RE`

The repo includes the decrypted xloader, the factory fastboot RAM loader,
`null`/`uce`, the stock fastboot payload, the static map/plan, and the VCOM
reference code under `tool-reference/`. The large raw dumps are kept out of the
repo for size/privacy; milestone 2 only needs the xloader and stock payload.

## Goal

Recover a **decrypted** copy of the stock EMUI 12 `fastboot` partition by
patching the already-decrypted Kirin 970 xloader so it loads/decrypts the
on-disk `fastboot` image into RAM and exposes the plaintext through a read
primitive. If that works, use the plaintext to patch the stock fastboot lock
state (FBLOCK/USERLOCK) and persist the unlock.

This exists because EMUI 10+ ignores the old `oeminfo 0x5d` USERLOCK write and
requires a signed `0x82` RDLOCK record for persistent FBLOCK. The free tool can
only run the factory fastboot from RAM; the 2022 xloader rejects the 2020
factory image on disk.

## Current facts (measured)

- Persistent USERLOCK: **unlocked** — the factory loader in RAM decrypts
  `oeminfo 0x5d` and reports `USER LockState: UNLOCKED`.
- `oeminfo 0x82` (RDLOCK): **absent**. `oeminfo` is version 6; `0x5d` payload is
  encrypted at rest.
- NVME: `USRKEY = 55 x 32`, `FBLOCK = 01` (locked).
- On-disk `fastboot`: stock EMUI 12 payload, i.e. `UPDATE.APP FASTBOOT[0x1000:]`
  (SHA256 `9D82C1CE...`), encrypted at rest.
- Factory `loaders/hisi970/fastboot.img` (5,992,448 B, SHA256 `301690CF...`) was
  flashed as payload; the 2022 xloader rejected it and the device did not
  reappear in fastboot. Recovered by writing `fastboot.stock.payload.img` back.

## Layout

```
artifacts/   decrypted loaders, dumps, stock payload (sensitive; gitignored)
notes/       static analysis and findings
tools/       local scripts (DTL decryptor, scanners)
reports/     generated reports
recovery/    recovery notes and stock fastboot payload copy
PROMPT.md    work order for the DeepSeek Harness agent team
```

## Rules

- No device writes without an explicit approval gate and a testpoint recovery
  baseline. The last factory-fastboot flash was rejected; do not repeat it
  blindly.
- Keep Huawei binaries, keys, and dumps out of public repositories.
- Prefer offline analysis and reproducible scripts. Save every finding under
  `notes/`.

