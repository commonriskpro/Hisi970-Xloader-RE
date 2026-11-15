# Roadmap — Android 17 on Huawei P20 (EML-L09, Kirin 970 / hi3660)

Status: planning. Date: 2026-11-15.

## Decision record

- Base: EMUI 9.1 (last bootloader generation without the RDLOCK 0x82 gate; on it
  userlock=0 is honoured and unsigned images boot).
- Product: full from-source AOSP device port. NO GSI. GSI hides HAL defects and caps
  what can be fixed; we want the whole stack under our control.
- Recovery: the VCOM RAM chain (pwn + our own loader) is the always-available recovery
  path. Every risky step must be reversible through it.

## Non-negotiables (verified on this hardware or in this repo)

1. ARB is a boot-time gate, not a write-time gate. VCOM gives free writes; the boot chain
   still compares the anti-rollback counter. Whether 9.1 can boot natively on a unit that
   took EMUI 12 (ARB=2) must be measured, not assumed. Booting under our RAM chain bypasses
   ARB entirely.
2. Kernel 4.9 is the long pole. Android 17 assumes GKI-class kernels (5.10/6.x): eBPF,
   cgroup v2, modern SELinux, scheduler and power features. A 4.9 kernel can host a modern
   userspace only partially and unreliably.
3. Vendor API 28 to AIDL. HIDL is deprecated and being removed. Every HAL we keep must be
   wrapped in AIDL.
4. Camera and modem have no open implementation. Control over them means writing wrappers
   over Huawei blobs, not replacing them.

## Workstreams

| id | stream | owner artefact |
|---|---|---|
| W1 | Boot chain, flashing, recovery | host/, build/, RAM loader patches |
| W2 | Kernel forward port to 5.10-class GKI | kernel/ fork + patches |
| W3 | Device tree + AIDL HALs + SELinux | device/huawei/eml-l09, vendor/ |
| W4 | AOSP platform build | manifests, lunch targets |
| W5 | Verification, CI, regression matrix | scripts + logs |
| W6 | Reproducibility and documentation | notes/, docs/ |

## Phases

### P0 — Discovery and baseline (1-2 weeks)

Exit criteria (all must be true):
- Full partition dump of the current EMUI 12 unit, hash-verified, stored twice.
- ARB state measured: efuse secure/ARB values vs the ARB field of the 9.1 images.
  Verdict recorded: 9.1 boots natively, or 9.1 only under the RAM chain.
- 9.1 firmware set identified with exact build numbers and hashes (xloader, uce, fastboot,
  boot, vendor, system, vbmeta).
- Partition write path validated on a disposable partition (write, read back, restore).
- Kernel source drop for the 9.1 build obtained and stored.

### P1 — 9.1 baseline and native unlock (2-4 weeks)

- Flash the 9.1 set, boot it, confirm userlock=0 persists across reboots.
- Confirm the 9.1 bootloader boots an UNSIGNED boot.img (the real unlock test, the same
  experiment that decided the EMUI 12 verdict).
- Establish the flash/restore loop so any image can be swapped in minutes.

Exit criteria: a 9.1 device that boots a modified boot.img without the RAM chain.

### P2 — From-source AOSP at the base API (4-8 weeks)

Goal: prove the whole toolchain with the smallest possible delta.
- device/huawei/eml-l09 skeleton: BoardConfig, fstab, init, minimal sepolicy.
- Build AOSP at the base API level for arm64, flashable as system/vendor.
- Boot it and fix what breaks (display, touch, storage, USB, RIL stub).

Exit criteria: a self-built system image booting to a usable UI.

### P3 — Kernel forward port (3-6 months, the real project)

Strategy: mainline hi3660 as the base, Huawei drivers ported on top, in increments.
- 3.1: 4.19 boots; display, storage, USB, input, battery.
- 3.2: 5.10 GKI-class boots; eBPF, cgroup v2, modern SELinux.
- Each milestone validated by booting the current AOSP build on it.

Exit criteria: 5.10-class kernel boots AOSP with no 4.9-only workarounds.

### P4 — HAL modernisation and platform rebase (6-9 months)

- AIDL wrappers: composer/display, audio, sensors, power, thermal, vibrator, GNSS, RIL.
- Camera: AIDL camera provider over the Huawei ISP blobs; expect partial capability.
- SELinux policy written for the new vendor interface.
- Rebase AOSP to the newest supported release at that time.

Exit criteria: daily-usable build on a modern AOSP release with a documented defect list.

### P5 — Android 17 rebase

- Only after P3 + P4 hold. Each release is a rebase of device tree, HAL wrappers and
  sepolicy against the new platform.
- The kernel must stay at or above the GKI version that release assumes.

Exit criteria: Android 17 boots, telephony and display stable, defects documented.

## Gates (what must be true before spending the next block)

| gate | question | method |
|---|---|---|
| G0 | Can 9.1 boot natively? **PASSED 2026-11-15** | 9.1 flashed and booting on the real unit |
| G1 | Does the 9.1 bootloader boot unsigned images? **PASSED 2026-11-15** | modified kernel_a.img booted; see notes/g1-milestone.md |
| G2 | Does our own system build boot? | flash self-built system, observe |
| G3 | Does a forward-ported kernel boot it? | same build, new kernel |
| G4 | Are HALs stable enough for daily use? | two-week soak, defect list |

## Risk register

| risk | impact | mitigation |
|---|---|---|
| efuse ARB blocks native 9.1 | device only runs under the RAM chain | measure at G0 before investing |
| kernel port stalls (no hi3660 block docs) | L5 unreachable | reuse mainline + postmarketOS work; timebox milestones |
| camera never fully works | product limitation | scope as best effort, document |
| each Android release widens the gap | perpetual catch-up | keep device tree thin; isolate blobs behind AIDL |
| brick while flashing | downtime | VCOM recovery validated at P0 and kept current |

## Immediate next actions

1. Measure ARB: read efuse secure/ARB values and compare with the 9.1 images' ARB field.
   Cheap, read-only, decides the whole plan.
2. Inventory the 9.1 firmware set and pin hashes.
3. Validate the partition write path on a disposable partition.

## Out of scope

- GSI-based products (allowed only as a temporary smoke test, never a deliverable).
- Anything requiring Huawei's signing key.
- Declaring a release supported without the soak test in G4.
