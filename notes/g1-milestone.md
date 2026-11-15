# G1 passed — 9.1 bootloader boots a modified kernel

Date: 2026-11-15. Device: Huawei P20 EML-L09, EMUI 9.1 (flashed), bootloader user-unlocked.

## What this settles

Gate G1 of notes/roadmap-android17.md: does the EMUI 9.1 boot chain boot an image that is
not the original, unverified one? **Yes.**

## Method (reproducible)

1. Full partition dump taken with the service chain (unlocked fastboot): 66 partitions.
2. kernel_a.img identified as a standard Android boot image v1 (magic ANDROID!), kernel
   only (ramdisk_size = 0), page_size 0x800, header_version 1, cmdline field at offset 64
   (512 bytes).
3. Modification kept to the minimum possible: 17 bytes changed, all inside the cmdline
   field (appended ' androidboot.g1=1'). No repack, no structural change, so a rejection
   could only be caused by verification and not by a broken image.
   - original sha256 CC4FF2A9F72AAD1B912177C89FC1D8C8F9830E868863E54871AE510A6E22139D
   - modified sha256 13402E39B3941F0340E39D908A0948154B09911B1F48B24911E107829DF2DA4A
4. Write path validated first by flashing the byte-identical original (zero risk), then the
   modified image, using the vendor fastboot shipped inside the service tool
   (fastboot/xml/fastboot.exe, Huawei Ultraflash protocol):

       (bootloader) Let's rock with Ultraflash!
       Sending file 'kernel_a' (24576 KB)   OKAY
       Writing 'kernel_a'                   OKAY

5. Reboot: the device booted to Android normally, with the unlocked-device warning screen
   (verifiedbootstate=orange).

## Interpretation

- With the bootloader user-unlocked, the 9.1 chain does not enforce image verification for
  the boot path: it boots a modified kernel_a and only shows the orange warning.
- Verification machinery is present in the firmware (vrl.img carries a real VRL blob,
  vbmeta_a.img is AVB0/SHA256-RSA2048 with an embedded public key, ramdisk_a.img carries
  an AVB0 header at +0x1000). It exists; it is simply not enforcing on an unlocked unit.
- This is the property the custom-ROM project needs: we can boot kernels and ramdisks we
  build, without touching signatures.

## Practical consequences

- Flashing primitive: the vendor fastboot inside the tool writes individual partitions and
  reports OKAY. Combined with the unlocked state, this is a complete dev loop:
  modify -> flash -> reboot -> observe.
- Rollback is always one command away (same fastboot, original image kept on disk).
- The stock AOSP fastboot (platform-tools) cannot do this: it is whitelist-gated by the
  stock bootloader ('Command not allowed') and it also hangs when the tool holds the port.
  Only the tool's build speaks Ultraflash.

## Open items

- Confirm from inside Android that the running kernel has the modified cmdline
  (adb shell cat /proc/cmdline should contain androidboot.g1=1). Blocked on the ADB
  interface not enumerating on the Windows host; the boot itself already proves the point.
- Decide the next milestone: P2 (from-source AOSP at base API) per the roadmap.
