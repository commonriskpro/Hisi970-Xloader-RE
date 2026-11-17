#!/usr/bin/env python3
"""Kirin 970 factory-fastboot patch kit (P20 / EML-L09, base VA 0x16800000).

Builds every image variant used in the 2026-11-15/16 sessions from the pristine
factory fastboot (artifacts/hisi970_fastboot_ram.bin), which is also exactly what
the service tool loads as loaders/hisi970/fastboot.ktl.

    python3 build/patch_fastboot_kit.py --variant avb        # AVB verdict forced to success
    python3 build/patch_fastboot_kit.py --variant mode       # + fastboot menu decisions forced to "next"
    python3 build/patch_fastboot_kit.py --variant trace      # + markers: load_kernel, AVB return
    python3 build/patch_fastboot_kit.py --variant modetrace  # + one marker per preboot mode
    python3 build/patch_fastboot_kit.py --variant boot       # stub calling the boot orchestrator

Every variant asserts the pristine bytes it overwrites, and prints the exact
diff. Wrap the result for the tool with build/wrap_ktl.py.

Facts the offsets rely on (verified by reading RAM back after a chain load):
  response dispatcher        0x1680AC6C(msg, type)   type 0=OKAY 1=FAIL else silent
  "OKAY" string              0x169B7E40              NULL msg crashes the OKAY path
  code cave                  0x168011D0 (1584 zero bytes)
  scratch cells              0x16801600
  AVB verdict translator     call at 0x168ADC0C     -> 0x168AC2F8
  load-kernel body entry     0x168AE018
  boot orchestrator          0x168AE5CC             (crashes when called from fastboot)
  preboot mode table         0x16B12B30 (stride 0x18: name, fn, flag)
"""

import argparse
import hashlib
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

BASE = 0x16800000
REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "artifacts" / "hisi970_fastboot_ram.bin"
OUTDIR = REPO / "build"

CELLS = 0x16801600
CAVE = 0x168011D0
OKAY = 0x169B7E40
RESPOND = 0x1680AC6C
AVB_SITE = 0x168ADC0C
LOAD_KERNEL = 0x168AE018
ORCHESTRATOR = 0x168AE5CC
CHECK_IMAGE_HANDLER = 0x16816488
BOOT_MODE_SITE = 0x16806E44
BOOT_MODE_NEXT = 0x16806E84
POWER_STATE = 0x16808098

MODES = [
    ("check_boot_mode", 0x16806E14),
    ("check_image_state", 0x168097DC),
    ("check_power_state", 0x16808098),
    ("check_smpl_state", 0x168073C8),
    ("check_unlock_misc_info", 0x1680624C),
    ("check_powerkey_misc_info", 0x1680662C),
    ("check_volumekey_state", 0x16805EF8),
    ("check_misc_info", 0x16808BF4),
]

STP_FP20, MOV_FP, LDP_FP20 = 0xA9BE7BFD, 0x910003FD, 0xA8C27BFD
STP_FP30, STP_19_20, MOV_W0_0, RET = 0xA9BD7BFD, 0xA90153F3, 0x52800000, 0xD65F03C0

MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)


def adrp(rd, addr, pc):
    imm = ((addr & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def movz(rd, imm16, hw=0):
    return 0x52800000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def movk(rd, imm16, hw=0):
    return 0x72A00000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def str_w(rt, rn, off=0):
    return 0xB9000000 | (((off >> 2) & 0xFFF) << 10) | (rn << 5) | rt


def bl(target, pc):
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def b(target, pc):
    return 0x14000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def stp_pair(off):
    return 0xA9000000 | (((off >> 3) & 0x7F) << 15) | (10 << 10) | (31 << 5) | 9


def ldp_pair(off):
    return 0xA9400000 | (((off >> 3) & 0x7F) << 15) | (10 << 10) | (31 << 5) | 9


def emit(words):
    return b"".join(w.to_bytes(4, "little") for w in words)


def marker_stub(stub_va, cell_off, magic, first_ins, resume):
    """Write magic into CELLS+cell_off, run the original first instruction, resume."""
    words, pc = [], [stub_va]

    def at(w):
        words.append(w)
        pc[0] += 4

    at(STP_FP20)
    at(MOV_FP)
    at(stp_pair(0x10))
    at(adrp(9, CELLS, pc[0]))
    at(add_imm(9, 9, CELLS & 0xFFF))
    at(movz(10, magic & 0xFFFF))
    at(movk(10, (magic >> 16) & 0xFFFF, 1))
    at(str_w(10, 9, cell_off))
    at(ldp_pair(0x10))
    at(LDP_FP20)
    if first_ins is not None:
        at(first_ins)
    at(b(resume, pc[0]))
    return emit(words)


class Image:
    def __init__(self, data):
        self.orig = data
        self.buf = bytearray(data)

    def put(self, va, blob, what):
        off = va - BASE
        assert all(x == 0 for x in self.orig[off:off + len(blob)]), f"{what}: cave not zero"
        self.buf[off:off + len(blob)] = blob
        return va + len(blob)

    def patch(self, va, word, expect, what):
        off = va - BASE
        assert self.orig[off:off + 4] == expect, f"{what}: unexpected bytes {self.orig[off:off+4].hex()}"
        self.buf[off:off + 4] = word.to_bytes(4, "little")

    def diff(self):
        return [i for i in range(len(self.buf)) if self.buf[i] != self.orig[i]]


def apply_avb(img):
    # force the AVB status translator call to report success
    img.patch(AVB_SITE, MOV_W0_0, bytes.fromhex("bbf9ff97"), "avb site")


def apply_mode(img):
    img.patch(BOOT_MODE_SITE, b(BOOT_MODE_NEXT, BOOT_MODE_SITE),
              bytes.fromhex("00020034"), "check_boot_mode")
    img.patch(POWER_STATE, MOV_W0_0, bytes.fromhex("fd7bbca9"), "check_power_state")
    img.patch(POWER_STATE + 4, RET, bytes.fromhex("fd030091"), "check_power_state+4")


def apply_trace(img):
    """Marker at load_kernel entry and at the AVB call, AVB forced to success."""
    cave = CAVE
    first_load = int.from_bytes(img.orig[LOAD_KERNEL - BASE:LOAD_KERNEL - BASE + 4], "little")
    stub = marker_stub(cave, 0, 0xB2A00001, first_load, LOAD_KERNEL + 0xC)
    img.patch(LOAD_KERNEL, b(cave, LOAD_KERNEL), bytes.fromhex("fd7bbda9"), "load_kernel")
    cave = img.put(cave, stub, "trace stub 1")

    stub2 = marker_stub(cave, 4, 0xB2A00002, MOV_W0_0, AVB_SITE + 4)
    img.patch(AVB_SITE, b(cave, AVB_SITE), bytes.fromhex("bbf9ff97"), "avb site")
    img.put(cave, stub2, "trace stub 2")


def apply_modetrace(img):
    cave = CAVE
    for i, (name, fn) in enumerate(MODES):
        first = int.from_bytes(img.orig[fn - BASE:fn - BASE + 4], "little")
        stub = marker_stub(cave, i * 4, 0xB2A00100 + i, first, fn + 4)
        img.patch(fn, b(cave, fn), img.orig[fn - BASE:fn - BASE + 4], name)
        cave = img.put(cave, stub, name)
        cave = (cave + 0xF) & ~0xF
    apply_avb(img)


def apply_boot(img):
    """Hook oem check-image to call the boot orchestrator (crashes from fastboot)."""
    words, pc = [], [CAVE]

    def at(w):
        words.append(w)
        pc[0] += 4

    at(STP_FP20)
    at(MOV_FP)
    at(stp_pair(0x10))
    at(bl(ORCHESTRATOR, pc[0]))
    at(adrp(0, OKAY, pc[0]))
    at(add_imm(0, 0, OKAY & 0xFFF))
    at(0x52800001)  # mov w1, #0
    at(bl(RESPOND, pc[0]))
    at(ldp_pair(0x10))
    at(LDP_FP20)
    at(RET)
    stub = emit(words)
    img.put(CAVE, stub, "boot stub")
    img.patch(CHECK_IMAGE_HANDLER, b(CAVE, CHECK_IMAGE_HANDLER),
              bytes.fromhex("fd7bbea9"), "oem check-image handler")
    apply_avb(img)


VARIANTS = {
    "avb": apply_avb,
    "mode": lambda img: (apply_avb(img), apply_mode(img)),
    "trace": lambda img: (apply_trace(img), apply_mode(img)),
    "modetrace": apply_modetrace,
    "boot": apply_boot,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", required=True, choices=sorted(VARIANTS))
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    img = Image(SRC.read_bytes())
    VARIANTS[args.variant](img)
    out = Path(args.out) if args.out else OUTDIR / f"hisi970_fastboot_{args.variant}.bin"
    out.write_bytes(bytes(img.buf))
    diff = img.diff()
    print(f"variant   : {args.variant}")
    print(f"source    : {SRC} sha256 {hashlib.sha256(img.orig).hexdigest().upper()}")
    print(f"output    : {out}")
    print(f"changed   : {len(diff)} bytes in {len({i for i in diff})} positions")
    print(f"sha256    : {hashlib.sha256(bytes(img.buf)).hexdigest().upper()}")


if __name__ == "__main__":
    raise SystemExit(main())
