#!/usr/bin/env python3
"""B2a v5 probe: four handler-entry patches, one boot, all open questions.

The previous iterations proved that the oem dispatch table is not the path
(filesystem table patch produced stock behaviour) and that a store into the
code page at 0x16801000 resets the SoC. This build answers, in a single boot:

  oem memcpy_count        -> respond-only stub (isolates the OKAY path)
  oem chipid              -> store MAGIC_DRAM at 0x16600000, then OKAY
  oem ufs_test            -> store MAGIC_BSS at 0x16B8F1F8, then OKAY
  oem onchiprom_download  -> decrypt the stock container, publish to
                             0x16600010 (len), 0x16600018 (ptr), 0x16600020
                             (32-byte preview), then OKAY

Every stub passes the same "OKAY" string the stock handlers use, because
0x1680AA54 initialises the response buffer and is only reached when the
message pointer is non-NULL.

Offline only. Produces build/hisi970_fastboot_b2a_probe.bin.
"""

import hashlib
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "artifacts" / "hisi970_fastboot_ram.bin"
DST = REPO / "build" / "hisi970_fastboot_b2a_probe.bin"
BASE = 0x16800000

HEX2UL = 0x169730E8
DECRYPT = 0x16989D30
RESPOND = 0x1680AC6C
GROUP_FASTBOOT = 0x169B0478
OKAY_STR = 0x169B7E40

STUB_OK = 0x168011D0
STUB_DRAM = 0x16801220
STUB_BSS = 0x16801270
STUB_DEC = 0x168012C0

DRAM_CELL = 0x16600000
BSS_CELL = 0x16B8F1F8
DEC_LEN = 0x16600010
DEC_PTR = 0x16600018
DEC_PREV = 0x16600020

MAGIC_DRAM = 0x7AB1E001
MAGIC_BSS = 0xB2A0C0DE

HANDLERS = [
    ("memcpy_count", 0x16814BC8, "fd7bbfa9", STUB_OK),
    ("chipid", 0x1680EC00, "fd7bb9a9", STUB_DRAM),
    ("ufs_test", 0x16810D60, "fd7bbda9", STUB_BSS),
    ("onchiprom_download", 0x16812534, "fd7bbda9", STUB_DEC),
]


def foff(va: int) -> int:
    return va - BASE


def adrp(rd: int, addr: int, pc: int) -> int:
    imm = ((addr & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def add_imm(rd: int, rn: int, imm: int) -> int:
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def movz(rd: int, imm16: int, hw: int = 0) -> int:
    return 0x52800000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def movk(rd: int, imm16: int, hw: int = 0) -> int:
    return 0x72A00000 | ((hw & 3) << 21) | ((imm16 & 0xFFFF) << 5) | rd


def str_w(rt: int, rn: int, off: int = 0) -> int:
    return 0xB9000000 | (((off >> 2) & 0xFFF) << 10) | (rn << 5) | rt


def str_x(rt: int, rn: int, off: int = 0) -> int:
    return 0xF9000000 | (((off >> 2) & 0xFFF) << 10) | (rn << 5) | rt


def ldr_w(rt: int, rn: int, off: int = 0) -> int:
    return 0xB9400000 | (((off >> 2) & 0xFFF) << 10) | (rn << 5) | rt


def cbnz(rt: int, off: int) -> int:
    return 0xB5000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def cbz(rt: int, off: int) -> int:
    return 0xB4000000 | (((off >> 2) & 0x7FFFF) << 5) | rt


def bl(target: int, pc: int) -> int:
    return 0x94000000 | (((target - pc) >> 2) & 0x3FFFFFF)


def b(target: int, pc: int) -> int:
    return 0x14000000 | (((target - pc) >> 2) & 0x3FFFFFF)


STP_FP = 0xA9BE7BFD
MOV_FP = 0x910003FD
STP_X19 = 0xA90153F3
LDP_X19 = 0xA94153F3
LDP_FP = 0xA8C27BFD
MOV_X19_X0 = 0xAA0003F3
MOV_W1_0 = 0x52800001
MOV_X0_CONTAINER = 0xD2A2C000
RET = 0xD65F03C0


def emit(words: list[int]) -> bytes:
    return b"".join(w.to_bytes(4, "little") for w in words)


def make_stub(va: int, store_va=None, magic: int = 0, respond: bool = True) -> bytes:
    words: list[int] = []
    pc = [va]

    def at(word: int) -> None:
        words.append(word)
        pc[0] += 4

    at(STP_FP)
    at(MOV_FP)
    at(STP_X19)
    if store_va is not None:
        at(adrp(8, store_va, pc[0]))
        at(add_imm(8, 8, store_va & 0xFFF))
        at(movz(9, magic & 0xFFFF))
        at(movk(9, (magic >> 16) & 0xFFFF, 1))
        at(str_w(9, 8))
    if respond:
        at(adrp(0, OKAY_STR, pc[0]))
        at(add_imm(0, 0, OKAY_STR & 0xFFF))
        at(MOV_W1_0)
        at(bl(RESPOND, pc[0]))
        assert words[-4] == adrp(0, OKAY_STR, va + 4 * (len(words) - 4))
    at(LDP_X19)
    at(LDP_FP)
    at(RET)
    return emit(words)


def make_decrypt(va: int) -> bytes:
    words: list[int] = []
    pc = [va]

    def at(word: int) -> None:
        words.append(word)
        pc[0] += 4

    at(STP_FP)
    at(MOV_FP)
    at(STP_X19)
    at(MOV_X19_X0)
    at(bl(HEX2UL, pc[0]))
    at(cbnz(0, 8))
    at(MOV_X0_CONTAINER)
    at(adrp(1, GROUP_FASTBOOT, pc[0]))
    at(add_imm(1, 1, GROUP_FASTBOOT & 0xFFF))
    at(adrp(2, DEC_LEN, pc[0]))
    at(add_imm(2, 2, DEC_LEN & 0xFFF))
    at(bl(DECRYPT, pc[0]))
    at(adrp(8, DEC_PTR, pc[0]))
    at(add_imm(8, 8, DEC_PTR & 0xFFF))
    at(str_x(0, 8))
    cbz_idx = len(words)
    at(cbz(0, 0))
    base = DEC_PREV - DEC_PTR
    for k in range(0, 32, 4):
        at(ldr_w(9, 0, k))
        at(str_w(9, 8, base + k))
    after_copy = pc[0]
    words[cbz_idx] = cbz(0, after_copy - (va + 4 * cbz_idx))
    at(adrp(0, OKAY_STR, pc[0]))
    at(add_imm(0, 0, OKAY_STR & 0xFFF))
    at(MOV_W1_0)
    at(bl(RESPOND, pc[0]))
    at(LDP_X19)
    at(LDP_FP)
    at(RET)
    return emit(words)


def check_bl(word: int, pc: int, target: int) -> None:
    assert word >> 26 == 0b100101, hex(word)
    imm = word & 0x3FFFFFF
    if imm & 0x2000000:
        imm -= 0x4000000
    assert pc + imm * 4 == target, f"bl from 0x{pc:X} -> 0x{pc + imm * 4:X} != 0x{target:X}"


def check_branch(word: int, pc: int, target: int) -> None:
    assert word >> 26 == 0b000101, hex(word)
    imm = word & 0x3FFFFFF
    if imm & 0x2000000:
        imm -= 0x4000000
    assert pc + imm * 4 == target, f"b from 0x{pc:X} -> 0x{pc + imm * 4:X} != 0x{target:X}"


def print_disasm(blob: bytes, va: int) -> None:
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    for ins in md.disasm(blob, va):
        print(f"  0x{ins.address:08X}  {ins.bytes.hex():<10} {ins.mnemonic:<8} {ins.op_str}")


def main() -> int:
    data = bytearray(SRC.read_bytes())
    print(f"source {SRC}")
    print(f"source sha256 {hashlib.sha256(data).hexdigest().upper()}")

    stubs = [
        ("respond-only", STUB_OK, make_stub(STUB_OK)),
        ("dram-store", STUB_DRAM, make_stub(STUB_DRAM, DRAM_CELL, MAGIC_DRAM)),
        ("bss-store", STUB_BSS, make_stub(STUB_BSS, BSS_CELL, MAGIC_BSS)),
        ("decrypt", STUB_DEC, make_decrypt(STUB_DEC)),
    ]
    for name, va, blob in stubs:
        print(f"\n== {name} @0x{va:08X} ({len(blob)} B) ==")
        print_disasm(blob, va)
        off = foff(va)
        assert all(x == 0 for x in data[off:off + len(blob)]), f"{name} cave not zero"
        data[off:off + len(blob)] = blob

    print("\n== entry patches ==")
    for name, va, expect_hex, target in HANDLERS:
        off = foff(va)
        assert data[off:off + 4] == bytes.fromhex(expect_hex), f"{name} prologue mismatch"
        word = b(target, va)
        check_branch(word, va, target)
        data[off:off + 4] = word.to_bytes(4, "little")
        print(f"  0x{va:08X}  {name:<20} -> 0x{target:08X}  ({word:08x})")

    out = bytes(data)
    DST.write_bytes(out)
    print(f"\nwrote {DST}")
    print(f"sha256 {hashlib.sha256(out).hexdigest().upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
