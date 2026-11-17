#!/usr/bin/env python3
"""B2a: repoint the factory fastboot `dump:` command to a decrypt stub.

Offline only. Produces build/hisi970_fastboot_b2a.bin from the decrypted
factory fastboot. No device, VCOM, or flash operation.
"""

import hashlib
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "artifacts" / "hisi970_fastboot_ram.bin"
DST = REPO / "build" / "hisi970_fastboot_b2a.bin"
BASE = 0x16800000

TABLE_VA = 0x16B135D8
TABLE_OLD = bytes.fromhex("98 b3 80 16 00 00 00 00")
TABLE_NEW = bytes.fromhex("d0 11 80 16 00 00 00 00")

# The host fastboot.exe cannot send the direct `dump:` command, but it can send
# `oem memcpy_count`. Repoint that benign oem handler to the same stub. The oem
# dispatcher passes the argument string (or an empty tail); the stub defaults to
# 0x16000000 when hex2unsignedlong returns 0.
OEM_HANDLER_VA = 0x16B13AF0
OEM_HANDLER_OLD = bytes.fromhex("c8 4b 81 16 00 00 00 00")
OEM_HANDLER_NEW = bytes.fromhex("d0 11 80 16 00 00 00 00")

STUB_VA = 0x168011D0
STUB = bytes.fromhex(
    "fd7bbea9 fd030091 f35301a9 f30300aa c2c70594 400000b5 00c0a2d2 610d00f0"
    "21e01191 621c00d0 42e00791 cd220694 681c00d0 08010891 000100f9 a00d00d0"
    "00003991 41008052 95260094 f35341a9 fd7bc2a8 c0035fd6"
)


def foff(va: int) -> int:
    return va - BASE


def main() -> int:
    data = bytearray(SRC.read_bytes())
    print(f"source: {SRC}")
    print(f"source size: {len(data)} (0x{len(data):X})")
    print(f"source sha256: {hashlib.sha256(data).hexdigest().upper()}")

    table_off = foff(TABLE_VA)
    oem_handler_off = foff(OEM_HANDLER_VA)
    stub_off = foff(STUB_VA)
    assert len(STUB) == 88, len(STUB)
    assert data[table_off:table_off + 8] == TABLE_OLD, data[table_off:table_off + 8].hex()
    assert data[oem_handler_off:oem_handler_off + 8] == OEM_HANDLER_OLD, data[oem_handler_off:oem_handler_off + 8].hex()
    assert all(b == 0 for b in data[stub_off:stub_off + len(STUB)]), "stub cave is not zero"

    data[table_off:table_off + 8] = TABLE_NEW
    data[oem_handler_off:oem_handler_off + 8] = OEM_HANDLER_NEW
    data[stub_off:stub_off + len(STUB)] = STUB

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    print("\n== stub disassembly ==")
    for ins in md.disasm(bytes(data[stub_off:stub_off + len(STUB)]), STUB_VA):
        print(f"  0x{ins.address:08X}  {ins.mnemonic:<8} {ins.op_str}")

    # Assert the intended call targets from the encoded words.
    words = [STUB[i:i + 4] for i in range(0, len(STUB), 4)]
    assert words[4] == bytes.fromhex("c2c70594"), "hex2unsignedlong call changed"
    assert words[11] == bytes.fromhex("cd220694"), "decrypt call changed"
    assert words[18] == bytes.fromhex("95260094"), "ack call changed"

    # Only the two intended ranges may differ.
    orig = SRC.read_bytes()
    diffs = [i for i in range(len(orig)) if orig[i] != data[i]]
    allowed = (set(range(table_off, table_off + 8))
               | set(range(oem_handler_off, oem_handler_off + 8))
               | set(range(stub_off, stub_off + len(STUB))))
    stray = [i for i in diffs if i not in allowed]
    assert not stray, f"stray diffs: {stray[:16]}"
    print(f"\nchanged bytes: {len(diffs)} (all inside the three intended ranges)")

    DST.write_bytes(data)
    print(f"output: {DST}")
    print(f"output sha256: {hashlib.sha256(data).hexdigest().upper()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

