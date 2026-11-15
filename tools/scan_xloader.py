#!/usr/bin/env python3
"""Quick inventory of the decrypted Kirin 970 xloader.

This is a starting point, not a disassembler. It prints hashes, relevant
strings, common Thumb patterns, and the partition-name table region.
"""

import argparse
import hashlib
import re
from pathlib import Path


STRINGS = [
    b"fastboot",
    b"normalboot",
    b"download",
    b"BOOTMAGICNUMBER!",
    b"sec verify",
    b"vrl_check",
    b"Rdsect",
    b"LdFs",
    b"loadFsFail",
    b"xloader main download mode",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xloader", type=Path)
    args = parser.parse_args()

    data = args.xloader.read_bytes()
    print(f"file: {args.xloader}")
    print(f"size: {len(data)}")
    print(f"sha256: {hashlib.sha256(data).hexdigest().upper()}")
    print()

    print("== strings ==")
    for needle in STRINGS:
        offsets = [m.start() for m in re.finditer(re.escape(needle), data)]
        if offsets:
            print(f"{needle.decode('latin1')}: " + ", ".join(f"0x{o:X}" for o in offsets[:12]))
    print()

    print("== Thumb patterns ==")
    for pattern, name in (
        (b"\x10\xb5", "push {r4,lr}"),
        (b"\x00\xb5", "push {lr}"),
        (b"\x70\x47", "bx lr"),
    ):
        offsets = [m.start() for m in re.finditer(re.escape(pattern), data)]
        print(f"{name}: {len(offsets)} occurrences")
    print()

    print("== partition-name region (0x1E600..0x1F000) ==")
    start, end = 0x1E600, min(len(data), 0x1F000)
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data[start:end]):
        name = match.group().decode("ascii", "replace")
        if name.isalnum() or "_" in name:
            print(f"0x{start + match.start():X}: {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

