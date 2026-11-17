#!/usr/bin/env python3
"""B2a VCOM loader: null + stock xloader + UCE + stock container + patched
factory fastboot, in one session.

The stock container is written to 0x16000000; the patched factory fastboot is
written to 0x16800000 last, so the xloader hands off after all payloads are in
RAM. No flash, no partition write.
"""

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import vcom_read as vr  # noqa: E402

REPO = HERE.parent


def read_file(path: Path, label: str) -> bytes:
    if not path.exists():
        raise SystemExit(f"missing {label}: {path}")
    return path.read_bytes()


def main() -> int:
    ap = argparse.ArgumentParser(description="B2a VCOM loader (RAM only)")
    ap.add_argument("--port", default="COM8")
    ap.add_argument("--null", default=str(REPO / "artifacts" / "hisi970_null.bin"))
    ap.add_argument("--xloader", default=str(REPO / "artifacts" / "hisi970_xloader.bin"),
                    help="stock xloader (pwn target)")
    ap.add_argument("--uce", default=str(REPO / "artifacts" / "hisi970_uce.bin"))
    ap.add_argument("--stage", default=str(REPO / "build" / "fastboot.stock.container.img"),
                    help="stock fastboot container (work/fastboot.img)")
    ap.add_argument("--stage-addr", type=lambda s: int(s, 0), default=0x16000000)
    ap.add_argument("--fastboot", default=str(REPO / "build" / "hisi970_fastboot_b2a.bin"),
                    help="patched factory fastboot")
    ap.add_argument("--ack-timeout", type=float, default=10.0)
    ap.add_argument("--settle", type=float, default=5.0)
    args = ap.parse_args()

    null = read_file(Path(args.null), "null loader")
    xloader = read_file(Path(args.xloader), "stock xloader")
    uce = read_file(Path(args.uce), "UCE")
    stage = read_file(Path(args.stage), "stock container")
    fastboot = read_file(Path(args.fastboot), "patched factory fastboot")

    print("B2a RAM-only loader")
    print(f"  null     : {len(null)} B -> 0x{vr.NULL_ADDR:08X}")
    print(f"  xloader  : {len(xloader)} B -> 0x{vr.XLOADER_ADDR:08X} (pwn)")
    print(f"  uce      : {len(uce)} B -> 0x{vr.UCE_ADDR:08X}")
    print(f"  stage    : {len(stage)} B -> 0x{args.stage_addr:08X}")
    print(f"  fastboot : {len(fastboot)} B -> 0x{vr.FB_ADDR:08X}")

    dev = vr.Vcom(args.port, verbose=True, ack_timeout=args.ack_timeout)
    dev.send_start_frame()
    dev.upload("null", null, vr.NULL_ADDR, pwn=False)
    dev.upload("xloader", xloader, vr.XLOADER_ADDR, pwn=True)
    dev.upload("uce", uce, vr.UCE_ADDR, pwn=False)
    dev.upload("stage", stage, args.stage_addr, pwn=False)
    dev.upload("fastboot", fastboot, vr.FB_ADDR, pwn=False)

    s = dev.ack_stats
    print(f"ACKs: {s['ack']} ok, {s['nak']} NAK, {s['none']} no-ack")
    if s["ack"] == 0 and s["none"] > 0:
        print("WARNING: no ACKs; check VCOM/port/flow control before retrying")
    print(f"waiting {args.settle:.1f}s for the factory fastboot...")
    time.sleep(args.settle)
    print("done. The factory fastboot should now be running; use fastboot.exe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

