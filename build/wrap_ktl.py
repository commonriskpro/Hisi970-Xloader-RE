#!/usr/bin/env python3
"""Wrap/unwrap Kirin-Tool .ktl loaders using the key the tool itself carries.

The tool ships its RSA-2048 private key inside Kirin-Tool.dll as a UTF-16 string
that is base64-encoded several times. This script finds it, loads it, and reuses
the container format:

    BE16 len | RSA-OAEP(SHA-256) wrapped AES key | 16-byte IV | AES-CBC/PKCS7 payload

That is enough to hand the tool any patched bootloader: wrap the image, drop it
in <tool>/loaders/<cpu>/fastboot.ktl (keep the original as .orig), and the tool
uploads it through its normal, working path.

    python3 build/wrap_ktl.py --dll "C:\path\Kirin-Tool.dll" --wrap img.bin img.ktl
    python3 build/wrap_ktl.py --dll ... --unwrap img.ktl out.bin
    python3 build/wrap_ktl.py --dll ... --key     # just show the key fingerprint
"""

import argparse
import base64
import hashlib
import os
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("needs the 'cryptography' package (pip install cryptography)")

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
AES_KEY_LEN = 32


def load_key(dll_path: Path):
    blob = dll_path.read_bytes()
    pat = re.compile(rb"(?:[A-Za-z0-9+/=]\x00){300,}")
    for m in pat.finditer(blob):
        value = m.group().decode("utf-16-le", "ignore")
        if not value.startswith("VkVa"):      # observed prefix of the encoded key
            continue
        layers = 0
        while not value.startswith("-----BEGIN"):
            value = base64.b64decode(value).decode()
            layers += 1
            if layers > 12:
                break
        pem = value.encode()
        return serialization.load_pem_private_key(pem, password=None), layers, pem
    raise SystemExit(f"no embedded key found in {dll_path}")


def wrap(plain: bytes, key) -> bytes:
    aek = os.urandom(AES_KEY_LEN)
    iv = os.urandom(16)
    pad = 16 - (len(plain) % 16)
    enc = Cipher(algorithms.AES(aek), modes.CBC(iv)).encryptor()
    edta = enc.update(plain + bytes([pad]) * pad) + enc.finalize()
    eaek = key.public_key().encrypt(aek, OAEP)
    return len(eaek).to_bytes(2, "big") + eaek + iv + edta


def unwrap(data: bytes, key) -> bytes:
    eklen = (data[0] << 8) | data[1]
    eaek = data[2:2 + eklen]
    iv = data[2 + eklen:2 + eklen + 16]
    edta = data[2 + eklen + 16:]
    aek = key.decrypt(eaek, OAEP)
    dec = Cipher(algorithms.AES(aek), modes.CBC(iv)).decryptor()
    plain = dec.update(edta) + dec.finalize()
    pad = plain[-1]
    if 1 <= pad <= 16 and plain.endswith(bytes([pad]) * pad):
        plain = plain[:-pad]
    return plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", required=True, help="path to Kirin-Tool.dll")
    ap.add_argument("--key", action="store_true", help="print key fingerprint only")
    ap.add_argument("--wrap", nargs=2, metavar=("IN", "OUT"))
    ap.add_argument("--unwrap", nargs=2, metavar=("IN", "OUT"))
    args = ap.parse_args()

    key, layers, pem = load_key(Path(args.dll))
    print(f"key: RSA-{key.key_size}, {layers} base64 layers, "
          f"sha256 {hashlib.sha256(pem).hexdigest().upper()[:32]}")

    if args.key:
        return 0
    if args.wrap:
        src, dst = map(Path, args.wrap)
        plain = src.read_bytes()
        out = wrap(plain, key)
        dst.write_bytes(out)
        ok = unwrap(out, key) == plain
        print(f"wrapped {src} ({len(plain)} B) -> {dst} ({len(out)} B)")
        print(f"round-trip identical: {ok}")
        return 0 if ok else 1
    if args.unwrap:
        src, dst = map(Path, args.unwrap)
        plain = unwrap(src.read_bytes(), key)
        dst.write_bytes(plain)
        print(f"unwrapped {src} -> {dst} ({len(plain)} B) "
              f"sha256 {hashlib.sha256(plain).hexdigest().upper()}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
