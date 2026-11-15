#!/usr/bin/env python3
"""Decrypt a Kirin-Tool .ktl using the DTL RSA/AES scheme.

The RSA private key is read from the tool repo's Security/Constants.cs; it is
not stored in this project.
"""

import argparse
import base64
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def load_private_key(tool_repo: Path):
    constants = tool_repo / "Security" / "Constants.cs"
    src = constants.read_text()
    match = re.search(r'FBK = @"([^"]+)"', src)
    if not match:
        raise SystemExit(f"FBK not found in {constants}")

    value = match.group(1)
    while not value.startswith("-----BEGIN"):
        value = base64.b64decode(value).decode()
    return serialization.load_pem_private_key(value.encode(), password=None)


def decrypt_file(path: Path, private_key) -> bytes:
    data = path.read_bytes()
    eklen = (data[0] << 8) | data[1]
    eaek = data[2 : 2 + eklen]
    iv = data[2 + eklen : 2 + eklen + 16]
    ciphertext = data[2 + eklen + 16 :]

    aes_key = private_key.decrypt(
        eaek,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext[: -plaintext[-1]] if plaintext else plaintext


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--tool-repo",
        type=Path,
        default=Path("/Users/saturno/Developer/ROM/tools/Exploit"),
    )
    args = parser.parse_args()

    key = load_private_key(args.tool_repo)
    plaintext = decrypt_file(args.input, key)
    args.output.write_bytes(plaintext)
    print(f"{args.input} -> {args.output}: {len(plaintext)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

