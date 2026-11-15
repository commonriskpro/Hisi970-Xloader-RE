import subprocess, time, os

FB = r"C:\Users\me\Desktop\Kirin-Tool-v2.4.2 (1)\fastboot\fastboot.exe"
OUT = r"C:\Users\me\b2a_probe"
os.makedirs(OUT, exist_ok=True)


def run(args, timeout=25):
    t = time.time()
    print("$ fastboot " + " ".join(args))
    try:
        p = subprocess.run([FB] + args, capture_output=True, timeout=timeout, cwd=OUT)
        out = (p.stdout + p.stderr).decode("utf8", "replace")
        out = out.replace("\b", "")
        keep = [l for l in out.splitlines() if l.strip() and "Transporting" not in l and "Complete!" not in l]
        print("  -> rc=%d t=%.2fs" % (p.returncode, time.time() - t))
        for line in keep:
            print("     " + line)
    except subprocess.TimeoutExpired:
        print("  -> NO RESPONSE / timeout %.0fs" % timeout)
    print("-" * 70)


def dump(name):
    path = os.path.join(OUT, name)
    if not os.path.exists(path):
        print("  !! %s not written" % name)
        print("-" * 70)
        return None
    b = open(path, "rb").read()
    print("  %s: %d bytes" % (name, len(b)))
    for i in range(0, min(len(b), 0x40), 16):
        print("    +%03x  %s" % (i, b[i:i + 16].hex(" ")))
    print("-" * 70)
    return b


print("=" * 70)
print("STEP 0: device + candidate scratches readable?")
run(["devices"])
run(["oem", "memupload", "0x16600000", "0x10", "pre_dram.bin"])
dump("pre_dram.bin")
run(["oem", "memupload", "0x16b8f1f8", "0x10", "pre_bss.bin"])
dump("pre_bss.bin")

print("STEP 1: respond-only stub (memory untouched)")
run(["oem", "memcpy_count", "0x16000000"], timeout=20)

print("STEP 2: DRAM store candidate 0x16600000")
run(["oem", "chipid"], timeout=20)
run(["oem", "memupload", "0x16600000", "0x10", "post_dram.bin"])
dump("post_dram.bin")

print("STEP 3: image-data store candidate 0x16b8f1f8")
run(["oem", "ufs_test"], timeout=20)
run(["oem", "memupload", "0x16b8f1f8", "0x10", "post_bss.bin"])
dump("post_bss.bin")

print("STEP 4: decrypt stub")
run(["oem", "onchiprom_download", "0x16000000"], timeout=60)
run(["oem", "memupload", "0x16600010", "0x30", "dec.bin"])
dump("dec.bin")

print("STEP 5: session sanity")
run(["oem", "memupload", "0x16800000", "0x40", "hdr.bin"])
dump("hdr.bin")
print("done")
