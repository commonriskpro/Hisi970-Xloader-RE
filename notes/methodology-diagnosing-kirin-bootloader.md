# How to diagnose this bootloader without guessing

A method note, not a findings note. Every technique here was used at least once on
2026-11-15 and produced a decision that would otherwise have been a guess. The addresses are
for `artifacts/hisi970_fastboot_ram.bin` (base VA 0x16800000) and will shift between builds,
but the techniques do not.

---

## 0. The rule

Never conclude from a command's *message*. Conclude from memory you read back, or from a
control experiment. Twice in one day a plausible-looking output (`OKAY`, `verify fail`) meant
something other than what it appeared to mean.

---

## 1. Know your instrument panel

| instrument | reads | writes | notes |
|---|---|---|---|
| `oem memupload <addr> <len> <file>` | **any RAM** | no | the single most useful primitive; works in the service bootloader |
| `fastboot flash <part> <file>` (vendor Ultraflash) | no | partitions | `Sending ... OKAY` / `Writing ... OKAY` |
| tool partition dump / `fastboot fetch` | partitions | no | `fetch` is broken on this firmware (`couldn't parse max-fetch-size '0.5'`) |
| the `rrecord` partition | the bootloader's own boot log, plain ASCII | no | survives a reset, so it is the only record of a failed boot |
| a stub that writes to a scratch cell | — | RAM | how you instrument code you cannot print from |

Scratch for instrumentation: `0x16801600` (inside the code cave, zero in the file).

---

## 2. The ladder: cheapest test first

**Step 1 — is my code even running?**
Patch a word you can read back. After loading, read the site:

    oem memupload 0x168ADC0C 0x4 out.bin     # expect 00 00 80 52 after the AVB patch

This single check splits the two worlds that look identical from the host: "the patch is not
loaded" vs "the patch is loaded and does not do what I hoped". Both happened today.

**Step 2 — did my command handler run?**
Hook a handler entry with a stub that answers OKAY through `0x1680AC6C`. If the command stops
printing its old message, the hook ran. Do not hook a handler that *hangs*: you lose the loop
and with it every instrument.

**Step 3 — what did the code decide?**
Have the stub store return codes into consecutive cells, then read the cells:

    cells[i] = w0 after each call;  read with oem memupload <cells> <4*(n+1)> file.bin

This is how the service bootloader's own state can be inspected without a serial console.

**Step 4 — what did the bootloader log?**
If the device resets, dump `rrecord` with the tool and grep it. It contains the full
`[cpu0][<ms>]` log of the last boot, including module init results and every failure string.
`dfx` looks similar but is obfuscated on this firmware and is not worth decoding.

**Step 5 — instrument the flow.**
Put markers at the stages you suspect and read them afterwards. A marker at a function entry
is a stub that writes a magic word and then executes the original prologue and branches to
the original body. This answers "how far did it get" instead of "why did it fail".

---

## 3. Control experiments

- **Write path**: before writing anything risky, flash a byte-identical copy of the partition
  and let it boot. That separates "our write is broken" from "our image is rejected".
- **Modified kernel (G1)**: change the *smallest* thing (17 bytes inside the cmdline field of a
  fixed-size header) so that a rejection can only be caused by verification, never by a
  broken repack.
- **A/B on the same variable**: run `oem check-image` before and after a change. If the answer
  does not move, the thing you changed is not the thing it reads.

---

## 4. Traps that produce confident wrong answers

1. **The response dispatcher has three behaviours, not two.** `0x1680AC6C(msg, type)`:
   `0 = OKAY`, `1 = FAIL`, **anything else = transmit nothing**. A stub that ends with type 2
   makes the host print the *stock* answer (from a previous command) and then desynchronises
   the session, which reads exactly like "my patch was ignored".
2. **A NULL message crashes the OKAY path.** `0x1680AA54` initialises the response buffer and
   is only reached when `msg != NULL`. Always pass the stock `"OKAY"` string.
3. **A file-table patch is not a runtime patch.** Repointing the oem dispatch table entry in
   the image did nothing; the live dispatch does not read that table. Patch the *handler
   entry point* instead.
4. **Three copies of the loaders exist on disk.** The service tool reads
   `<its cwd>/loaders/<cpu>/fastboot.ktl`; the shortcut runs the build under
   `Kirin-Tool-LockDiag/bin/Release/net8.0-windows/`. Patching another copy is silent.
   Verify by unwrapping the file the tool will actually load and comparing hashes.
5. **`oem check-image` is not the AVB check.** It reads a different state and says `fail` even
   with the AVB verdict patched. Do not use it as a regression test for AVB.
6. **A reset destroys everything.** Commands whose names suggest booting (`reboot`, and the
   `reboot_enter_normal` family) set a reason and reset the SoC; the RAM image is gone and the
   unpatched flash bootloader runs. Any in-place experiment must never reset.
7. **A command that "hangs" may have jumped.** After a successful handoff the fastboot
   protocol dies but USB keeps enumerating; `no link` on the next command can mean success,
   not failure. Distinguish by watching the screen, not the host.

---

## 5. Verified facts that make the ladder faster next time

- `0x1680AC6C(msg, type)` — response dispatcher; `0x169B7E40` is the `"OKAY"` string.
- Code cave at `0x168011D0`, 1584 zero bytes, used for every stub.
- Handler entries: `oem check-image` = `0x16816488`, `oem memcpy_count` = `0x16814BC8`,
  `ufs_test` = `0x16810D60`, `onchiprom_download` = `0x16812534`.
- Response/verdict globals: bootloader mode struct behind `0x16B89E30` -> `0x16BAE480` ->
  real struct at `0x16B0F030`; AVB publishes `0xA5A5A5A5` on success.
- Mode table at `0x16B12B30` (name, function, stride 0x18).
- The service bootloader is `hisi970/fastboot.ktl` = `artifacts/hisi970_fastboot_ram.bin`;
  re-wrap with `build/ktl.py --wrap` to load a patched copy through the tool.

---

## 6. Reusable recipes

**Is the loaded bootloader mine?**

    oem memupload <patched offset> 0x10 x.bin   # compare against the file

**What is the bootloader's mode state?**

    read qword @0x16B89E30 -> p1 ; read qword @p1 -> p2 ; read 0x10 @p2

**Why did the last boot fail?**

    tool -> dump rrecord -> strings | grep -i 'fail|verify|bootfail|secureboot'

**Did code path X execute?**

    marker stub at X's entry (write magic to 0x16801600+n), then read the cells

**Does my patch survive?**

    read the patched address; if it shows the original bytes, the image was not the one loaded
