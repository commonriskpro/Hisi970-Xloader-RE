# B2 live validation — factory fastboot memory dump

Date: 2026-11-15. Device: P20 EML-L09, factory fastboot loaded via VCOM/RAM.
No flash, no partition write.

## Result

The factory fastboot was loaded with the existing VCOM reference flow
(`null` + stock xloader + UCE + factory fastboot), then the host-side
`fastboot.exe` was used. The device enumerated as fastboot and the built-in
memory-dump command worked:

```text
fastboot oem memupload 0x16800000 0x1000 mem16800000_1000.bin
```

- 4096 bytes returned, SHA256
  `B7AFCAF01595C983812BE9E90392E23B5F64005A1E2DB7A6EBE099A60ADCD155`.
- Byte-identical to `artifacts/hisi970_fastboot_ram.bin[0:0x1000]`
  (AArch64 vectors, `0x16800000` at +0x20, `BOOTMAGICNUMBER!` at +0x24).
- Saved as `notes/poc/b2-mem-16800000-1000.bin`.

More read-only probes:

| Address | Length | Result | Evidence |
|---|---|---|---|
| `0x16dfe000` | `0x1000` | OK; header contains ASCII `fastbkj4` at +0x1C | `notes/poc/b2-mem-16dfe000-1000.bin` |
| `0x16000000` | `0x10` | OK; bytes `ff` x16 | `notes/poc/b2-mem-16000000-10.bin` |
| `0x10000000` | `0x10` | OK; bytes `00` x16 | `notes/poc/b2-mem-10000000-10.bin` |

`getvar memory_num` = 7; `memory_info_0..6` = app, modem, modem_share, dump,
iom3, hifi, teeos.

## Conclusion

The factory fastboot runs at EL3 with its own MMU and **can read the DRAM
window** that the 32-bit xloader cannot. `oem memupload` is the host primitive;
no custom USB client is needed. B2 T1/T2/T3 are passed.

The remaining problem is the stock plaintext: the factory fastboot must decrypt
the stock image (B2a: `hisi_secboot_decrypt_encrypted_xloader` 0x16989D30) or
the xloader must materialise it in a second buffer (B2b: P-A/P-B).

The phone can stay in fastboot for read-only tests; any reboot requires loading
the factory fastboot again.

