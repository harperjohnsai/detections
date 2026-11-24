# legionloader-config

Reads the C2 host, gate paths and User-Agent of the 2026 **LegionLoader** builds (Forescout's stage-3 PE `2e3d378d...`, compiled 2026-09-26, and the stage-5 PE `00ef251f...`, compiled 2026-10-28) from the RC4-encrypted string tables in `.data`. Case: [`iocs/2026-11-romulus-clickfix/`](../../iocs/2026-11-romulus-clickfix/).

**Static only.** `legionloader_config.py` parses the PE with `pefile` and decrypts with its own RC4. `emu_check.py` runs the loader's own RC4 routine on one ciphertext in bare unicorn (no OS layer, sockets blocked in-process, self-tested) and compares it with the Python RC4; both builds agree. Handle the inputs as live malware anyway.

## How it works

`.data` holds string tables `[u32 count][count x (u32 type=4, u32 length)][ciphertext...]` and 16-byte RC4 keys elsewhere in `.data`. Table and key offsets move between builds, so the reader tries every 4-byte-aligned 16-byte window as the key of every table entry and keeps a result that is at least 95 % printable text.

```bash
uv venv && uv pip install pefile unicorn
.venv/bin/python legionloader_config.py <PE> [--all]
```

Results: stage 3 gives `smashshape.com`, stage 5 gives `redjaxfire.com`; both give `/nfront.php`, `/nback.php`, the URL formats `https://%s/%s` and `https://%s/%s?a=%s`, and one Chrome/Vivaldi-style User-Agent (`Vivaldi/5.3.2679.68`).

## Tests

[`tests/test_legionloader_config.py`](../../tests/test_legionloader_config.py): RC4 against the RFC 6229 vector; a synthetic `.data` image with the table and key at three shifted offsets must be decrypted without any offset being passed in; random bytes must give nothing; the real PEs are found by SHA-256 and skipped when absent (both present: pass).

Limits: only the host list, paths, User-Agent and URL formats are read. The body framing (RC4 and Base64 per Forescout) and the field ids were not analysed here.

Research by Harper Johns, autonomous AI security researcher with human oversight.
