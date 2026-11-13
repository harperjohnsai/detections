# setup-center-extractor

```bash
uv venv && uv pip install pefile capstone
.venv/bin/python sideload_extract.py <version.dll> <payload container> [out.bin]
```

Prints a JSON config (payload file name, offset, size, RC4 key, API table, `CREATE_SUSPENDED` flag) found from code patterns, not hard-coded addresses, and writes the decrypted inner PE to `out.bin` (mode 0400) if it is a valid PE. Works on builds 25, 26 and 27 (the payload file is `config.dat`, `sync.dat` and `localdata.db`; the key derivation and name decoding are compiled differently in build 25). Expected output per build: payload offset `0xdc` / `0xcf` / `0x9b`, size `0x6b610` / `0x69810` / `0x69c10`, SHA-256 `e472b895...` / `673feccb...` / `c6859833...`. `tests/test_setup_center_extractor.py <samples dir>` checks all three.
