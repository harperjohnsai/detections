# setup-center-extractor

```bash
uv venv && uv pip install pefile capstone
.venv/bin/python sideload_extract.py <version.dll> <localdata.db> [out.bin]
```

Prints a JSON config (payload file name, offset, size, RC4 key, API table, `CREATE_SUSPENDED` flag) found from code patterns, not hard-coded addresses, and writes the decrypted inner PE to `out.bin` (mode 0400) if it is a valid PE. Expected output for the reference samples: payload offset `0x9b`, size `0x69c10`, SHA-256 `c6859833...`.
