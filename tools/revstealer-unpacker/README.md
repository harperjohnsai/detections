# revstealer-unpacker

```bash
uv venv && uv pip install pefile capstone unicorn cryptography
.venv/bin/python inner_unpack.py <inner_payload.bin> <outdir>
```

Input is the output of `setup-center-extractor`. Output: `config.json` (C2, dead drops, contract, all decrypted strings), a copy of the PE with every string patched to cleartext, and the embedded helper DLL. String decryption runs the sample's own leaf routines in the Unicorn CPU emulator (no OS layer, no network). Re-running on the reference payload reproduces the same files byte for byte.
