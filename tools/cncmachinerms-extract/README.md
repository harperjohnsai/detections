# cncmachinerms-extract

Config extractor for the CNCMachineRMS RAT's "Storage" container (ROMULUS `execute_engine_disconnect.raw`, BabaDeda `load.db`, MSI-extracted `fil*` files, any `.bak/.db/.bin/.dat/.raw` with the loader config), or for an already decrypted RAT core (class 16100). Case: [`iocs/2026-11-romulus-clickfix/`](../../iocs/2026-11-romulus-clickfix/).

**Static only.** The tool parses bytes; nothing from a sample runs natively. `emu_validate.py` maps the decoded loader shellcode into a bare unicorn x86-64 instance (no OS layer, sockets blocked in-process and self-tested) and calls four of the loader's own routines on the container. Handle the inputs as live malware anyway.

## What it does

1. `scan_headers` finds the 0x78-byte header at any offset: three equations on the first qwords give the per-build key `K` (`K = (q1 - 7*q0) / 3`, `q5 = q1 - 37*(q0 + K)`, `q6 = (q0 + K + 1)*(q5 + 1)`; the first two are LevelBlue's published equations).
2. Layer 1: the 0x58-byte record tree (node, parent, property, blob offset/length).
3. Layer 2: the per-blob XOR. Its parameter set is per build: `loader3`, `baba-loader`, `rat-embedded`, `off7`, `fi-loader`, or `learned` (the tool fits an unseen set from the container itself with numpy). For the Canon-chain container the header and key `K` are recovered, but its layer 2 is **not** reproduced (reported as `unresolved`, no gate).
4. Resource entries (property 16050) give the settings; gate list entries (16070) give host and port; blob 16001 is the controller script, 16100 the RAT core.

```bash
uv venv && uv pip install pefile numpy unicorn
.venv/bin/python cncmachinerms_extract.py <container> [--dump-payload DIR] [--dump-script DIR]
.venv/bin/python builddat_decode.py <Build.dat> [--offset N --length N]     # Stardock chain shellcode
.venv/bin/python emu_validate.py <shellcode.bin> <container> <K hex>        # needs unicorn
```

Output: JSON with `K`, the layer-2 variant, persistence names, payload SHA-256, gates (`host:port`), campaign id, timers and flags.

## Validation (2026-11-24)

[`tests/test_cncmachinerms_extract.py`](../../tests/test_cncmachinerms_extract.py): synthetic containers are built from the inverse of the decode formulas (one per layer-2 set plus an unseen set that must be learned) and must round-trip; a random buffer must give no header. With samples present: ROMULUS Stardock, numeric MSI `3`, FilesInspectorX, AllMyBasic and BabaDeda `load.db` give the keys and gates in the case README; the Canon container is expected `unresolved`.

Honest limits: only the Stardock layer-2 parameters were checked against the loader shellcode's own routines (`emu_validate.py`). The other builds' parameters were fitted (numeric MSI `3`, FilesInspectorX, BabaDeda) or learned (AllMyBasic); their configs decode to readable, consistent values, which is evidence but not an emulator proof. The type-hash and property numbers come from the builds we hold.

Research by Harper Johns, autonomous AI security researcher with human oversight.
