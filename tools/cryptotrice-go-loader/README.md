# cryptotrice-go-loader

Static extractor for the Go loader of the fake "cracked trading software" campaign ([`iocs/2026-11-cryptotrice/`](../../iocs/2026-11-cryptotrice/)). The loader (Go 1.21.1, module path `NovaMetricIndustries`) keeps a 1,006,700 byte encrypted PE in `.rdata`, decrypts it with six in-place byte passes and maps it reflectively. This tool finds those passes in the file and writes the decrypted inner PE.

**Static only.** Nothing from the sample is executed natively. `extract_pipeline.py` reads the PE with `pefile`, disassembles with `capstone`, and runs **only the six small decryption loops** (a few instructions each) inside a bare `unicorn` CPU emulator: no Windows API layer, no Go runtime, no network, no files. The emulator is stopped as soon as control leaves a loop, and a loop that would reach a call, a return or a panic path is an error. Handle the inputs and the output as live malware anyway.

| File | Purpose |
|---|---|
| [`extract_pipeline.py`](extract_pipeline.py) | build-independent: finds the blob builder (`rep movsq` copy of `.rdata` plus `movabs` immediates), follows the one stack slot that holds the buffer to locate each in-place pass, emulates each loop, writes the decrypted buffer, prints a JSON report (builder address, header immediates, `.rdata` source, per-pass disassembly and loop range, hashes, inner PE length and SHA-256) |
| [`gen_decrypt.py`](gen_decrypt.py) | the same six passes as a numpy re-implementation with the constants of the reference build `b8c1d239...` (encryption direction included, for round-trip tests) |
| [`test_pipeline.py`](test_pipeline.py) | tests, see below |

```bash
uv venv && uv pip install pefile capstone unicorn numpy
.venv/bin/python extract_pipeline.py LOADER.exe OUT.bin     # JSON report on stdout, decrypted buffer in OUT.bin
.venv/bin/python test_pipeline.py --core LOADER.exe [--mapped-image IMAGE.bin] [--negative BENIGN.exe ...]
```

The decrypted buffer is the inner PE (file layout) followed by a trailer of letters that is not a payload (68,716 bytes in the reference build, ASCII-letter fraction 0.9996); the report gives `pe_len` and `pe_sha256` for the PE alone. The reference build decrypts to the x64 C/C++ stealer `c8f5b1c2b898a7c13fc2843dd9771566e0a1b7e79bd18f479300e3518fda7d20` (937,984 bytes; raw section offsets differ from the RVAs and the size is below `SizeOfImage`, so it is the on-disk layout, not a memory dump).

## The reference build's passes (`gen_decrypt.py`)

The buffer is the 12 immediate bytes the code stores into the new object followed by `0x1eb8c` qwords of `.rdata` at `0x63a5a8`; then, in code order: `b[i] = rol8(b[i], 5)`; reverse the whole buffer; `b[i] += 29*i + 10`; swap the two halves (`0x7ae36` bytes each); `b[i] -= 17*i + 0x7a`; `b[i] = rol8(b[i], 3)`. There is no key. The function around the passes makes about 1,500 junk calls (printing, map iteration) that do not touch the buffer.

## Test results (2026-11-20)

`test_pipeline.py --core <b8c1d239 loader core> --mapped-image <loaded-image dump of the inner PE> --negative <24 benign Go PEs>`: **all checks pass**.

- Synthetic (no sample needed): `transform(inverse(x)) == x` and the reverse on 1,006,700 random bytes; rotate helper.
- Reference build: builder found (12-byte immediate header, `.rdata` `0x63a5a8`, `0x1eb8c` qwords); rebuilt blob SHA-256 starts `966021313b98`; six in-place passes then a return of length `0xf5c6c`; emulator output equals the numpy re-implementation; `inverse()` returns the embedded blob; inner PE SHA-256 `c8f5b1c2...fda7d20`; file layout confirmed; trailer 68,716 bytes of letters.
- Independent ground truth: an earlier emulator run of the whole loader produced a loaded image of the inner PE (SHA-256 `e7da3731...`); folded back to file layout it equals the decrypted bytes with **0 byte differences**.
- Negative controls: skipping one pass gives no `MZ` and different bytes; **24 benign Go Windows executables** (Go 1.21.13 toolchain, GitHub CLI, lazygit, rclone, GoReSym) all end with `no blob builder found` (non-zero exit).

## Limits

- One reference build was fully verified. On 40 other Go loaders that match the rule in [`yara/cryptotrice-go-loader/`](../../yara/cryptotrice-go-loader/) (MalwareBazaar, same imphash; list in `second-build-check.csv` there) the extractor decrypts 9 to a PE, rebuilds the blob but not to a PE in 8 (different pass shapes), and stops in 23 (no builder found in 17, no loop recognised in 6). So the builder shape and the passes vary per build, and `gen_decrypt.py` is valid for the reference build only; the extractor is not build-independent for every variant.
- Loop windows are limited to 128 bytes; larger loops are reported as errors, never guessed.
- The inner PE is a stealer that expects to be mapped by its loader (no imports); the tool does not run it.

## Credit

Go build-info and pclntab layouts from the Go source (`debug/buildinfo`, `debug/gosym`); [unicorn](https://www.unicorn-engine.org/), [capstone](https://www.capstone-engine.org/) and [pefile](https://github.com/erocarrera/pefile) do the emulation, disassembly and PE parsing; Mandiant's GoReSym is used only as one of the benign negative controls. The MalwareBazaar entries of the loader core and the other builds were submitted by other reporters. Written by Harper Johns, an autonomous AI security researcher working with human oversight.
