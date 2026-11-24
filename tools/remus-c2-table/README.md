# remus-c2-table

Decrypts the **hard-coded fallback C2 table** of Remus stealer payloads (the 64-bit Lumma successor). Remus tries these URLs before its EtherHiding (smart-contract) lookup on a cold boot (Malware Cake Factory, "Remus Stealer: C2 protocol" write-up), so the table gives the C2 domains of a build without touching any blockchain or attacker host.

**Static only.** The tool parses the PE with `pefile`, locates the cipher setup by byte pattern and decrypts in Python. Nothing from the sample is executed. Handle the inputs as live malware anyway.

## Layout (as found in the 14 builds we hold, 27.10-18.11.2026)

- `.rdata`: 32-byte ChaCha20 key, 8-byte nonce, then the table at key+0x30: **3 entries x 64 bytes**.
- The init routine is reached by `lea rcx,[ctx]; lea rdx,[key]; lea r8,[nonce]; xor r9d,r9d; jmp init`. It builds the state in the original DJB layout (64-bit block counter starting at 0, 64-bit nonce; not the RFC 8439 96-bit-nonce layout). The sigma constants are computed at run time from immediate pairs (`0x10a3b10f ^ 0x71d3c96a = 0x61707865`), so a scan for `expand 32-byte k` finds nothing.
- The table is one ChaCha20 stream (entry *i* = block *i*). The result is XORed with a 4-byte mask that the code builds from two immediates (a one-instruction getter `mov dword [rcx],imm` and an `imul ecx,ecx,imm` in a one-pass loop); the mask was `ef50ab47` in every build. Then each entry is a NUL-terminated `https://` URL.
- When the mask code pattern is not matched (2 of 14 builds), the tool falls back to a known-plaintext check (`http` at the start of all three entries must give one and the same mask) and says so in `mask_src`.

The routine was cross-checked by running the sample's own init and decrypt functions in bare unicorn (no OS layer, no imports): output identical to the Python code, block counter 0 -> 3 after the three entries.

```bash
uv venv && uv pip install pefile
.venv/bin/python remus_c2_table.py INNER1.bin INNER2.bin ...
.venv/bin/python test_remus_c2_table.py expected.csv DIR_WITH_<sha256>.bin [NEGATIVE_FILE ...]
```

The payloads come from the Go crypter in [`tools/cryptotrice-go-loader/`](../cryptotrice-go-loader/); [`tools/remus-cleartext/`](../remus-cleartext/) reads the build date and campaign ID of the same payloads.

## Results (2026-11-24)

- **14 of 14** Remus-class payloads: 3 URLs each, 42 URLs, **11 distinct domains** (all `https://`, no port). They are case rows in [`iocs/2026-11-cryptotrice/`](../../iocs/2026-11-cryptotrice/).
- 9 of the 11 were already on ThreatFox, tagged Remus or WARDENStealer by other reporters; `neeft[.]tattoo` and `servicesbo[.]com` were not listed and were submitted on 2026-11-24.
- The same fallback domains are labelled Remus on some ThreatFox entries and WARDENStealer on others, which supports reading the WARDEN-labelled payloads of this crypter as Remus builds.
- `test_remus_c2_table.py`: **86 passed, 0 failed** = RFC 8439 2.3.2 block vector, the 14 payloads against `expected.csv`, and 71 negatives (the 18 non-Remus payloads, the 41 Go loaders, 12 benign PEs).

## Limits

- An earlier build described publicly used a plain-HTTP fallback on a high port; this tool only reports `https://` entries and needs adapting if the URL format changes.
- The EtherHiding contract address (a separate stack-built string) is not decoded here, and no contract was read.
- Entry count 3 and the table position are observations on these builds, not a format guarantee.

Research by Harper Johns, autonomous AI security researcher with human oversight.
