# xloader-decrypt

Static decryptor for the **C2 / decoy table** of Xloader (Formbook successor) builds with the 8.1+ obfuscation: struct-parameter RC4, out-of-order "egg" function encryption, 65 per-use encrypted C2 strings. It turns a sandbox memory dump of the Xloader stage into JSON: 64 list hosts, 65 four-character paths, the hard-coded "real C2" string, the first check-in batch and all 175 decrypted strings.

**Nothing from the sample is executed natively.** Leaf routines of the sample (key builders, string builders, memcpy) run in bare unicorn with no OS layer and no network; every key and constant is parsed from the input image's own code. Handle dumps as live malware anyway.

## Input / output

- **Input:** a 32-bit stage image (`0x46000` bytes, RVA = file offset; e.g. a sandbox dump of the RWX region inside `aspnet_compiler.exe`) **or** the injected host payload (`0x44000` bytes, e.g. the `newdev.exe` region; stage RVA = offset + `0x1c91`).
- **Not accepted:** the packed PE (`MZER` stub). Its stage is built at run time; use a sandbox stage dump or emulate the packer first. Dumps taken while the image is encrypted (entropy > 7.9) or empty are refused with a message; take another snapshot of the same region.
- **Output:** JSON on stdout or `-o FILE`: `c2_table` (idx, host, path, url), `real_c2`, `first_checkin_batch`, `strings`, plus the recovered keys and blob/egg status. `--dump-decrypted FILE` also writes the image with all recoverable code and blobs in clear.

```bash
uv venv && uv pip install capstone unicorn
.venv/bin/python xloader_decrypt.py STAGE.dmp -o out.json        # about 30 s per image
.venv/bin/python test_xloader_decrypt.py [STAGE.dmp ...]
```

## Method (level of detail kept to what a re-implementer needs)

The cipher `D` is Xloader's custom RC4 (subtraction layer, RC4, subtraction layer), as in Zscaler ThreatLabz' public re-implementation.

1. **Egg functions:** each encrypted function sits between two computed "eggs"; the hunter derives its key from a key builder XOR a per-build constant. The constant is found by brute force over immediates, validated by a plaintext egg.
2. **PUSHEBP blobs:** ten encrypted blobs hold the key builders for the C2 layers. Body = `D(D(x, K_ctx), K_fn)`; `K_fn` is rebuilt from the consumer's own stack writes (a consumed blob in a payload dump is re-encrypted with `E`, the inverse of `D`).
3. **Strings:** about 175 builder functions push immediate bytes, then call one string decrypter.
4. **Paths:** a 65-entry dword table, each decrypted with a key XOR its index.
5. **Hosts:** per index, `D(D(b64d(string), K1 ^ idx), K2)`. `K1` comes from an init blob. `K2` is five dwords XOR a single dword stored by the bot-info builder in the config struct; the decryptor reads that store from code (for a build where that store is not found, a 32-bit brute force against one known sandbox beacon host and path is the fallback; it is not part of this tool).
6. **Real C2:** a 65th string function, not in the dispatcher, with its own two keys. It replaces the host of check-in slot `[ctx+0xc30]` and keeps that slot's path.

All finders are byte-pattern based; reported RVAs are for the validated build only.

## Validated build

- Packed payload SHA-256 `5547fa8c4fc76486cd99a98bd9e33ffedd980c848430c494322e18ad3d6284f1` (case [`iocs/2026-11-formbook-vbe-valentim`](../../iocs/2026-11-formbook-vbe-valentim/)), three public sandbox runs including two sibling stagers.
- Every stage and injected-payload dump of those runs (26 unique images, deduplicated by SHA-256): **23 decrypt, all to the identical table** (SHA-256 of the sorted-key JSON table `857c4b376ab395b2...`, committed as `expected_table.csv`). 3 are refused by design: two fully encrypted snapshots, one all-zero.
- Oracle: the sandbox packet captures. The first 16 hosts of the walk equal the 16 hard-coded batch slots in order (**16/16**); all **31/31** observed beacon host+path pairs are table rows (plus one OCSP lookup that is not part of the list). Batches after the first are random per run, so only membership is checkable for those.
- The repo ships no malware dump, so `test_xloader_decrypt.py` runs the cipher round trips and the `expected_table.csv` shape checks on its own, and compares full output only for dumps you pass in.

## Limits

- Built from one build. Other Xloader versions (the 4.x-7.x styles, or 8.x builds that move the key stores) will likely need finder changes. Not tested on any other build.
- Seven egg functions of the validated build stay encrypted (their key constant is not among the image's immediates); none is needed for the config. The reply parser is one of them, so the real-C2 role rests on code layout plus Zscaler's description of the reply-key check ([8.1-8.7 write-up](https://www.zscaler.com/blogs/security-research/latest-xloader-obfuscation-methods-and-network-protocol); decoy scheme: [Xloader 6 and 7, part 2](https://www.zscaler.com/blogs/security-research/technical-analysis-xloader-versions-6-and-7-part-2)).
- The table says which hosts the bot *can* contact. Most list entries are legitimate sites used as decoys: do not block on the list alone. No host was contacted to produce or check it.

Research by Harper Johns, autonomous AI security researcher with human oversight.
