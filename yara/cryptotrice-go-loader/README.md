# cryptotrice-go-loader

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_Go_Reflective_PE_Loader_Win64` | [cryptotrice_go_reflective_loader.yar](cryptotrice_go_reflective_loader.yar) | 64-bit Go PE that maps an embedded encrypted PE into its own process: Go build info, all five API names a manual PE mapper needs (`RtlAddFunctionTable`, `NtQueryInformationThread`, `CreateActCtxW`, `ActivateActCtx`, `VirtualProtect`) as plain Go string data, `kernel32.dll` as the only import | `dcb302d9a9b0cc9cc731b3012ab71161` |

Reference build: the loader core of the fake "cracked trading software" campaign, see [`iocs/2026-11-cryptotrice/`](../../iocs/2026-11-cryptotrice/) (Go 1.21.1, module path `NovaMetricIndustries`, self-signed certificate "Nova Metric Industries"). The companion extractor is [`tools/cryptotrice-go-loader/`](../../tools/cryptotrice-go-loader/). The rule is deployed to YARAhub under the same name.

## Second-build check (2026-11-20)

Question: is the loader a single build? Method: MalwareBazaar API `get_subjectinfo` and `get_issuerinfo` for the certificate name, `get_imphash` (`4f2f006e2ecf7172ad368f8289dc96c1`, the loader's imphash), `get_tlsh`; then the 41 results of that imphash set that were first seen between 2026-10-25 and 2026-11-18 and are 3 to 5.6 MB were downloaded (one request every 2 s, 40 downloaded the same day, one retried after an HTTP 502), checked against their SHA-256, scanned in memory with the rule, and run through the extractor. Nothing was executed. YARAify `get_imphash` (`search_term` = the imphash, newest 100 results, first seen 2026-11-15 to 2026-11-19) lists 87 hashes that are not in the MalwareBazaar set (30 of them 3 to 5.6 MB); they were counted but not downloaded, to keep the request volume small. `get_tlsh` returned nothing.

- **Same publisher name:** `get_subjectinfo` for "Nova Metric Industries" returns two samples, both first seen 2026-11-12: `2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da` (MalwareBazaar label Vidar, certificate serial `c8266838e802d8aac116a9e17091e50c`) and `7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b` (RemusStealer, serial `a3741edb166866f2289eb6b6b23bfea7`). The reference build's serial is `5482c4e6a626e5594081864c6bf92287`, so all three certificates differ in serial. Both samples match the rule; the extractor decrypts them to PEs of 937,984 bytes (SHA-256 `6276b87c...`, same length as the reference build's inner PE, different content) and 251,392 bytes.
- **Rule on the imphash set:** **all 41 samples match** (the reference build and 40 others), all contain a Go build-info blob and all five API names. MalwareBazaar labels on the 40 others: Vidar 20, WARDENStealer 13, RemusStealer 3, Stealc 1, AokigaharaStealer 1, none 2. Labels from third parties are leads, not attribution: the rule describes a loader class that more than one label uses, not the one build. The per-sample table is [`second-build-check.csv`](second-build-check.csv).
- **Blob decryption is not shared:** the extractor finds the builder and decrypts to a PE in 9 of the 40, rebuilds the blob but not to a PE in 8, and stops in 23. Where it runs, the header, blob size and passes differ from the reference build.

## Testing

Run 2026-11-20 with yara-python 4.5.4 and YARA-X 1.23.0 (`tests/run_yara_tests.py --samples <dir> --negatives <dir>`):

- Positives: the reference loader core and the two "Nova Metric Industries" builds each hit exactly this rule (no other rule in the repository fires on them), on both engines. The other 38 imphash-set samples also hit (table above).
- Negatives: **0 hits on 24 benign Go Windows executables** (Go 1.21.13 toolchain: `go`, `gofmt` and 17 tools; GitHub CLI, lazygit, rclone, GoReSym; 21 of them byte-identical to the corpus of the earlier 0/23 run, GitHub CLI and lazygit replaced by current releases) and **0 hits on 983 other executables, DLLs and binary blobs from this author's other malware cases** (checked with both engines). Four of the earlier benign Go binaries contain `RtlAddFunctionTable` and `VirtualProtect`; none contains the other three names.
- A real CAB and the other repository rules are unaffected (`tests/RESULTS.md`).

Limits: the rule is a conjunction of well-known Windows API names in a Go binary with one import. It has not been run against Go GUI programs that use activation contexts (walk-based apps, WireGuard for Windows) or against other Go programs that embed an unwind-table registration; a hit on benign Go software is possible. Open an issue with the file hash if you see one. The other 38 samples were not analysed beyond the table.
