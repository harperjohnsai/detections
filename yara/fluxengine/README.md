# fluxengine

Rules for the FluxEngine Delphi remote-access banker, see [`iocs/2026-11-fluxengine/`](../../iocs/2026-11-fluxengine/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_FluxEngine_Loader_dhlib_DLL` | [fluxengine_loader_dhlib_dll.yar](fluxengine_loader_dhlib_dll.yar) | the loader DLL (`dhlib.dll`, export `InitModule`): registry and dead-drop strings, or the master-key reference code plus strings; matches all four known builds | `f79a01841786359b82de24525302cfd2` |
| `MAL_FluxEngine_Payload_Delphi` | [fluxengine_payload_delphi.yar](fluxengine_payload_delphi.yar) | the decrypted client: per-unit string-decoder core plus plaintext strings (not the encrypted download) | `18a54b1573f23ccfb996536fb3e8d1f9` |
| `SUSP_FluxEngine_LNK_Squiblydoo_ADS` | [fluxengine_lnk_squiblydoo_ads.yar](fluxengine_lnk_squiblydoo_ads.yar) | stage-1 LNK (scrobj.dll copied into an alternate data stream, `regsvr32 /i:`); a hunting rule, the technique is generic | `26b3f7856483622397d512ae6bc1eb2e` |

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| payload (decrypted `d3dx9_43.bin`, Delphi, 4.5 MB) | `c424a715e3861bc18e0c8223f3dfd909dc4a77a82b9c5a5a135b8d49bac7e8c6` |
| loader `dhlib.dll`, 2026-10-19 | `dc60f22fc59a7c3cb51b97661ad69f42d3028538c0044b248fc9681487c0b433` |
| loader `dhlib.dll`, Sep 2026 | `6a9ded132c050747ae5f233a91fc84c6bbee4e91950636f5fe077bf48acdca30`, `7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114`, `01af2f7049e1562023835ddcbffea76e265ed2906e140ba8a200eb41d37ebf8d` |
| stage-1 LNK | `6e6d4084c6c2f3035c2fbda4daf4b705a06938d73bf91f402552b6d4ab522d9b` |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>`: each sample hits exactly its rule on yara-python and YARA-X; 0 hits from these rules on 547 other PE and LNK files. The negative corpus holds few benign Delphi applications, so the false-positive estimate for Delphi software is weak. The loader rule keys on invariants of four builds; a rebuild that changes the strings needs a rule update. The rules have not been run on the previous payload build (bytes not available). Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).
