# fluxengine

Rules for the FluxEngine Delphi remote-access banker, see [`iocs/2026-11-fluxengine/`](../../iocs/2026-11-fluxengine/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_FluxEngine_Loader_dhlib_DLL` | [fluxengine_loader_dhlib_dll.yar](fluxengine_loader_dhlib_dll.yar) | the loader DLL (`dhlib.dll` / `Project1.dll`, export `InitModule`): registry and dead-drop strings, the master-key reference code plus strings, or the November anti-analysis list plus strings; matches all five known builds | `f79a01841786359b82de24525302cfd2` |
| `MAL_FluxEngine_Payload_Delphi` | [fluxengine_payload_delphi.yar](fluxengine_payload_delphi.yar) | the decrypted client (builds 1.0.3.111 and 1.0.3.113): per-unit string-decoder core plus plaintext strings (not the encrypted download) | `18a54b1573f23ccfb996536fb3e8d1f9` |
| `SUSP_FluxEngine_LNK_Squiblydoo_ADS` | [fluxengine_lnk_squiblydoo_ads.yar](fluxengine_lnk_squiblydoo_ads.yar) | stage-1 LNK (scrobj.dll copied into an alternate data stream, `regsvr32 /i:`); a hunting rule, the technique is generic | `26b3f7856483622397d512ae6bc1eb2e` |
| `MAL_FluxEngine_VBS_Downloader` | [fluxengine_vbs_downloader.yar](fluxengine_vbs_downloader.yar) | stage-1 `DOC-*.vbs`: reversed regsvr32/scrobj and MSIE 8 UA strings plus the download-and-save calls (part 2) | `edcbd5d4880ef969c822fb96b70afe6b` |
| `MAL_FluxEngine_SCT_Recon_Stage2` | [fluxengine_sct_recon_stage2.yar](fluxengine_sct_recon_stage2.yar) | stage-2 recon scriptlet: XOR string decoder, analyst PC names, AV query, `registrar.php?dominio=` (part 2) | `3a965be846451c5dbfe70ad6a6c3f34d` |
| `MAL_FluxEngine_SCT_Installer_Stage3` | [fluxengine_sct_installer_stage3.yar](fluxengine_sct_installer_stage3.yar) | stage-3 installer scriptlet: install-name hash, history wipe, ZIP extraction, status beacons (part 2) | `fddba692fac85b5e614f22627f36dcc2` |
| `SUSP_AutoIt_A3X_Large_NoExt_Script` | [autoit_a3x_large_noext_script.yar](autoit_a3x_large_noext_script.yar) | hunting: raw compiled AutoIt script (`AU3!EA06`) of 1 to 20 MB; generic, other AutoIt loaders match too (part 2) | `0230434cef5c8ab9a29303ca48642fa2` |
| `MAL_FluxEngine_AU3_PELoader_Decompiled` | [fluxengine_au3_peloader_decompiled.yar](fluxengine_au3_peloader_decompiled.yar) | decompiled AutoIt stage or AutoIt script memory (the raw a3x is encrypted and does not match); not deployed to YARAhub (part 2) | - |

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| payload (decrypted `d3dx9_43.bin`, Delphi, 4.5 MB) | `c424a715e3861bc18e0c8223f3dfd909dc4a77a82b9c5a5a135b8d49bac7e8c6` |
| loader `dhlib.dll`, 2026-10-19 | `dc60f22fc59a7c3cb51b97661ad69f42d3028538c0044b248fc9681487c0b433` |
| loader `dhlib.dll`, Sep 2026 | `6a9ded132c050747ae5f233a91fc84c6bbee4e91950636f5fe077bf48acdca30`, `7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114`, `01af2f7049e1562023835ddcbffea76e265ed2906e140ba8a200eb41d37ebf8d` |
| stage-1 LNK | `6e6d4084c6c2f3035c2fbda4daf4b705a06938d73bf91f402552b6d4ab522d9b` |
| payload build 1.0.3.113 (part 2) | `c2225d927b1461354418ce8067574e2c48dcd19be9d5150b68a3bcfbdd0e5c25` |
| loader `dhlib.dll`, Nov 2026 (part 2, carved from the a3x) | `c3dc04853487b4a8f0e25a9527c250c45de5f8ba8153ec5e0c83ad834a0c81de` |
| stage-1 VBS (part 2) | `e683253477ca1b9b22c285cbc854a50284256b4d246b151e63dc171830bf7192` |
| stage-2 / stage-3 scriptlets (part 2) | `2ec8894d0cc8b092c5525a12254cad122d34933a349c3eff14f1af02836177ac`, `f32d6dc8c15efe4473e5a400cacb15cb28bcde2daf74fa2c99fa86d4936c7880` |
| compiled AutoIt script (part 2) | `4fc99727bbb91087a474126049ced32b69d252c5ed93e2b1fa40d8c13d10257e` |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>`: each sample hits exactly its rule on yara-python and YARA-X; 0 hits from these rules on 547 other PE and LNK files. The negative corpus holds few benign Delphi applications, so the false-positive estimate for Delphi software is weak. The loader rule keys on invariants of four builds; a rebuild that changes the strings needs a rule update. The rules have not been run on the previous payload build (bytes not available). Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).

Part 2 run (2026-11-22, yara-python 4.5.4 and YARA-X 1.23.0): the 13 FluxEngine reference files (5 loader builds, 2 payload builds, LNK, VBS, 2 scriptlets, a3x, decompiled AutoIt text) hit exactly their rule on both engines; the genuine AutoIt3.exe, the genuine WebView2Loader.dll and the install icon hit nothing. 0 hits on 1,295 benign library files (both engines) and on 10,039 other files of the author's cases (scripts, PEs, archives; YARA-X), EICAR clean. The script rules key on strings of one build each and the scriptlets look generated per serve (progid/classid change), so expect updates.
