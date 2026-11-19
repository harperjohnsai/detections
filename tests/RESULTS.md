# Test results

Run date: 2026-11-13. Engines: yara-python 4.5.4, YARA-X 1.23.0, Python 3.12. Samples: the five reference artefacts listed in the READMEs; negatives: 34 benign or unrelated PE files.

## YARA (tests/run_yara_tests.py --samples ... --negatives ...)

```
PASS at least one YARA engine available
PASS 5 rule files compiled together
ENGINE yara-python 4.5.4
ENGINE yara-x 1.23.0
PASS [yara-python 4.5.4] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-python 4.5.4] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] c6859833796f -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] c6859833796f -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] 3c6330d06b57 -> REVSTEALER_ABE_Helper_DLL
PASS [yara-x 1.23.0] 3c6330d06b57 -> REVSTEALER_ABE_Helper_DLL
PASS [yara-python 4.5.4] negative corpus: 34 files, 0 hits []
PASS [yara-x 1.23.0] negative corpus: 34 files, 0 hits []
PASS [yara-python 4.5.4] real CAB (compress=False) -> no hit
PASS [yara-x 1.23.0] real CAB (compress=False) -> no hit
PASS [yara-python 4.5.4] real CAB (compress=True) -> no hit
PASS [yara-x 1.23.0] real CAB (compress=True) -> no hit
ALL CHECKS PASS
```

## Sigma logic tests (tests/test_sigma_synthetic.py)

```
PASS revstealer_c2_domain.yml: C2 subdomain -> fire
PASS revstealer_c2_domain.yml: C2 apex -> fire
PASS revstealer_c2_domain.yml: unrelated domain -> silent
PASS revstealer_c2_gate_uri.yml: gate path 1 -> fire
PASS revstealer_c2_gate_uri.yml: gate path 3 -> fire
PASS revstealer_c2_gate_uri.yml: unrelated path -> silent
PASS revstealer_telegraph_dead_drop.yml: metadata-only getPage -> fire
PASS revstealer_telegraph_dead_drop.yml: getPage with content -> silent
PASS revstealer_telegraph_dead_drop.yml: normal page view -> silent
PASS revstealer_polygon_rpc_non_browser.yml: non-browser process -> fire
PASS revstealer_polygon_rpc_non_browser.yml: browser (filtered) -> silent
PASS revstealer_polygon_rpc_non_browser.yml: other domain -> silent
PASS revstealer_renamed_onedrive_host.yml: OneDrive renamed Installer.exe -> fire
PASS revstealer_renamed_onedrive_host.yml: genuine OneDrive.exe -> silent
PASS revstealer_renamed_onedrive_host.yml: other binary -> silent
PASS image_load_win_susp_unsigned_version_dll_user_path.yml: unsigned version.dll in Downloads -> fire
PASS image_load_win_susp_unsigned_version_dll_user_path.yml: System32 copy -> silent
PASS image_load_win_susp_unsigned_version_dll_user_path.yml: signed vendor copy -> silent
PASS image_load_win_susp_unsigned_version_dll_user_path.yml: documented miss: unsigned proxy in Program Files -> silent
PASS every rule file has at least one test event
ALL CHECKS PASS
```

## Sigma validation

SigmaHQ master 54967d6: `python tests/test_logsource.py` OK (3 tests), `python tests/test_rules.py` OK (11 tests) with the five RevStealer rules added, and:

```
=== Summary ===
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

## YARA, MioLab macOS rules added (2026-11-13, YARA-X 1.23.0)

Same harness, 14 rule files compiled together. Samples: the case artefacts listed in `yara/miolab-macos/README.md` (universal files, per-architecture slices, the two wallet `app.asar` files extracted from the zips, the Ledger `app-update.yml`, three decoded-text artefacts) plus the Windows reference files. Negatives, 1,683 files, 0 hits: the 35 files of the python.org 3.12 embeddable distribution, 1,264 files from four public macOS Python wheels (numpy, grpcio, lxml, pyzmq; 28 of them are Mach-O files, several C++), 376 JavaScript files above 20 KB from the build host, and the genuine Trezor Suite `app-update.yml` plus two synthetic updater feeds (a Ledger-hosted feed must not match). yara-python was not used for this run (the local libyara build has no `pe` signature fields); all nine new files also compile with yara-python 4.5.4, and CI compiles everything with both engines.

```
NOTE yara-python not installed, skipping
PASS at least one YARA engine available
PASS 14 rule files compiled together
ENGINE yara-x 1.23.0
PASS [yara-x 1.23.0] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 49de3b526ee4 -> MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt
PASS [yara-x 1.23.0] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] 978c98b401a6 -> HUNT_macOS_MioLab_Agent_Plaintext_Artifacts
PASS [yara-x 1.23.0] 2b4f61c274bf -> MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt
PASS [yara-x 1.23.0] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] 05ca25705ce7 -> MAL_JS_MioLab_Trojanised_TrezorSuite_SeedPhrase_Modal
PASS [yara-x 1.23.0] b6e9f44926dd -> MAL_JS_MioLab_Trojanised_LedgerLive_SeedPhrase_Modal, MAL_MioLab_Trojanised_Wallet_Locale_Strings
PASS [yara-x 1.23.0] c6859833796f -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] c383789cf980 -> SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet
PASS [yara-x 1.23.0] 3c6330d06b57 -> REVSTEALER_ABE_Helper_DLL
PASS [yara-x 1.23.0] 5a2bef675eae -> MAL_macOS_MioLab_Agent_Backdoor_Clipper
PASS [yara-x 1.23.0] 77a41f1a86f3 -> MAL_macOS_MioLab_Agent_Backdoor_Clipper
PASS [yara-x 1.23.0] 8281c8dc3f59 -> MAL_macOS_MioLab_Agent_Backdoor_Clipper
PASS [yara-x 1.23.0] 3bf97f7e851e -> HUNT_MioLab_Agent_C2_Body
PASS [yara-x 1.23.0] 31a4f6a8aecd -> HUNT_macOS_MioLab_Cpp_Stealer_Plaintext_Artifacts
PASS [yara-x 1.23.0] f9a80a964748 -> MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt
PASS [yara-x 1.23.0] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] negative corpus: 1683 files, 0 hits []
SKIP synthetic CAB test (pip install cabarchive)
ALL CHECKS PASS
```

## Sigma, MioLab macOS rules added (2026-11-13)

`tests/test_sigma_synthetic.py`: 16 new hand-made events for the four MioLab rules (fire and silent cases), all PASS. On a SigmaHQ master 54967d6 checkout with the four files under `rules-emerging-threats/2026/Malware/MioLab/`: `python tests/test_logsource.py` OK (3 tests), `python tests/test_rules.py` OK (11 tests), `sigma check --fail-on-error --fail-on-issues --validation-config tests/sigma_cli_conf.yml` with the SigmaHQ validators: 0 errors, 0 issues. Upstream pull request: https://github.com/SigmaHQ/sigma/pull/6614.

## YARA, Setup Center loader rule v2 (2026-11-13, yara-python 4.5.4 and YARA-X 1.23.0)

`SetupCenter_ProxyVersionDll_Loader` v1 missed the build-25 `version.dll`; v2 matches builds 25, 26 and 27. Samples: the three `version.dll` files, the three payload containers (`config.dat`, `sync.dat`, `localdata.db`), the three decrypted inner payloads, the ABE helper DLL and decrypted-strings artefacts. Negatives, 1,478 files, 0 hits in both engines: the 1,443 PE files (DLLs and EXEs, all unsigned, including Wine's own unsigned `version.dll`, which exports the same function names) of two Wine builds (10.0 and 8.0, `x86_64-windows`), the 34 files of the python.org 3.12 embeddable distribution, and the genuine signed OneDrive client renamed `Installer.exe`. A wider scan of 6,778 files of the case folders (containers, payloads, helper DLLs, archives, scripts) hit only the `version.dll` files. Per-string check: every build matches on the hollowing-API-table pattern alone and on the code patterns alone. Output of the harness (the other rule files' samples were not provided and are skipped):

```
PASS at least one YARA engine available
PASS 14 rule files compiled together
ENGINE yara-python 4.5.4
ENGINE yara-x 1.23.0
PASS [yara-python 4.5.4] 3c6330d06b57 -> REVSTEALER_ABE_Helper_DLL
PASS [yara-x 1.23.0] 3c6330d06b57 -> REVSTEALER_ABE_Helper_DLL
PASS [yara-python 4.5.4] 673feccbcec6 -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] 673feccbcec6 -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] 193f259776d3 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-python 4.5.4] 973ad2986d6e -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 973ad2986d6e -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] b484561cc81d -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] b484561cc81d -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-python 4.5.4] 2903e5e3363c -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 2903e5e3363c -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] ca82cb69da22 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-x 1.23.0] ca82cb69da22 -> SetupCenter_FakeCab_PayloadContainer
PASS [yara-python 4.5.4] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] c6859833796f -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] c6859833796f -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] e472b895f15e -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-x 1.23.0] e472b895f15e -> REVSTEALER_x64_Core_SetupCenter
PASS [yara-python 4.5.4] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] b371d2e01562 -> SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] negative corpus: 1478 files, 0 hits []
PASS [yara-x 1.23.0] negative corpus: 1478 files, 0 hits []
PASS [yara-python 4.5.4] real CAB (compress=False) -> no hit
PASS [yara-x 1.23.0] real CAB (compress=False) -> no hit
PASS [yara-python 4.5.4] real CAB (compress=True) -> no hit
PASS [yara-x 1.23.0] real CAB (compress=True) -> no hit
ALL CHECKS PASS
```

`tests/test_setup_center_extractor.py` (tools/setup-center-extractor on the three builds):

```
PASS 973ad2986d6e -> config.dat off=0xdc size=0x6b610 payload=e472b895f15e apis=17
PASS 2903e5e3363c -> sync.dat off=0xcf size=0x69810 payload=673feccbcec6 apis=17
PASS b371d2e01562 -> localdata.db off=0x9b size=0x69c10 payload=c6859833796f apis=17
ALL CHECKS PASS
```


## Run 2026-11-15: anti-VM hash-table rule and hashed-evasion rule added

Engines: yara-python 4.5.4, YARA-X 1.23.0. Excerpt of `tests/run_yara_tests.py --samples ... --negatives ...` (lines for the two new rules; every other expected match was unchanged and passed), plus the wider negative scan of both rules with each engine.

```
PASS 16 rule files compiled together
ENGINE yara-python 4.5.4
ENGINE yara-x 1.23.0
PASS [yara-python 4.5.4] b371d2e01562 -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] b371d2e01562 -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] 2903e5e3363c -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 2903e5e3363c -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] 673feccbcec6 -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] 673feccbcec6 -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] c036690cb8e6 -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] c036690cb8e6 -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] c6859833796f -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] c6859833796f -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] 973ad2986d6e -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-x 1.23.0] 973ad2986d6e -> SetupCenter_Loader_AntiVM_HashTables, SetupCenter_ProxyVersionDll_Loader
PASS [yara-python 4.5.4] e472b895f15e -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] e472b895f15e -> REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] 5e3c4ef86cd0 -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] 5e3c4ef86cd0 -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-x 1.23.0] 0a48e7ed139a -> REVSTEALER_Decrypted_Strings_Memory, REVSTEALER_x64_Core_SetupCenter, REVSTEALER_x64_Hashed_Evasion_Shapes
PASS [yara-python 4.5.4] negative corpus: 36 files, 0 hits []
PASS [yara-x 1.23.0] negative corpus: 36 files, 0 hits []
ALL CHECKS PASS
```

Wider negative corpus (both engines, about 650 files per rule: unrelated PEs, DLLs, Python extension modules and other stages of the case): 0 hits outside the reference samples. `SetupCenter_Loader_AntiVM_HashTables` hit `version.dll` of builds 25, 26, 27 (3 distinct hashes); `REVSTEALER_x64_Hashed_Evasion_Shapes` hit 6 distinct payload / strings-decrypted artefacts of builds 25, 26, 27. The 59 (loader) and 69 (REVSTEALER) decoded hash-table plaintexts were re-hashed against the binaries and all match.

## Grandoreiro rules (yara/grandoreiro), run 2026-11-16

Engines: yara-python 4.5.4 and YARA-X 1.23.0, all repository rules compiled together.

```
PASS [yara-python 4.5.4] 93845bd3c4d6 -> Grandoreiro_Loader_Delphi_BMP_Padding_Hunt, Grandoreiro_Loader_Delphi_StrCrypt_PortCalc
PASS [yara-x 1.23.0] 93845bd3c4d6 -> Grandoreiro_Loader_Delphi_BMP_Padding_Hunt, Grandoreiro_Loader_Delphi_StrCrypt_PortCalc
PASS [yara-python 4.5.4] 29db0be6d95b -> Grandoreiro_Loader_Delphi_StrCrypt_PortCalc
PASS [yara-x 1.23.0] 29db0be6d95b -> Grandoreiro_Loader_Delphi_StrCrypt_PortCalc
```

`29db0be6d95b` is the same loader with the padding resource stripped (a derived test copy, not a sample in the wild). Negative corpus: 611 files (606 unrelated PE files from other analyses and tools, a VBS, two ZIPs, two benign Delphi installers). Grandoreiro rules: 0 hits on all 611. The other rule sets hit 26 of those files, all of them reference artefacts of the Setup Center / REVSTEALER case (expected positives, so the generic "0 hits" line of the harness is not applicable to this corpus). Only two benign Delphi binaries are in the corpus.

## Mispadu rules (yara/mispadu), run 2026-11-19

Engines: yara-python 4.5.4 and YARA-X 1.23.0, all repository rules compiled together (21 rule files).

```
PASS [yara-python 4.5.4] 4f4129e8f79b -> MAL_Mispadu_URSA_Delphi_Cipher_Code, MAL_Mispadu_URSA_Payload_Build108
PASS [yara-x 1.23.0] 4f4129e8f79b -> MAL_Mispadu_URSA_Delphi_Cipher_Code, MAL_Mispadu_URSA_Payload_Build108
PASS [yara-python 4.5.4] 352c8d5d8cc8 -> MAL_Mispadu_URSA_Hook_DLL_pDLL
PASS [yara-x 1.23.0] 352c8d5d8cc8 -> MAL_Mispadu_URSA_Hook_DLL_pDLL
```

`352c8d5d8cc8` is the `PDLL` resource extracted from the payload (a derived test copy of an embedded component). Negative corpus (both engines): 550 files, 0 hits (unrelated PE files from other analyses and tools, among them the Grandoreiro loader, the two NirSoft tools bundled in the payload, and six Delphi DLLs of an unrelated banker cluster). The corpus holds only a few benign Delphi binaries, so the false-positive rate on benign Delphi software is not established.
