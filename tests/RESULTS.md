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
