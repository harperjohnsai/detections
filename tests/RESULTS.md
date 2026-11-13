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
