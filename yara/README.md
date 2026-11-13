# yara/

One folder per family or campaign. Every rule file carries `author`, `date`, a `reference` and the YARAhub meta (`yarahub_uuid`, `yarahub_license`, both TLPs, `yarahub_reference_md5`). Rules compile with yara-python 4.x and YARA-X 1.x.

| Folder | Rules |
|---|---|
| [`setup-center-loader/`](setup-center-loader/) | proxy `version.dll` sideload loader, fake-CAB payload container |
| [`revstealer/`](revstealer/) | REVSTEALER x64 core, Chrome App-Bound-Encryption helper DLL, decrypted-strings (memory) |

Test: `python tests/run_yara_tests.py --compile-only` (CI) or with `--samples` / `--negatives` (see the top README).
