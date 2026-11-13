# setup-center-loader

Rules for the loader stage of the "Setup Center" chain: a Microsoft-signed OneDrive client (original file name `OneDrive.exe`) renamed `Installer.exe`, a malicious x64 proxy `version.dll` that re-exports the real System32 DLL, and `localdata.db`, an RC4-encrypted payload that starts with the bytes `MSCF` but is not a cabinet file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `SetupCenter_ProxyVersionDll_Loader` | [setup_center_proxy_version_dll.yar](setup_center_proxy_version_dll.yar) | proxy `version.dll` | `51061df0511cc9d758230ba75f3954b4` |
| `SetupCenter_FakeCab_PayloadContainer` | [setup_center_fake_cab_container.yar](setup_center_fake_cab_container.yar) | `localdata.db` | `b80f3e45c3cc6f38aa3505ab70cd3017` |

## Samples (SHA-256)

| Artefact | SHA-256 | MalwareBazaar |
|---|---|---|
| `version.dll` | `b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960` | [entry](https://bazaar.abuse.ch/sample/b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960/) |
| `localdata.db` | `193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62` | uploaded but not listed by MalwareBazaar |
| `Installer.zip` (all of the above) | `2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49` | [entry](https://bazaar.abuse.ch/sample/2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49/) |

## Test results (2026-11-13)

yara-python 4.5.4 and YARA-X 1.23.0: `version.dll` matches only the loader rule; `localdata.db` matches only the fake-CAB rule; 0 hits on 34 benign / unrelated PE files (including the genuine signed OneDrive `Installer.exe` and the python.org embeddable distribution); a real CAB (uncompressed and MSZIP) does not match the fake-CAB rule. Full log: [../../tests/RESULTS.md](../../tests/RESULTS.md).

## Notes

- The loader rule needs an unsigned x64 DLL that exports `GetFileVersionInfoW` / `VerQueryValueW`, loads the system copy by path and carries VM-check registry strings plus the key-derivation or RC4 code. A rebuilt loader with different code will not match.
- The fake-CAB rule uses CFHEADER fields that a real cabinet cannot have (`reserved1` must be 0, `cbCabinet` is the file size) and high entropy.
- Extractor used to derive these: [`tools/setup-center-extractor`](../../tools/setup-center-extractor/).
