# mispadu

Rules for the 2026 Mispadu (URSA) Delphi payload, build 108, see [`iocs/2026-11-mispadu-ursa/`](../../iocs/2026-11-mispadu-ursa/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_Mispadu_URSA_Delphi_Cipher_Code` | [mispadu_ursa_delphi_cipher_code.yar](mispadu_ursa_delphi_cipher_code.yar) | the payload: decoder and encoder code of the base-25 letter-pair cipher plus socket-protocol strings | `97e42e50ecb6690f179b58c20f9de633` |
| `MAL_Mispadu_URSA_Payload_Build108` | [mispadu_ursa_payload_build108.yar](mispadu_ursa_payload_build108.yar) | the payload: encrypted `IMG*` resource loop and resource names, build and protocol strings (build-specific) | `97e42e50ecb6690f179b58c20f9de633` |
| `MAL_Mispadu_URSA_Hook_DLL_pDLL` | [mispadu_ursa_hook_dll_pdll.yar](mispadu_ursa_hook_dll_pdll.yar) | the extracted keyboard-hook DLL (exports `InstallHook`, `UninstallHook`, `setafase`), not the outer payload | `3af08f56f23af7902a307f776e98b83e` |

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| payload EXE (Delphi, 6.9 MB, build 108) | `4f4129e8f79bde102875417f64a3258226ae93658776a416aaf4383698a6ea7d` |
| pDLL.dll (resource `PDLL` of the payload) | `352c8d5d8cc824c41d143af2504d2cdf5d8a16e5f4df019032a5241859b1900b` |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>` (see the top README). The payload matches the first two rules, the DLL the third; 0 hits on 550 other PE files. The rules key on code idioms and resource names of one build: a rebuild with a different compiler setup or renamed resources may need an update. The negative corpus holds few benign Delphi applications. Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).
