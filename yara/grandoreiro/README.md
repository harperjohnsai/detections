# grandoreiro

Rules for a 2026 build of the Grandoreiro loader (Delphi downloader stage, 85.6 MB) seen in a Portuguese/Spanish phishing wave, see [`iocs/2026-11-grandoreiro-es-pt/`](../../iocs/2026-11-grandoreiro-es-pt/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `Grandoreiro_Loader_Delphi_StrCrypt_PortCalc` | [grandoreiro_delphi_strcrypt_portcalc.yar](grandoreiro_delphi_strcrypt_portcalc.yar) | the loader EXE, also with the padding removed (key-derivation, decoder and port-calculation code idioms) | `a11531c8aaa981bcb1ff3feec1d43b21` |
| `Grandoreiro_Loader_Delphi_BMP_Padding_Hunt` | [grandoreiro_delphi_bmp_padding_hunt.yar](grandoreiro_delphi_bmp_padding_hunt.yar) | hunting: Delphi PE over 40 MB with a uniform BMP in RCDATA, ZipForge and an HTTP client class | `a11531c8aaa981bcb1ff3feec1d43b21` |

## Sample (SHA-256)

| Artefact | SHA-256 |
|---|---|
| loader EXE (Delphi, 85.6 MB) | `93845bd3c4d6cb0a15c75d82903a88776e07bf90634f8d794aca8fd476539a52` |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>` (see the top README). Both rules match the EXE; the first also matches a copy with the padding stripped; 0 hits on 611 unrelated files. Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).
