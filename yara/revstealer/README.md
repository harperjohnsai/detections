# revstealer

Rules for REVSTEALER (Elastic REF2859) as seen in the "Setup Center" campaign ([Elastic write-up](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer)). Elastic's public rule `Windows_Trojan_RevStealer_efc8ff20` does not match this build, because a `call nop; nop; ret` stub is inserted into every function prologue, so these rules anchor on other code.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `REVSTEALER_x64_Core_SetupCenter` | [revstealer_core.yar](revstealer_core.yar) | decrypted x64 payload (file or memory) | `eef82bab267ed96d30653ffad896c002` |
| `REVSTEALER_ABE_Helper_DLL` | [revstealer_abe_helper_dll.yar](revstealer_abe_helper_dll.yar) | embedded Chrome App-Bound-Encryption helper DLL | `b8cd5e7e7e90ffc4b0a7779cd3e2d8ac` |
| `REVSTEALER_Decrypted_Strings_Memory` | [revstealer_decrypted_strings_memory.yar](revstealer_decrypted_strings_memory.yar) | process memory after string decryption | `8a6b89debf9a0cf5925b195e1143ec79` (analysis artefact: payload with its 1,400 strings decrypted; not an in-the-wild file) |

## Samples (SHA-256)

| Artefact | SHA-256 | MalwareBazaar |
|---|---|---|
| REVSTEALER payload (RC4-decrypted `localdata.db`) | `c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad` | [entry](https://bazaar.abuse.ch/sample/c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad/) |
| `abe_helper.dll` (ChaCha20-decrypted from the payload) | `3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632` | [entry](https://bazaar.abuse.ch/sample/3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632/) |
| payload with strings decrypted (artefact) | `0a48e7ed139a1cbe38c4ccb98edf2ff99bc53933f07942fa02fcf054dc14e0a6` | not uploaded |

## Test results (2026-11-13)

yara-python 4.5.4 and YARA-X 1.23.0: the payload matches only `REVSTEALER_x64_Core_SetupCenter`; the helper DLL matches only `REVSTEALER_ABE_Helper_DLL`; the strings-decrypted artefact matches `REVSTEALER_x64_Core_SetupCenter` + `REVSTEALER_Decrypted_Strings_Memory`; 0 hits on 34 benign / unrelated PE files. Full log: [../../tests/RESULTS.md](../../tests/RESULTS.md).

## Notes

- The Memory rule is meant for memory scans (the on-disk build keeps these strings encrypted); the reference artefact is the only file it was verified on.
- Extractor used to derive these: [`tools/revstealer-unpacker`](../../tools/revstealer-unpacker/).
