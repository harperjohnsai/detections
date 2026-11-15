# revstealer

Rules for REVSTEALER (Elastic REF2859) as seen in the "Setup Center" campaign ([Elastic write-up](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer)). Elastic's public rule `Windows_Trojan_RevStealer_efc8ff20` does not match this build, because a `call nop; nop; ret` stub is inserted into every function prologue, so these rules anchor on other code.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `REVSTEALER_x64_Core_SetupCenter` | [revstealer_core.yar](revstealer_core.yar) | decrypted x64 payload (file or memory) | `eef82bab267ed96d30653ffad896c002` |
| `REVSTEALER_ABE_Helper_DLL` | [revstealer_abe_helper_dll.yar](revstealer_abe_helper_dll.yar) | embedded Chrome App-Bound-Encryption helper DLL | `b8cd5e7e7e90ffc4b0a7779cd3e2d8ac` |
| `REVSTEALER_x64_Hashed_Evasion_Shapes` | [revstealer_hashed_evasion.yar](revstealer_hashed_evasion.yar) | decrypted x64 payload (file or memory), builds 25 to 27 | `eef82bab267ed96d30653ffad896c002` |
| `REVSTEALER_Decrypted_Strings_Memory` | [revstealer_decrypted_strings_memory.yar](revstealer_decrypted_strings_memory.yar) | process memory after string decryption | `8a6b89debf9a0cf5925b195e1143ec79` (analysis artefact: payload with its 1,400 strings decrypted; not an in-the-wild file) |

## Hashed-evasion rule

`REVSTEALER_x64_Hashed_Evasion_Shapes` keys on how the payload hides its sandbox and locale checks. Names, process names, CPUID vendor strings and the CIS language list exist only as 32-bit hashes, FNV-1a over the UTF-16LE bytes of the string. The offset basis and the prime are built at run time from blinded constants (96 helper calls that xor or add two stack arguments; the prime comes from a getter call before every multiply), so neither constant appears in `.text`. Both are re-salted per build, so hash values do not carry over between builds; the rule matches the code shape instead: the xor and add blinding helpers (all required), plus a wide-FNV loop (with length or null-terminated variant) or the one-at-a-time export-name hash (`h = (h + c) * 0x401; h ^= h >> 6`, builds 27 and later only). Windows API names are resolved by that export hash as well (`ExitProcess`, `GetUserDefaultUILanguage`, `GetSystemDefaultUILanguage` verified). Static analysis only; no sample was run.

- Test (2026-11-15, yara-python 4.5.4 and YARA-X 1.23): 6 of 6 distinct positives (builds 25, 26 and 27 payload, the two strings-decrypted artefacts of builds 25 and 26, and the strings-decrypted artefact of build 27); 0 hits on 652 negative files (PE and non-PE, including the proxy `version.dll` of all three builds, the ABE helper and unrelated DLLs/.so/.pyd). The plaintext lists below are identical in builds 25 to 27, only the per-build salts differ.
- Case build (27): basis `0x612bdd50`, multiplier `0x0100024b`; builds 25 and 26 use the standard prime `0x01000193` with other bases. These are build parameters, not stable indicators.
- Each decoded entry was re-hashed with the recovered function and equals its table entry. Hashes are 32 bits, so decoded words are verified candidates; entries not listed as decoded had no hit in the dictionaries or in an exhaustive search of up to 7 lower-case characters.

### Decoded evasion lists

| Table | Entries | Decoded |
|---|---|---|
| UI language gate | 10 | 10 of 10: primary language IDs for ru (`0x19`), uk (`0x22`), be (`0x23`), kk (`0x3f`), uz (`0x43`), ky (`0x40`), tk (`0x42`), tg (`0x28`), hy (`0x2b`), az (`0x2c`). The user UI language (`GetUserDefaultUILanguage`) and the system UI language (`GetSystemDefaultUILanguage`) must both match. |
| User / computer names | 45 | 26 of 45: tequilaboomboom, malware, maltest, johndoe, sandbox, virus, wdagutilityaccount, analysis, cuckoo, vmware, hapubws, it-admin, 7silvia, hanspeter-pc, win7-traps, fortinet, hal9th, wilber, wilbert, klone_x64-pc, systemit, mueller-pc, john-pc, nepenthes, malnetvm, virusclone |
| Process names | 33 | 26 of 33: x32dbg, x64dbg, windbg, ollydbg, ida, ida64, idaq, idaq64, radare2, ghidra, dnspy, de4dot, dotpeek64, scylla (3 variants), die, pestudio, apimonitor (x64, x86), regshot, fakenet, xenservice, qemu-ga, joeboxcontrol, joeboxserver (all `.exe`) |
| CPUID hypervisor vendor, leaf `0x40000000` | 8 | 6 of 8: `vmwarevmware`, `kvmkvmkvm`, `vboxvboxvbox`, `xenvmmxenvmm`, `tcgtcgtcgtcg`, `bhyve bhyve ` (decoded lower-case) |
| CPUID hypervisor vendor, second table | 1 | 1 of 1: `microsoft hv` (decoded lower-case) |
| Further table of 30 hashes | 30 | 0 of 30 |

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| REVSTEALER payload (RC4-decrypted `localdata.db`) | `c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad` |
| `abe_helper.dll` (ChaCha20-decrypted from the payload) | `3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632` |
| payload with strings decrypted (artefact) | `0a48e7ed139a1cbe38c4ccb98edf2ff99bc53933f07942fa02fcf054dc14e0a6` |

## Testing

Run `tests/run_yara_tests.py` (see the top README). Reference samples must match exactly the rules listed above; benign and unrelated PE files must not match. Recorded runs: [`tests/RESULTS.md`](../../tests/RESULTS.md).

## Notes

- The Memory rule is meant for memory scans (the on-disk build keeps these strings encrypted); the reference artefact is the only file it was verified on.
- Extractor used to derive these: [`tools/revstealer-unpacker`](../../tools/revstealer-unpacker/).
