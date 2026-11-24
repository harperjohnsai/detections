# romulus-cncmachinerms

Rules for the ROMULUS ClickFix delivery platform and its CNCMachineRMS RAT (also the August BabaDeda chain that carries the same RAT). Case notes, IOCs and the decoded gates: [`iocs/2026-11-romulus-clickfix/`](../../iocs/2026-11-romulus-clickfix/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_ROMULUS_MSI_Builder_Script_CustomAction` | [romulus_msi_builder_script_customaction.yar](romulus_msi_builder_script_customaction.yar) | MSI from the ROMULUS builder: random-named `Binary.*` streams with a plain-text script custom action (nibble-pair VBS, base64 stride/reverse PowerShell, `OriginalDatabase` + ADODB.Stream dropper) | `2c0f9df2db104af1b75c471a4e7465ca` (`37e56899...`) |
| `MAL_ROMULUS_PS_IntArray_CharOffset_Stager` | [romulus_ps_intarray_charoffset_stager.yar](romulus_ps_intarray_charoffset_stager.yar) | PowerShell stage whose API and type names are int64 arrays decoded with a per-string character offset | `bfe4df50d25820185868df0ce873e183` (`281.ps1`, `7eb0d8e8...`) |
| `MAL_ROMULUS_Script_Nibble_Base64_Decoders` | [romulus_script_nibble_base64_decoders.yar](romulus_script_nibble_base64_decoders.yar) | script streams extracted from the MSIs (VBS nibble decoder, PowerShell CSV/base64 decoders) | `a22ca56fe10d62888b0727586ac9fc72` (extracted stage, `98a1d42a...`) |
| `MAL_ROMULUS_Stardock_DeElevator64_Patched_Import` | [romulus_stardock_deelevator64_patched_import.yar](romulus_stardock_deelevator64_patched_import.yar) | Stardock `DeElevator64.dll` with one extra non-system import (`I++u.dll`) | `8986af3c278b5384af6d0f1d954ed5fc` (`0457414c...`) |
| `MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL` | [romulus_sideloaded_decoy_loader_dll.yar](romulus_sideloaded_decoy_loader_dll.yar) | unsigned x64 decoy-body loader DLLs side-loaded by the signed hosts (`I++u.dll`, `senddmp.resources.dll`, `res.dll`, `rdCore.dll` and 12 more) | `06d5f06cd54c326750d1544290017174` (`I++u.dll`, `3cd1484c...`) |
| `MAL_CNCMachineRMS_Storage_Container` | [cncmachinerms_storage_container.yar](cncmachinerms_storage_container.yar) | the "Storage" container as a standalone file (header equations, no strings): `execute_engine_disconnect.raw`, `load.db`, `monitor.raw`, MSI-extracted `fil*` files | `d8326e736280b2b73d1bb83bb9b56489` (`d5acf446...`) |
| `MAL_CNCMachineRMS_Core_Decrypted_x64` | [cncmachinerms_core_decrypted_x64.yar](cncmachinerms_core_decrypted_x64.yar) | decrypted RAT core (class 16100) in memory or as a dump, not the encrypted container | `e22c0b881f7bacf6d1610a7622eb71a0` (`ab65bbfc...`) |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>` (see the top README). Results 2026-11-24 with yara-python 4.5.4 and YARA-X 1.24.0: 63 reference files (62 hit exactly the expected rule, the genuine signed `DeElevate64.exe` hits none), 1,628 benign files with 0 hits. The negative corpus is the Debian `libwine` Windows PE set (1,603 PEs, includes a `version.dll` with the same export names as real side-load targets), 7 vendor MSI installers, 13 PowerShell installer scripts, and two installers (Stardock Fences, Notepad++).

## Notes and limits

- The storage-container rule has no strings: it tests the three header equations (`K = (q1 - 7*q0) / 3`, `q5 = q1 - 37*(q0 + K)`), written with 32-bit halves so it also compiles with yara-python. It only matches the container at offset 0 of a standalone file; a container embedded inside a memory image or a cabinet is not found (the extractor in [`tools/cncmachinerms-extract/`](../../tools/cncmachinerms-extract/) scans every offset).
- The core rule keys on the compiled-in key `0x16DF3822A8` (the embedded-container key LevelBlue also reported), which is present as an immediate 56 times in all four decrypted builds we hold; the other three builds' decrypted cores differ in size by under 2 KB. It is a memory/dump rule: the on-disk container is encrypted.
- The MSI-builder and script rules cover five different custom-action layouts seen in the 31 builder MSIs we hold. A new builder revision may need a new layout line. The sideload-DLL rule covers decoy bodies seen in 16 DLLs from five MSIs and one zip; it is a hunting-grade rule (score 70) and is the one most likely to need an update.
- MSI cabinets are often compressed, so an MSI whose script streams are not stored in clear needs the extracted stream (`MAL_ROMULUS_Script_Nibble_Base64_Decoders`).
- Numeric MSI `3` (`28520147...`) does not match any MSI rule as a whole file (its container sits in a stored cabinet); the extracted container matches the storage rule.
- Tools used to derive these: [`tools/cncmachinerms-extract`](../../tools/cncmachinerms-extract/), [`tools/legionloader-config`](../../tools/legionloader-config/).
