# miolab-macos

Rules for the macOS branch of the "Setup Center" YouTube-lure campaign: a ClickFix page leads to a universal Mach-O stealer (**MioLab / Nova**, C++ build, see Unit 42's ["modern C++ Odyssey variant"](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/47b53a06affd56b4fefbbcb1fb9fdaf88e3cca5e/2026-06-20-ClickFix-campaign-delivers-macOS-infostealer-via-DMG.txt)). The stealer installs a LaunchAgent `com.hlpr.agent` for a second-stage backdoor (`~/.hlpr/.agnt`) and downloads trojanised Ledger Wallet and Trezor Suite apps that show a fake recovery-phrase form. One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt` | [miolab_macos_cpp_stealer_config_decrypt.yar](miolab_macos_cpp_stealer_config_decrypt.yar) | stage-2 Mach-O (x86_64, arm64, universal) | `90f962d66963f7189a00ad58e88cfd7c` |
| `HUNT_macOS_MioLab_Cpp_Stealer_Plaintext_Artifacts` | [miolab_macos_cpp_stealer_plaintext_hunt.yar](miolab_macos_cpp_stealer_plaintext_hunt.yar) | decrypted strings: memory, EDR command lines | `bee4f6ac2058d4c42a89517bea441118` (analysis artefact: decoded string dump) |
| `MAL_macOS_MioLab_Agent_Backdoor_Clipper` | [miolab_macos_agent_backdoor_clipper.yar](miolab_macos_agent_backdoor_clipper.yar) | `~/.hlpr/.agnt` Mach-O | `e4b4324e0c44ccff3de04b60edf4a3e5` |
| `HUNT_macOS_MioLab_Agent_Plaintext_Artifacts` | [miolab_macos_agent_plaintext_hunt.yar](miolab_macos_agent_plaintext_hunt.yar) | decrypted agent strings, memory, command lines | `d18cd572397c2ccb266ad787037ffe0a` (artefact) |
| `HUNT_MioLab_Agent_C2_Body` | [miolab_macos_agent_c2_body_hunt.yar](miolab_macos_agent_c2_body_hunt.yar) | beacon `curl --data` argument in logs/PCAP-derived text | `916f51d51b410b0ed58be7ee3c11c61e` (artefact: public sandbox command lines) |
| `MAL_JS_MioLab_Trojanised_LedgerLive_SeedPhrase_Modal` | [miolab_wallet_ledger_seed_phrase_modal.yar](miolab_wallet_ledger_seed_phrase_modal.yar) | `app.asar` / renderer bundle of the trojanised Ledger Wallet | `c914a08a7796dd0c444626d202402669` |
| `MAL_JS_MioLab_Trojanised_TrezorSuite_SeedPhrase_Modal` | [miolab_wallet_trezor_seed_phrase_modal.yar](miolab_wallet_trezor_seed_phrase_modal.yar) | `app.asar` / bundle of the trojanised Trezor Suite | `28ef243b2e947695539b21dd1e7294f7` |
| `MAL_MioLab_Trojanised_Wallet_Locale_Strings` | [miolab_wallet_locale_strings.yar](miolab_wallet_locale_strings.yar) | injected locale strings in the Ledger app | `c914a08a7796dd0c444626d202402669` |
| `SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet` | [miolab_wallet_electron_update_feed.yar](miolab_wallet_electron_update_feed.yar) | `app-update.yml` with a non-Ledger feed | `26c0e2570bee3b504a16c8d633f521ec` |

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| stage-2 stealer, universal Mach-O | `2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a` |
| stage-2 stealer, x86_64 / arm64 slice | `49de3b526ee449d9a28f73d85af2fb0b40d721b45693d80119f8db47d4bba51a` / `f9a80a964748880116c22e1353072b31a966a5744e930d7a1bd376cf75ba5532` |
| agent `.agnt`, universal Mach-O | `5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e` |
| agent x86_64 / arm64 slice | `77a41f1a86f3bd778fd4febda4d2dc7ff77b53ec16f5e1ea52c29f2fc642d1ee` / `8281c8dc3f595064d5edad2ab479727358ac84af83ffb5604ab56929a5cd0c1b` |
| trojanised Ledger Wallet 2.133.0 `app.asar` | `b6e9f44926dda38bdd080e6cf23001546aee34f4b5f5eaf94e54ebcd73afa44a` |
| trojanised Trezor Suite 26.3.3 `app.asar` | `05ca25705ce7acffc20bbbf74ed4ec9fcd0b9a19307cb08f46e2d73d53b8802b` |

## Testing

`tests/run_yara_tests.py --samples <dir> --negatives <dir>` (see the top README). Every reference sample must match exactly the rules listed for it; benign files must not match. Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).

## Notes

- The stealer's strings are encrypted on disk, so the `MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt` rule anchors on the config-decryption loop (x86_64 and arm64 encodings plus a looser arm64 form) and on imports. A rebuild with different codegen may need the loose form or a new rule.
- The `HUNT_*` rules read decrypted text. They are for memory scans, EDR command-line stores and decoded string dumps, not for packed binaries on disk. Their reference files are analysis artefacts, not in-the-wild files.
- The wallet rules need the app's `app.asar` (or the extracted bundle). A `.zip` stores the JavaScript compressed, so scan after extraction. `SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet` is narrow by design: it flags a Ledger bundle whose updater feed is not on a Ledger domain.
- Tools used to derive these: [`tools/miolab-macos-config-extractor`](../../tools/miolab-macos-config-extractor/), [`tools/miolab-agent-wire-decoder`](../../tools/miolab-agent-wire-decoder/).
