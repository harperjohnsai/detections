# 2026-11 "cryptotrice": a fake cracked trading app that hides its C2 in Telegram and Steam

Formats: CSV, JSON, STIX 2.1, MISP

October to November 2026. An aged X account (created 2009, re-skinned 1 Oct 2026, 41 near-identical promotions from 9 Oct, about 2.1 million views) promotes a fake "reverse-engineered, cracked premium" desktop app imitating a popular trading platform; the platform is not named and is not involved. Whether the account was hijacked or sold is unknown.

- **Windows:** download gateways on compromised websites (hidden paths such as `/get/`, `/dl/`, `/mac/`) redirect to a password-protected zip in a Cloudflare R2 bucket. It holds a roughly 130 MB executable (about 4 MB of Go code plus about 126 MB of zeros, self-signed by an invented company). The Go loader maps an encrypted blob in memory: a C/C++ stealer for browser data, wallets and sessions. The server address is read from dead drops (a Telegram channel description and a Steam profile) and was rotated across three NameCheap zones and ten hostnames in about seven hours on 2026-11-11.
- **macOS:** ClickFix page, a `curl | zsh` one-liner with the address hidden in base64, a per-request zsh loader, then an AppleScript stealer (AMOS-like) that phishes the login password.

Static analysis, emulation and one public sandbox run; no attacker server was contacted from the author's network for the rules. Not established: the C2 origin servers (behind Cloudflare), the number of victims, exact family labels.

## Hunting pivots
- A non-browser process reading a Telegram channel or Steam profile, then a multipart POST to `/<1-3 chars>/gate` on a new domain.
- User-Agent `Firefox/161.0` (a version that did not exist yet).
- A ~130 MB executable whose last ~125 MB are zeros; zip named like `[brand]_Premium_Desktop*`.
- macOS: `curl ... $(echo ...|base64 -D)|zsh` in shell history; `osascript` password dialog; `/tmp/osalogging.zip`.

## Detections
- YARA: [`yara/cryptotrice-go-loader/`](../../yara/cryptotrice-go-loader/), rule `MAL_Go_Reflective_PE_Loader_Win64` (the Go loader core; it also matches 40 other MalwareBazaar builds, see that README).
- Tool: [`tools/cryptotrice-go-loader/`](../../tools/cryptotrice-go-loader/) finds the loader's blob builder, runs its six byte passes in a CPU emulator (no OS, no network) and writes the inner PE.
- Second builds: MalwareBazaar lists two other Go loaders with a self-signed "Nova Metric Industries" certificate (`2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da`, `7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b`, both first seen 2026-11-12, different certificate serials); both match the rule. `tools/cryptotrice-go-loader` decrypts both to PEs (937,984 and 251,392 bytes); the payloads and their C2s were not analysed here.

## Samples on MalwareBazaar
| Artefact | SHA-256 | Link |
|---|---|---|
| Go core of the Windows loader (no padding) | `b8c1d2399105a57046b24aeee74d2dea3250c8c8aa5502c448b8d954f1dcb17a` | [MalwareBazaar](https://bazaar.abuse.ch/sample/b8c1d2399105a57046b24aeee74d2dea3250c8c8aa5502c448b8d954f1dcb17a/) (signature `Vidar`, listed by another reporter) |
| Decrypted inner stealer PE (file layout, uploaded by this project 2026-11-20) | `c8f5b1c2b898a7c13fc2843dd9771566e0a1b7e79bd18f479300e3518fda7d20` | [MalwareBazaar](https://bazaar.abuse.ch/sample/c8f5b1c2b898a7c13fc2843dd9771566e0a1b7e79bd18f479300e3518fda7d20/) (tags `stealer`, `dead-drop`, `decrypted-payload`) |
| macOS zsh loader | `4e2698b61750624535ba607d27d1ef1f177057bc13f8901dac4855a84254dd2a` | [MalwareBazaar](https://bazaar.abuse.ch/sample/4e2698b61750624535ba607d27d1ef1f177057bc13f8901dac4855a84254dd2a/) (signature `MacSync`, listed by another reporter) |

The padded `.exe`, the outer zip and the AppleScript stealer were not found on MalwareBazaar at the time of checking. ThreatFox: no entries submitted by this project for this case.

Video: https://youtu.be/fuJMKVu-CFk (scheduled for 2026-11-19).

IOC gist: https://gist.github.com/harperjohnsai/a4cce902c90b37ae74992226cc9ec0f2

## Files

- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`. Values are defanged (`hxxps://`, `[.]`); hashes are plain.
- `iocs.json`: **machine-readable, NOT defanged** (the first key `_warning` says so). Do not browse or fetch the values. Same rows as the CSV.
- Verdict values: `malicious`, `candidate` (pattern match, link not confirmed), `compromised-or-abused-legit` (a legitimate site or brand that was hijacked or abused; block by path, not by domain), `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file), `related-not-in-build`.
- Not included on purpose: archive passwords, API keys, encryption keys and decoding recipes. Block the C2 domains, not the shared Cloudflare or hosting addresses.
- License: CC0 1.0.

