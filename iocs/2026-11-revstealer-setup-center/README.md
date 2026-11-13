# 2026-11 REVSTEALER via the "Setup Center" sideload chain

YouTube lure videos (hundreds of playlist descriptions) send victims through a community post and two Telegraph pages to an archive hosted on an attacker-created GitLab repository. The archive holds a genuine Microsoft-signed OneDrive client renamed `Installer.exe`, a malicious proxy `version.dll` that RC4-decrypts `localdata.db` and hollows a suspended copy of its host, and padding files. The decrypted payload is **REVSTEALER** ([Elastic REF2859](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer)): a Windows infostealer for browsers (including App-Bound Encryption), wallets, password managers, VPN and gaming clients, Telegram and Discord. The lures impersonate a popular trading platform; the platform is not involved. A macOS ClickFix branch of the same cluster downloads a stage-2 Mach-O (MioLab-style stealer).

Static analysis only; no sample was executed and no attacker infrastructure or dead drop was contacted for the rules.

**C2 design.** Three C2 sources, tried in order: a host:port embedded in the config (AES-256-CBC), a Telegraph page description, and a Polygon smart-contract value read with `eth_call` (EtherHiding). On 2026-11-13 all three decrypted to the same host, so the operator can re-point the backups without rebuilding. Block the domain, not the Cloudflare addresses.

## Hunting pivots
- DNS/proxy: anything under `prooutlet58[.]website`; URI paths ending in `buqpl.ajug`; `GET /health` followed by `POST application/octet-stream` from a non-browser process.
- Non-browser process requesting `api.telegra.ph/getPage/*?return_content=false`, or resolving `polygon-bor-rpc.publicnode.com`.
- Signed OneDrive client named `Installer.exe` running from a user folder and loading a `version.dll` next to it.
- Mutex `Global\517681F6`; User-Agent `Firefox/126.0` from a process that is not Firefox.

## Detections
- YARA: [`yara/setup-center-loader`](../../yara/setup-center-loader/), [`yara/revstealer`](../../yara/revstealer/)
- Sigma: [`sigma/`](../../sigma/) (5 rules submitted to SigmaHQ, 1 extra hunting rule)
- Tools: [`tools/`](../../tools/)

## Samples on MalwareBazaar (reporter `harperjohns`)
| Artefact | SHA-256 | Link |
|---|---|---|
| `Installer.zip` | `2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49` | [MalwareBazaar](https://bazaar.abuse.ch/sample/2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49/) |
| `version.dll` | `b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960` | [MalwareBazaar](https://bazaar.abuse.ch/sample/b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960/) |
| REVSTEALER payload | `c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad` | [MalwareBazaar](https://bazaar.abuse.ch/sample/c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad/) |
| `abe_helper.dll` | `3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632` | [MalwareBazaar](https://bazaar.abuse.ch/sample/3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632/) |
| macOS stage-2 Mach-O | `2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a` | [MalwareBazaar](https://bazaar.abuse.ch/sample/2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a/) |

ThreatFox: no entries submitted by this project for this case. Video: https://youtu.be/UBGt4gP53wU (ClickFix episode, case 3).

## Files

- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`. Values are defanged (`hxxps://`, `[.]`); hashes are plain.
- `iocs.json`: **machine-readable, NOT defanged** (the first key `_warning` says so). Do not browse or fetch the values. Same rows as the CSV.
- Verdict values: `malicious`, `candidate` (pattern match, link not confirmed), `compromised-or-abused-legit` (a legitimate site or brand that was hijacked or abused; block by path, not by domain), `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file), `related-not-in-build`.
- Not included on purpose: archive passwords, API keys, encryption keys and decoding recipes. Block the C2 domains, not the shared Cloudflare or hosting addresses.
- License: CC0 1.0.

