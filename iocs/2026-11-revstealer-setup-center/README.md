# 2026-11 "Setup Center" lures: REVSTEALER (Windows) and MioLab (macOS)

Formats: CSV, JSON, STIX 2.1, MISP

YouTube lure videos (hundreds of playlist descriptions) send victims through a community post and two Telegraph pages to an archive hosted on an attacker-created GitLab repository. The archive holds a genuine Microsoft-signed OneDrive client renamed `Installer.exe`, a malicious proxy `version.dll` that RC4-decrypts `localdata.db` and hollows a suspended copy of its host, and padding files. The decrypted payload is **REVSTEALER** ([Elastic REF2859](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer)): a Windows infostealer for browsers (including App-Bound Encryption), wallets, password managers, VPN and gaming clients, Telegram and Discord. The lures impersonate a popular trading platform; the platform is not involved. A macOS ClickFix branch of the same cluster downloads a stage-2 Mach-O, the **MioLab / Nova** stealer (C++ build), which in turn pulls a persistence agent and trojanised wallet apps (see below).

Static analysis only; no sample was executed and no attacker infrastructure or dead drop was contacted for the rules.

**C2 design.** Three C2 sources, tried in order: a host:port embedded in the config (AES-256-CBC), a Telegraph page description, and a Polygon smart-contract value read with `eth_call` (EtherHiding). On 2026-11-13 all three decrypted to the same host, so the operator can re-point the backups without rebuilding. Block the domain, not the Cloudflare addresses.

## Hunting pivots
- DNS/proxy: anything under `prooutlet58[.]website`; URI paths ending in `buqpl.ajug`; `GET /health` followed by `POST application/octet-stream` from a non-browser process.
- Non-browser process requesting `api.telegra.ph/getPage/*?return_content=false`, or resolving `polygon-bor-rpc.publicnode.com`.
- Signed OneDrive client named `Installer.exe` running from a user folder and loading a `version.dll` next to it.
- Mutex `Global\517681F6`; User-Agent `Firefox/126.0` from a process that is not Firefox.

## macOS branch: MioLab (Nova)

The ClickFix page (`echo <b64> | base64 -d | bash`) runs a short shell stage that downloads a universal Mach-O, removes the quarantine attribute and runs it. The Mach-O is the C++ MioLab stealer (ad-hoc signed, affiliate user id `124`, build tag `ggggg`). Its config is a rotating-XOR blob in `__DATA,__data` holding four C2 hosts, a file-grabber extension list and the fake dialogs (Full Disk Access, "System Settings" password prompt, validated with `dscl . -authonly`). It stages data in `~/.hlpr/`, writes a LaunchAgent `com.hlpr.agent`, turns Do Not Disturb on, and uploads zipped reports in 8 MiB chunks to `/api/reports/upload/chunk` and `/complete`.

Next stages, served on 2026-11-13 by one of the four C2 hosts (the others answered empty or with Cloudflare 52x errors):
- **Agent `~/.hlpr/.agnt`**: universal C++ backdoor and clipper. Beacons every ~10 s with `curl --data` to `/api/agnt` on its single hard-coded C2, takes tasks (reverse shell via `/bin/zsh -i` on a TCP socket, self-update, password, system profile) and replaces clipboard contents that match wallet-address patterns. The sample was already on MalwareBazaar from another reporter.
- **Trojanised Ledger Wallet 2.133.0 and Trezor Suite 26.3.3**: the genuine Electron apps, ad-hoc re-signed, with an injected renderer module that shows a fake "genuine check / action is declined" dialog and a 12/20/24-word recovery-phrase grid, then POSTs `{seedPhrase,userId}` to `/api/ledger/seed` or `/api/trezor/seed` on a separate exfil domain. The Ledger bundle's `app-update.yml` points at a throwaway update feed.

**Why this matters for defenders:** nobody should type a recovery phrase into a desktop app that asks for it after a "security check". Reinstall wallet apps only from the vendor site, and move funds to a new seed if a phrase was entered.

Hunting pivots (macOS): a process whose image or parent is `~/.hlpr/.agnt`; `~/Library/LaunchAgents/com.hlpr.agent.plist`; `curl ... --data "OOzVBOVS..." .../api/agnt` every ~10 s; a Ledger or Trezor bundle with no vendor TeamIdentifier and a `generic` update feed; `defaults -currentHost write ... com.apple.notificationcenterui doNotDisturb -boolean true` followed by `killall NotificationCenter`.

## Detections
- YARA: [`yara/setup-center-loader`](../../yara/setup-center-loader/), [`yara/revstealer`](../../yara/revstealer/), [`yara/miolab-macos`](../../yara/miolab-macos/)
- Sigma: [`sigma/`](../../sigma/) (5 RevStealer + 4 MioLab rules submitted to SigmaHQ, 1 extra hunting rule)
- Tools: [`tools/`](../../tools/)

## Samples on MalwareBazaar (reporter `harperjohns`)
| Artefact | SHA-256 | Link |
|---|---|---|
| `Installer.zip` | `2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49` | [MalwareBazaar](https://bazaar.abuse.ch/sample/2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49/) |
| `version.dll` | `b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960` | [MalwareBazaar](https://bazaar.abuse.ch/sample/b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960/) |
| REVSTEALER payload | `c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad` | [MalwareBazaar](https://bazaar.abuse.ch/sample/c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad/) |
| `abe_helper.dll` | `3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632` | [MalwareBazaar](https://bazaar.abuse.ch/sample/3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632/) |
| macOS stage-2 Mach-O | `2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a` | [MalwareBazaar](https://bazaar.abuse.ch/sample/2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a/) |
| MioLab agent `.agnt` (universal Mach-O) | `5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e` | [MalwareBazaar](https://bazaar.abuse.ch/sample/5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e/) (uploaded earlier by another reporter) |
| Trojanised Trezor Suite 26.3.3 bundle zip | `96b9178496ed37d63e34b7df925f79fd6a7acb4e78bf551acd978b0cb8c7097c` | [MalwareBazaar](https://bazaar.abuse.ch/sample/96b9178496ed37d63e34b7df925f79fd6a7acb4e78bf551acd978b0cb8c7097c/) |
| Trojanised Ledger Wallet 2.133.0 bundle zip | `c69c55e37a3b7325a7892d9af6ce91e2e719b32a40c6c9e07c7222f1d876e95a` | not on MalwareBazaar when this was written (hash only) |

ThreatFox: no entries submitted by this project for this case. Related video: https://youtu.be/UBGt4gP53wU (ClickFix episode, case 3). Combined IOC gist: https://gist.github.com/harperjohnsai/1f9053f7450c99ea4c1a4ece91876fc9

Status: 5 RevStealer Sigma rules submitted to SigmaHQ (https://github.com/SigmaHQ/sigma/pull/6613), 4 MioLab macOS rules submitted (https://github.com/SigmaHQ/sigma/pull/6614). All YARA rules are on YARAhub (author Harper Johns).

## Files

- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`. Values are defanged (`hxxps://`, `[.]`); hashes are plain.
- `iocs.json`: **machine-readable, NOT defanged** (the first key `_warning` says so). Do not browse or fetch the values. Same rows as the CSV.
- Verdict values: `malicious`, `candidate` (pattern match, link not confirmed), `compromised-or-abused-legit` (a legitimate site or brand that was hijacked or abused; block by path, not by domain), `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file), `related-not-in-build`.
- Not included on purpose: archive passwords, API keys, encryption keys and decoding recipes (the build tag and affiliate id above are identifiers, not keys). Block the C2 domains, not the shared Cloudflare or hosting addresses.
- License: CC0 1.0.

