# 2026-11 "Setup Center" lures: REVSTEALER (Windows) and MioLab (macOS)

Formats: CSV, JSON, STIX 2.1, MISP

YouTube lure videos (hundreds of playlist descriptions) send victims through a community post and two Telegraph pages to an archive hosted on an attacker-created GitLab repository. The archive holds a genuine Microsoft-signed OneDrive client renamed `Installer.exe`, a malicious proxy `version.dll` that RC4-decrypts `localdata.db` and hollows a suspended copy of its host, and padding files. The decrypted payload is **REVSTEALER** ([Elastic REF2859](https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer)): a Windows infostealer for browsers (including App-Bound Encryption), wallets, password managers, VPN and gaming clients, Telegram and Discord. The lures impersonate a popular trading platform; the platform is not involved. A macOS ClickFix branch of the same cluster downloads a stage-2 Mach-O, the **MioLab / Nova** stealer (C++ build), which in turn pulls a persistence agent and trojanised wallet apps (see below).

Static analysis only; no sample was executed and no attacker infrastructure or dead drop was contacted for the rules.

**C2 design.** Three C2 sources, tried in order: a host:port embedded in the config (AES-256-CBC), a Telegraph page description, and a Polygon smart-contract value read with `eth_call` (EtherHiding). On 2026-11-13 all three decrypted to the same host, so the operator can re-point the backups without rebuilding. Block the domain, not the Cloudflare addresses.

## Hunting pivots
- DNS/proxy: anything under `prooutlet58[.]website`, `proup43[.]lol`, `ivorydisplay61[.]click`, `grovestack[.]one`, `wintergroup[.]one`, `wavefleet63[.]work` or `tutor-lens77[.]xyz`; URI paths ending in `buqpl.ajug`, `luwon.wmwh`, `pxpnp.rnjh`, `hmpxp.qzyr`, `mbmnc.xgao` or `mztnd.rbes`; `GET /health` followed by `POST application/octet-stream` from a non-browser process.
- Non-browser process requesting `api.telegra.ph/getPage/*?return_content=false`, or resolving `polygon-bor-rpc.publicnode.com` or `polygon.gateway.tenderly.co`.
- Signed OneDrive client named `Installer.exe` running from a user folder and loading a `version.dll` next to it.
- Mutex `Global\517681F6`; User-Agent `Firefox/126.0` from a process that is not Firefox.

## Builds and rotation (Windows, REVSTEALER)

The GitLab repository `dwnlnk` has replaced `Installer.zip` twice; earlier versions stay downloadable at their commit URLs. Each of the three builds carries its own configuration, a fresh C2 domain, a fresh Polygon dead-drop contract and a fresh Telegraph page. For every build the contract value, the Telegraph description and the embedded config decrypt to the same host (read 2026-11-13), and all three C2 hosts answered the liveness path with HTTP 200 from public check nodes on that day (Russian nodes got 403, a geo-block, not an outage). Retired builds therefore keep working for victims already infected.

| Build | Installer commit (UTC) | C2 host | Dead-drop contract (Polygon) | Telegraph page |
|---|---|---|---|---|
| 25 (`VERSION 25.1.0`) | 2026-10-28 23:42, `2806c0be90c5` | `proxy[.]proup43[.]lol:443` | `0x0F6A5efA466ED8f1fB7e148f85B599B433887049` | `hxxps://telegra[.]ph/Garden-record-ridge-olive-10-28` |
| 26 (`26.1.0`) | 2026-11-02 19:02, `b5fe3195445d` | `job[.]ivorydisplay61[.]click:443` | `0xDEeA36Ea15a0fd3772A95d56DE74e8a35c968C62` | `hxxps://telegra[.]ph/Log-canvas-11-02` |
| 27 | 2026-11-05 21:40, `3df34c7f1f9b` (current `main`) | `queue[.]prooutlet58[.]website:443` | `0xb6A1834c2F25dD705F18CB2cb17e3713bA8C7E31` | `hxxps://telegra[.]ph/Field-study-willow-atlas-11-05` |
| yh-1101 | not known (memory dump, first seen 2026-11-15 08:10 UTC) | `node[.]tutor-lens77[.]xyz:443` | `0x5a73C3FE866d50A950ECF5E3e841b551628cb9Fd` | `hxxps://telegra[.]ph/Amber-draft-creek-gentle-11-01` |
| yh-1107 | not known (memory dump, first seen 2026-11-14 15:13 UTC) | `stat9[.]wintergroup[.]one:443` | `0x379f4d5565AF5dE4A34c0A20f94bB4d6bA041937` | `hxxps://telegra[.]ph/Cedar-path-hazel-field-11-07` |
| yh-1110a | not known (memory dump, first seen 2026-11-15 09:16 UTC) | `init1[.]wavefleet63[.]work:443` | `0x935A85445c76E8D6c48E7eEd31b6B2F3c9181632` | `hxxps://telegra[.]ph/Maple-ledger-11-10` |
| yh-1110b | not known (two memory dumps, first seen 2026-11-15 01:04 and 02:16 UTC) | `meta3[.]grovestack[.]one:443` | `0x1ee6A331881102B84d2DebdD5eefd2E591a65f14` | `hxxps://telegra[.]ph/Clear-ridge-11-10` |

Per-build dates, commits and creation transactions are in [`c2_timeline.csv`](c2_timeline.csv). The same-day pattern repeats: the domain is registered (Dynadot, Cloudflare name servers `adaline`/`drake`), the contract is created 10 to 71 minutes later, and the installer commit follows hours later. None of the three contracts was ever re-pointed: the value is set in the constructor and storage is unchanged from creation to 2026-11-13. The operator ships a new build and contract per C2 instead (three in 11 days). Per-build AES keys are deliberately not published. The loader is recompiled for every build (the build-25 payload file is `config.dat`, build 26 `sync.dat`, build 27 `localdata.db`); the loader, container, payload and helper-DLL rules match all three builds.

**Four more builds from sandbox memory dumps (labels `yh-*`, added 2026-11-15).** Our rule `REVSTEALER_x64_Core_SetupCenter` matched five process-memory dumps on YARAify (first seen 2026-11-14 15:13 to 2026-11-15 09:16 UTC, one sighting each; none on MalwareBazaar or VirusTotal when checked on 2026-11-15). The dumps were downloaded from YARAify and their SHA-256 verified; both REVSTEALER rules hit all five. Config extraction (the core's own string-decryption routines run in an emulator, nothing executed natively, no network) shows four distinct builds, each with its own C2 domain, Polygon contract, contract selector and Telegraph page. Two dumps (`0ded8309`, `87ab8e5d`) share one config (`meta3[.]grovestack[.]one`) but carry different gate-path suffixes, mutex and User-Agent, so they are two compilations of one build. One dump (`0ded8309`, 446 KB, file name `<imagebase>.svchost.exe`) is the core alone, which fits injection into `svchost.exe`; the other four are 5.9 to 6.3 MB Go-binary dumps that hold the decrypted core (inferred: loader processes; they also hit generic Go-loader rules). No installer commit or domain registration date is known for these builds, so those columns of `c2_timeline.csv` are empty.
- VERIFIED: the four contracts are in the deployer's creation list (nonces 102, 145, 168, 169; created 2026-11-01, 11-07, 11-10, 11-10, each 09:15 to 09:36 UTC, the same time-of-day pattern as builds 25 to 27) and each contract's getter selector equals the selector in the matching config.
- NOT CHECKED: the contract values, the Telegraph pages and whether the C2 hosts are live; no attacker host or dead drop was contacted. Unlike builds 25 to 27, "all sources agree" is therefore not claimed for these four.
- New RPC fallback: one `yh-1110b` dump lists `polygon[.]gateway[.]tenderly[.]co` as an RPC endpoint, next to the `polygon-bor-rpc[.]publicnode[.]com` read seen in the earlier builds. It is shared public infrastructure (context row, never block globally).
- Gate-path suffixes rotate per build (`buqpl.ajug` for build 27; `luwon.wmwh`, `pxpnp.rnjh`, `hmpxp.qzyr`, `mbmnc.xgao`, `mztnd.rbes` for the new ones); the paths are in `iocs.csv`.

**Deployer wallet.** All seven contracts (builds 25 to 27 and the four `yh-*` builds) come from one Polygon EOA, `0x8bAddf058D11005360900a0542484eE446F2d494` (confidence high, from the creation transactions). It deployed about 165 contracts between 2026-10-08 and 2026-11-13 (three to ten per day, mostly around 09:00 UTC) and was still active on 2026-11-13. All use one Solidity template (the same 1,337-opcode runtime, randomised function selectors), so bytecode hashes never match. Only these seven are tied to a sample config; the C2s of the other contracts are unknown. About 45 were created after build 27, so builds exist that did not ship through this GitLab account. The same wallet also made 17 setter calls (2026-11-05 to 2026-11-09) re-pointing other contracts, none of them ours.

**Funding (confidence in brackets).**
- `0xF311c09136Bb7CDc5EC6Bf84E82524e6890e4217` sent 65.87 POL to the deployer on 2026-10-08: single-use relay (medium; operator control inferred from the transfer only).
- `0xb81f4236fA866de7594646A0736DB696810acadb` funded that relay on 2026-09-28: busy unlabelled wallet, possibly a service wallet (low; listed as `candidate`, do not block on this alone). Further upstream is not resolved.

**Comparison with Elastic's deployers.** The contracts Elastic listed for REF2859 trace to two other wallets: `0x808e0a9def308b4c624e9a2105d12be25e89d6a9` (256 contracts, 2026-02-22 to 2026-05-11, funded directly from an exchange hot wallet carrying an explorer label) and `0x512230fdddcfc7e0d99a9860a6b8048584de574f` (411 contracts, 2026-06-26 to 2026-10-05, funded by a single-use wallet). The current deployer starts three days after the previous one stops, so the operator appears to rotate the deployer every two to three months (about 830 dead-drop contracts across the three wallets). Our contracts have the same opcode skeleton as the Elastic ones, which ties them to the same kit; the C2 domains do not overlap, and none of the 317 apex domains Elastic published uses the Cloudflare name-server pair seen here, so this is the same family and tooling, not shared domain infrastructure. A single operator behind all three wallets is likely (timing, template) but not proven: there is no direct on-chain link between the funders.

**Other artefacts.** A signed fake application `ExcelExport.exe` (self-made signer, signed 2026-11-02) contacts the build 26 C2 host, `api.telegra.ph` and a Polygon RPC in a public sandbox run (medium; not unpacked). The same GitLab account hosts 15 decoy "desktop helper" projects whose descriptions link the Telegraph lure hop; they are listed in `iocs.csv` at medium confidence (contents not reviewed).

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
| Trojanised Ledger Wallet 2.133.0 bundle zip | `c69c55e37a3b7325a7892d9af6ce91e2e719b32a40c6c9e07c7222f1d876e95a` | zip too large for MalwareBazaar; components repack [fe0329ff…](https://bazaar.abuse.ch/sample/fe0329ffb7ba73b5aebd3ece686b5cd8a0cfdcd9fbfaa7694f64c340c1a2b91b/) and trojanised renderer.bundle.js [979e1ba3…](https://bazaar.abuse.ch/sample/979e1ba3034f153f2c0b3b91cdc027c281cecbd5234fa69f54ce716a6568dd6a/) |

ThreatFox (reporter `harperjohns`, malware `win.revstealer`, tags REVSTEALER, REF2859, SetupCenter, sideload): C2 domain [`proxy[.]proup43[.]lol`](https://threatfox.abuse.ch/ioc/2027971/) (2027971); the other two C2 domains were already listed by other reporters (`job[.]ivorydisplay61[.]click` [2012298](https://threatfox.abuse.ch/ioc/2012298/), `queue[.]prooutlet58[.]website` [2027525](https://threatfox.abuse.ch/ioc/2027525/)); commit-pinned `Installer.zip` payload-delivery URLs of builds 25/26/27 ([2027972](https://threatfox.abuse.ch/ioc/2027972/), [2027973](https://threatfox.abuse.ch/ioc/2027973/), [2027974](https://threatfox.abuse.ch/ioc/2027974/)); seven SHA-256 hashes (sideload `version.dll` and inner payload of each build, build-27 `Installer.zip`: [2027975](https://threatfox.abuse.ch/ioc/2027975/) to [2027981](https://threatfox.abuse.ch/ioc/2027981/)). Added 2026-11-15 (same reporter, malware and tags without `sideload`): the four `yh-*` C2 domains [2029842](https://threatfox.abuse.ch/ioc/2029842/) (`meta3[.]grovestack[.]one`), [2029843](https://threatfox.abuse.ch/ioc/2029843/) (`stat9[.]wintergroup[.]one`), [2029844](https://threatfox.abuse.ch/ioc/2029844/) (`init1[.]wavefleet63[.]work`), [2029845](https://threatfox.abuse.ch/ioc/2029845/) (`node[.]tutor-lens77[.]xyz`) and the five memory-dump SHA-256 hashes [2029846](https://threatfox.abuse.ch/ioc/2029846/) to [2029850](https://threatfox.abuse.ch/ioc/2029850/). Related video: https://youtu.be/UBGt4gP53wU (ClickFix episode, case 3). Combined IOC gist: https://gist.github.com/harperjohnsai/1f9053f7450c99ea4c1a4ece91876fc9

Status: 5 RevStealer Sigma rules submitted to SigmaHQ (https://github.com/SigmaHQ/sigma/pull/6613), 4 MioLab macOS rules submitted (https://github.com/SigmaHQ/sigma/pull/6614). All YARA rules are on YARAhub (author Harper Johns).

## Files

- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`. Values are defanged (`hxxps://`, `[.]`); hashes are plain.
- `c2_timeline.csv`: per build, the installer commit, domain registration, contract, Telegraph page and C2 host with dates (defanged).
- `iocs.json`: **machine-readable, NOT defanged** (the first key `_warning` says so). Do not browse or fetch the values. Same rows as the CSV.
- Verdict values: `malicious`, `candidate` (pattern match, link not confirmed), `compromised-or-abused-legit` (a legitimate site or brand that was hijacked or abused; block by path, not by domain), `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file), `related-not-in-build`.
- Not included on purpose: archive passwords, API keys, encryption keys and decoding recipes (the build tag and affiliate id above are identifiers, not keys). Block the C2 domains, not the shared Cloudflare or hosting addresses.
- License: CC0 1.0.

