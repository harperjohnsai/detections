# tools/

Static helpers used to derive the rules. They parse and decrypt files only; nothing is executed natively. Handle the inputs as live malware.

| Tool | Purpose |
|---|---|
| [`setup-center-extractor/`](setup-center-extractor/) | recovers the config of the proxy `version.dll` from code patterns and RC4-decrypts `localdata.db` into the inner PE |
| [`revstealer-unpacker/`](revstealer-unpacker/) | decrypts REVSTEALER's strings (CPU emulation of its own leaf routines), the embedded helper DLL and the AES-256-CBC C2 config |
| [`miolab-macos-config-extractor/`](miolab-macos-config-extractor/) | parses the MioLab macOS stealer's rotating-XOR config blob (affiliate id, build tag, C2 hosts, dialogs) from a Mach-O |
| [`miolab-agent-wire-decoder/`](miolab-agent-wire-decoder/) | decodes the beacon body of the MioLab macOS agent from logged curl command lines |
| [`cryptotrice-go-loader/`](cryptotrice-go-loader/) | finds the blob builder and the six in-place byte passes of the cryptotrice Go loader, runs only those loops in a CPU emulator (no OS, no network) and writes the decrypted inner PE; tests with a negative control on 24 benign Go PEs |
| [`remus-cleartext/`](remus-cleartext/) | reads the cleartext build date and campaign ID of Remus stealer payloads from `.rdata` (fixed 0x5e4 offset between them); regression test on 14 Remus payloads plus 53 negatives |
| [`cncmachinerms-extract/`](cncmachinerms-extract/) | finds the CNCMachineRMS "Storage" container header at any offset, decodes both layers and prints the gate list, campaign id, persistence names and timers; decodes the `Build.dat` shellcode of the Stardock chain; `emu_validate.py` cross-checks the decoder against the loader shellcode's own routines in a bare emulator |
| [`legionloader-config/`](legionloader-config/) | reads the RC4 string tables of the 2026 LegionLoader builds (C2 host, gate paths, User-Agent) without hard-coded offsets; `emu_check.py` cross-checks the RC4 routine in a bare emulator |
| [`build_index.py`](build_index.py) | generates `INDEX.md` from `iocs/*/case.yml` (`--check` in CI) |
| [`wl_known.py`](wl_known.py) | classifies exported MISP attributes against a pinned misp-warninglists commit (category `known` lists only, type-aware; shared infrastructure vs rented cloud ranges) and writes `warninglist_known.json`, which the exporter reads |
| [`export_iocs.py`](export_iocs.py) | generates `iocs/<case>/stix2.json` (STIX 2.1) and `iocs/<case>/misp_event.json` (MISP) from `iocs.json` + `case.yml`; deterministic (uuid5 ids), `--check` fails on stale files |

## export_iocs.py rules

- Optional `case.yml` keys used by the export: `campaigns` (family names that are campaigns, not malware), `malpedia` (MISP galaxy tags), `references` (`source_name` + `url`), `indicates` (`family` + `role_match` regex over the IOC role; builds Malware objects and `indicates` relationships for malicious rows only).
- STIX: indicators only for types with a standard pattern (domain, url, IPv4, IP:port, SHA-256, URI path as `LIKE`, mutex, user agent, command line, file/path, certificate, account); the Polygon contract and wallet use the custom observables `x-polygon-contract:address` and `x-polygon-wallet:address`. Candidates get `anomalous-activity` and low confidence.
- MISP: `to_ids=true` only for malicious rows with high/medium confidence of type domain, url, ip, ip|port, sha256, uri, mutex. Context rows (shared infrastructure, genuine files, paths, user agents, dead-drop values) stay as attributes with `to_ids=false`.
- Warninglist rule (pinned misp-warninglists commit `40e2b570fd`, 19 `known`-category lists, each assigned to one of two classes in `CLASSES` of `wl_known.py`, decided from the list's MISP name and description):

  | class | lists | export |
  |---|---|---|
  | (a) shared infrastructure: many unrelated users behind one address or host | `akamai`, `cloudflare`, `fastly` (CDN/anycast proxy ranges), `github` (shared service front ends), `ovh-cluster` (OVH shared web-hosting clusters), `parking-domain`, `sinkholes`, `telegram-ips`, `check-host-net`, `dynamic-dns`, `link-in-bio`, `public-ipfs-gateways`, `url-shortener` | value equals an entry (domain, IP inside a range, `ip\|port` by its IP half, path-less URL): `to_ids=false` and the note `warninglist known infrastructure`; STIX keeps the indicator with the label `known-infrastructure`. Subdomain of an entry (`guild.<dyndns zone>`) or path URL on a listed host (`bit.ly/<code>`): `to_ids` kept, review note |
  | (b) rented hosting/cloud compute ranges: the list only says the address belongs to a provider | `amazon-aws`, `google-gcp`, `microsoft-azure`, `hetzner`, `digitalocean`, `vultr` | `to_ids` is not touched (an attacker rents a server there like any customer, so a C2 on such an address is alertable) and the comment (STIX: description) gets `[cloud-hosted (<list>): attacker-rented server; IP may be reassigned after takedown, treat as time-bound]`. An address that is in a class (a) range too (GitHub and Azure overlap) stays class (a). `amazon-aws` also lists some CDN/S3 service prefixes that the list cannot separate: check such a hit by hand |

  Nothing is removed from `iocs.csv`/`iocs.json`. Refresh with `python tools/wl_known.py --update` after adding a case; `tests/validate_exports.py` fails when the file is stale, when a `to_ids=true` attribute still equals a class (a) entry, or when a class (b) match lost `to_ids` (if the row is otherwise eligible) or its note. The large `datacenter-*`, `vpn-*` and `tor-exit-nodes` lists are not used: they cover most hosting space where dedicated C2 servers live.
- STIX ids are uuid5, so the validator's UUIDv4 recommendation (103) is disabled in `tests/validate_exports.py`.
