# tools/

Static helpers used to derive the rules. They parse and decrypt files only; nothing is executed natively. Handle the inputs as live malware.

| Tool | Purpose |
|---|---|
| [`setup-center-extractor/`](setup-center-extractor/) | recovers the config of the proxy `version.dll` from code patterns and RC4-decrypts `localdata.db` into the inner PE |
| [`revstealer-unpacker/`](revstealer-unpacker/) | decrypts REVSTEALER's strings (CPU emulation of its own leaf routines), the embedded helper DLL and the AES-256-CBC C2 config |
| [`miolab-macos-config-extractor/`](miolab-macos-config-extractor/) | parses the MioLab macOS stealer's rotating-XOR config blob (affiliate id, build tag, C2 hosts, dialogs) from a Mach-O |
| [`miolab-agent-wire-decoder/`](miolab-agent-wire-decoder/) | decodes the beacon body of the MioLab macOS agent from logged curl command lines |
| [`build_index.py`](build_index.py) | generates `INDEX.md` from `iocs/*/case.yml` (`--check` in CI) |
| [`export_iocs.py`](export_iocs.py) | generates `iocs/<case>/stix2.json` (STIX 2.1) and `iocs/<case>/misp_event.json` (MISP) from `iocs.json` + `case.yml`; deterministic (uuid5 ids), `--check` fails on stale files |

## export_iocs.py rules

- Optional `case.yml` keys used by the export: `campaigns` (family names that are campaigns, not malware), `malpedia` (MISP galaxy tags), `references` (`source_name` + `url`), `indicates` (`family` + `role_match` regex over the IOC role; builds Malware objects and `indicates` relationships for malicious rows only).
- STIX: indicators only for types with a standard pattern (domain, url, IPv4, IP:port, SHA-256, URI path as `LIKE`, mutex, user agent, command line, file/path, certificate, account); the Polygon contract and wallet use the custom observables `x-polygon-contract:address` and `x-polygon-wallet:address`. Candidates get `anomalous-activity` and low confidence.
- MISP: `to_ids=true` only for malicious rows with high/medium confidence of type domain, url, ip, ip|port, sha256, uri, mutex. Context rows (shared infrastructure, genuine files, paths, user agents, dead-drop values) stay as attributes with `to_ids=false`.
- STIX ids are uuid5, so the validator's UUIDv4 recommendation (103) is disabled in `tests/validate_exports.py`.
