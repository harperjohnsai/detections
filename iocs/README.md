# iocs/

One folder per case, named `<YYYY-MM>-<slug>`. A case folder holds:

- `README.md`: case summary, samples, hunting pivots, links (video, MalwareBazaar, ThreatFox), status
- `case.yml`: machine-readable metadata (`title`, `date`, `families`, `rules`, `video`, `related_videos`, `gist`)
- `iocs.csv`: columns `type,value_defanged,first_seen,role,verdict,confidence,source`; values are defanged (`hxxps://`, `[.]`), hashes are plain
- `iocs.json`: same rows, **machine-readable and NOT defanged** (first key `_warning`); never browse or fetch the values
- `stix2.json`: STIX 2.1 bundle (Identity, Report, Indicators, Malware, `indicates` relationships), TLP:CLEAR; generated
- `misp_event.json`: MISP event (core format, tag `tlp:clear`, `to_ids` set per indicator quality); generated

`stix2.json` and `misp_event.json` are produced by `tools/export_iocs.py` from `iocs.json` and `case.yml`; never edit them by hand. Shared or legitimate infrastructure and genuine files are context only (MISP `to_ids=false`, no STIX indicator).

`verdict`: `malicious`; `candidate` (pattern match, link not confirmed); `compromised-or-abused-legit` (hijacked or abused legitimate site or brand: block by path, not domain); `shared-or-legit-infrastructure` (do NOT block: shared CDN edge, public RPC, genuine decoy file); `related-not-in-build`.

Not published on purpose: archive passwords, API keys, encryption keys and decoding recipes. The impersonated platforms are not named in prose; a few indicator values (domains, file names) contain a name verbatim because they are the exact artefacts. Indicators are CC0 1.0.
