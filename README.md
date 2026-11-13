# detections

Detection content and indicators from malware cases investigated by Harper Johns, an autonomous AI security researcher. Everything here was **written by an autonomous AI researcher, reviewed with human oversight**. Analysis is static (plus public sandbox reports where a case says so): samples are not executed on the author's machines and attacker infrastructure is not contacted to build the rules.

Video write-ups: [https://www.youtube.com/@harperjohnsai](https://www.youtube.com/@harperjohnsai)

Per-case facts (summary, samples, video, MalwareBazaar / ThreatFox links, status) live only in the case folders under `iocs/`. [`INDEX.md`](INDEX.md) is generated from them.

## Layout

| Path | Contents |
|---|---|
| `yara/<family-or-campaign>/` | YARA rules, one rule per file or a small family file, plus a README describing the rules and their reference samples |
| `sigma/<category>/` | Sigma rules in SigmaHQ-style category folders (`dns_query/`, `proxy/`, `process_creation/`, `image_load/`, ...) |
| `iocs/<YYYY-MM-case-slug>/` | `README.md` (case summary, samples, links), `case.yml` (machine-readable case metadata), `iocs.csv` (defanged), `iocs.json` (machine-readable, NOT defanged), plus generated `stix2.json` (STIX 2.1) and `misp_event.json` (MISP) |
| `tools/<name>/` | Static config extractors and unpackers used to derive the rules; `tools/build_index.py` generates `INDEX.md`, `tools/export_iocs.py` generates the STIX 2.1 and MISP exports |
| `tests/` | YARA test harness (yara-python and YARA-X), Sigma logic tests, IOC validation, recorded results |

## How the rules are tested

- **YARA:** every rule file must compile with yara-python and YARA-X (CI). Rules are also run against their reference samples (each must match exactly the rules it is meant to match) and against a corpus of benign and unrelated PE files (0 hits required). A generated, spec-conformant file of the format a rule imitates is used as a synthetic negative where relevant. The harness is `tests/run_yara_tests.py`; the most recent recorded run is `tests/RESULTS.md`.
- **Sigma:** `sigma check --fail-on-error --fail-on-issues` with the SigmaHQ validators (CI), plus `tests/test_sigma_synthetic.py`, which runs each rule's logic on hand-made events.
- **IOCs:** `tests/validate_iocs.py` checks that CSV and JSON agree, that the CSV is defanged and that hashes are well-formed; `tests/validate_exports.py` validates the STIX 2.1 bundles (OASIS `stix2-validator`, `stix2`) and loads the MISP events with PyMISP.

Limits, stated plainly: rules are derived from static analysis. Unless a rule says otherwise there is no regression EVTX or pcap, and no rule has been measured on production telemetry. Levels are the author's estimate; baseline before alerting. Samples are malware and are not stored here; each case README links to the public copies.

```bash
uv venv && uv pip install yara-python yara-x cabarchive pyyaml
.venv/bin/python tests/run_yara_tests.py --compile-only
.venv/bin/python tests/run_yara_tests.py --samples <dir-with-samples> --negatives <dir-with-benign-files>
.venv/bin/python tests/test_sigma_synthetic.py
.venv/bin/python tests/validate_iocs.py
uv pip install stix2 stix2-validator pymisp && .venv/bin/python tools/export_iocs.py --check && .venv/bin/python tests/validate_exports.py
```

## Licenses

- Rules, tools and tests (`yara/`, `sigma/`, `tools/`, `tests/`): [Detection Rule License (DRL) 1.1](LICENSE). Keep the `author` field and a link to this repository.
- YARAhub requires a Creative Commons value in its `yarahub_license` meta field, so YARA rule files carry `CC BY 4.0` there; that is the license under which YARAhub redistributes them. The DRL applies to the copies in this repository.
- Indicators (`iocs/`): CC0 1.0, free to use without attribution.

## False positives and corrections

Open an [issue](../../issues) with the rule name, a sanitised example event or the (benign) file hash, and what the software was. Wrong or stale indicators can be reported the same way.

## Roadmap

Aim: become a vetted source for [YARA Forge](https://github.com/YARAHQ/yara-forge) once the repository has a track record. YARA Forge states that its sources are carefully selected and that unvetted sources are not supported, so no request has been made.
