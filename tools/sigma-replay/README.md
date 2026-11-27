# sigma-replay: run Sigma rules against real log corpora

Counts, per rule, how many events it fires on **attack logs** (true-positive evidence) and on **benign logs**
(false-positive evidence), with example hits. Built because hand-made test events (`tests/test_sigma_synthetic.py`)
only prove that a rule matches what its author wrote down.

Author: Harper Johns (autonomous AI security researcher, human oversight).

## Quick start

```
uv venv .venv && uv pip install --python .venv/bin/python pyyaml pytest evtx
.venv/bin/python -m pytest -q tests                      # engine tests + one known TP on real Sysmon events
.venv/bin/python corpus.py otrf splunk evtx mordor benign  # normalise fetched corpora -> corpora/norm/*.jsonl.gz
.venv/bin/python replay.py --rules ../../sigma --corpus all --json out.json
```

`replay.py --rules <dir|file> [--rules ...] --corpus all|otrf,splunk,evtx,mordor,benign [--json out.json] [--examples N]`

Output per rule: `TP` (events on attack corpora), `TPnamed` (events on datasets labelled with the rule's own ATT&CK
technique), `FP` (events on benign corpora), plus unique-event counts, the number of events the rule was evaluated on
(its log source), FP per 100k evaluated events, top datasets and example events (`--json`).
CI gates: `--fail-on-fp N` (exit 1 if a rule has more than N unique benign hits; rules that were skipped or never saw a benign event of their log source are listed as `WARN fp gate blind`, and `--strict-coverage` turns those into a failure) and `--require-tp "<rule title>"`.

## How it works

* `sigma_engine.py`: in-process matcher (PyYAML only). Modifiers `contains startswith endswith all re(i,m,s) cidr
  windash base64 base64offset utf16le/be wide lt/lte/gt/gte exists fieldref cased`, wildcards, null, keyword lists,
  `and/or/not`, parentheses, `1 of x*`, `all of them`. Skipped with a stated reason: aggregations (`| count`),
  correlation rules, `expand`, log sources with no corpus (proxy, DNS server, Linux, macOS...). It is not a
  pySigma backend: no SQL, no pipelines, so one rule file is one code path and the verdict can be read in the source.
  `tests/test_parity_synthetic.py` checks it against the repo's own synthetic-event verdicts.
* Log source routing: `category` -> Sysmon EventID (`process_creation` = Sysmon 1 and Security 4688, `image_load` = 7,
  `registry_set` = 13, `registry_add` = 12 CreateKey, `registry_delete` = 12 Delete*, `network_connection` = 3,
  `file_event` = 11, `dns_query` = 22, `process_access` = 10, `pipe_created` = 17/18, ...), `service` -> channel.
* Field mapping: every corpus is normalised to Sysmon field names (`Image`, `CommandLine`, `ParentImage`, `TargetObject`,
  `Details`, `ImageLoaded`...). OTRF/nxlog JSON is already flat; Mordor/winlogbeat `winlog.event_data.*` is flattened;
  Splunk `XmlWinEventLog` XML and EVTX (`evtx` package) are parsed to the same shape; Security 4688 gets `Image`,
  `ParentImage`, `User` aliases; `Hashes` is split into `MD5 SHA1 SHA256 Imphash`.
* Dedup: identical events (ignoring times, GUIDs, process/record ids) are stored once with a multiplicity, so counts
  are events and `unique` counts are distinct events.

## Corpora (fetched by the scripts, not stored in git)

| name | source | licence | content |
|---|---|---|---|
| `otrf` | OTRF/Security-Datasets, Windows host zips <= 1.5 MB (`fetch_otrf_meta.py`, `fetch_otrf.py`) | MIT | Sysmon + Security + PowerShell JSON, technique-labelled |
| `splunk` | splunk/attack_data Windows Sysmon XML logs <= 6 MB via media.githubusercontent.com (`fetch_corpora.py splunk`) | Apache-2.0 | Atomic Red Team and others, technique = directory name |
| `evtx` | sbousseaden/EVTX-ATTACK-SAMPLES, files <= 2 MB (`fetch_corpora.py evtx`) | GPL-3.0 | EVTX, tactic folder only |
| `mordor` | Kaggle `vinayakathadakar/mordor-windows-events` (OTRF Mordor slice) (`fetch_corpora.py mordor`) | MIT | APT29 eval day 1, Empire APT3, campaign level |
| `benign` | Kaggle `ramachandrabharadwaj/sysmon` and `sysmon-csv-ds` benign captures, unpacked to `corpora/benign_src` or `$SIGMA_REPLAY_BENIGN_DIR` | unknown (not redistributed) | one workstation, Sysmon EID 1 (CSV: 7 fields only) |

`fetch_*.py` need `cache/*_tree.json` (the GitHub tree API output for each repo, one request each, `curl
https://api.github.com/repos/<owner>/<repo>/git/trees/master?recursive=1`). Requests are paced; none touches a malicious host and
no binaries are downloaded.

## Read the numbers with care

* The benign pool is thin: one host, two captures, labelled per capture file. Zero FP here is not evidence of a quiet rule.
* Attack datasets are lab runs: louder than real intrusions, and they contain ordinary OS activity too (`TP` counts every hit
  inside an attack dataset; `TPnamed` restricts to datasets labelled with the rule's own technique).
* Campaign-specific (IOC-style) rules cannot get a TP from these corpora; the harness then shows FP evidence only.
* Test fixtures (`tests/fixtures/otrf_sample_events.jsonl`) are two Sysmon events from OTRF/Security-Datasets (MIT).
* `--json` output embeds example events from the corpora. The benign corpus has an unknown licence: keep that file local, do not publish it or upload it as a CI artifact.
* Known gaps: Security 4688 events lack `ParentCommandLine`, `OriginalFileName`, `IntegrityLevel` and `Hashes`; `Provider_Name` is not mapped; `base64` without `contains` matches as a substring.
* The repo's CI job runs only the unit tests (no corpus is fetched there) and has no false-positive gate.
* Fixture licence text: `tests/fixtures/NOTICE.md`.
