"""Corpus readers: turn OTRF nxlog JSON, Mordor/winlogbeat JSON, Splunk/Sysmon XML, EVTX and CSV into
flat event dicts with Sysmon-style field names, then dedup (count multiplicity) into corpora/norm/*.jsonl.gz.

Event dict keys: `_eid` (int), `_kind` (sysmon|security|system|powershell|...), event fields (original names).
Dedup drops volatile fields (times, GUIDs, process ids, record ids) from the key; see VOLATILE.
"""
from __future__ import annotations
import csv, gzip, html, io, json, os, pathlib, re, sys, zipfile

ROOT = pathlib.Path(__file__).resolve().parent
NORM = ROOT / "corpora" / "norm"

KIND = {
    "microsoft-windows-sysmon/operational": "sysmon", "security": "security", "system": "system",
    "application": "application", "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell-classic", "microsoft-windows-taskscheduler/operational": "taskscheduler",
    "microsoft-windows-wmi-activity/operational": "wmi", "microsoft-windows-windows defender/operational": "windefend",
    "microsoft-windows-bits-client/operational": "bits-client", "microsoft-windows-dns-server/audit": "dns-server",
    "microsoft-windows-ntlm/operational": "ntlm", "microsoft-windows-codeintegrity/operational": "codeintegrity-operational",
    "microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
    "microsoft-windows-windows firewall with advanced security/firewall": "firewall-as",
    "microsoft-windows-smbclient/security": "smbclient-security",
    "microsoft-windows-applocker/exe and dll": "applocker",
}
VOLATILE = {
    "UtcTime", "ProcessGuid", "ParentProcessGuid", "SourceProcessGuid", "TargetProcessGuid", "SourceProcessGUID",
    "TargetProcessGUID", "LogonGuid", "ProcessId", "ParentProcessId", "SourceProcessId", "TargetProcessId",
    "SourceThreadId", "NewThreadId", "StartAddress", "EventRecordID", "RecordNumber", "record_id", "EventTime",
    "EventReceivedTime", "@timestamp", "ThreadID", "ExecutionProcessID", "ProcessID", "LogonId", "SubjectLogonId",
    "TargetLogonId", "CreationUtcTime", "PreviousCreationUtcTime", "NewProcessId", "Keywords", "SystemTime",
    "TimeCreated", "ActivityID", "RelatedActivityID", "SequenceNumber", "TerminalSessionId", "MessageNumber",
    "MessageTotal", "ScriptBlockId", "_ts",
}
DROP = {"tags", "@version", "port", "EventTypeOrignal", "EventTime", "@timestamp", "Message", "message", "SeverityValue", "Severity", "EventType_nxlog", "SourceModuleName", "SourceModuleType",
        "OpcodeValue", "Opcode", "Task", "Version", "Level", "Hostname", "host", "Domain", "AccountName", "AccountType",
        "UserID", "ProviderGuid", "EventReceivedTime", "Category", "ThreadID", "ExecutionProcessID", "RecordNumber",
        "SourceName", "ExecutionThreadID", "Guid"}


def kind_of(channel):
    c = (channel or "").lower()
    return KIND.get(c, re.sub(r"[^a-z0-9]+", "-", c).strip("-"))


def finish(d, eid, channel):
    d["_eid"] = int(eid)
    d["_kind"] = kind_of(channel)
    d["Channel"] = channel
    k, e = d["_kind"], d["_eid"]
    h = d.get("Hashes")
    if isinstance(h, str) and "=" in h:
        for part in re.split(r"[,;]", h):
            if "=" in part:
                a, b = part.split("=", 1)
                a = a.strip().upper()
                if a == "IMPHASH": d["Imphash"] = b
                elif a in ("MD5", "SHA1", "SHA256"): d[a] = b
    if k == "security" and e == 4688:
        d.setdefault("Image", d.get("NewProcessName"))
        d.setdefault("ParentImage", d.get("ParentProcessName"))
        d.setdefault("User", d.get("SubjectUserName"))
    if k == "powershell" and e == 4104:
        pass
    return d


def dkey(d):
    return hash(tuple(sorted((k, str(v)) for k, v in d.items() if k not in VOLATILE)))


# -------------------------------------------------------------------- readers (generators of dicts)
def read_nxlog(fh):
    for line in fh:
        line = line.strip()
        if not line: continue
        try: o = json.loads(line)
        except ValueError: continue
        if "EventID" not in o: continue
        eid, ch = o["EventID"], o.get("Channel", "")
        d = {k: v for k, v in o.items() if k not in DROP and k != "EventID" and v is not None}
        # Security 4688 etc keep original names
        yield finish(d, eid, ch)


def read_winlogbeat(fh):
    for line in fh:
        line = line.strip()
        if not line: continue
        try: o = json.loads(line)
        except ValueError: continue
        w = o.get("winlog") or {}
        ed = w.get("event_data") or o.get("event_data") or {}
        eid = w.get("event_id") or o.get("event_id") or (o.get("event") or {}).get("code")
        ch = w.get("channel") or o.get("channel") or o.get("log_name") or ""
        if eid is None: continue
        if ch.lower() == "security": ch = "Security"
        elif ch.lower() == "system": ch = "System"
        elif ch.lower() == "application": ch = "Application"
        elif ch.lower() == "windows powershell": ch = "Windows PowerShell"
        d = {k: v for k, v in ed.items() if v is not None}
        # winlogbeat puts 4104 text under event_data.ScriptBlockText; 4103 under ContextInfo/Payload
        if "param1" in d and "Payload" not in d: pass
        yield finish(d, eid, ch)


_ev_re = re.compile(r"<Event\b.*?</Event>", re.S)
_data_re = re.compile(r"<Data(?: Name=['\"]([^'\"]*)['\"])?\s*(?:/>|>(.*?)</Data>)", re.S)
_eid_re = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_ch_re = re.compile(r"<Channel>(.*?)</Channel>")


def read_xml_text(text):
    for m in _ev_re.finditer(text):
        x = m.group(0)
        me, mc = _eid_re.search(x), _ch_re.search(x)
        if not me: continue
        ed = x.split("<EventData", 1)[1] if "<EventData" in x else ""
        d = {}
        for n, v in _data_re.findall(ed):
            if n: d[n] = html.unescape(v) if v else ""
        ud = x.split("<UserData", 1)[1] if "<UserData" in x else ""
        yield finish(d, me.group(1), html.unescape(mc.group(1)) if mc else "")


def read_xml(path):
    raw = pathlib.Path(path).read_bytes()
    try: text = raw.decode("utf-8-sig")
    except UnicodeDecodeError: text = raw.decode("utf-16", "replace")
    yield from read_xml_text(text)


def read_evtx(path):
    from evtx import PyEvtxParser
    p = PyEvtxParser(str(path))
    for rec in p.records_json():
        try: o = json.loads(rec["data"])["Event"]
        except Exception: continue
        s = o.get("System", {})
        eid = s.get("EventID")
        if isinstance(eid, dict): eid = eid.get("#text")
        ch = s.get("Channel", "")
        ed = o.get("EventData") or {}
        d = {}
        if isinstance(ed, dict):
            for k, v in ed.items():
                if k == "Data" and isinstance(v, dict) and "#attributes" not in v and False: pass
                if isinstance(v, dict): v = v.get("#text", json.dumps(v))
                if v is not None: d[k] = v if not isinstance(v, list) else " ".join(map(str, v))
        ud = o.get("UserData")
        if isinstance(ud, dict):
            for sub in ud.values():
                if isinstance(sub, dict):
                    for k, v in sub.items():
                        if k != "#attributes" and not isinstance(v, dict): d[k] = v
        if eid is None: continue
        yield finish(d, eid, ch)


def read_sysmon_csv(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        for r in csv.DictReader(fh):
            if r["event_id"] not in ("1",): continue   # EID1 only carries command lines; EID5 has no rule value
            d = {"Image": r["image"], "CommandLine": r["command_line"], "ParentImage": r["parent_image"] if r["parent_image"] != "-" else "",
                 "User": r["user"], "IntegrityLevel": r["integrity_level"], "Hashes": r["hashes"]}
            d = {k: v for k, v in d.items() if v not in (None, "")}
            yield finish(d, 1, "Microsoft-Windows-Sysmon/Operational")


# -------------------------------------------------------------------- ingest
def write_dataset(corpus, name, events, meta):
    out = NORM / corpus
    out.mkdir(parents=True, exist_ok=True)
    seen, rows, cnt, total = {}, [], [], 0
    for d in events:
        total += 1
        k = dkey(d)
        i = seen.get(k)
        if i is None:
            seen[k] = len(rows); rows.append(json.dumps(d, ensure_ascii=False)); cnt.append(1)   # keep serialised: ~3x less RAM
        else:
            cnt[i] += 1
    f = out / (name + ".jsonl.gz")
    with gzip.open(f, "wt", encoding="utf-8") as fh:
        for n, r in zip(cnt, rows): fh.write("[%d,%s]\n" % (n, r))
    meta = dict(meta, corpus=corpus, name=name, file=str(f.relative_to(ROOT)), events=total, unique=len(rows))
    (out / (name + ".meta.json")).write_text(json.dumps(meta))
    print(f"{corpus}/{name}: {total} events -> {len(rows)} unique", flush=True)
    return meta


def _otrf_meta():
    idx = json.load(open(ROOT / "cache/otrf_index.json"))
    import yaml
    out = {}
    for f in (ROOT / "cache/otrf_meta").glob("*.yaml"):
        d = yaml.safe_load(f.read_text())
        techs = []
        for m in d.get("attack_mappings") or []:
            t = m.get("technique")
            subs = m.get("sub-technique")
            if subs:
                subs = subs if isinstance(subs, list) else [subs]
                for s in subs: techs.append(f"{t}.{str(s).zfill(3)}")
            elif t: techs.append(t)
        out[d["id"]] = dict(title=d.get("title"), techniques=techs, tactics=[x for m in (d.get("attack_mappings") or []) for x in (m.get("tactics") or [])])
    return out


def ingest(corpus):
    if corpus == "otrf":
        meta = _otrf_meta()
        for d in sorted((ROOT / "corpora/otrf").iterdir()):
            if not d.is_dir(): continue
            m = meta.get(d.name, {})
            files = sorted(d.glob("*.json"))
            def gen():
                for f in files:
                    with open(f, encoding="utf-8", errors="replace") as fh: yield from read_nxlog(fh)
            write_dataset("otrf", d.name, gen(), dict(label="attack", title=m.get("title"), techniques=m.get("techniques", []), tactics=m.get("tactics", []),
                                                      licence="MIT (OTRF/Security-Datasets)"))
    elif corpus == "splunk":
        for f in sorted((ROOT / "corpora/splunk").glob("*.log")):
            tech = f.name.split("__")[0].upper()
            write_dataset("splunk", f.stem, read_xml(f), dict(label="attack", techniques=[tech], title=f.name, licence="Apache-2.0 (splunk/attack_data)"))
    elif corpus == "evtx":
        for f in sorted((ROOT / "corpora/evtx").glob("*.evtx")):
            tact = f.name.split("__")[0]
            techs = sorted(set(t.upper() for t in re.findall(r"[Tt]\d{4}(?:\.\d{3})?", f.name)))
            try:
                write_dataset("evtx", f.stem, read_evtx(f), dict(label="attack", techniques=techs, tactics=[tact], title=f.name, licence="GPL-3.0 (sbousseaden/EVTX-ATTACK-SAMPLES)"))
            except Exception as e:
                print("evtx fail", f.name, e, file=sys.stderr)
    elif corpus == "mordor":
        z = zipfile.ZipFile(ROOT / "corpora/mordor_kaggle/mordor.zip")
        for n in z.namelist():
            if not n.endswith(".json"): continue
            name = pathlib.Path(n).stem
            def gen(n=n):
                with io.TextIOWrapper(z.open(n), encoding="utf-8", errors="replace") as fh: yield from read_winlogbeat(fh)
            write_dataset("mordor", name, gen(), dict(label="attack", techniques=[], title=n, licence="MIT (OTRF Mordor via Kaggle vinayakathadakar)",
                                                      note="campaign-level (APT29 eval day1 / Empire APT3), no per-technique label"))
    elif corpus == "benign":
        base = pathlib.Path(os.environ.get("SIGMA_REPLAY_BENIGN_DIR", str(ROOT / "corpora/benign_src")))   # unpacked Kaggle ramachandrabharadwaj/sysmon + sysmon-csv-ds
        write_dataset("benign", "sysmon_h1_benign_xml", read_xml(base / "ramachandrabharadwaj_sysmon/sysmon ds/benign/sysmon-h1-benign-1.xml"),
                      dict(label="benign", techniques=[], title="ramachandrabharadwaj/sysmon benign XML (1 host, 2022-07)", licence="Unknown (Kaggle)"))
        write_dataset("benign", "sysmon_h1_benign_csv", read_sysmon_csv(base / "ramachandrabharadwaj_sysmon-csv-ds/benign_logs.csv"),
                      dict(label="benign", techniques=[], title="ramachandrabharadwaj/sysmon-csv-ds benign (EID1 only, 7 fields)", licence="Unknown (Kaggle)"))
    else:
        raise SystemExit("unknown corpus " + corpus)


def iter_dataset(meta_file):
    meta = json.loads(pathlib.Path(meta_file).read_text())
    with gzip.open(ROOT / meta["file"], "rt", encoding="utf-8") as fh:
        for line in fh:
            n, d = json.loads(line)
            yield n, d


def list_datasets(corpora=None, label=None):
    out = []
    for f in sorted(NORM.glob("*/*.meta.json")):
        m = json.loads(f.read_text()); m["meta_file"] = str(f)
        if corpora and m["corpus"] not in corpora: continue
        if label and m["label"] != label: continue
        out.append(m)
    return out


if __name__ == "__main__":
    for c in sys.argv[1:]: ingest(c)
