#!/usr/bin/env python3
"""Fetch selected logs for the replay corpora. Paced, resumable, no binaries (EVTX/XML/JSON logs only).
 - splunk/attack_data Windows Sysmon XML logs (LFS via media.githubusercontent.com), <=6 MB each, <=450 MB total
 - sbousseaden/EVTX-ATTACK-SAMPLES evtx <=2 MB each
 - Kaggle vinayakathadakar/mordor-windows-events zip (anonymous API)
"""
import json, time, urllib.request, urllib.error, pathlib, subprocess, sys
W = pathlib.Path(__file__).resolve().parent
UA = {"User-Agent": "sigma-replay/1 (research; paced)"}

def get(url, method="GET", tries=5):
    for i in range(tries):
        try:
            return urllib.request.urlopen(urllib.request.Request(url, headers=UA, method=method), timeout=120)
        except urllib.error.HTTPError as e:
            if e.code in (429, 403, 502, 503):
                time.sleep(5 * 2 ** i); continue
            raise
        except Exception:
            time.sleep(2 ** i)
    raise RuntimeError(url)

def splunk():
    t = json.load(open(W / "cache/splunk_tree.json"))["tree"]
    c = [x["path"] for x in t if x["path"].startswith("datasets/attack_techniques/") and "sysmon" in x["path"].lower()
         and x["path"].endswith(".log") and "linux" not in x["path"].lower()]
    d = W / "corpora/splunk"; d.mkdir(parents=True, exist_ok=True)
    idx_f = W / "cache/splunk_sizes.json"
    sizes = json.load(open(idx_f)) if idx_f.exists() else {}
    base = "https://media.githubusercontent.com/media/splunk/attack_data/master/"
    for p in c:
        if p in sizes: continue
        try:
            sizes[p] = int(get(base + p, "HEAD").headers.get("Content-Length", -1))
        except Exception as e:
            sizes[p] = -1
        time.sleep(0.2)
    json.dump(sizes, open(idx_f, "w"))
    tot = 0
    for p in sorted(c, key=lambda p: sizes[p]):
        s = sizes[p]
        if s < 5000 or s > 6_000_000 or tot + s > 450_000_000: continue
        name = p.replace("datasets/attack_techniques/", "").replace("/", "__")
        f = d / name
        if not f.exists():
            f.write_bytes(get(base + p).read()); time.sleep(0.3)
        tot += s
    print("splunk files", len(list(d.glob('*.log'))), tot / 1e6, "MB")

def evtx():
    t = json.load(open(W / "cache/evtx_tree.json"))["tree"]
    d = W / "corpora/evtx"; d.mkdir(parents=True, exist_ok=True)
    base = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/"
    n = 0
    for x in t:
        p = x["path"]
        if not p.lower().endswith(".evtx") or x.get("size", 0) > 2_000_000: continue
        f = d / p.replace("/", "__")
        if not f.exists():
            f.write_bytes(get(base + urllib.request.quote(p)).read()); time.sleep(0.25)
        n += 1
    print("evtx files", n)

def mordor():
    d = W / "corpora/mordor_kaggle"; d.mkdir(parents=True, exist_ok=True)
    z = d / "mordor.zip"
    if not z.exists():
        subprocess.run(["curl", "-sL", "-o", str(z), "https://www.kaggle.com/api/v1/datasets/download/vinayakathadakar/mordor-windows-events"], check=True)
    print("mordor zip", z.stat().st_size / 1e6, "MB")

if __name__ == "__main__":
    for fn in sys.argv[1:]:
        globals()[fn]()
