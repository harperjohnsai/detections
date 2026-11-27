#!/usr/bin/env python3
"""Download Windows host-side OTRF zips <=1.5 MB (paced) into corpora/otrf/ and unzip."""
import json, time, urllib.request, pathlib, zipfile
W = pathlib.Path(__file__).resolve().parent
tree = {x["path"]: x["size"] for x in json.load(open(W / "cache/otrf_tree.json"))["tree"] if "size" in x}
rows = json.load(open(W / "cache/otrf_index.json"))
dst = W / "corpora/otrf"; dst.mkdir(parents=True, exist_ok=True)
base = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
n = 0; tot = 0
for r in rows:
    if r["type"] != "Host" or "Windows" not in (r["platform"] or []) or not r["link"].endswith(".zip"): continue
    path = r["link"].replace(base, "")
    sz = tree.get(path, 0)
    if sz > 1_500_000 or sz < 2000: continue
    f = dst / (r["id"] + ".zip")
    if not f.exists():
        for i in range(4):
            try:
                f.write_bytes(urllib.request.urlopen(urllib.request.Request(r["link"], headers={"User-Agent": "sigma-replay/1"}), timeout=60).read()); break
            except Exception as e:
                print("retry", r["id"], e); time.sleep(2 ** i)
        time.sleep(0.4)
    if f.exists():
        n += 1; tot += f.stat().st_size
        d = dst / r["id"]
        if not d.exists():
            with zipfile.ZipFile(f) as z: z.extractall(d)
print(n, "datasets", tot / 1e6, "MB zipped")
