#!/usr/bin/env python3
"""Fetch OTRF/Security-Datasets atomic metadata yaml (small files, paced) and index host-side zips."""
import json, time, urllib.request, pathlib, yaml
W = pathlib.Path(__file__).resolve().parent
tree = json.load(open(W / "cache/otrf_tree.json"))["tree"]
meta = [x["path"] for x in tree if "atomic/_metadata/" in x["path"] and x["path"].endswith(".yaml")]
out = W / "cache/otrf_meta"; out.mkdir(exist_ok=True)
for p in meta:
    f = out / pathlib.Path(p).name
    if f.exists(): continue
    url = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/" + p
    for i in range(4):
        try:
            f.write_bytes(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "sigma-replay/1"}), timeout=30).read()); break
        except Exception as e:
            time.sleep(2 ** i)
    time.sleep(0.3)
rows = []
for f in sorted(out.glob("*.yaml")):
    d = yaml.safe_load(f.read_text())
    for fl in d.get("files", []):
        rows.append(dict(id=d["id"], title=d.get("title"), platform=d.get("platform"),
                         attack=[(m.get("technique"), tuple(m.get("sub-technique") or [])) for m in (d.get("attack_mappings") or [])],
                         type=fl.get("type"), link=fl.get("link"), size=None))
json.dump(rows, open(W / "cache/otrf_index.json", "w"), indent=1, default=list)
print(len(rows), "file rows")
