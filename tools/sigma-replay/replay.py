#!/usr/bin/env python3
"""Replay Sigma rules over real-log corpora (normalised by corpus.py) and report per-rule TP/FP counts.

  replay.py --rules <dir|file> [--rules ...] --corpus all|otrf,splunk,evtx,mordor,benign [--json out.json] [--examples 3]

TP = hits on attack corpora (lab logs, whole dataset is labelled attack; background noise inside the lab is
included, so also see tp_named = hits on datasets whose ATT&CK technique matches the rule's tag).
FP = hits on the benign corpora. Counts are events (with multiplicity) and unique events (dedup).
"""
import argparse, collections, json, pathlib, sys, time
import corpus, sigma_engine

KEEP = ["Image", "CommandLine", "ParentImage", "ParentCommandLine", "TargetObject", "Details", "ImageLoaded", "QueryName",
        "DestinationIp", "DestinationPort", "TargetFilename", "SourceImage", "TargetImage", "GrantedAccess", "ScriptBlockText",
        "PipeName", "NewProcessName", "ServiceName", "ImagePath", "Payload", "TargetUserName", "LogonType"]


def tech_match(rt, dt):
    rb, rs = (rt.split(".") + [None])[:2]
    db, ds = (dt.split(".") + [None])[:2]
    return rb == db and (rs is None or ds is None or rs == ds)


def compact(d, ds):
    o = {"dataset": ds, "eid": d.get("_eid")}
    for k in KEEP:
        v = d.get(k)
        if v not in (None, ""):
            o[k] = str(v)[:220]
    return o


def replay(rule_paths, corpora, n_examples=3, rules=None, progress=False):
    rules = rules if rules is not None else sigma_engine.load_rules(rule_paths)
    eng = sigma_engine.Engine(rules)
    st = {r.path + "|" + r.title: dict(rule=r, att=collections.Counter(), attu=collections.Counter(), ben=collections.Counter(),
                                       benu=collections.Counter(), named=collections.Counter(), ds_hit={}, ex_att=[], ex_ben=[],
                                       eval_att=0, eval_ben=0) for r in rules}
    rule_id = lambda r: r.path + "|" + r.title
    totals = collections.Counter()
    dsets = corpus.list_datasets(corpora)
    t0 = time.time()
    for m in dsets:
        lab = "att" if m["label"] == "attack" else "ben"
        totals[lab + "_events"] += m["events"]; totals[lab + "_datasets"] += 1
        dtech = m.get("techniques") or []
        for n, d in corpus.iter_dataset(m["meta_file"]):
            hit, seen = eng.run(d)
            for r in seen:
                st[rule_id(r)]["eval_" + lab] += n
            for r in hit:
                s = st[rule_id(r)]
                if lab == "att":
                    s["att"]["events"] += n; s["attu"]["unique"] += 1
                    s["ds_hit"][m["name"]] = s["ds_hit"].get(m["name"], 0) + n
                    if any(tech_match(rt, dt) for rt in r.techniques for dt in dtech):
                        s["named"]["events"] += n; s["named"][m["name"]] = s["named"].get(m["name"], 0) + n
                    if len(s["ex_att"]) < n_examples: s["ex_att"].append(compact(d, m["name"]))
                else:
                    s["ben"]["events"] += n; s["benu"]["unique"] += 1
                    if len(s["ex_ben"]) < n_examples: s["ex_ben"].append(compact(d, m["name"]))
        if progress: print(f"  {m['corpus']}/{m['name']} done ({time.time()-t0:.0f}s)", file=sys.stderr, flush=True)
    out = []
    for k, s in st.items():
        r = s["rule"]
        named_ds = [m["name"] for m in dsets if m["label"] == "attack" and any(tech_match(rt, dt) for rt in r.techniques for dt in (m.get("techniques") or []))]
        out.append(dict(
            title=r.title, id=r.id, path=r.path, level=r.level, status=r.status, techniques=r.techniques,
            skipped=r.skip_reason,
            tp_events=s["att"]["events"], tp_unique=s["attu"]["unique"], tp_datasets=len(s["ds_hit"]),
            named_datasets_available=len(named_ds),
            tp_named_events=s["named"]["events"], tp_named_datasets=sum(1 for x in named_ds if s["named"].get(x)),
            fp_events=s["ben"]["events"], fp_unique=s["benu"]["unique"],
            eval_attack_events=s["eval_att"], eval_benign_events=s["eval_ben"],
            fp_per_100k=round(100000 * s["ben"]["events"] / s["eval_ben"], 1) if s["eval_ben"] else None,
            top_datasets=sorted(s["ds_hit"].items(), key=lambda x: -x[1])[:5],
            examples_tp=s["ex_att"], examples_fp=s["ex_ben"]))
    return dict(totals=dict(totals), n_rules=len(rules), n_skipped=len(eng.skipped), rules=out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", action="append", required=True)
    ap.add_argument("--corpus", default="all")
    ap.add_argument("--json")
    ap.add_argument("--examples", type=int, default=3)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--fail-on-fp", type=int, metavar="N", help="exit 1 if any rule has more than N unique benign hits (CI gate)")
    ap.add_argument("--strict-coverage", action="store_true", help="with --fail-on-fp: also exit 1 when a rule was skipped or never evaluated on a benign event (0 hits would not mean quiet)")
    ap.add_argument("--require-tp", action="append", default=[], metavar="TITLE", help="exit 1 unless the rule with this title fires on the attack corpora")
    a = ap.parse_args()
    corp = None if a.corpus == "all" else a.corpus.split(",")
    res = replay(a.rules, corp, a.examples, progress=not a.quiet)
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(res, indent=1))
    t = res["totals"]
    print(f"rules {res['n_rules']} (skipped {res['n_skipped']}); attack events {t.get('att_events',0)} in {t.get('att_datasets',0)} datasets; benign events {t.get('ben_events',0)} in {t.get('ben_datasets',0)}")
    print(f"{'TP':>7} {'TPnamed':>7} {'FP':>7}  rule")
    for r in sorted(res["rules"], key=lambda r: (-r["tp_events"], r["title"])):
        if r["skipped"]:
            print(f"{'-':>7} {'-':>7} {'-':>7}  {r['title']}  [skipped: {r['skipped']}]"); continue
        print(f"{r['tp_events']:>7} {r['tp_named_events']:>7} {r['fp_events']:>7}  {r['title']}")
    rc = 0
    if a.fail_on_fp is not None:
        bad = [r for r in res["rules"] if not r["skipped"] and r["fp_unique"] > a.fail_on_fp]
        for r in bad: print(f"FAIL fp: {r['title']} has {r['fp_unique']} unique benign hits", file=sys.stderr)
        rc |= bool(bad)
        blind = [r for r in res["rules"] if r["skipped"] or not r["eval_benign_events"]]
        for r in blind: print(f"WARN fp gate blind: {r['title']} ({r['skipped'] or 'no benign event of its log source'})", file=sys.stderr)
        if a.strict_coverage: rc |= bool(blind)
    for t in a.require_tp:
        ok = any(r["title"] == t and r["tp_events"] > 0 for r in res["rules"])
        if not ok: print(f"FAIL tp: {t!r} did not fire on the attack corpora", file=sys.stderr)
        rc |= (not ok)
    sys.exit(rc)


if __name__ == "__main__":
    main()
