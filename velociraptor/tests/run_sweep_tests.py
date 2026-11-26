#!/usr/bin/env python3
"""Regression test for velociraptor/linux/Custom.Linux.Persistence.Sweep.yaml.

Seeds three inert fixture sets into temporary fake roots (text files only, nothing is executed, every
network target is 127.0.0.1:9), runs the artifact against each with the Velociraptor CLI and checks the
flagged rows:

  plants   5 generic persistence plants + 2 decoys        -> exactly the 5 plants flagged
  etherrat 5 EtherRAT Linux persistence templates + 5 decoys -> 5/5 flagged, 0 decoys
  devhost  13 benign developer-host entries, 2 legit @reboot lines, 3 attack controls
           -> 0 benign flagged, 3/3 attack controls flagged, the 2 @reboot lines flagged (by design)

Usage: VELOCIRAPTOR=/path/to/velociraptor python3 run_sweep_tests.py   (exit 0 = all pass)
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ART_DIR = os.path.join(HERE, "..", "linux")
VELO = os.environ.get("VELOCIRAPTOR", "velociraptor")
FIX = os.path.join(HERE, "fixtures")


def sweep(fixture):
    root = tempfile.mkdtemp(prefix=f"sweep-{fixture}-")
    subprocess.run([sys.executable, os.path.join(FIX, f"{fixture}.py"), "seed", root], check=True,
                   stdout=subprocess.DEVNULL)
    try:
        out = subprocess.run([VELO, "--definitions", ART_DIR, "artifacts", "collect",
                              "Custom.Linux.Persistence.Sweep", "--args", f"Roots={root}/", "--format", "jsonl"],
                             check=True, capture_output=True, text=True).stdout
    finally:
        subprocess.run([sys.executable, os.path.join(FIX, f"{fixture}.py"), "remove", root], check=True,
                       stdout=subprocess.DEVNULL)
    rows = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
    for r in rows:
        r["Path"] = r["Path"].split(root, 1)[-1]
    return rows, [r for r in rows if r.get("Suspicious")]


def check(name, ok, detail):
    print(("PASS" if ok else "FAIL"), name, detail)
    return ok


def main():
    results = []
    subprocess.run([VELO, "artifacts", "verify", os.path.join(ART_DIR, "Custom.Linux.Persistence.Sweep.yaml")],
                   check=True)
    results.append(check("verify", True, "artifacts verify exit 0"))

    rows, flag = sweep("plants")
    want = {"/etc/cron.d/sysupdate", "/home/victim/.config/systemd/user/updater.service",
            "/home/victim/.ssh/authorized_keys", "/home/victim/.bashrc", "/etc/ld.so.preload"}
    got = {r["Path"] for r in flag}
    results.append(check("plants", got == want and len(flag) == 5,
                         f"rows={len(rows)} flagged={len(flag)} missing={sorted(want - got)} extra={sorted(got - want)}"))

    rows, flag = sweep("plants_etherrat")
    hits = {
        "E1": any("a1b2c3d4e5f6.service" in r["Path"] for r in flag),
        "E2": any("9f8e7d6c5b4a.desktop" in r["Path"] for r in flag),
        "E3": any("crontabs" in r["Path"] and "@reboot" in str(r["Detail"]) for r in flag),
        "E4": any(r["Path"].endswith(".bashrc") and "nohup" in str(r["Detail"]) for r in flag),
        "E5": any(r["Path"].endswith(".profile") and ".7vfgycfd01.js" in str(r["Detail"]) for r in flag),
    }
    results.append(check("etherrat", all(hits.values()) and len(flag) == 5,
                         f"rows={len(rows)} flagged={len(flag)} recall={sum(hits.values())}/5"))

    rows, flag = sweep("plants_devhost")
    attack = [r for r in flag if "127.0.0.1:9" in str(r["Detail"]) or "/tmp/.x1y2z3q" in str(r["Detail"])]
    noise = [r for r in flag if str(r["Detail"]).startswith("@reboot")]
    fp = [r for r in flag if r not in attack and r not in noise]
    results.append(check("devhost", len(attack) == 3 and len(noise) == 2 and not fp,
                         f"rows={len(rows)} attack={len(attack)}/3 reboot_noise={len(noise)} "
                         f"false_positives={[str(r['Detail'])[:60] for r in fp]}"))
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
