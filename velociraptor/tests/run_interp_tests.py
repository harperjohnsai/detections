#!/usr/bin/env python3
"""Regression test for velociraptor/linux/Custom.Linux.Hunt.UserDirInterpreter.yaml.

Starts 16 inert process plants (renamed copies of /bin/bash that only sleep, see fixtures/plants_interp.py) in a
temporary fake home R and fake temp dir T, runs the artifact with the Velociraptor CLI scoped to those two dirs
(UserDirRegex=^R/|^T/, TempRegex=^T/, ShowAllowListed=Y) and checks the severity of every plant:

  4 attack-like plants (Interlock-style php + .cfg, EtherRAT-style node in a random hidden dir, python in temp,
    perl in ~/bin)                                   -> high, high, high, medium
  2 official one-line installer runtimes (bun, deno)  -> medium (deliberately not allow-listed)
  10 developer-host runtimes (nvm, uv, VS Code server, mise, pyenv, miniforge, miniconda, Homebrew on Linux,
    Playwright driver node, volta)                   -> allow (hidden unless ShowAllowListed=Y)

A second run with the default ShowAllowListed=N must return exactly the 6 non-allow rows.

Usage: VELOCIRAPTOR=/path/to/velociraptor python3 run_interp_tests.py   (Linux only, exit 0 = all pass)
"""
import json, os, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ART_DIR = os.path.join(HERE, "..", "linux")
ART = "Custom.Linux.Hunt.UserDirInterpreter"
VELO = os.environ.get("VELOCIRAPTOR", "velociraptor")
sys.path.insert(0, os.path.join(HERE, "fixtures"))
import plants_interp  # noqa: E402


def collect(R, T, show_all):
    args = [VELO, "--definitions", ART_DIR, "artifacts", "collect", ART,
            "--args", f"UserDirRegex=^{R}/|^{T}/", "--args", f"TempRegex=^{T}/", "--format", "jsonl"]
    if show_all:
        args += ["--args", "ShowAllowListed=Y"]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return [json.loads(l) for l in out.splitlines() if l.startswith("{")]


def check(name, ok, detail):
    print(("PASS" if ok else "FAIL"), name, detail)
    return ok


def main():
    results = []
    subprocess.run([VELO, "artifacts", "verify", os.path.join(ART_DIR, ART + ".yaml")], check=True)
    results.append(check("verify", True, "artifacts verify exit 0"))

    R = tempfile.mkdtemp(prefix="interp-home-")
    T = tempfile.mkdtemp(prefix="interp-temp-")
    procs = plants_interp.start(R, T)
    try:
        time.sleep(2)
        rows_all = collect(R, T, True)
        rows_default = collect(R, T, False)
    finally:
        plants_interp.stop(procs)
        shutil.rmtree(R, ignore_errors=True)
        shutil.rmtree(T, ignore_errors=True)

    by_pid = {r["Pid"]: r for r in rows_all}
    for k, (p, want) in sorted(procs.items()):
        r = by_pid.get(p.pid)
        got = r["Severity"] if r else "MISSING"
        results.append(check(k, got == want, f"want={want} got={got} reason={r and r['Reason']}"))
    plant_pids = {p.pid for p, _ in procs.values()}
    extra = [r for r in rows_all if r["Pid"] not in plant_pids]
    results.append(check("no-extra-rows", not extra, f"extra={[(r['Exe'], r['Severity']) for r in extra]}"))

    want_default = {p.pid for p, w in procs.values() if w != "allow"}
    got_default = {r["Pid"] for r in rows_default}
    results.append(check("default-hides-allow-listed", got_default == want_default,
                         f"rows={len(rows_default)} want={len(want_default)}"))
    n_ok = sum(results)
    print(f"{n_ok}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
