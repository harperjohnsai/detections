#!/usr/bin/env python3
"""Inert process plants for Custom.Linux.Hunt.UserDirInterpreter.

Every "interpreter" is a COPY OF /bin/bash renamed (php, node, python3, perl, ruby, bun, deno) that only runs
`sleep 150; :` (the trailing ':' stops bash from exec-ing sleep directly, so the renamed bash stays the process).
The extra argv only mimic real command lines (PHP Interlock RAT, EtherRAT node, developer tools); nothing is
downloaded, no script is read, nothing else runs.

  R = fake home directory, T = fake temp directory (both temporary dirs created by the test).
  expect = severity the artifact must report ('allow' = allow-listed runtime, row hidden by default).

Usage as a module: layout(R, T) -> {id: (exe, argv, expect)}; start(R, T) -> [Popen]; stop(procs).
"""
import os, shutil, subprocess

SLEEP = "sleep 150; :"


def layout(R, T):
    return {
        # attack-like plants
        "P1-interlock-php-cfg": (f"{R}/.config/php/php",
                                 ["-d", "extension=zip", "-d", "extension_dir=ext", f"{R}/.config/php/wefs.cfg", "1"], "high"),
        "P2-etherrat-node-hidden-dir": (f"{R}/.local/share/.05bf0e9b/node-v20.10.0-linux-x64/bin/node",
                                        [f"{R}/.local/share/.05bf0e9b/.7vfgycfd01.js"], "high"),
        "P3-python-in-temp": (f"{T}/python3", [f"{T}/run.py"], "high"),
        "P4-perl-in-home-bin": (f"{R}/bin/perl", [f"{R}/bin/tool.pl"], "medium"),
        # official one-line installers, deliberately NOT allow-listed (Bun was used to run Mini Shai-Hulud)
        "M1-bun-default-install": (f"{R}/.bun/bin/bun", ["run", f"{R}/proj/index.ts"], "medium"),
        "M2-deno-default-install": (f"{R}/.deno/bin/deno", ["run", f"{R}/proj/main.ts"], "medium"),
        # benign developer-host runtimes: allow-listed
        "D1-nvm-node": (f"{R}/.nvm/versions/node/v20.11.0/bin/node", [f"{R}/src/app.js"], "allow"),
        "D2-uv-python": (f"{R}/.local/share/uv/python/cpython-3.12.7-linux-x86_64-gnu/bin/python3.12",
                         ["-m", "http.server", "8000"], "allow"),
        "D3-vscode-server-node": (f"{R}/.vscode-server/bin/0a1b2c3d4e5f/node",
                                  [f"{R}/.vscode-server/bin/0a1b2c3d4e5f/out/server-main.js"], "allow"),
        "D4-mise-ruby": (f"{R}/.local/share/mise/installs/ruby/3.3.0/bin/ruby", [f"{R}/src/script.rb"], "allow"),
        "D5-pyenv-python": (f"{R}/.pyenv/versions/3.11.9/bin/python3.11", ["-m", "pytest"], "allow"),
        "D6-miniforge-env-python": (f"{R}/miniforge3/envs/ds/bin/python3.12", ["-m", "jupyter", "lab"], "allow"),
        "D7-miniconda-base-python": (f"{R}/miniconda3/bin/python3.12", [f"{R}/notebooks/train.py"], "allow"),
        "D8-linuxbrew-node": (f"{R}/.linuxbrew/Cellar/node/22.1.0/bin/node", [f"{R}/src/app.js"], "allow"),
        "D9-playwright-driver-node": (f"{R}/proj/.venv/lib/python3.12/site-packages/playwright/driver/node",
                                      [f"{R}/proj/.venv/lib/python3.12/site-packages/playwright/driver/package/cli.js",
                                       "run-driver"], "allow"),
        "D10-volta-node": (f"{R}/.volta/tools/image/node/20.11.0/bin/node", [f"{R}/src/app.js"], "allow"),
    }


def start(R, T, bash="/bin/bash"):
    procs = {}
    for k, (exe, argv, expect) in layout(R, T).items():
        os.makedirs(os.path.dirname(exe), exist_ok=True)
        shutil.copy2(bash, exe)
        os.chmod(exe, 0o755)
        procs[k] = (subprocess.Popen([exe, "-c", SLEEP] + argv, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL), expect)
    return procs


def stop(procs):
    for p, _ in procs.values():
        p.terminate()
    for p, _ in procs.values():
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
