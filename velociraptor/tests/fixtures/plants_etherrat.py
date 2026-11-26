#!/usr/bin/env python3
"""plants_etherrat.py seed|remove|list [ROOT] -- replay EtherRAT's five Linux persistence mechanisms
(Sysdig EtherRAT write-up, 2025-12-08) as INERT plants in a fake root, plus realistic benign decoys.
Nothing is executed; the "node" binary and .js are 0-byte-ish placeholders; no network target at all.

Plants (E1-E5, exact templates from the Sysdig write-up, P = "<node> <hidden .js>"):
  E1 ~/.config/systemd/user/<12 hex>.service   ExecStart=P, Description=User Application Service
  E2 ~/.config/autostart/<12 hex>.desktop       Exec=P, Hidden=true, NoDisplay=true
  E3 var/spool/cron/crontabs/victim             @reboot sleep 30 && P >/dev/null 2>&1 &
  E4 ~/.bashrc                                  # System / (nohup P >/dev/null 2>&1 &) 2>/dev/null
  E5 ~/.profile                                 # App / (P >/dev/null 2>&1 &) 2>/dev/null
  + the staging tree ~/.local/share/.05bf0e9b/.4dai8ovb/bin/node and .7vfgycfd01.js (placeholders)
Decoys (must NOT be flagged):
  D1 ~/.bashrc nvm loader (sources a script from the hidden dir ~/.nvm)
  D2 ~/.config/systemd/user/syncthing.service ExecStart=/usr/bin/syncthing serve --no-browser
  D3 ~/.config/autostart/nextcloud.desktop Exec=/usr/bin/nextcloud --background
  D4 user crontab 0 2 * * * /usr/bin/restic backup /home/victim/docs
  D5 ~/.profile standard Debian PATH block
"""
import os, shutil, sys
ROOT = sys.argv[2]  # required: a scratch directory used as a fake filesystem root
H = "home/victim"
HOME_ABS = f"/{H}"   # paths as the victim host would see them (root-relative)
D = f"{HOME_ABS}/.local/share/.05bf0e9b"
P = f"{D}/.4dai8ovb/bin/node {D}/.7vfgycfd01.js"

def w(p, t, mode=0o644):
    p = f"{ROOT}/{p}"; os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f: f.write(t)
    os.chmod(p, mode)

def seed():
    remove(quiet=True)
    # staging tree (placeholders, not executable)
    w(f"{H}/.local/share/.05bf0e9b/.4dai8ovb/bin/node", "placeholder, not a binary\n", 0o444)
    w(f"{H}/.local/share/.05bf0e9b/.7vfgycfd01.js", "// placeholder\n", 0o444)
    # decoys first (so the plants are appended like the malware does)
    w(f"{H}/.bashrc", "# ~/.bashrc\nalias ll='ls -l'\nexport NVM_DIR=\"$HOME/.nvm\"\n"
      "[ -s \"$NVM_DIR/nvm.sh\" ] && \\. \"$NVM_DIR/nvm.sh\"  # This loads nvm\n")
    w(f"{H}/.profile", "# ~/.profile\nif [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\n")
    w(f"{H}/.config/systemd/user/syncthing.service", "[Unit]\nDescription=Syncthing\n[Service]\n"
      "ExecStart=/usr/bin/syncthing serve --no-browser\nRestart=on-failure\n[Install]\nWantedBy=default.target\n")
    w(f"{H}/.config/autostart/nextcloud.desktop", "[Desktop Entry]\nType=Application\nName=Nextcloud\n"
      "Exec=/usr/bin/nextcloud --background\nX-GNOME-Autostart-enabled=true\n")
    w("var/spool/cron/crontabs/victim", "0 2 * * * /usr/bin/restic backup /home/victim/docs\n", 0o600)
    # E1-E5 (Sysdig templates)
    w(f"{H}/.config/systemd/user/a1b2c3d4e5f6.service", "[Unit]\nDescription=User Application Service\n"
      f"After=network.target\n[Service]\nType=simple\nExecStart={P}\nRestart=always\nRestartSec=30\n"
      "[Install]\nWantedBy=default.target\n")
    w(f"{H}/.config/autostart/9f8e7d6c5b4a.desktop", f"[Desktop Entry]\nType=Application\nName=System Service\n"
      f"Exec={P}\nHidden=true\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n")
    w("var/spool/cron/crontabs/victim", f"@reboot sleep 30 && {P} >/dev/null 2>&1 &\n", 0o600)
    w(f"{H}/.bashrc", f"\n# System\n(nohup {P} >/dev/null 2>&1 &) 2>/dev/null\n")
    w(f"{H}/.profile", f"\n# App\n({P} >/dev/null 2>&1 &) 2>/dev/null\n")
    print("seeded 5 EtherRAT plants + 5 decoys under", ROOT)

def remove(quiet=False):
    if os.path.isdir(ROOT):
        for r, ds, fs in os.walk(ROOT):
            for x in ds + fs: os.chmod(os.path.join(r, x), 0o755)
        shutil.rmtree(ROOT)
    if not quiet: print("removed", ROOT, "exists_now=", os.path.exists(ROOT))

cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
if cmd == "seed": seed()
elif cmd == "remove": remove()
else:
    for r, _, fs in os.walk(ROOT):
        for f in fs: print(os.path.join(r, f))
