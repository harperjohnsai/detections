# Velociraptor artifacts

Custom [Velociraptor](https://docs.velociraptor.app/) artifacts for triage, tested against inert fixtures (text files in a temporary fake root; nothing is executed). Load one into a server with `artifact_set(definition=read_file(filename=...))` or run it locally:

```bash
velociraptor --definitions velociraptor/linux artifacts collect Custom.Linux.Persistence.Sweep --format jsonl
# a mounted image or extracted triage tree instead of the live system:
velociraptor --definitions velociraptor/linux artifacts collect Custom.Linux.Persistence.Sweep --args Roots=/mnt/image/ --format jsonl
```

## `linux/Custom.Linux.Persistence.Sweep.yaml`

One pass over the common Linux persistence locations: systemd system and user units, cron (system, user, anacron, cron.d and periodic dirs), shell profiles (bash/zsh, system and per user), SSH `authorized_keys` and `sshd_config`, `ld.so.preload`, XDG autostart, `rc.local`/`init.d`, `sudoers.d` and at-jobs. Each row has `Category`, `Path`, `Mtime`, `Detail` (the line) and a `Suspicious`/`Reason` triage hint. Static file reads only.

The hint is a regex verdict, not a detection: it fires on download-and-run tools, reverse-shell idioms, execution from tmp-like paths, `LD_PRELOAD`/`PROMPT_COMMAND`, aliases that shadow security-relevant commands, any `ld.so.preload` entry, `NOPASSWD`, forced-command keys, and (since v2) stealth launch lines with no download idiom: `nohup`, cron `@reboot`, random-looking hidden paths that contain a digit, hidden directories directly under `~/.local/share/`. All regexes are parameters.

ATT&CK: T1053.003, T1543.002, T1574.006, T1098.004, T1546.004.

### Tests (`tests/run_sweep_tests.py`, Velociraptor v0.77.4)

| Fixture set | What it holds | Result |
|---|---|---|
| `plants` | 5 generic plants (cron `curl \| sh`, user unit in a hidden `/tmp` dir, forced-command key, `ssh` alias wrapper, `ld.so.preload` entry) + 2 decoys | 5/5 flagged, 0 decoys |
| `plants_etherrat` | the 5 Linux persistence templates of EtherRAT as published by Sysdig (systemd user unit, XDG autostart with `Hidden=true`, `@reboot` cron, `.bashrc` `nohup`, `.profile`) + 5 decoys (nvm loader, Syncthing unit, Nextcloud autostart, restic cron, Debian `.profile`) | 5/5 flagged, 0 decoys |
| `plants_devhost` | 13 benign developer-host entries (nvm, pyenv, Homebrew on Linux, `ssh-agent`, direnv/zoxide/starship, powerlevel10k, a pm2 startup unit running node from `~/.nvm`, the VS Code CLI tunnel user unit, rootless Docker, Flatpak/Snap/JetBrains Toolbox autostart, a node cron job) + 2 legit `@reboot` lines + 3 attack controls | 0 benign flagged, 3/3 controls flagged, both `@reboot` lines flagged |

Version history in short: v1 found 0 of the 5 EtherRAT entries (no download or tmp idiom in them); v2 added the stealth regex (5/5). The developer-host set then showed that the bare `eval` token flagged 6 of 13 benign profile lines (`eval "$(pyenv init - bash)"`, `brew shellenv`, `ssh-agent`, direnv, zoxide, starship); v2.1 exempts a line only when the WHOLE line is `eval "$(<known tool> <plain args>)"`. The controls `eval "$(curl ...)"`, a fake `brew` under `/tmp` and an allowed idiom with a chained `curl | sh` still flag.

Known limits: `@reboot` and `nohup` are flagged on purpose and will fire on hosts that use them legitimately; baseline per fleet. The developer-host entries partly follow the tools' own templates (nvm and pyenv READMEs, Homebrew docs, the pm2 systemd template, the VS Code CLI unit writer) and partly typical forms written by the author; no production telemetry has been measured. Root-owned files need a root client.

```bash
VELOCIRAPTOR=/path/to/velociraptor python3 velociraptor/tests/run_sweep_tests.py
```
