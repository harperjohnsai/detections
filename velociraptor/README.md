# Velociraptor artifacts

Custom [Velociraptor](https://docs.velociraptor.app/) artifacts for triage, tested against inert synthetic fixtures (files, plists and small databases in a temporary fake root; nothing is executed except one stub program in the unified-log test). Linux: `linux/`. macOS: `macos/`. Load one into a server with `artifact_set(definition=read_file(filename=...))` or run it locally:

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

## `linux/Custom.Linux.Hunt.UserDirInterpreter.yaml`

Running script interpreters (php, node, python, perl, ruby, deno, bun, lua) whose binary lives in a user-writable place (home directories, `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`). Malware that brings or downloads its own runtime shows up here: the Interlock RAT's PHP variant runs a downloaded `php.exe` from the user profile against a `.cfg` file (Linux analogue `~/.config/php/php ... wefs.cfg`), and EtherRAT downloads Node.js into a random hidden directory under `~/.local/share`. Uses `pslist()` only: no exec, no upload, no network.

Severity: `high` = not allow-listed and (a random digit-bearing hidden directory in the exe or script path, or a script argument with a data extension such as `.cfg`/`.dat`/`.txt`/`.png`, or the exe in a temp dir); `medium` = any other non-allow-listed user-dir interpreter. Per-user runtime managers and editor servers (nvm, pyenv, uv, volta, asdf, mise, fnm, rbenv, plenv, pnpm, conda/miniforge, Homebrew on Linux, VS Code / Cursor server, Playwright) are allow-listed by path and hidden unless `ShowAllowListed=Y`. The Bun and Deno default installs (`~/.bun/bin`, `~/.deno/bin`) are deliberately kept at `medium`: MITRE ATT&CK records Mini Shai-Hulud being deployed with the Bun runtime. All regexes are parameters.

ATT&CK: T1059.007 (JavaScript), T1059.006 (Python), T1059 (other interpreters), T1105.

### Tests (`tests/run_interp_tests.py`, Velociraptor v0.77.4, 19 checks)

16 inert process plants: renamed copies of `/bin/bash` that only sleep, with command lines that imitate the real ones (`tests/fixtures/plants_interp.py`). The test scopes the artifact to its temporary directories, so the runner's own processes do not count.

| Set | What it holds | Result |
|---|---|---|
| attack-like | Interlock-style php + `.cfg`, EtherRAT-style node in a hidden digit dir, python in temp, perl in `~/bin` | high, high, high, medium (as designed) |
| installer runtimes | bun and deno at their default install paths | medium (not allow-listed on purpose) |
| developer host | nvm, uv, VS Code server, mise, pyenv, miniforge env, miniconda base, Homebrew on Linux, the Playwright Python driver's node, volta | 10/10 allow-listed, hidden by default |

v1 (lab only, not published) flagged 4 of these 10 developer runtimes (conda twice, Homebrew, Playwright driver) as `medium`; v2 adds them to the allow-list. Known limits: the allow-list is a path match, so malware placed inside an allow-listed directory is hidden (hunt with `ShowAllowListed=Y`); interpreters started from system paths (`/usr/bin/python3`) are out of scope by design; no production telemetry has been measured, and the developer runtimes are synthetic stand-ins at their documented default paths.

```bash
VELOCIRAPTOR=/path/to/velociraptor python3 velociraptor/tests/run_interp_tests.py
```

# macOS artifacts (`macos/`)

Three artifacts for triage of a Mac that its owner has agreed to examine. Each one was checked against the built-in registry (v0.77.4) and the Artifact Exchange / `Generic.Forensic.SQLiteHunter` before publishing; artifacts that duplicate existing ones are not published here. Load one into a server with `artifact_set(definition=read_file(filename=...))` or run it against a tree:

```bash
velociraptor --definitions velociraptor/macos artifacts collect Custom.MacOS.Browser.Extensions --format jsonl
# synthetic or mounted tree instead of the live system (test hook, works on Linux):
velociraptor --definitions velociraptor/macos artifacts collect Custom.MacOS.TCC.Review --args Root=/mnt/tree --args IgnoreOSCheck=Y --format jsonl
```

| Artifact | What it does | Existing artifacts | Full Disk Access | Executes a program | Uploads a file |
|---|---|---|---|---|---|
| `Custom.MacOS.Persistence.BTM` (v2) | Reads Background Task Management stores (login items, launch agents/daemons, helper tools) and reports paths, URLs, bundle ids and team ids; decodes the base64 bookmark blobs to paths; flags tmp/hidden paths, executables in user-writable Library folders, user LaunchAgents named `com.apple.*` | none parses BTM (new) | for the system store; the per-user store needs none | no | no |
| `Custom.MacOS.Browser.Extensions` | Chromium-family manifests (id, version, name, permissions, host permissions, `update_url`), native messaging hosts, Safari app extensions (`.appex` plus bundled manifest permissions, enabled state), Firefox `extensions.json`. Flags risky permissions (`<all_urls>`, `webRequest`, `nativeMessaging`, `debugger`, `cookies`, `proxy`, `management`), non-store or missing `update_url`, non-AMO or unsigned Firefox add-ons, native hosts in user-writable paths | `Generic.Forensic.SQLiteHunter` source `ChromiumBrowser_Extensions` covers Chromium manifests only; this adds Safari, Firefox, native hosts and the verdict | helpful (Safari container, some profile folders) | no | no |
| `Custom.MacOS.TCC.Review` | Reads `TCC.db` (system and each user), joins every grant with the installed apps (bundle id or path) and flags Accessibility, ScreenCapture, SystemPolicyAllFiles, ListenEvent, PostEvent, AppleEvents, Microphone and Camera granted to remote-access tools, to apps that are no longer installed, or to terminals/shells; inventories installed remote-access tools | built-in `MacOS.System.TCC` dumps the rows; this adds the installed-app join, the verdict and the remote-tool inventory | **required** | no | no |

Capability notes. None of the three executes a program, uploads files, writes to the device or opens network connections; the tests scan the artifact text for `execve(`, `upload(`, `http_client(` and similar calls. The output of the TCC and extension artifacts is personal data (user names, installed software): collect it only with the owner's consent and keep it off shared systems.

Flags are leads, not verdicts: password managers legitimately hold `<all_urls>` and `cookies`, remote-support tools legitimately hold Accessibility and Screen Recording, and helper tools or Homebrew binaries can look "not installed". Read the Reasons column together with the app name and source.

### Tests (`tests/run_macos_tests.py`, Velociraptor v0.77.4, 36 checks)

All three artifacts run against invented synthetic fixtures built by `tests/fixtures/mac_fixtures.py` (fake `/Users/...` and `/Applications/...` trees in a temporary directory). No data from any real device is used.

| Artifact | Fixture | Result |
|---|---|---|
| `Browser.Extensions` | 10 Chromium-family manifests (Chrome, Brave, Edge): 6 planted (risky permissions, sideloaded `update_url`, no `update_url`, unparseable, wildcard only in optional hosts / content scripts, webRequestBlocking + proxy) and 4 clean store extensions incl. a localized `__MSG_x__` name; 2 native hosts; 3 Safari web extensions + 1 non-Safari appex; 5 Firefox add-ons + 1 theme | 6/6 planted flagged, 4/4 clean silent, localized name resolved, appex decoy and theme skipped, Firefox system add-on with broad permissions silent |
| `TCC.Review` | user + system `TCC.db` (modern schema) with 11 planted grants and 4 benign ones, 1 denied row, 6 app bundles | 11/11 flagged with the right reasons, 4/4 clean silent, limited grants count, denied rows hidden unless asked |
| `Persistence.BTM` | binary-plist NSKeyedArchive with dict objects, base64 `book` bookmark blobs (bytes), a user store and a system store | bookmark blobs decoded to paths, exactly 3 suspicious values |

Limits. All tests use synthetic fixtures only: the Safari enabled-state plist layout is inferred from public write-ups, the TCC schema is the documented macOS 11+ one, and the BTM layout is undocumented and changes between macOS releases. Treat results as unverified until compared with a known host.
