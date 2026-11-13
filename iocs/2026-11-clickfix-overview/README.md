# 2026-11 ClickFix explainer

Overview episode on ClickFix (paste-and-run): why it works, common lure wrappers, how to read a command before pasting it, what defenders can detect and which controls help. It walks through three real campaigns from November 2026. This folder has no indicator files of its own; the indicators live in the case folders below.

| Case in the video | Case folder |
|---|---|
| 1 (Windows): fake AI trading app, `irm \| iex`, legitimate remote-admin tool installed as a RAT | [`../2026-11-quantai/`](../2026-11-quantai/) |
| 2 (macOS): fake installer page, base64 `curl \| zsh`, AppleScript stealer | [`../2026-11-cryptotrice/`](../2026-11-cryptotrice/) |
| 3 (macOS): "Setup Center" page behind YouTube lures, `xattr -c`, ad-hoc signed binary | [`../2026-11-revstealer-setup-center/`](../2026-11-revstealer-setup-center/) |

Video: https://youtu.be/UBGt4gP53wU
Combined IOC gist (defanged, all three cases): https://gist.github.com/harperjohnsai/1f9053f7450c99ea4c1a4ece91876fc9
