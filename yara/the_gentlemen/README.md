# the_gentlemen

Rules for The Gentlemen (Storm-2697) ransomware, see [`iocs/2026-11-the-gentlemen/`](../../iocs/2026-11-the-gentlemen/). One rule per file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `MAL_Gentlemen_Locker_Go` | [gentlemen_locker_go.yar](gentlemen_locker_go.yar) | the Go locker, Windows PE or Linux ELF, also an unpacked in-memory image: Go build-info magic plus at least three of the footer / worker / note-name strings plus one CLI string. No MZ/ELF header condition | `4200b46a93c6ab059e2b34ce200c4a5b` |
| `HUNT_Gentlemen_Ransom_Note` | [gentlemen_ransom_note.yar](gentlemen_ransom_note.yar) | the text note `README-GENTLEMEN.txt` (fixed sentences; hunting rule, file below 20 KB) | `e9d2df69b580a8e41d4811a1433cf090` |

## Not covered: the VMProtect-packed 2025-09 Windows build

`51b9f246d6dad…` (14.9 MB, MalwareBazaar 2025-09-17) is **not matched by any rule here, on purpose**.

- Its Go image is encrypted by VMProtect (Detect It Easy via VirusTotal); no family string is in the file.
- What is left in the file is the packer stub: Go-style section names with raw size 0, four random section names, a `kernel32`-only import table, a junk-padded entry point. That is not family-specific: MalwareBazaar returns the same imphash (`9da18038e0ba9a33fbbaf76636ea1aff`) for a SparkRAT, a Cobalt Strike, a Sliver and two LaplasClipper samples. A rule on those traits would label other families as The Gentlemen.
- It was not unpacked (static analysis only, nothing executed).
- `MAL_Gentlemen_Locker_Go` has no header condition, so it should match the build once unpacked in a process dump. Not tested on a real dump (none available); tested on a section-mapped copy of the unpacked Windows locker and on a copy with the first 4 KB removed, both match.
- The hash is published as an IOC. `tests/run_yara_tests.py` records it as a documented miss (expected 0 hits).

## Samples (SHA-256)

| Artefact | SHA-256 | Expected |
|---|---|---|
| Windows locker, Go, garbled (MB 2026-04-03) | `3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235` | `MAL_Gentlemen_Locker_Go` |
| Linux ELF locker, Go (MB 2026-10-22) | `53d2484ae1ad6ff9547d90f5f5ccd6ae1dca8cb24e622a07dfc74c9593b2c3fa` | `MAL_Gentlemen_Locker_Go` |
| `README-GENTLEMEN.txt` extracted from the note zip | `32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134` | `HUNT_Gentlemen_Ransom_Note` |
| VMProtect-packed Windows build | `51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2` | none (documented miss) |
| note zip (deflate container) | `f8b07ce20ae77fec0905724a466196a5ba8281e9ba9534808ab7e7bf15f37516` | none (documented miss; the extracted note matches) |

## Testing

Run 2026-11-19, yara-python 4.5.4 and YARA-X 1.23.0, `tests/run_yara_tests.py --samples <dir> --negatives <dirs>`: 3 of 3 positives hit exactly the intended rule on both engines, the 2 documented misses give 0 hits, and **0 hits on 869 negatives**: 24 Go executables (12 Windows PE and 12 ELF: GitHub CLI, restic, Hugo, Caddy, Syncthing and the age tools, current releases), 483 files of a Linux `/usr/bin`, and 58 saved vendor reports and news pages about the group (20 of them quote at least one of the locker strings, 5 quote three or more: hard text negatives). Limits: only two real locker builds (April and October 2026, Windows and Linux) were available as positives, so a rebuild that renames the footer markers would need a rule update; the Go negatives are tools of 7 projects, not Garble-obfuscated or UPX-packed Go programs. Recorded run: [`tests/RESULTS.md`](../../tests/RESULTS.md).
