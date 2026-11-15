# setup-center-loader

Rules for the loader stage of the "Setup Center" chain: a Microsoft-signed OneDrive client (original file name `OneDrive.exe`) renamed `Installer.exe`, a malicious x64 proxy `version.dll` that re-exports the real System32 DLL, and an RC4-encrypted payload file (`config.dat` in build 25, `sync.dat` in build 26, `localdata.db` in build 27) that starts with the bytes `MSCF` but is not a cabinet file.

| Rule | File | Target | Reference MD5 |
|---|---|---|---|
| `SetupCenter_ProxyVersionDll_Loader` | [setup_center_proxy_version_dll.yar](setup_center_proxy_version_dll.yar) | proxy `version.dll` | `51061df0511cc9d758230ba75f3954b4` |
| `SetupCenter_FakeCab_PayloadContainer` | [setup_center_fake_cab_container.yar](setup_center_fake_cab_container.yar) | `localdata.db` | `b80f3e45c3cc6f38aa3505ab70cd3017` |
| `SetupCenter_Loader_AntiVM_HashTables` | [setup_center_antivm_hash_tables.yar](setup_center_antivm_hash_tables.yar) | proxy `version.dll` (anti-VM gate) | `51061df0511cc9d758230ba75f3954b4` |

## Anti-VM gate rule

`SetupCenter_Loader_AntiVM_HashTables` keys on the loader's anti-sandbox gate instead of its imports or code layout. The loader never stores the blocklists as text: each entry is a 32-bit hash, FNV-1a (prime `0x01000193`) with the custom offset basis `0x7c4e9f2b` and an extra `x ^= x >> 16` after every byte, over the lower-cased input. The rule matches the `mov r10d, 0x7c4e9f2b` seed, the `imul ... 0x01000193` / `shr 16` mix pattern and the little-endian hash tables (first three entries of each list, with the stored length for the substring lists). It fires on the seed and mix code plus one table, or on three tables alone, so a rebuilt loader with the same blocklists still matches. Static analysis only; no sample was run.

- Test (2026-11-15, yara-python 4.5.4 and YARA-X 1.23): hits `version.dll` of builds 25, 26 and 27 (3 distinct files, `973ad298...`, `2903e5e3...`, `b371d2e0...`); 0 hits on 659 files (about 420 PE, including the OneDrive host, the REVSTEALER inner payloads, the ABE helper and unrelated DLLs/.so/.pyd). The three builds carry identical tables.
- Every decoded plaintext below was re-hashed with the loader's own function and equals the table entry (59 of 59). Hashes are 32-bit, so a decoded word is a verified candidate, not proof of the author's original string: `hugo` and `millerm` have random collisions of the same length that are not word-like.

### Decoded evasion lists

| List | How the loader uses it | Decoded entries |
|---|---|---|
| BIOS / system vendor, substring (20) | `HKLM\HARDWARE\DESCRIPTION\System\BIOS` values `SystemManufacturer`, `SystemProductName`, `BIOSVendor`, `SystemFamily` joined with a space; any substring match aborts | qemu, xen, bochs, seabios, innotek, vmware, virtualbox, kvm, parallels, bhyve, virtual machine, hvm domu, openstack; cloud and hosting providers: amazon, google, compute engine, digitalocean, hetzner, linode, vultr |
| User / computer name, exact (3) | `GetUserNameA` and `GetComputerNameA`, lower-cased, whole string | john, emily, hugo |
| User / computer name, substring (12) | same names, every substring of the stored length | sandbox, virus, malware, maltest, sample, tequila, cuckoo, wilber, wdagutilityaccount, johnson, millerm, bruno |
| Display adapter, VM words (14) | `EnumDisplayDevicesA` `DeviceString` split into words; a hit with no real-GPU word aborts | virtual, vmware, virtualbox, basic, hyper-v, hyperv, qxl, cirrus, virtio, stdvga, parallels, xen, citrix, svga |
| Display adapter, real-GPU words (10) | any of these means a physical GPU, so the check passes | nvidia, amd, radeon, geforce, quadro, intel, ati, arc, iris, uhd |

Other VM checks use plain strings that the main rule already anchors on: the registry keys `SOFTWARE\VMware, Inc.\VMware Tools` and `SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`, and the BIOS key above. The cloud-provider entries mean the gate also stops runs on rented VPS and analysis cloud hosts, not only on desktop hypervisors.

## Samples (SHA-256)

| Artefact | SHA-256 |
|---|---|
| `version.dll`, build 25 (2026-10-28) | `973ad2986d6eda8a8936342ba64fda6e2909cc8527a83bb2f474c13d76c0b6e7` |
| `version.dll`, build 26 (2026-11-02) | `2903e5e3363c1c15725a5343d31429490ce662cdc3df3c1f0dbf8ba7863aa4c3` |
| `version.dll`, build 27 (2026-11-05) | `b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960` |
| `config.dat` (build 25) | `b484561cc81da34990824452d4ce4002d0520c71c71e3eeb2f248e57e1f5bc3f` |
| `sync.dat` (build 26) | `ca82cb69da221788258d659b0eb8c84b7cfe0a99710037d40edd73e8ed330827` |
| `localdata.db` (build 27) | `193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62` |
| `Installer.zip` (all of the above) | `2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49` |

## Testing

Run `tests/run_yara_tests.py` (see the top README). Reference samples must match exactly the rules listed above; benign and unrelated PE files must not match. Recorded runs: [`tests/RESULTS.md`](../../tests/RESULTS.md).

## Notes

- The loader is recompiled for every build, so the rule does not depend on one compiler output. It needs an unsigned x64 DLL that exports `GetFileVersionInfoW` / `VerQueryValueW`, imports what a real `version.dll` never does (`GetSystemDirectoryW`, `LoadLibraryW`, `GlobalMemoryStatusEx`, `EnumDisplayDevicesA`, `RegQueryValueExA`), the `\version.dll` wide string, the VM-check registry strings and `SystemManufacturer`, plus one of: the layout of the XOR-encrypted hollowing API table in `.rdata` (module index and name length of the first eight entries; identical in builds 25 to 27), or the key-derivation / RC4 code of either compiler variant (separate byte patterns for build 25 and builds 26/27).
- Build 25 differs from 26/27 in code only: the 32-byte key XOR is a helper with an SSE loop, RC4 is inlined with a fixed 32-byte key, and the payload file name is a plain stack string instead of a XOR-obscured one.
- The fake-CAB rule uses CFHEADER fields that a real cabinet cannot have (`reserved1` must be 0, `cbCabinet` is the file size) and high entropy.
- Extractor used to derive these: [`tools/setup-center-extractor`](../../tools/setup-center-extractor/).
