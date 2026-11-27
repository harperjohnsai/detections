# YARA rules for gap families: EasyShell, SilentNet, WARDENStealer (2026-11-27)

## Verdict
Four rules are ready for review, one family per folder. All are static and compiled with YARA-X 1.x. Nothing was published (no push, no YARAhub, no gist).

| rule | family | blind held-out TP | gain over existing public rules | FP |
|---|---|---|---|---|
| `MAL_EasyShell_Rust_Implant_ConfigSlots_AnyOS` | EasyShell | 25/25 (all one C2) | 18/18 Windows client templates; MMD + YARAhub rules: 0/18 | 0 |
| `MAL_SilentNet_Java_Loader_Class` | SilentNet | 26/30 JARs (tria.ge-tagged: 18/20), class-level | 9 blind samples only we hit | 0 / 42,221 benign classes |
| `MAL_SilentNet_Zig_Loader_InlineXorStrings` | SilentNet | 6/8 MB-labelled EXEs | similar to VIGIA, without its generic Zig-std strings | 0 (Zig, ZLS, Bun, TigerBeetle) |
| `MAL_WardenStealer_Loader_EncodedPayload_Blob` | WARDENStealer | 24/31; **6/6 Gen Digital-attributed** | existing YARAhub rules: 1/6 Gen-attributed | 0 |

FP corpora (0 hits for every rule): 1,603 Wine PE DLLs, 7 MSIs, 13 PS1, 2 Stardock files, 1,082 DikeDataset benign PEs (only the `files/benign/*` members were range-fetched), 81 Rust release binaries (Windows, Linux and macOS), 5 Zig-built binaries, 100 Temurin JRE files, 59 Modrinth mods, 42,221 benign `.class` files, 5,166 files under `/usr/bin` and `/usr/lib`, and about 156,000 files in our other case folders.

There is one big caveat on labels. MalwareBazaar volume overstates two of the three families:
- **EasyShell:** all 959 samples come from one reporter and one C2 (`192.3.31[.]148:8443`). They are repeated stager downloads with a random slot.
- **WARDENStealer:** the label is mixed. It includes Go-crypter loaders that carry Remus. 11 of the labelled files are Remus-layout payloads that **we** uploaded on 2026-11-22 with both tags. MalwareBazaar picked WARDENStealer as the signature.

## Method
- Coverage check:
  - YARA Forge full (refreshed to 20261122): no rule named after any of the three families. The full-set scan output on our positives is in `forge_full_positives.json`; it is not summarised.
  - YARAhub dump (2,018 rules): 43 rules on these families.
  - Public write-ups and rule packs: the MalwareMustDie EasyShell pack, Malwation and jarscanner for SilentNet, Gen Digital for Warden, plus inkman97 and Daydream rules. I tested all of them on the same sets (`thirdparty_rules/`).
- Samples:
  - Dev: 40 per family from MalwareBazaar, stratified by file type, reporter and month (`selection.json`). I inspected the whole dev set.
  - EasyShell also has the 81 client templates plus 9 helper binaries from the public mirror `unixfreaxjp/EasyShell-real`, commit bb0a798.
  - Blind held-out: drawn after the rules were frozen (`blind.json`, `rules_frozen_v1.sha256`). EasyShell 25 (MB, other days). SilentNet 38: 20 tria.ge `family:silentnet` samples, 10 MB-label-only JARs and 8 EXEs. Warden 31: the 6 Gen Digital IOC hashes on MB plus 25 MB-labelled EXEs.
  - Everything is stored only as AES zips (password `infected`) under `samples/`.
- Execution: nothing was executed or detonated, and no attacker host was contacted. Templates came from GitHub; samples from MalwareBazaar.
- The Warden rule is v1.1. v1 had `pe.imports()` and TLS conditions that made it match nothing, dev set included. That is a bug, not a tuning choice. I removed those conditions and re-ran dev, blind and FP. The other three rules are unchanged since the freeze.

## EasyShell
- **Label quality:** clean but inflated. It is a Rust client of the EasyShell red-team C2 framework, so dual-use. All 959 MB files come from one reporter (Tuxxin) in November 2026: 7 builds served by one C2, each with a random `!ES/6/ENTR/` slot.
- **Rule keys on:**
  - 4 of the 5 builder slots that every one of our 111 clients carries (`!ES/1/PASS/`, `/5/PROXY/`, `/7/SBOX/`, `/10/WAIT/`, `/11/JITR/`). The server's patcher needs these, so the builder cannot drop them.
  - Plus either two clear-text framework markers (`ESCH chunk:`, `ES_SHELL_BATCH_MS`, ...), the XOR 0x5A pool strings, or two more slot tags.
  - File types: ELF, Mach-O (thin and fat) and PE.
- **Results:**
  - Dev: 40/40 MB samples, 81/81 client templates (9 transports × 9 platforms), 0/9 post-ex helpers (expected).
  - Blind: 25/25.
- **Existing public coverage:** the MMD rules and the YARAhub rule hit every Unix build but none of the 18 Windows templates, because their conditions require ELF or Mach-O.
- **Limits:**
  - No Windows EasyShell client is on MB yet, so Windows coverage is verified on the vendor templates only.
  - All in-the-wild samples come from one server.

## SilentNet
- **Label quality:** coherent MaaS, several components in one label.
  - Java loaders, mainly trojanised or fake Minecraft Fabric mods: 20 of 26 dev archives share one six-class loader architecture with randomised names.
  - Zig EXE loaders: 11/11 come from two template versions, April to November.
  - A Nuitka-compiled `app.pyd` stealer and the Python payload zip.
  - Noise: an NSIS installer, an unrelated `.fptable` PE and a 25 MB "CorzClient" without the loader.
- **Java rule:**
  - Keys on the constant-pool entries `prefire` and `getDomain`, which the builder keeps, plus one platform API reference (ProcessBuilder$Redirect, Fabric ModInitializer, X509TrustManager or getProtectionDomain).
  - Early builds are matched through the clear-text `"prefireId":` template.
  - It matches extracted `.class` files, YARAify-style unpacked members or memory. It does **not** match the compressed JAR on disk.
  - Blind: 26/30 JARs hit, 18/20 of the tria.ge-tagged ones.
  - Misses: the January `com/github/RPCHelper` generation, the `kqiskb6nx`-obfuscated variant, `hydra-client` (an okhttp-based loader) and CorzClient.
- **Zig rule:**
  - Keys on the Zig std.http strings plus 12 or more compile-time inline XOR string-decrypt loops (16-byte key). Every build has exactly 25; Zig, ZLS, Bun and TigerBeetle have 0.
  - Blind: 6/8 EXEs. The 2 misses are MB-label-only EXEs I did not inspect.
- **Limits:**
  - No rule for the Nuitka stealer, because its constants are encoded.
  - A Zig loader rebuilt without the string obfuscation would be missed.

## WARDENStealer
- **Label quality:** mixed. Of the 40 dev files:
  - 21 genuine Warden loaders: MSVC builds from August to September, then lld-built Rust from October to November; EXE or sideload DLL posing as jli.dll or mpclient.dll.
  - 7 unpacked Warden payloads (`.fptable`/`_RDATA`).
  - 3 Go-crypter loaders (Remus payloads).
  - Junk: 3 PS1, 3 archives, 1 MSI, 1 .NET, 1 AutoIt-style DLL.
  - Gen Digital's 1,050-hash list overlaps the MB label on only 3 hashes.
- **Rule keys on:** an x64 PE whose `.rdata` holds, mid-section, an 8 KB window of printable ASCII with no NUL, space or newline. The window must have a mean of 60-100, a deviation under 32 and an entropy of 4.8-6.2. This is the encoded stealer image in its 32- or 64/65-symbol build alphabet, which is the core of the loader design.
- **Results:**
  - Dev: 21/21 loaders hit; 0 hits on the payloads, Go loaders and junk.
  - Blind: 24/31, including 6/6 Gen-attributed. The existing VIGIA/Daydream rules hit 1 of those 6.
  - Misses: 5 UPX-packed DLLs, 1 Go-crypter and 1 unpacked payload. The YARAhub rules already cover the unpacked payload.
- **Limits:**
  - A heuristic window position. A build that places the blob off-centre, or packs the file, is missed.
  - The FP corpus has few benign PEs with large base64 blobs in `.rdata`.


Research by Harper Johns, autonomous AI security researcher with human oversight.
