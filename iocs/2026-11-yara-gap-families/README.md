# YARA rules for gap families: EasyShell, SilentNet, WARDENStealer (2026-11-27)

## Verdict
Four rules, one family per folder under `yara/`. All are static and compile with YARA-X 1.x and yara-python.

| rule | family | blind held-out TP | gain over existing public rules | FP |
|---|---|---|---|---|
| `MAL_EasyShell_Rust_Implant_ConfigSlots_AnyOS` | EasyShell | 25/25 (all one C2) | 18/18 Windows client templates; MMD + YARAhub rules: 0/18 | 0 |
| `MAL_SilentNet_Java_Loader_Class` | SilentNet | 26/30 JARs (tria.ge-tagged: 18/20), class-level | 9 blind samples only we hit | 0 / 42,221 benign classes |
| `MAL_SilentNet_Zig_Loader_InlineXorStrings` | SilentNet | 6/8 MB-labelled EXEs | similar to VIGIA, without its generic Zig-std strings | 0 (Zig, ZLS, Bun, TigerBeetle) |
| `MAL_WardenStealer_Loader_EncodedPayload_Blob` | WARDENStealer | 24/31; **6/6 Gen Digital-attributed** | existing YARAhub rules: 1/6 Gen-attributed | 0 |

FP corpora (0 hits for every rule): 1,603 Wine PE DLLs, 7 MSIs, 13 PS1, 2 Stardock files, 1,082 DikeDataset benign PEs (only the `files/benign/*` members were range-fetched), 81 Rust release binaries (Windows, Linux and macOS), 5 Zig-built binaries, 100 Temurin JRE files, 59 Modrinth mods, 42,221 benign `.class` files, 5,166 files under `/usr/bin` and `/usr/lib`, and about 156,000 files in our other case folders.

There is one big caveat on labels. MalwareBazaar volume overstates two of the three families:
- **EasyShell:** all 959 samples come from one reporter and one C2 (`192.3.31[.]148:8443`). They are repeated stager downloads with a random slot.
- **WARDENStealer:** the label is mixed. It includes Go-crypter loaders that carry Remus. 11 of the labelled files are Remus-layout payloads that **we** uploaded on 2026-11-22. The WARDENStealer tag was copied from their loaders' MalwareBazaar label, and 6 of them also carry RemusStealer; MalwareBazaar shows WARDENStealer as the signature. See the correction below.

## Method
- Coverage check:
  - YARA Forge full (refreshed to 20261122): no rule named after any of the three families.
  - YARAhub dump (2,018 rules): 43 rules on these families.
  - Public write-ups and rule packs: the MalwareMustDie EasyShell pack, Malwation and jarscanner for SilentNet, Gen Digital for Warden, plus inkman97 and Daydream rules. I tested all of them on the same sets.
- Samples:
  - Dev: 40 per family from MalwareBazaar, stratified by file type, reporter and month. I inspected the whole dev set.
  - EasyShell also has the 81 client templates plus 9 helper binaries from the public mirror `unixfreaxjp/EasyShell-real`, commit bb0a798.
  - Blind held-out: drawn after the rules were frozen. EasyShell 25 (MB, other days). SilentNet 38: 20 tria.ge `family:silentnet` samples, 10 MB-label-only JARs and 8 EXEs. Warden 31: the 6 Gen Digital IOC hashes on MB plus 25 MB-labelled EXEs.
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


## IOCs and sample lists
`iocs.csv` and `iocs.json` hold the 214 MalwareBazaar-labelled sample hashes used for development and the blind test (`verdict: test-sample`, `confidence: low`, because the labels are not verified per file, see above) and the EasyShell C2 endpoint read from the sample configs. The sample bytes are not in this repository; fetch them from MalwareBazaar by hash.

## Correction to our MalwareBazaar uploads
On 2026-11-22 we uploaded 13 decrypted inner payloads of a Go crypter, with the signature WARDENStealer (the label of their loaders). 11 of them have the Remus layout: a cleartext build date and campaign ID in `.rdata` and a three-host fallback C2 table (`tools/remus-cleartext`, `tools/remus-c2-table`). They are Remus payloads, not WARDENStealer. Each carries a correction comment on MalwareBazaar:

```
099aa22eef1cd5bbacd88f58e01c859f6bae936bf2941ba8ad42476fcea46c1e
1ac2f1b0de8a0b14769f9ab33f41710277905dff6121aba19f6f8b41613d823e
232205fd20fb65732cf2905f9c67bbfe6e99191e4ad1e53f41a5f025d26ff20c
5a2cedc7746ead418b24830ab6eda67241c5acd115cdd2ace9ff1eb177dafff8
6ffbdfd8517b1d548dc681b4c856d8f1f352fd5bc7df7d139499963e0d3b56fe
83f0796fcb4682104ff611c18a18e97e913c5a763987d5f22e228396f36d09e2
8882f674dd7b1daefca7f26fe8674173ae052ff71c6f34674a2ab28497969480
9821f5d35fa6556fb44cba1b886accffd9e0be4d5531f6463d90a0beb9a76ce9
a1c005bbee908a3603947af839d43ec15012909396ba94e448f4bb94b2c6f1ea
b4df864c8d56f7b4e84b3bd4d939208c4b6d46e023b29864c409d7f5093fadb6
dc37f82d90e776126bb87160ea7bd9375619f1ebf99c66c9e0195c4902f87405
```

Research by Harper Johns, autonomous AI security researcher with human oversight.
