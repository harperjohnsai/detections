#!/usr/bin/env python3
"""Compile and test the YARA rules in ../yara with yara-python and YARA-X.

Modes
  --compile-only            only check that every rule file compiles (used in CI, no samples needed)
  --samples DIR [DIR ...]   directories holding the real samples (identified by SHA-256, not by name)
  --negatives DIR [DIR ...] directories of benign files; every file there must produce 0 hits

Samples are malware and are NOT part of this repository. Get them from MalwareBazaar
(links in iocs/*/README.md) and put them in a directory of your own.
Static only: YARA reads bytes, nothing is executed.
"""
import argparse, glob, hashlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
YARA_DIR = os.path.join(HERE, '..', 'yara')

# sha256 -> rules that MUST match (and no others)
EXPECTED = {
    'b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 27 (2026-11-05)
    '973ad2986d6eda8a8936342ba64fda6e2909cc8527a83bb2f474c13d76c0b6e7': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 25 (2026-10-28)
    '2903e5e3363c1c15725a5343d31429490ce662cdc3df3c1f0dbf8ba7863aa4c3': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 26 (2026-11-02)
    '193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62': ['SetupCenter_FakeCab_PayloadContainer'],           # localdata.db
    'b484561cc81da34990824452d4ce4002d0520c71c71e3eeb2f248e57e1f5bc3f': ['SetupCenter_FakeCab_PayloadContainer'],           # config.dat, build 25
    'ca82cb69da221788258d659b0eb8c84b7cfe0a99710037d40edd73e8ed330827': ['SetupCenter_FakeCab_PayloadContainer'],           # sync.dat, build 26
    'e472b895f15e4e17d3d35102ac6bc3eba9f707cb1da95df3ac2e7e9113825e81': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 25
    '673feccbcec6008354e4b3b7711de22953445d5314721097b041eb020e6cd231': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 26
    'c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 27
    '3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632': ['REVSTEALER_ABE_Helper_DLL'],                       # ABE helper DLL
    '0a48e7ed139a1cbe38c4ccb98edf2ff99bc53933f07942fa02fcf054dc14e0a6': ['REVSTEALER_Decrypted_Strings_Memory', 'REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact
    '5e3c4ef86cd0bb65f30fc919681a07126b8d3918419446b3c88d2ccbacf3dc86': ['REVSTEALER_Decrypted_Strings_Memory', 'REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact, build 25
    'c036690cb8e6965d3d2e1091d10ca78994e4440808813db032fa121fb0517ce9': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact, build 26
    # MioLab macOS chain (yara/miolab-macos)
    '2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # stage-2 universal Mach-O
    '49de3b526ee449d9a28f73d85af2fb0b40d721b45693d80119f8db47d4bba51a': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # x86_64 slice
    'f9a80a964748880116c22e1353072b31a966a5744e930d7a1bd376cf75ba5532': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # arm64 slice
    '5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent, universal
    '8281c8dc3f595064d5edad2ab479727358ac84af83ffb5604ab56929a5cd0c1b': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent arm64 slice
    '77a41f1a86f3bd778fd4febda4d2dc7ff77b53ec16f5e1ea52c29f2fc642d1ee': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent x86_64 slice
    'b6e9f44926dda38bdd080e6cf23001546aee34f4b5f5eaf94e54ebcd73afa44a': ['MAL_JS_MioLab_Trojanised_LedgerLive_SeedPhrase_Modal', 'MAL_MioLab_Trojanised_Wallet_Locale_Strings'],  # Ledger app.asar
    '05ca25705ce7acffc20bbbf74ed4ec9fcd0b9a19307cb08f46e2d73d53b8802b': ['MAL_JS_MioLab_Trojanised_TrezorSuite_SeedPhrase_Modal'],  # Trezor app.asar
    'c383789cf9809290ae2a194ed44176e4fc36fbceb0260958e481a8562b0f16c9': ['SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet'],  # Ledger app-update.yml
    '31a4f6a8aecd2b18107dfff5e68581804a68e9d61fc68e3ccf01d54225ae5cde': ['HUNT_macOS_MioLab_Cpp_Stealer_Plaintext_Artifacts'],  # decoded string dump (artefact)
    '978c98b401a6124e0522043b983911f7f57fc7b64868164cc158439ae5b07dd9': ['HUNT_macOS_MioLab_Agent_Plaintext_Artifacts'],       # decoded agent strings (artefact)
    '3bf97f7e851e3bfb9c16872a55364af1e6a95455d24b8d25e8dfc57e4c587a56': ['HUNT_MioLab_Agent_C2_Body'],                          # sandbox curl command lines (artefact)
    # Grandoreiro Delphi loader (yara/grandoreiro)
    '93845bd3c4d6cb0a15c75d82903a88776e07bf90634f8d794aca8fd476539a52': ['Grandoreiro_Loader_Delphi_BMP_Padding_Hunt', 'Grandoreiro_Loader_Delphi_StrCrypt_PortCalc'],  # loader EXE, 85.6 MB
    '29db0be6d95b24744259cba90c29fb34df596fb88d321dcc14e5873fd5a6ac6f': ['Grandoreiro_Loader_Delphi_StrCrypt_PortCalc'],  # same loader, padding resource stripped (derived test copy)
    # Mispadu (URSA) 2026 payload (yara/mispadu)
    '4f4129e8f79bde102875417f64a3258226ae93658776a416aaf4383698a6ea7d': ['MAL_Mispadu_URSA_Delphi_Cipher_Code', 'MAL_Mispadu_URSA_Payload_Build108'],  # payload EXE, build 108 (Delphi, 6.9 MB)
    '352c8d5d8cc824c41d143af2504d2cdf5d8a16e5f4df019032a5241859b1900b': ['MAL_Mispadu_URSA_Hook_DLL_pDLL'],  # pDLL keyboard-hook DLL extracted from the payload resources
    # FluxEngine (yara/fluxengine)
    'dc60f22fc59a7c3cb51b97661ad69f42d3028538c0044b248fc9681487c0b433': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, 2026-10-19 build
    '6a9ded132c050747ae5f233a91fc84c6bbee4e91950636f5fe077bf48acdca30': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    '7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    '01af2f7049e1562023835ddcbffea76e265ed2906e140ba8a200eb41d37ebf8d': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    'c424a715e3861bc18e0c8223f3dfd909dc4a77a82b9c5a5a135b8d49bac7e8c6': ['MAL_FluxEngine_Payload_Delphi'],  # decrypted payload (Delphi, 4.5 MB)
    '6e6d4084c6c2f3035c2fbda4daf4b705a06938d73bf91f402552b6d4ab522d9b': ['SUSP_FluxEngine_LNK_Squiblydoo_ADS'],  # stage-1 LNK
    # The Gentlemen (yara/the_gentlemen)
    '3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235': ['MAL_Gentlemen_Locker_Go'],  # Windows locker (Go, garbled), 2026-04
    '53d2484ae1ad6ff9547d90f5f5ccd6ae1dca8cb24e622a07dfc74c9593b2c3fa': ['MAL_Gentlemen_Locker_Go'],  # Linux ELF locker (Go), 2026-10
    '32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134': ['HUNT_Gentlemen_Ransom_Note'],  # README-GENTLEMEN.txt (extracted from the note zip)
    '51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2': [],  # DOCUMENTED MISS: VMProtect-packed Windows build, no family-specific rule possible (yara/the_gentlemen/README.md)
    'f8b07ce20ae77fec0905724a466196a5ba8281e9ba9534808ab7e7bf15f37516': [],  # DOCUMENTED MISS: the note zip (deflate container); the extracted note matches
}
ok = True


def check(cond, msg):
    global ok
    print(('PASS ' if cond else 'FAIL ') + msg)
    ok &= bool(cond)


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def walk(dirs):
    for d in dirs:
        for r, _, fs in os.walk(d):
            for f in fs:
                yield os.path.join(r, f)


class Engines:
    def __init__(self):
        self.eng = {}
        files = sorted(glob.glob(os.path.join(YARA_DIR, '**', '*.yar'), recursive=True))
        self.files = files
        try:
            import yara
            self.eng['yara-python ' + yara.__version__] = self._py(yara, files)
        except ImportError:
            print('NOTE yara-python not installed, skipping')
        try:
            import yara_x
            self.eng['yara-x ' + __import__('importlib.metadata').metadata.version('yara-x')] = self._x(yara_x, files)
        except ImportError:
            print('NOTE yara-x not installed, skipping')

    def _py(self, yara, files):
        rules = yara.compile(filepaths={os.path.basename(f): f for f in files})
        return lambda p=None, data=None: sorted(r.rule for r in (rules.match(p) if p else rules.match(data=data)))

    def _x(self, yara_x, files):
        c = yara_x.Compiler()
        for f in files:
            c.add_source(open(f, encoding='utf-8').read(), origin=f)
        rules = yara_x.Scanner(c.build())
        def scan(p=None, data=None):
            res = rules.scan(data if data is not None else open(p, 'rb').read())
            return sorted(m.identifier for m in res.matching_rules)
        return scan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--compile-only', action='store_true')
    ap.add_argument('--samples', nargs='*', default=[])
    ap.add_argument('--negatives', nargs='*', default=[])
    a = ap.parse_args()
    E = Engines()
    check(E.eng, 'at least one YARA engine available')
    check(len(E.files) >= 16, f'{len(E.files)} rule files compiled together')
    for name in E.eng:
        print('ENGINE', name)
    if a.compile_only:
        print('COMPILE OK' if ok else 'COMPILE FAILED')
        return 0 if ok else 1

    seen = set()
    for p in walk(a.samples):
        h = sha256(p)
        if h in EXPECTED:
            seen.add(h)
            for name, scan in E.eng.items():
                check(scan(p) == sorted(EXPECTED[h]), f'[{name}] {h[:12]} -> {", ".join(sorted(EXPECTED[h]))}')
    for h in EXPECTED:
        if h not in seen:
            print(f'SKIP sample {h[:12]} not provided')

    negs = [p for p in walk(a.negatives) if os.path.isfile(p) and sha256(p) not in EXPECTED]  # known positives are never negatives
    for name, scan in E.eng.items():
        fp = [p for p in negs if scan(p)]
        check(not fp, f'[{name}] negative corpus: {len(negs)} files, 0 hits {[os.path.basename(x) for x in fp]}')

    # synthetic negatives: a real, spec-conformant cabinet must not trigger the fake-cab rule
    try:
        from cabarchive import CabArchive, CabFile
        arc = CabArchive(); arc['a.bin'] = CabFile(os.urandom(300000)); arc['b.txt'] = CabFile(b'hello ' * 5000)
        for comp in (False, True):
            cab = arc.save(compress=comp)
            for name, scan in E.eng.items():
                check(scan(data=cab) == [], f'[{name}] real CAB (compress={comp}) -> no hit')
    except ImportError:
        print('SKIP synthetic CAB test (pip install cabarchive)')
    print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
    return 0 if ok else 1


sys.exit(main())
