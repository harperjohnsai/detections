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
    'b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960': ['SetupCenter_ProxyVersionDll_Loader'],              # version.dll
    '193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62': ['SetupCenter_FakeCab_PayloadContainer'],           # localdata.db
    'c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad': ['REVSTEALER_x64_Core_SetupCenter'],                # inner payload
    '3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632': ['REVSTEALER_ABE_Helper_DLL'],                       # ABE helper DLL
    '0a48e7ed139a1cbe38c4ccb98edf2ff99bc53933f07942fa02fcf054dc14e0a6': ['REVSTEALER_Decrypted_Strings_Memory', 'REVSTEALER_x64_Core_SetupCenter'],  # strings-decrypted artefact
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
    check(len(E.files) >= 5, f'{len(E.files)} rule files compiled together')
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
