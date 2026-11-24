#!/usr/bin/env python3
"""Regression tests for tools/cncmachinerms_extract (static; nothing is executed).

usage: test_cncmachinerms_extract.py [<dir-with-samples>]

1. Synthetic round-trips: a Storage container is BUILT here from the inverse of the decode formulas (one per
   layer-2 parameter set seen in the wild plus an unseen set that must be learned) and the extractor must
   return the planted gates and settings.  No sample needed; runs in CI-less local use and in CI.
2. Per-build regression on the real containers (found by SHA-256, not by name; builds that are not present are
   skipped): ROMULUS Stardock, ROMULUS numeric MSI, FilesInspectorX, AllMyBasic, BabaDeda load.db, and the Canon-chain
   container whose layer 2 is documented as not reproduced.
"""
import hashlib, json, os, random, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, '..', 'tools', 'cncmachinerms-extract')
sys.path.insert(0, TOOL)
import storage as S                                   # noqa: E402
import cncmachinerms_extract as X                     # noqa: E402

M = 1 << 64


def wstr(s):
    return s.encode('utf-16le')


def build_container(K, params, tree, k=0x13579BDF2468ACE, seed=1):
    """tree: list of (node, parent, prop, plaintext_blob). Returns container bytes (header + records + blobs)."""
    rnd = random.Random(seed)
    base = (k * (7 * k + 3 * K)) % M
    D = [0] * 15
    D[0] = k
    D[1] = (7 * k + 3 * K) % M
    D[5] = (D[1] - 37 * (k + K)) % M
    D[6] = ((k + K + 1) * (D[5] + 1)) % M
    D[2] = (K - base + D[5] + 1) % M              # header meta version == 1
    n = len(tree)
    T0, T1 = rnd.getrandbits(40), rnd.getrandbits(40)
    D[10], D[11] = T0, T1
    D[12] = (n + K * T1 + T0) % M
    D[13] = (n + K * T0 - T1) % M
    D[14] = rnd.getrandbits(40)
    for i in (3, 4, 7, 8, 9):
        D[i] = rnd.getrandbits(64)
    head = struct.pack('<15Q', *D)
    recs, blobs = b'', b''
    for node, parent, prop, blob in tree:
        x = rnd.getrandbits(40)
        key = rnd.randrange(1, 256)
        enc = 1
        R = [x,
             (node + K * x + x) % M, (parent + K - 3 * x) % M, (prop + K * (x + 5) - 2 * x) % M,
             (len(blob) + K + 7 * x) % M, (2 * K - 2 * x + (1 if blob == b'' else 0)) % M,
             (K - 4 * x) % M, (3 * K - 3 * x + enc) % M, (key + K * x - 4 * x) % M, (5 * K - x) % M, (K - 5 * x) % M]
        recs += struct.pack('<11Q', *R)
        blobs += S.dec_blob(blob, key, params)       # XOR keystream is its own inverse
    return head + recs + blobs


def planted_tree(gates, campaign='unit'):
    t, n = [], [0]

    def add(parent, prop, blob):
        n[0] += 1
        t.append((n[0], parent, prop, blob))
        return n[0]
    root = add(0, 16000, b'')
    def res(name, typ, val):
        r = add(root, 16050, b'')
        add(r, 16051, os.urandom(8))
        add(r, 16052, wstr(name))
        add(r, 16053, struct.pack('<Q', typ))
        if val is not None:
            add(r, 16054, val)
    res('campaign', X.T_STR, wstr(campaign))
    res('gate_connect_period_seconds', X.T_INT, struct.pack('<q', 600))
    res('is_vmcheck', X.T_BOOL, b'\x01')
    gl = add(root, 16050, b'')
    add(gl, 16051, os.urandom(8)); add(gl, 16052, wstr('gate_list')); add(gl, 16053, struct.pack('<Q', X.T_DICT))
    for i in range(600):                          # filler like the real trees: many small ints / short strings
        add(root, 16030 + i % 8, struct.pack('<q', i % 97) if i % 3 == 1 else wstr('value-%d' % i * (1 + i % 5)))
    add(root, 16001, wstr('task preparations[active=true,async=false] { delayer::delay_in_seconds(2); }\r\n' * 40))
    gd = add(root, 16070, b'')
    for host, port in gates:
        e = add(gd, 16071, b'')
        add(e, 16072, wstr(host)); add(e, 16073, wstr(str(port)))
    return t


def synthetic():
    ok = True
    sets = dict(S.KNOWN)
    sets['unseen-build'] = (0, 17, 5, 0x27, 5, 21, 7)       # must be learned from the data
    gates = [('gate-one.example', 443), ('203.0.113.7', 8443)]
    for name, p in sets.items():
        K = 0x1234567890 + len(name)
        data = os.urandom(300) + build_container(K, p, planted_tree(gates)) + os.urandom(300)
        res = X.analyse(data)
        c = res['containers'][0] if res['containers'] else {}
        good = (len(res['containers']) == 1 and c.get('build_key') == hex(K) and c.get('gates') == [dict(host=h, port=pt) for h, pt in gates]
                and c['resources']['campaign'] == 'unit' and c['resources']['gate_connect_period_seconds'] == 600
                and c['resources']['is_vmcheck'] is True)
        print(('PASS ' if good else 'FAIL ') + f'synthetic {name:13s} variant={c.get("layer2_variant")} params={c.get("layer2_params")}')
        ok &= bool(good)
    # negative: random bytes carry no header
    rnd = os.urandom(2_000_000)
    n = len(list(S.scan_headers(rnd)))
    print(('PASS ' if n == 0 else 'FAIL ') + f'negative: {n} headers in 2 MB of random data')
    ok &= n == 0
    # header equations must be solvable for K from the first two qwords (LevelBlue's published primitive)
    K = 0x16DF3822A8
    blob = build_container(K, S.KNOWN['rat-embedded'], planted_tree(gates))
    q = struct.unpack_from('<7Q', blob)
    ok &= S.header_key(q) == K
    print(('PASS ' if S.header_key(q) == K else 'FAIL ') + 'header key recovery 0x16df3822a8')
    return ok


# container sha256 -> expectations (None gates = layer 2 not reproduced)
BUILDS = {
    'd5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90': dict(label='ROMULUS Stardock (IconEdit2Turb.msi)', K='0x366b20a1', persist='Stardock DeElevation Tool',
        payload='ab65bbfc505dbe1cebe6021fb36e2011f6aa1d64f5d87cee1cbee3fc2a0c7907', gates=[('nfenribj3.com', 443), ('45.140.205.28', 443)], campaign='test'),
    '06b8adb4f361ba2cbcf35379e4dfd3d6291167bb987bd0b1817d3358c3e8fb5c': dict(label='ROMULUS numeric MSI "3"', K='0x4870ffc2', persist='Easy Data Transform Suite',
        payload='ab65bbfc505dbe1cebe6021fb36e2011f6aa1d64f5d87cee1cbee3fc2a0c7907', gates=[('nfenribj3.com', 443), ('45.140.205.28', 443)], campaign='test'),
    '4652fe86f16373375dbc84894917e34b4ea67b91a4b86d62c03fce96d9a985e8': dict(label='FilesInspectorX.msi', K='0x71f0b446', persist='CatchPulse Notifier',
        payload='d9274c98d7be30e6045e63d3acc190055a3849e2992b7382643c16a5aefa22dc', gates=[('wizardexpensive.com', 443), ('96.62.218.59', 443)], campaign='default'),
    'd95a5e3447077a4cb0cad3110bf761b26270a140a4817744b9570e0887591e4c': dict(label='AllMyBasic.msi', K='0x32be4757', persist='Siemens Software Center',
        payload='29340068aa98c9720340fb1aa6f21f8314d939519db5e26cdd5e7d9c321816db', gates=[('wizardexpensive.com', 443), ('96.62.218.59', 443)], campaign='first'),
    '9a7ec20cfe939a0739819262c1e3ff0265c851136cc263597936773376a5d907': dict(label='BabaDeda load.db (Aug 2026)', K='0x43d75dfd', persist='SPSS WinWrap Basic IDE 27.4',
        payload='51c25fdf3a1aae25b7f489577f279839ec6c802ed3ba17b07d58c1fd055d7d70', gates=[('triotmelon.com', 443), ('144.124.242.171', 443)], campaign='first'),
    'e614b7d5a7a363fb1b355a87e2e8d9e8a05bbbca08f2cee3d606bdb5015ac53b': dict(label='Canon chain monitor.raw (layer 2 NOT reproduced)', K='0x26ace8d1', persist=None,
        payload=None, gates=None, campaign=None),
}


def real(dirpath):
    files = {}
    for r, _, fs in os.walk(dirpath):
        for f in fs:
            p = os.path.join(r, f)
            if os.path.getsize(p) < 1_700_000 and os.path.getsize(p) > 1_000_000:
                files[hashlib.sha256(open(p, 'rb').read()).hexdigest()] = p
    ok, ran = True, 0
    for sha, exp in BUILDS.items():
        if sha not in files:
            print(f'SKIP {exp["label"]} (container {sha[:12]} not provided)')
            continue
        ran += 1
        r = subprocess.run([sys.executable, os.path.join(TOOL, 'cncmachinerms_extract.py'), files[sha]], capture_output=True, text=True)
        try:
            res = json.loads(r.stdout)
        except ValueError:
            print(f'FAIL {exp["label"]}: unreadable output {r.stderr[-200:]}'); ok = False; continue
        c = res['containers'][0]
        good = c['build_key'] == exp['K']
        if exp['gates'] is None:
            good &= c['layer2_variant'] == 'unresolved' and 'payload' not in c
        else:
            good &= c['resources'].get('registryAutorunValue') == exp['persist']
            if exp['payload']:
                good &= c['payload']['sha256'] == exp['payload']
            inner = c['payload_analysis']['containers'][0]
            good &= [(g['host'], g['port']) for g in inner['gates']] == exp['gates'] and inner['resources']['campaign'] == exp['campaign']
        print(('PASS ' if good else 'FAIL ') + f'{exp["label"]}: K={c["build_key"]} layer2={c["layer2_variant"]}')
        ok &= bool(good)
    return ok, ran


def main():
    ok = synthetic()
    ran = 0
    if len(sys.argv) > 1:
        r_ok, ran = real(sys.argv[1])
        ok &= r_ok
    else:
        print('SKIP real-sample regression (no sample directory given)')
    print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED', f'(real builds tested: {ran})')
    return 0 if ok else 1


sys.exit(main())
