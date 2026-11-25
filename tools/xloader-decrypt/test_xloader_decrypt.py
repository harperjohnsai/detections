#!/usr/bin/env python3
"""Regression test for xloader_decrypt.py.

usage: test_xloader_decrypt.py [IMAGE ...]

Always runs the self-contained checks (cipher round trips, expected_table.csv shape). For every IMAGE given (a sandbox
stage or injected-payload dump of the validated build; not shipped in this repo) it runs the tool and compares the
decrypted C2 table, the real-C2 string and the first check-in batch with expected_table.csv.
Needs capstone and unicorn (the tool imports them).
"""
import csv, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ok = True


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


import xloader_decrypt as X  # noqa: E402

for n, key in ((1, b'k'), (7, b'0123456789abcdef0123'), (64, bytes(range(20)))):
    pt = bytes((i * 37 + n) & 0xff for i in range(n))
    check(X.D(X.E(pt, key), key) == pt, f'E then D round trip, {n} bytes')
    check(X.E(X.D(pt, key), key) == pt, f'D then E round trip, {n} bytes')
check(X.D(b'', b'k') == b'' and X.D(b'A', b'k') != b'', 'edge sizes 0 and 1 do not crash')

exp = list(csv.DictReader(open(os.path.join(HERE, 'expected_table.csv'))))
check(len(exp) == 65 and [int(r['idx']) for r in exp] == list(range(65)), 'expected_table.csv: 65 rows, idx 0..64')
check(len({r['path'] for r in exp}) == 65 and all(len(r['path']) == 6 for r in exp), 'expected_table.csv: 65 distinct /xxxx/ paths')
check(sum(1 for r in exp if r['host']) == 64 and not exp[0]['host'], 'expected_table.csv: 64 hosts, idx 0 is path-only')
BATCH = [40, 27, 23, 8, 3, 17, 60, 22, 41, 20, 61, 42, 47, 9, 33, 48]

for img in sys.argv[1:]:
    out = subprocess.run([sys.executable, os.path.join(HERE, 'xloader_decrypt.py'), img], capture_output=True, text=True)
    check(out.returncode == 0, f'{os.path.basename(img)}: tool exit code 0 ({out.stderr.strip().splitlines()[-1:] if out.returncode else ""})')
    if out.returncode:
        continue
    j = json.loads(out.stdout)
    got = [(r['idx'], r['host'] or '', r['path']) for r in j['c2_table']]
    want = [(int(r['idx']), r['host'], r['path']) for r in exp]
    check(got == want, f'{os.path.basename(img)}: 65-row C2 table equals expected_table.csv')
    check(j['real_c2'] and j['real_c2']['host'] == 'www.thecalmdogguide.com', f'{os.path.basename(img)}: real-C2 string')
    check([b['idx'] for b in j['first_checkin_batch']] == BATCH, f'{os.path.basename(img)}: first check-in batch order')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
