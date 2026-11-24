#!/usr/bin/env python3
"""Regression test for remus_c2_table.py.

usage: test_remus_c2_table.py EXPECTED.csv DIR [NEGATIVE_FILE ...]
EXPECTED.csv: sha256,idx,url. Every <sha256>.bin in DIR listed there must give exactly those three URLs.
Other files in DIR and NEGATIVE_FILEs (benign PEs, non-Remus payloads, the Go loaders) must give no table.
Also checks the ChaCha20 block function against the RFC 8439 section 2.3.2 test vector.
"""
import csv
import os
import sys

from remus_c2_table import analyse, chacha_block

exp = {}
for r in csv.DictReader(open(sys.argv[1])):
    exp.setdefault(r['sha256'], {})[int(r['idx'])] = r['url']
ok = fail = 0

def res(good, *msg):
    global ok, fail
    ok += good
    fail += not good
    print('PASS' if good else 'FAIL', *msg)

blk = chacha_block(bytes(range(32)), 1 | (0x09000000 << 32), bytes.fromhex('0000004a00000000'))
res(blk[:16].hex() == '10f1e7e4d13b5915500fdd1fa32071c4', 'chacha20 RFC 8439 2.3.2 block')
negatives = list(sys.argv[3:])
for name in sorted(os.listdir(sys.argv[2])):
    h = name.split('.')[0]
    if h not in exp:
        negatives.append(os.path.join(sys.argv[2], name))
        continue
    r = analyse(os.path.join(sys.argv[2], name))
    got = {e['idx']: e['url'] for e in r.get('entries', [])}
    res(got == exp[h], h[:12], r.get('mask'), ' '.join(str(got.get(i)) for i in range(3)))
for f in negatives:
    try:
        r = analyse(f)
    except Exception as e:  # not a PE
        print('SKIP', os.path.basename(f), type(e).__name__)
        continue
    good = r['result'] != 'ok' or not any(e['url'] and e['url'].startswith('https://') for e in r.get('entries', []))
    res(good, 'negative', os.path.basename(f)[:40], r['result'])
print(f'{ok} passed, {fail} failed')
sys.exit(1 if fail else 0)
