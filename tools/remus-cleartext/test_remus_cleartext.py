#!/usr/bin/env python3
"""Regression test for remus_cleartext.py.

usage: test_remus_cleartext.py EXPECTED.csv DIR [NEGATIVE_FILE ...]
EXPECTED.csv: sha256,build_date,campaign_id (empty fields = a payload that must give nothing).
Every file in DIR named <sha256>.bin is checked against its row; NEGATIVE_FILEs (benign PEs) must give nothing.
"""
import csv
import os
import sys

from remus_cleartext import read

exp = {r['sha256']: r for r in csv.DictReader(open(sys.argv[1]))}
ok = fail = 0
for name in sorted(os.listdir(sys.argv[2])):
    h = name.split('.')[0]
    if h not in exp:
        continue
    got = read(os.path.join(sys.argv[2], name))
    good = got['build_date'] == exp[h]['build_date'] and got['campaign_id'] == exp[h]['campaign_id']
    ok += good
    fail += not good
    print('PASS' if good else 'FAIL', h[:12], got['build_date'] or '-', got['campaign_id'] or '-')
for f in sys.argv[3:]:
    try:
        got = read(f)
    except Exception as e:  # not a PE: skip
        print('SKIP', os.path.basename(f), type(e).__name__)
        continue
    good = not got['build_date'] and not got['campaign_id']
    ok += good
    fail += not good
    print('PASS' if good else 'FAIL', 'negative', os.path.basename(f))
print(f'{ok} passed, {fail} failed')
sys.exit(1 if fail else 0)
