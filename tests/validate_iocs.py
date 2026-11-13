#!/usr/bin/env python3
"""Sanity checks for iocs/*: JSON loads, CSV and JSON agree, CSV is defanged, hashes look like hashes."""
import csv, glob, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ok = True


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


for d in sorted(glob.glob(os.path.join(HERE, '..', 'iocs', '*', ''))):
    name = os.path.basename(os.path.dirname(d))
    j = json.load(open(d + 'iocs.json', encoding='utf-8'))
    rows = list(csv.DictReader(open(d + 'iocs.csv', encoding='utf-8')))
    check(j.get('_warning', '').startswith('MACHINE-READABLE'), f'{name}: json carries the not-defanged warning')
    check(len(rows) == j['count'] == len(j['iocs']), f'{name}: csv rows == json count == {j["count"]}')
    live = [r['value_defanged'] for r in rows if r['type'] not in ('reference', 'sha256') and re.search(r'https?://', r['value_defanged'])]
    check(not live, f'{name}: no live http(s) URLs in the defanged csv {live[:2]}')
    bad = [r['value_defanged'] for r in rows if r['type'] == 'sha256' and not re.fullmatch(r'[0-9a-f]{64}', r['value_defanged'])]
    check(not bad, f'{name}: all sha256 values are 64 hex chars {bad[:2]}')
    check(os.path.exists(d + 'README.md'), f'{name}: README.md present')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
