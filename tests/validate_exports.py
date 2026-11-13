#!/usr/bin/env python3
"""Validate the generated exports: STIX 2.1 with the OASIS stix2-validator and the stix2 parser,
MISP events by loading them with PyMISP (no server). Needs stix2 stix2-validator pymisp."""
import glob, json, os, sys

import stix2
from pymisp import MISPEvent
from stix2validator import ValidationOptions, validate_file

HERE = os.path.dirname(os.path.abspath(__file__))
ok = True


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


for d in sorted(glob.glob(os.path.join(HERE, '..', 'iocs', '*', ''))):
    name = os.path.basename(os.path.dirname(d))
    if not os.path.exists(d + 'iocs.json'):
        continue
    n_iocs = len(json.load(open(d + 'iocs.json', encoding='utf-8'))['iocs'])
    check(os.path.exists(d + 'stix2.json') and os.path.exists(d + 'misp_event.json'), f'{name}: stix2.json and misp_event.json present')
    # 103: ids are deliberately uuid5 (deterministic, no diff churn); 302: external-reference hashes are not available
    res = validate_file(d + 'stix2.json', ValidationOptions(version='2.1', disabled='103,302'))
    errs = [str(e) for o in res.object_results for e in o.errors]
    warns = [str(w) for o in res.object_results for w in o.warnings]
    check(res.is_valid and not errs, f'{name}: stix2-validator (2.1) valid, {len(errs)} errors, {len(warns)} warnings {(errs + warns)[:3]}')
    bundle = stix2.parse(open(d + 'stix2.json', encoding='utf-8').read(), allow_custom=True, version='2.1')
    types = {}
    for o in bundle.objects:
        types[o['type']] = types.get(o['type'], 0) + 1
    check(types.get('indicator', 0) > 0 and types.get('report') == 1 and types.get('identity') == 1,
          f'{name}: stix2 parsed, objects {types}')
    ids = {o['id'] for o in bundle.objects}
    rep = next(o for o in bundle.objects if o['type'] == 'report')
    check(set(rep['object_refs']) <= ids, f'{name}: report object_refs all resolve')
    check(all(o['id'] == 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487' or
              'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487' in o.get('object_marking_refs', [])
              for o in bundle.objects if o['type'] not in ('identity',)), f'{name}: TLP:CLEAR on all objects')
    ev = MISPEvent()
    ev.load(open(d + 'misp_event.json', encoding='utf-8').read())
    check(len(ev.attributes) > 0 and ev.distribution == 3 and any(t.name == 'tlp:clear' for t in ev.tags),
          f'{name}: pymisp loaded event, {len(ev.attributes)} attributes ({sum(a.to_ids for a in ev.attributes)} to_ids) of {n_iocs} rows + links')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
