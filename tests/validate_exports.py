#!/usr/bin/env python3
"""Validate the generated exports: STIX 2.1 with the OASIS stix2-validator and the stix2 parser,
MISP events by loading them with PyMISP (no server), the MISP category/type matrix (A-CAT) and a warninglist gate
(pinned misp-warninglists commit, see tools/wl_known.py; fetched with git unless WL_DIR points at a checkout).
Needs stix2 stix2-validator pymisp."""
import glob, json, os, sys

import stix2
from pymisp import MISPAttribute, MISPEvent
from stix2validator import ValidationOptions, validate_file

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
import wl_known  # noqa: E402

ok = True
# MISP category/type matrix of the installed PyMISP (describeTypes); MISPEvent.load() does not enforce it
MATRIX = MISPAttribute().describe_types['category_type_mappings']


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


def bad_categories(attrs):
    """A-CAT: attributes whose category is not a valid selection for their type."""
    return [f"{a['type']}:{str(a['value'])[:60]} in {a['category']!r}" for a in attrs
            if a['category'] not in MATRIX or a['type'] not in MATRIX[a['category']]]


# negative control: the matrix check must flag the pair PyMISP's loader lets through
check(bad_categories([{'type': 'url', 'category': 'Social network', 'value': 'https://x.test/'},
                      {'type': 'url', 'category': 'Payload delivery', 'value': 'https://x.test/'}]) ==
      ["url:https://x.test/ in 'Social network'"], 'A-CAT control: url in "Social network" is flagged, url in "Payload delivery" is not')


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
    raw = json.load(open(d + 'misp_event.json', encoding='utf-8'))['Event']
    raw_attrs = raw.get('Attribute', []) + [a for o in raw.get('Object', []) for a in o.get('Attribute', [])]
    bad = bad_categories(raw_attrs)
    check(not bad, f'{name}: A-CAT every attribute category valid for its type ({len(raw_attrs)} checked) {bad[:3]}')
    ev = MISPEvent()
    ev.load(open(d + 'misp_event.json', encoding='utf-8').read())
    check(len(ev.attributes) > 0 and ev.distribution == 3 and any(t.name == 'tlp:clear' for t in ev.tags),
          f'{name}: pymisp loaded event, {len(ev.attributes)} attributes ({sum(a.to_ids for a in ev.attributes)} to_ids) of {n_iocs} rows + links')
# ---- warninglist gate (T0163): pinned misp-warninglists commit, type-aware ---------------------------------
# Class (a), shared infrastructure (tools/wl_known.py CLASSES): a to_ids=true attribute must not equal an entry; the
# exporter withdraws the flag. Subdomain/path matches keep to_ids but must carry a review note in the comment.
# Class (b), rented hosting/cloud ranges: the flag is NOT withdrawn (attacker-rented C2 servers live there); the
# comment must carry the "cloud-hosted ... time-bound" note, and an attribute that is otherwise to_ids-eligible
# (malicious verdict, confidence high/medium, type ip) must still have to_ids=true.
WL = wl_known.Lists(wl_known.ensure_lists())
cl = WL.classify
check(('url-shortener', 'exact') in [h[:2] for h in cl('domain', 'bit.ly')],
      'warninglist control: domain bit.ly is an exact hit of url-shortener')
check(any(h[:2] == ('amazon-aws', 'cloud') for h in cl('ip-dst', '3.80.57.117')) and
      any(h[:2] == ('amazon-aws', 'cloud') for h in cl('ip-dst|port', '3.80.57.117|9136')),
      'warninglist control: ip-dst and ip-dst|port (IP half) hit amazon-aws as class (b) cloud, not exact')
check(any(h[:2] == ('hetzner', 'cloud') for h in cl('ip-dst', '91.107.247.163')) and
      not any(h[1] == 'exact' for h in cl('ip-dst', '91.107.247.163')),
      'warninglist control: Hetzner address is class (b) cloud, not exact')
check(any(h[:2] == ('cloudflare', 'exact') for h in cl('ip-dst', '104.21.12.25')) and
      not any(h[1] == 'cloud' for h in cl('ip-dst', '104.21.12.25')),
      'warninglist control: Cloudflare address is class (a) exact')
check(set(wl_known.CLASSES.values()) == {'shared', 'cloud'} and set(wl_known.LISTS) == set(wl_known.CLASSES),
      'warninglist control: every pinned list has a class (shared|cloud)')
check(cl('text', 'bit.ly') == [] and cl('domain', '3.80.57.117') == [],
      'warninglist control: type-aware, same value as another attribute type is not consulted')
check(['dynamic-dns'] == [h[0] for h in cl('domain', 'guild.hopto.me') if h[1] == 'subdomain'] and
      all(h[1] == 'path' for h in cl('url', 'https://bit.ly/3WCrex2')) and cl('url', 'https://bit.ly/3WCrex2'),
      'warninglist control: subdomain of a zone entry and a path URL on a shortener are not exact')
check(cl('domain', 'example-unlisted-domain.test') == [] and cl('ip-dst', '203.0.113.5') == [],
      'warninglist control: unlisted domain and documentation IP give no hit')
check(wl_known.dumps(wl_known.derive(WL)) == open(wl_known.DATA, encoding='utf-8').read(),
      f'tools/warninglist_known.json equals a fresh derivation from {wl_known.PIN[:10]} (run tools/wl_known.py --update)')
n_exact = n_review = n_cloud = 0
ELIGIBLE_TYPES = ('ip-dst', 'ip-src', 'ip-dst|port', 'ip-src|port', 'domain', 'url', 'sha256', 'uri', 'mutex')


def ids_eligible(a):
    """Would the exporter set to_ids=true without the gate? (row verdict malicious, confidence high/medium)."""
    return ('verdict: malicious' in a['comment'] and a['type'] in ELIGIBLE_TYPES and
            any(t['name'].endswith(('"high"', '"moderate"')) for t in a.get('Tag', [])))


for d in sorted(glob.glob(os.path.join(HERE, '..', 'iocs', '*', ''))):
    name = os.path.basename(os.path.dirname(d))
    if not os.path.exists(d + 'misp_event.json'):
        continue
    ev = json.load(open(d + 'misp_event.json', encoding='utf-8'))['Event']
    attrs = ev.get('Attribute', []) + [a for o in ev.get('Object', []) for a in o.get('Attribute', [])]
    exact_ids, unreviewed, cloud_bad = [], [], []
    for a in attrs:
        hits = cl(a['type'], str(a['value']))
        if not hits:
            continue
        if any(h[1] == 'exact' for h in hits):
            n_exact += 1
            if a['to_ids']:
                exact_ids.append(f"{a['type']}:{a['value']}")
            elif wl_known.NOTE_EXACT not in a['comment']:
                unreviewed.append(f"{a['type']}:{a['value']}")
        elif any(h[1] == 'cloud' for h in hits):
            n_cloud += 1
            if wl_known.NOTE_CLOUD not in a['comment'] or 'time-bound' not in a['comment'] or \
                    wl_known.NOTE_EXACT in a['comment']:
                cloud_bad.append(f"{a['type']}:{a['value']} (note)")
            if ids_eligible(a) and not a['to_ids']:
                cloud_bad.append(f"{a['type']}:{a['value']} (to_ids withdrawn)")
        elif a['to_ids']:
            n_review += 1
            if wl_known.NOTE_REVIEW not in a['comment']:
                unreviewed.append(f"{a['type']}:{a['value']}")
    check(not exact_ids, f'{name}: no to_ids=true attribute equals a shared-infrastructure (class a) warninglist entry {exact_ids[:3]}')
    check(not unreviewed, f'{name}: every shared/review warninglist hit carries its note in the comment {unreviewed[:3]}')
    check(not cloud_bad, f'{name}: cloud-hosted (class b) matches keep to_ids when otherwise eligible and carry the time-bound note {cloud_bad[:3]}')
# regression pins: attacker-rented servers that the first version of the gate wrongly withdrew
pins = {('2026-11-grandoreiro-es-pt', 'ip-dst', '3.80.57.117'), ('2026-11-grandoreiro-es-pt', 'ip-dst|port', '3.80.57.117|9136'),
        ('2026-11-the-gentlemen', 'ip-dst', '91.107.247.163'), ('2026-11-the-gentlemen', 'ip-dst|port', '91.107.247.163|443'),
        ('2026-11-the-gentlemen', 'ip-dst|port', '91.107.247.163|80')}
seen = set()
for slug, t, v in pins:
    ev = json.load(open(os.path.join(HERE, '..', 'iocs', slug, 'misp_event.json'), encoding='utf-8'))['Event']
    for a in ev.get('Attribute', []) + [x for o in ev.get('Object', []) for x in o.get('Attribute', [])]:
        if (a['type'], a['value']) == (t, v) and a['to_ids'] and wl_known.NOTE_CLOUD in a['comment']:
            seen.add((slug, t, v))
check(seen == pins, f'regression: {len(seen)} of {len(pins)} attacker-rented C2 attributes are to_ids=true with the cloud-hosted note')
print(f'warninglist: {n_exact} shared exact hits (to_ids withdrawn), {n_cloud} cloud-hosted hits (to_ids kept, note), {n_review} subdomain/path hits kept with review note')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
