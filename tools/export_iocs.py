#!/usr/bin/env python3
"""Generate STIX 2.1 and MISP exports for every case from iocs.json + case.yml.

usage: export_iocs.py [--check]

Writes iocs/<case>/stix2.json and iocs/<case>/misp_event.json. Both files are
generated, never hand-edited. Output is deterministic (uuid5 ids, timestamps
derived from the case date), so re-runs produce no diff. --check exits 1 if a
committed file is missing or stale (used by CI). Needs PyYAML only.

Policy (see tools/README.md):
  * STIX carries indicators only for types with a standard pattern. Rows with
    verdict shared-or-legit-infrastructure, genuine/legit files and generic
    paths are context: no STIX indicator, MISP attribute with to_ids=false.
  * to_ids=true only for malicious rows of confidence high/medium whose type is
    blocklist-grade (domain, url, ip, ip|port, sha256, uri path, mutex).
  * 'indicates' relationships come from the optional `indicates` list in case.yml.
Notes-only cases (no iocs.json) are skipped.
"""
import datetime as dt
import glob
import json
import os
import re
import sys
import uuid

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wl_known  # noqa: E402  (pinned MISP warninglist matches)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
NS = uuid.UUID('6f0c1d52-8d3e-5a47-9b8e-2c7f4a1e90d3')  # fixed namespace: do not change, ids derive from it
AUTHOR = 'Harper Johns'
AUTHOR_URL = 'https://github.com/harperjohnsai/detections'
TLP_CLEAR_ID = 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487'
TLP_EXT_ID = 'extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d'
TLP_CLEAR = {  # OASIS STIX 2.1 TLP 2.0 object, verbatim
    'type': 'marking-definition', 'spec_version': '2.1', 'id': TLP_CLEAR_ID,
    'created': '2022-10-01T00:00:00.000Z', 'name': 'TLP:CLEAR',
    'extensions': {TLP_EXT_ID: {'extension_type': 'property-extension', 'tlp_2_0': 'clear'}},
}
CONF = {'high': 85, 'medium': 50, 'low': 15}
MISP_CONF = {'high': 'high', 'medium': 'moderate', 'low': 'low'}
CONF_ALIAS = {'med': 'medium', 'mid': 'medium'}
WL_EXACT = wl_known.NOTE_EXACT
WL_REVIEW = wl_known.NOTE_REVIEW
IDS_TYPES = {'domain', 'url', 'ipv4', 'endpoint', 'sha256', 'url-path', 'mutex'}
HASH_TYPES = {'sha256', 'filename', 'path', 'file-path'}
LEGIT_ROLE = re.compile(r'\blegit\b|genuine|do not block|not malicious', re.I)
LABEL_WORDS = [('c2', r'\bc2\b'), ('lure', r'\blure'), ('stage', r'\bstage'), ('distribution', r'distribution'),
               ('payload', r'payload'), ('dead-drop', r'dead[- ]drop'), ('loader', r'loader'),
               ('exfiltration', r'exfil'), ('persistence', r'persistence'), ('gate', r'\bgate\b'),
               ('redirector', r'redirect|shortener|shortlink'), ('delivery', r'delivery|download'),
               ('phishing', r'phish'), ('sideload', r'sideload'), ('compromised-site', r'compromised')]
MALWARE_TYPES = [('stealer', 'spyware'), ('rat', 'remote-access-trojan'), ('netsupport', 'remote-access-trojan'),
                 ('loader', 'dropper')]


def uid(kind, *parts):
    return str(uuid.uuid5(NS, '|'.join((kind,) + parts)))


def ts(d, ms=True):
    return d.strftime('%Y-%m-%dT%H:%M:%S.000Z' if ms else '%Y-%m-%dT%H:%M:%SZ')


def to_dt(v):
    if isinstance(v, dt.datetime):
        return v
    if isinstance(v, dt.date):
        return dt.datetime(v.year, v.month, v.day)
    return dt.datetime.strptime(str(v), '%Y-%m-%d')


def first_seen(row, fallback):
    s = (row.get('first_seen') or '').strip()
    for fmt, n in (('%Y-%m-%d', 10), ('%Y', 4)):
        try:
            d = dt.datetime.strptime(s[:n], fmt)
            return d if d <= fallback else fallback
        except ValueError:
            pass
    return fallback


def q(s):
    return "'" + s.replace('\\', '\\\\').replace("'", "\\'") + "'"


def labels_for(row):
    role = row.get('role') or ''
    out = [name for name, rx in LABEL_WORDS if re.search(rx, role, re.I)]
    return out + [row['type']]


def conf(row):
    c = (row.get('confidence') or 'low').lower()
    return CONF_ALIAS.get(c, c)


def is_context(row):
    """Rows that are not blocklist material even when listed in iocs.json."""
    t, v = row['type'], row['value']
    if row['verdict'] == 'shared-or-legit-infrastructure':
        return True
    if t in HASH_TYPES and LEGIT_ROLE.search(row.get('role') or ''):
        return True
    if t == 'url-path' and len(v) < 10:
        return True
    return False


def split_path(v):
    """Return (dir, name) for a file path, name None for a directory; None if unusable."""
    if '<' in v:
        return None
    if v.endswith('/') or v.endswith('\\'):
        return v, None
    m = re.match(r'^(.*[/\\])([^/\\]+)$', v)
    return (m.group(1).rstrip('/\\') or v[0], m.group(2)) if m else (None, v)


def stix_pattern(row):
    t, v = row['type'], row['value']
    if t == 'domain':
        return f'[domain-name:value = {q(v)}]'
    if t in ('url', 'x-post'):
        return f'[url:value = {q(v)}]'
    if t == 'ipv4':
        return f'[ipv4-addr:value = {q(v)}]'
    if t == 'endpoint':
        ip, _, port = v.rpartition(':')
        return (f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = {q(ip)}"
                f' AND network-traffic:dst_port = {int(port)}]')
    if t == 'sha256':
        return f"[file:hashes.'SHA-256' = {q(v)}]"
    if t == 'url-path':
        return f'[url:value LIKE {q("%" + v)}]'
    if t == 'mutex':
        return f'[mutex:name = {q(v)}]'
    if t == 'user-agent':
        return f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = {q(v)}]"
    if t == 'command':
        return f'[process:command_line = {q(v)}]'
    if t == 'polygon-contract':
        return f'[x-polygon-contract:address = {q(v)}]'
    if t == 'polygon-wallet':
        return f'[x-polygon-wallet:address = {q(v)}]'
    if t == 'youtube-channel':
        return f'[url:value = {q("https://www.youtube.com/channel/" + v)}]'
    if t == 'youtube-video':
        return f'[url:value = {q("https://www.youtube.com/watch?v=" + v)}]'
    if t == 'x-account':
        m = re.search(r'user id (\d+)', v)
        return f"[user-account:account_type = 'twitter' AND user-account:user_id = {q(m.group(1))}]" if m else None
    if t == 'code-signing-cert':
        subj = v.split(' (serial')[0].strip()
        m = re.search(r'serial (\d+)', v)
        p = f'x509-certificate:subject = {q(subj)}'
        return f'[{p} AND x509-certificate:serial_number = {q(m.group(1))}]' if m else f'[{p}]'
    if t == 'cert-cn':
        return f'[x509-certificate:subject = {q("CN=" + v)}]'
    if t == 'cert-serial':
        return f'[x509-certificate:serial_number = {q(v)}]'
    if t in ('filename', 'file-path', 'path'):
        sp = split_path(v)
        if not sp:
            return None
        d, n = sp
        if n is None:
            return f'[directory:path = {q(d)}]'
        if d is None:
            return f'[file:name = {q(n)}]'
        return f'[file:name = {q(n)} AND file:parent_directory_ref.path = {q(d)}]'
    return None


def malware_types(name):
    low = name.lower()
    out = []
    for kw, mt in MALWARE_TYPES:
        if re.search(r'\b' + kw + r'\b|' + kw + r'$', low) and mt not in out:
            out.append(mt)
    return out


def host_label(url):
    h = re.sub(r'^https?://', '', url).split('/')[0].lower()
    return {'bazaar.abuse.ch': 'MalwareBazaar', 'threatfox.abuse.ch': 'ThreatFox', 'www.elastic.co': 'Elastic Security Labs',
            'hybrid-analysis.com': 'Hybrid Analysis', 'gist.github.com': 'GitHub Gist',
            'youtu.be': 'YouTube', 'www.youtube.com': 'YouTube'}.get(h, h)


def case_refs(c):
    refs, seen = [], set()

    def add(src, url, desc=None):
        if url and url not in seen:
            seen.add(url)
            r = {'source_name': src, 'url': url}
            if desc:
                r['description'] = desc
            refs.append(r)
    add('YouTube', c.get('video'), 'Video write-up')
    for v in c.get('related_videos') or []:
        add('YouTube', v, 'Related video')
    add('GitHub Gist', c.get('gist'), 'Defanged IOC gist')
    for r in c.get('references') or []:
        add(r['source_name'], r['url'])
    return refs


def build_stix(slug, case, rows, known=None):
    created = to_dt(case['date'])
    ident = {'type': 'identity', 'spec_version': '2.1', 'id': 'identity--' + uid('identity', AUTHOR),
             'created': ts(created), 'modified': ts(created), 'name': AUTHOR, 'identity_class': 'individual',
             'description': 'Autonomous AI security researcher, reviewed with human oversight.',
             'external_references': [{'source_name': 'GitHub', 'url': AUTHOR_URL}]}
    common = {'spec_version': '2.1', 'created_by_ref': ident['id'], 'object_marking_refs': [TLP_CLEAR_ID],
              'created': ts(created), 'modified': ts(created)}
    objs = []
    # malware families / campaigns
    campaigns = list(case.get('campaigns') or [])
    ind_rules = case.get('indicates') or []
    fam_names = [f for f in (case.get('families') or []) if f not in campaigns]
    for r in ind_rules:
        if r['family'] not in fam_names:
            fam_names.append(r['family'])
    malware = {}
    for f in fam_names:
        m = dict(common, type='malware', id='malware--' + uid('malware', slug, f), name=f, is_family=True)
        mt = malware_types(f)
        if mt:
            m['malware_types'] = mt
        malware[f] = m
    camps = [dict(common, type='campaign', id='campaign--' + uid('campaign', slug, c), name=c) for c in campaigns]
    # indicators
    inds = {}
    for row in rows:
        if is_context(row):
            continue
        if row['verdict'] == 'compromised-or-abused-legit' and row['type'] in ('domain', 'ipv4'):
            continue
        pat = stix_pattern(row)
        if not pat:
            continue
        vf = first_seen(row, created)
        role = (row.get('role') or '').strip()
        cand = row['verdict'] == 'candidate'
        labels = labels_for(row) + (['candidate'] if cand else [])
        tv = misp_tv(row)
        kn = (known or {}).get((tv[0], tv[2]))
        if kn and kn['kind'] == 'exact':  # STIX has no to_ids flag: keep the indicator, mark it
            labels.append('known-infrastructure')
            role += f" [{WL_EXACT} ({', '.join(kn['lists'])}); block only with other evidence]"
        if pat in inds:
            inds[pat]['labels'] = sorted(set(inds[pat]['labels']) | set(labels))
            continue
        name = row['value'] if len(row['value']) <= 100 else row['value'][:97] + '...'
        d = dict(common, type='indicator', id='indicator--' + uid('indicator', slug, pat), name=name,
                 description=role + (f" [verdict: {row['verdict']}; source: {row['source']}]" if row.get('source') else ''),
                 indicator_types=['anomalous-activity' if cand else 'malicious-activity'],
                 pattern=pat, pattern_type='stix', pattern_version='2.1', valid_from=ts(vf),
                 labels=sorted(set(labels)), confidence=CONF[conf(row)])
        d['_row'] = row
        inds[pat] = d
    rels = []
    for ind in inds.values():
        row = ind.pop('_row')
        if row['verdict'] != 'malicious':
            continue
        for rule in ind_rules:
            if re.search(rule['role_match'], row.get('role') or ''):
                rels.append(dict(common, type='relationship', id='relationship--' + uid('relationship', slug, ind['id'], malware[rule['family']]['id']),
                                 relationship_type='indicates', source_ref=ind['id'], target_ref=malware[rule['family']]['id']))
                break
    refs = case_refs(case)
    seen = {r['url'] for r in refs}
    for row in rows:  # reference rows from iocs.json
        if row['type'] == 'reference' and row['value'] not in seen:
            seen.add(row['value'])
            refs.append({'source_name': host_label(row['value']), 'url': row['value'], 'description': row.get('role') or None})
    for r in refs:
        if r.get('description') is None:
            r.pop('description', None)
    members = list(inds.values()) + list(malware.values()) + camps
    report = dict(common, type='report', id='report--' + uid('report', slug), name=case['title'],
                  description=(f"IOC set for case {slug}. Values are live indicators (not defanged): do not browse or fetch them. "
                               'Rows judged shared/legitimate infrastructure are context only and are not exported as indicators. '
                               'License: CC0 1.0.'),
                  published=ts(created), report_types=['indicator'] + (['malware'] if malware else []),
                  object_refs=[o['id'] for o in members + rels])
    if refs:
        report['external_references'] = refs
    sdo = [report] + members + rels
    bundle = {'type': 'bundle', 'id': 'bundle--' + uid('bundle', slug),
              'objects': [TLP_CLEAR, ident] + sdo}
    return bundle


# ---- MISP -----------------------------------------------------------------

MISP_MAP = {  # type -> (misp type, category)
    'domain': ('domain', 'Network activity'), 'url': ('url', 'Network activity'), 'ipv4': ('ip-dst', 'Network activity'),
    'endpoint': ('ip-dst|port', 'Network activity'), 'sha256': ('sha256', 'Payload delivery'),
    'url-path': ('uri', 'Network activity'), 'mutex': ('mutex', 'Artifacts dropped'),
    'user-agent': ('user-agent', 'Network activity'), 'filename': ('filename', 'Artifacts dropped'),
    'file-path': ('filename', 'Artifacts dropped'), 'path': ('filename', 'Artifacts dropped'),
    'process': ('text', 'Artifacts dropped'), 'command': ('text', 'Payload delivery'),
    'polygon-contract': ('text', 'Network activity'), 'polygon-wallet': ('text', 'Financial fraud'), 'x-post': ('url', 'Payload delivery'),
    # MISP has no 'url' type in 'Social network' (describeTypes.json); lure posts/videos deliver the payload link
    'youtube-channel': ('url', 'Payload delivery'), 'youtube-video': ('url', 'Payload delivery'),
    'x-account': ('twitter-id', 'Social network'), 'reference': ('link', 'External analysis'),
}


def misp_tv(row):
    """MISP (type, category, value, comment prefix) of one IOC row."""
    t, v = row['type'], row['value']
    mtype, cat = MISP_MAP.get(t, ('text', 'Other'))
    comment_extra = ''
    if t == 'endpoint':
        ip, _, port = v.rpartition(':')
        v = f'{ip}|{port}'
    elif t == 'youtube-channel':
        v = 'https://www.youtube.com/channel/' + v
    elif t == 'youtube-video':
        v = 'https://www.youtube.com/watch?v=' + v
    elif t == 'x-account':
        m = re.search(r'user id (\d+)', v)
        if m:
            comment_extra = v
            v = m.group(1)
        else:
            mtype, cat = 'text', 'Social network'
    elif t == 'code-signing-cert' or t.startswith('cert-'):
        cat = 'Payload delivery'
    elif t in ('discord-server', 'dead-drop-value'):
        cat = 'Social network' if t == 'discord-server' else 'Network activity'
    return mtype, cat, v, comment_extra


def misp_attr(slug, row, created, known=None):
    t = row['type']
    mtype, cat, v, comment_extra = misp_tv(row)
    ids = (row['verdict'] == 'malicious' and conf(row) in ('high', 'medium') and t in IDS_TYPES
           and not is_context(row))
    kn = (known or {}).get((mtype, v))  # pinned 'known' warninglist match (tools/wl_known.py)
    comment = (row.get('role') or '').strip()
    if comment_extra:
        comment = f'{comment_extra}; {comment}'
    comment += f" [type: {t}; verdict: {row['verdict']}"
    if row.get('source'):
        comment += f"; source: {row['source']}"
    comment += ']'
    if kn:
        names = ', '.join(kn['lists'])
        if kn['kind'] == 'exact':
            # shared infrastructure: the IOC row stays published, only the IDS flag is withdrawn
            comment += f" [{WL_EXACT} ({names}); to_ids=false; shared by other users, block only with other evidence]"
            ids = False
        else:
            comment += f" [{WL_REVIEW} {names} (known) matches the {kn['kind']}; kept to_ids, check before blocking]"
    epoch = str(int(created.replace(tzinfo=dt.timezone.utc).timestamp()))
    a = {'uuid': uid('misp-attribute', slug, mtype, v), 'type': mtype, 'category': cat, 'value': v,
         'to_ids': ids, 'distribution': '5', 'comment': comment, 'timestamp': epoch,
         'Tag': [{'name': f'estimative-language:confidence-in-analytic-judgment="{MISP_CONF[conf(row)]}"'}]}
    fs = (row.get('first_seen') or '').strip()
    if re.fullmatch(r'\d{4}-\d\d-\d\d', fs):
        a['first_seen'] = fs + 'T00:00:00.000000+00:00'
    return a


def build_misp(slug, case, rows, known=None):
    created = to_dt(case['date'])
    epoch = str(int(created.replace(tzinfo=dt.timezone.utc).timestamp()))
    attrs, seen = [], {}
    for row in rows:
        a = misp_attr(slug, row, created, known)
        key = (a['type'], a['value'])
        if key in seen:
            if a['to_ids']:
                seen[key]['to_ids'] = True
            continue
        seen[key] = a
        attrs.append(a)
    for r in case_refs(case):
        if ('link', r['url']) in seen:
            continue
        a = {'uuid': uid('misp-attribute', slug, 'link', r['url']), 'type': 'link', 'category': 'External analysis',
             'value': r['url'], 'to_ids': False, 'distribution': '5', 'comment': r['source_name'], 'timestamp': epoch}
        seen[('link', r['url'])] = a
        attrs.append(a)
    tags = [{'name': 'tlp:clear'}] + [{'name': f'misp-galaxy:malpedia="{m}"'} for m in case.get('malpedia') or []]
    return {'Event': {
        'uuid': uid('misp-event', slug), 'info': case['title'], 'date': str(case['date']),
        'threat_level_id': '2', 'analysis': '2', 'distribution': '3', 'published': False, 'timestamp': epoch,
        'Orgc': {'uuid': uid('misp-orgc', AUTHOR), 'name': AUTHOR},
        'Tag': tags, 'Attribute': attrs}}


# ---- driver -----------------------------------------------------------------

def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + '\n'


def outputs():
    res = {}
    known = wl_known.load_known()
    for p in sorted(glob.glob(os.path.join(ROOT, 'iocs', '*', 'iocs.json'))):
        d = os.path.dirname(p)
        slug = os.path.basename(d)
        case = yaml.safe_load(open(os.path.join(d, 'case.yml'), encoding='utf-8'))
        rows = json.load(open(p, encoding='utf-8'))['iocs']
        res[os.path.join(d, 'stix2.json')] = dump(build_stix(slug, case, rows, known))
        res[os.path.join(d, 'misp_event.json')] = dump(build_misp(slug, case, rows, known))
    return res


if __name__ == '__main__':
    out = outputs()
    if '--check' in sys.argv:
        stale = [os.path.relpath(f, ROOT) for f, t in out.items()
                 if not os.path.exists(f) or open(f, encoding='utf-8').read() != t]
        if stale:
            print('stale or missing, run tools/export_iocs.py:\n  ' + '\n  '.join(stale))
            sys.exit(1)
        print(f'{len(out)} export files up to date')
    else:
        for f, t in out.items():
            open(f, 'w', encoding='utf-8').write(t)
            print('wrote', os.path.relpath(f, ROOT))
