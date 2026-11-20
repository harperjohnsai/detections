#!/usr/bin/env python3
"""MISP warninglist 'known' matches for the published IOC sets (stdlib only, offline once the lists exist).

The exporter (export_iocs.py) must not mark shared infrastructure as to_ids=true. MISP warninglists with
category "known" describe two different things, which this module keeps apart (table CLASSES below):

  (a) SHARED infrastructure: many unrelated parties use the same address or host (CDN/anycast proxy ranges,
      parking, link-in-bio, URL shorteners, dynamic DNS, public IPFS gateways, public service hostnames, sinkholes).
      Blocking on the value alone hits other users.
  (b) RENTED hosting/cloud compute ranges (AWS, GCP, Azure, Hetzner, DigitalOcean, Vultr): the list only says that
      an address belongs to a provider. An attacker simply rents a server there (MISP's own description of the
      hetzner and vultr lists says so), so a C2 on such an address is a real, alertable indicator. The address may be
      reassigned after the server is taken down: time-bound, not benign.

This module classifies every exported MISP attribute against a PINNED misp-warninglists commit and a fixed
subset of its lists, type-aware (a list is only consulted for the MISP attribute types in its
`matching_attributes`; ip-dst|port is split to its IP half; a URL is reduced to its host):

  exact      class (a): domain equals a list entry, or an IP lies inside a listed CIDR, or a path-less URL has an
             entry host -> exporter sets to_ids=false (the IOC row stays in iocs.csv/json/STIX, only the flag changes)
  subdomain  host is a subdomain of an entry (guild.<dyndns zone>)           -> to_ids kept, review note in comment
  path       URL with a path on a listed host (bit.ly/<code>)                -> to_ids kept, review note in comment
  cloud      class (b): IP inside a rented-compute range                     -> to_ids kept, "cloud-hosted" note
             An IP that is in a class (a) range as well (GitHub and Azure ranges overlap) stays 'exact'.

Output of --update is tools/warninglist_known.json, read by the exporter (no network at export time).
tests/validate_exports.py re-derives it from the pinned lists and fails if it is stale, if a to_ids=true
attribute still carries an exact (class a) match, or if a class (b) match lost its to_ids flag or its note.

usage: wl_known.py --update | --check [--lists-dir DIR]
  DIR = misp-warninglists checkout at PIN (default: shallow fetch of PIN into a temp dir; env WL_DIR also works)
"""
import bisect
import glob
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'warninglist_known.json')
REPO_URL = 'https://github.com/MISP/misp-warninglists.git'
PIN = '40e2b570fda2e5443a2d6fa1d1db16c37ab0a956'
# Subset: lists of category "known". The full repo also carries datacenter-ipv4, vpn-ipv4, tor-exit-nodes, ...
# which would cover most hosting space and are deliberately not used.
#
# CLASSES: decided per list from its MISP name/description at PIN. 'shared' = class (a), 'cloud' = class (b).
CLASSES = {
    # (a) shared: many unrelated users behind one address or host
    'akamai': 'shared',               # CDN edge ranges (BGP search): proxy in front of many customers
    'check-host-net': 'shared',       # check-host.net probe nodes: a public measurement service
    'cloudflare': 'shared',           # anycast CDN/proxy ranges: thousands of sites per address
    'dynamic-dns': 'shared',          # dynamic DNS zones, anyone can register a subdomain
    'fastly': 'shared',               # CDN edge ranges
    'github': 'shared',               # api.github.com/meta ranges: Pages/raw/web front ends shared by all users
    'link-in-bio': 'shared',          # link-in-bio hostnames (shared landing-page services)
    'ovh-cluster': 'shared',          # OVH web-hosting clusters and SHARED hosting IPs (docs: "clusters and shared
                                      # hosting IP"): many customers' sites on one address. Not OVH VPS/dedicated.
    'parking-domain': 'shared',       # parking-domain addresses, shared by every parked domain
    'public-ipfs-gateways': 'shared', # public IPFS gateways, content of any user behind one hostname
    'sinkholes': 'shared',            # sinkhole addresses: victims' traffic, not an operator server
    'telegram-ips': 'shared',         # Telegram service ranges, shared by all clients
    'url-shortener': 'shared',        # shortener hostnames, one host for any destination
    # (b) rented hosting/cloud compute: provider ranges, an attacker can rent an address like any customer
    'amazon-aws': 'cloud',            # AWS ip-ranges.json (EC2 etc.; includes some CDN/S3 service prefixes, which
                                      # the list cannot separate: review such a hit by hand)
    'digitalocean': 'cloud',          # DigitalOcean droplet ranges (RFC 8805 geofeed)
    'google-gcp': 'cloud',            # GCP cloud.json: Compute Engine and other customer-rented ranges
    'hetzner': 'cloud',               # MISP: "general-purpose rented compute ... an attacker can simply rent one"
    'microsoft-azure': 'cloud',       # Azure datacenter ranges
    'vultr': 'cloud',                 # MISP: "general-purpose rented compute ... an attacker can simply rent one"
}
LISTS = sorted(CLASSES)
IP_TYPES = {'ip-dst': 0, 'ip-src': 0, 'ip-dst|port': 0, 'ip-src|port': 0}
HOST_TYPES = {'domain', 'hostname', 'url'}
NOTE_EXACT = 'warninglist known infrastructure'
NOTE_REVIEW = 'review: warninglist'
NOTE_CLOUD = 'cloud-hosted'
RANK = {'exact': 0, 'cloud': 1, 'subdomain': 2, 'path': 3}


def cloud_note(lists):
    return (f"[{NOTE_CLOUD} ({', '.join(lists)}): attacker-rented server; IP may be reassigned after takedown, "
            "treat as time-bound]")


def ensure_lists(path=None):
    """Return a directory holding lists/<name>/list.json at PIN (verified)."""
    path = path or os.environ.get('WL_DIR')
    if not path:
        path = tempfile.mkdtemp(prefix='misp-warninglists-')
        run = lambda *a: subprocess.run(['git', '-C', path] + list(a), check=True, capture_output=True, text=True)
        run('init', '-q')
        run('remote', 'add', 'origin', REPO_URL)
        run('fetch', '-q', '--depth', '1', 'origin', PIN)
        run('checkout', '-q', 'FETCH_HEAD')
    try:
        head = subprocess.run(['git', '-C', path, 'rev-parse', 'HEAD'], check=True, capture_output=True,
                              text=True).stdout.strip()
    except Exception:
        head = open(os.path.join(path, 'COMMIT')).read().strip()
    if head != PIN:
        raise SystemExit(f'misp-warninglists at {head}, expected pinned {PIN}')
    return path


class Lists:
    def __init__(self, path):
        self.host, self.ip = [], []   # host: (name, types, set(entries), category, version); ip: (name, types, starts, ends, ...)
        for name in LISTS:
            d = json.load(open(os.path.join(path, 'lists', name, 'list.json'), encoding='utf-8'))
            assert d.get('category') == 'known', f'{name}: category {d.get("category")!r}, expected known'
            meta = (name, set(d['matching_attributes']), d['version'])
            if d['type'] == 'hostname':
                zones = {e.lower().strip('.') for e in d['list']}  # '.zone' entries cover the zone and its subdomains
                self.host.append(meta + (zones,))
            elif d['type'] == 'cidr':
                nets = []
                for e in d['list']:
                    n = ipaddress.ip_network(e, strict=False)
                    if n.version == 4:
                        nets.append((int(n.network_address), int(n.broadcast_address)))
                nets.sort()
                merged = []
                for s, e in nets:   # merge so one bisect per list answers containment
                    if merged and s <= merged[-1][1] + 1:
                        merged[-1][1] = max(merged[-1][1], e)
                    else:
                        merged.append([s, e])
                self.ip.append(meta + ([m[0] for m in merged], [m[1] for m in merged]))
            else:
                raise SystemExit(f'{name}: unsupported list type {d["type"]}')

    def classify(self, mtype, value):
        """Return [(list, kind, version)] with kind exact|cloud|subdomain|path for one MISP attribute."""
        hits = []
        if mtype in IP_TYPES:
            try:
                ip = ipaddress.ip_address(value.split('|')[IP_TYPES[mtype]])
            except ValueError:
                return hits
            if ip.version != 4:
                return hits
            n = int(ip)
            for name, types, ver, starts, ends in self.ip:
                if mtype in types:
                    i = bisect.bisect_right(starts, n) - 1
                    if i >= 0 and n <= ends[i]:
                        hits.append((name, 'cloud' if CLASSES[name] == 'cloud' else 'exact', ver))
        elif mtype in HOST_TYPES:
            pathful = False
            if mtype == 'url':
                u = urlsplit(value if '//' in value else '//' + value)
                host, pathful = (u.hostname or '').lower(), (u.path not in ('', '/') or bool(u.query))
            else:
                host = value.lower().rstrip('.')
            labels = host.split('.')
            for name, types, ver, entries in self.host:
                if mtype not in types:
                    continue
                for i in range(len(labels) - 1):   # never a bare TLD
                    if '.'.join(labels[i:]) in entries:
                        kind = 'path' if pathful else ('exact' if i == 0 else 'subdomain')
                        hits.append((name, kind, ver))
                        break
        return sorted(set(hits))


def case_attrs():
    """(slug, misp type, value) for every IOC row of every case, via the exporter's own mapping."""
    sys.path.insert(0, HERE)
    import export_iocs as ex
    out = []
    for p in sorted(glob.glob(os.path.join(ex.ROOT, 'iocs', '*', 'iocs.json'))):
        slug = os.path.basename(os.path.dirname(p))
        for row in json.load(open(p, encoding='utf-8'))['iocs']:
            mtype, _cat, value, _extra = ex.misp_tv(row)
            out.append((slug, mtype, value))
    return out


def derive(lists):
    ent = {}
    for _slug, mtype, value in case_attrs():
        hits = lists.classify(mtype, value)
        if not hits:
            continue
        kind = min((h[1] for h in hits), key=RANK.get)
        ent[(mtype, value)] = {'type': mtype, 'value': value, 'kind': kind,
                               'lists': sorted(h[0] for h in hits if h[1] == kind)}
    return {'misp_warninglists_commit': PIN, 'lists': LISTS, 'classes': CLASSES,
            'entries': sorted(ent.values(), key=lambda e: (e['type'], e['value']))}


def load_known():
    """Lookup used by the exporter: (misp type, value) -> entry; empty if the file is absent."""
    if not os.path.exists(DATA):
        return {}
    d = json.load(open(DATA, encoding='utf-8'))
    return {(e['type'], e['value']): e for e in d['entries']}


def dumps(d):
    return json.dumps(d, indent=1, ensure_ascii=False) + '\n'


if __name__ == '__main__':
    args = sys.argv[1:]
    ld = args[args.index('--lists-dir') + 1] if '--lists-dir' in args else None
    lists = Lists(ensure_lists(ld))
    new = dumps(derive(lists))
    if '--check' in args:
        cur = open(DATA, encoding='utf-8').read() if os.path.exists(DATA) else ''
        if cur != new:
            print('tools/warninglist_known.json is stale, run tools/wl_known.py --update')
            sys.exit(1)
        print('warninglist_known.json up to date')
    elif '--update' in args:
        open(DATA, 'w', encoding='utf-8').write(new)
        d = json.loads(new)
        kinds = {}
        for e in d['entries']:
            kinds[e['kind']] = kinds.get(e['kind'], 0) + 1
        print('wrote', DATA, kinds)
    else:
        sys.exit(__doc__)
