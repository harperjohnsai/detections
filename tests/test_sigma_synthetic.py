#!/usr/bin/env python3
"""Logic test for the Sigma rules in ../sigma on hand-made events (no real logs, no regression EVTX).
A tiny evaluator supports exactly the modifiers/conditions these rules use: exact, startswith, endswith,
contains, 'sel', 'not', 'and', 'or', '1 of sel_*'. Needs PyYAML."""
import glob, os, re, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ok = True


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


FN = {'': lambda a, b: a == b, 'startswith': str.startswith, 'endswith': str.endswith, 'contains': lambda a, b: b in a}


def sel(s, ev):
    for k, v in s.items():
        f, _, mod = k.partition('|')
        val = str(ev.get(f, '')).lower()
        if not any(FN[mod](val, str(x).lower()) for x in (v if isinstance(v, list) else [v])):
            return False
    return True


def fires(rule, ev):
    d = rule['detection']; cond = d['condition']
    names = [k for k in d if k != 'condition']
    def of(m):
        pat = m.group(2).replace('*', '.*')
        vals = [str(sel(d[k], ev)) for k in names if re.fullmatch(pat, k)]
        return '(' + (' or ' if m.group(1) == '1' else ' and ').join(vals or ['False']) + ')'
    expr = re.sub(r'(1|all) of (\w+\*)', of, cond)
    expr = re.sub(r'\b(?!and\b|or\b|not\b|True\b|False\b)(\w+)\b', lambda m: str(sel(d[m.group(1)], ev)) if m.group(1) in d else m.group(1), expr)
    return eval(expr)


def load(name):
    return yaml.safe_load(open(glob.glob(os.path.join(HERE, '..', 'sigma', '*', name))[0]))


# (rule file, event, expected, label)
T = [
    ('dns_query_win_malware_revstealer_c2_domain.yml', dict(QueryName='queue.prooutlet58.website'), True, 'C2 subdomain'),
    ('dns_query_win_malware_revstealer_c2_domain.yml', dict(QueryName='prooutlet58.website'), True, 'C2 apex'),
    ('dns_query_win_malware_revstealer_c2_domain.yml', dict(QueryName='example.com'), False, 'unrelated domain'),
    ('proxy_malware_revstealer_c2_gate_uri.yml', dict(**{'c-uri': '/finsii/fahuy/buqpl.ajug'}), True, 'gate path 1'),
    ('proxy_malware_revstealer_c2_gate_uri.yml', dict(**{'c-uri': '/ojb/buqpl.ajug'}), True, 'gate path 3'),
    ('proxy_malware_revstealer_c2_gate_uri.yml', dict(**{'c-uri': '/api/health'}), False, 'unrelated path'),
    ('proxy_malware_revstealer_telegraph_dead_drop.yml', {'cs-host': 'api.telegra.ph', 'c-uri': '/getPage/Field-study-willow-atlas-11-05?return_content=false'}, True, 'metadata-only getPage'),
    ('proxy_malware_revstealer_telegraph_dead_drop.yml', {'cs-host': 'api.telegra.ph', 'c-uri': '/getPage/Some-Page-01-01?return_content=true'}, False, 'getPage with content'),
    ('proxy_malware_revstealer_telegraph_dead_drop.yml', {'cs-host': 'telegra.ph', 'c-uri': '/Some-Page-01-01'}, False, 'normal page view'),
    ('dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml', dict(QueryName='polygon-bor-rpc.publicnode.com', Image='C:\\Users\\a\\AppData\\Local\\Temp\\x.exe'), True, 'non-browser process'),
    ('dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml', dict(QueryName='polygon-bor-rpc.publicnode.com', Image='C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'), False, 'browser (filtered)'),
    ('dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml', dict(QueryName='example.com', Image='C:\\x.exe'), False, 'other domain'),
    ('proc_creation_win_renamed_onedrive.yml', dict(OriginalFileName='OneDrive.exe', Image='C:\\Users\\a\\Downloads\\Installer\\Installer.exe'), True, 'OneDrive renamed Installer.exe'),
    ('proc_creation_win_renamed_onedrive.yml', dict(OriginalFileName='OneDrive.exe', Image='C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe'), False, 'genuine OneDrive.exe'),
    ('proc_creation_win_renamed_onedrive.yml', dict(OriginalFileName='cmd.exe', Image='C:\\Windows\\System32\\cmd.exe'), False, 'other binary'),
    ('image_load_win_susp_unsigned_version_dll_user_path.yml', dict(ImageLoaded='C:\\Users\\a\\Downloads\\Installer\\version.dll', Signed='false'), True, 'unsigned version.dll in Downloads'),
    ('image_load_win_susp_unsigned_version_dll_user_path.yml', dict(ImageLoaded='C:\\Windows\\System32\\version.dll', Signed='true'), False, 'System32 copy'),
    ('image_load_win_susp_unsigned_version_dll_user_path.yml', dict(ImageLoaded='C:\\Users\\a\\Downloads\\x\\version.dll', Signed='true'), False, 'signed vendor copy'),
    ('image_load_win_susp_unsigned_version_dll_user_path.yml', dict(ImageLoaded='C:\\Program Files\\Game\\version.dll', Signed='false'), False, 'documented miss: unsigned proxy in Program Files'),
]
for f, ev, exp, label in T:
    check(fires(load(f), ev) == exp, f'{f.split("_malware_")[-1] if "_malware_" in f else f}: {label} -> {"fire" if exp else "silent"}')
files = {os.path.basename(p) for p in glob.glob(os.path.join(HERE, '..', 'sigma', '*', '*.yml'))}
check(files == {t[0] for t in T}, 'every rule file has at least one test event')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
