#!/usr/bin/env python3
"""Check tools/setup-center-extractor against the three known builds (static; nothing is executed).

usage: test_setup_center_extractor.py <dir-with-samples>
The directory must hold the proxy version.dll and the payload container of the builds you have
(found by SHA-256, not by name). Builds that are not present are skipped. Needs: pefile, capstone.
"""
import hashlib, json, os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACTOR = os.path.join(HERE, '..', 'tools', 'setup-center-extractor', 'sideload_extract.py')
# version.dll sha256 -> (container sha256, expected config)
BUILDS = {
    '973ad2986d6eda8a8936342ba64fda6e2909cc8527a83bb2f474c13d76c0b6e7': ('b484561cc81da34990824452d4ce4002d0520c71c71e3eeb2f248e57e1f5bc3f',
        dict(payload_name='config.dat', payload_offset=0xdc, payload_size=0x6b610, payload_sha256='e472b895f15e4e17d3d35102ac6bc3eba9f707cb1da95df3ac2e7e9113825e81')),
    '2903e5e3363c1c15725a5343d31429490ce662cdc3df3c1f0dbf8ba7863aa4c3': ('ca82cb69da221788258d659b0eb8c84b7cfe0a99710037d40edd73e8ed330827',
        dict(payload_name='sync.dat', payload_offset=0xcf, payload_size=0x69810, payload_sha256='673feccbcec6008354e4b3b7711de22953445d5314721097b041eb020e6cd231')),
    'b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960': ('193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62',
        dict(payload_name='localdata.db', payload_offset=0x9b, payload_size=0x69c10, payload_sha256='c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad')),
}
HOLLOWING = {'kernel32!CreateProcessW', 'ntdll!NtSetContextThread', 'ntdll!NtResumeThread', 'ntdll!NtWriteVirtualMemory'}


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def main():
    files = {sha(os.path.join(r, f)): os.path.join(r, f) for r, _, fs in os.walk(sys.argv[1]) for f in fs}
    ok, ran = True, 0
    for dll, (cont, exp) in BUILDS.items():
        if dll not in files or cont not in files:
            print(f'SKIP build {dll[:12]} (version.dll or container not provided)')
            continue
        ran += 1
        r = subprocess.run([sys.executable, EXTRACTOR, files[dll], files[cont]], capture_output=True, text=True)
        try:
            cfg = json.loads(r.stdout)
        except ValueError:
            print(f'FAIL {dll[:12]} extractor output unreadable: {r.stderr[-200:]}'); ok = False; continue
        good = r.returncode == 0 and cfg.get('payload_is_pe') and all(cfg.get(k) == v for k, v in exp.items()) \
            and HOLLOWING <= set(cfg.get('api_table', [])) and len(cfg.get('rc4_key', '')) == 64 \
            and cfg.get('create_flags', '').startswith('CREATE_SUSPENDED')
        print(('PASS ' if good else 'FAIL ') + f'{dll[:12]} -> {cfg.get("payload_name")} off={hex(cfg.get("payload_offset", 0))} '
              f'size={hex(cfg.get("payload_size", 0))} payload={cfg.get("payload_sha256", "")[:12]} apis={len(cfg.get("api_table", []))}')
        ok &= bool(good)
    print('ALL CHECKS PASS' if ok and ran else 'NO BUILD TESTED' if not ran else 'SOME CHECKS FAILED')
    return 0 if ok and ran else 1


sys.exit(main())
