#!/usr/bin/env python3
"""Tests for tools/legionloader-config (static).

1. RC4 against the RFC 6229 test vector.
2. Synthetic .data image: a planted string table + key at shifted offsets must be decrypted without any offset
   being passed in (guards against a regression to hard-coded offsets), random bytes must yield nothing.
3. Real samples (found by SHA-256 in the directory given as argv[1]; skipped when absent):
   2e3d378d... -> smashshape.com, 00ef251f... -> redjaxfire.com, both with /nfront.php and /nback.php.
usage: test_legionloader_config.py [<dir-with-samples>]
"""
import hashlib, json, os, random, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, '..', 'tools', 'legionloader-config')
sys.path.insert(0, TOOL)
import legionloader_config as L                       # noqa: E402

ok = True


def check(c, m):
    global ok
    print(('PASS ' if c else 'FAIL ') + m)
    ok &= bool(c)


# 1. RFC 6229, key 0102030405, first 16 keystream bytes
ks = L.rc4(bytes([1, 2, 3, 4, 5]), bytes(16))
check(ks.hex() == 'b2396305f03dc027ccc3524a0a1118a8', 'RC4 RFC 6229 vector')

# 2. synthetic image
rnd = random.Random(7)
for shift in (0, 0x24, 0x1F0):
    img = bytearray(rnd.getrandbits(8) for _ in range(0x3000))
    key = bytes(rnd.getrandbits(8) for _ in range(16))
    key_at = 0x200 + shift
    img[key_at:key_at + 16] = key
    strings = [b'c2-example.invalid\x00', b'nfront.php\x00', b'https://%s/%s?a=%s\x00']
    table = struct.pack('<I', len(strings)) + b''.join(struct.pack('<II', 4, len(x)) for x in strings) + b''.join(L.rc4(key, x) for x in strings)
    at = 0x800 + shift
    img[at:at + len(table)] = table
    got = {s['text'] for s in L.scan_data(bytes(img), 0, len(img))}
    check({'c2-example.invalid', 'nfront.php', 'https://%s/%s?a=%s'} <= got, f'synthetic table decrypted (shift {shift:#x})')
noise = bytes(random.Random(1).getrandbits(8) for _ in range(0x4000))
check(L.scan_data(noise, 0, len(noise)) == [], 'random .data -> no strings')

# 3. real samples
EXP = {
    '2e3d378d6a842af2404dfcd1dcbfc0df84b01b799b2c8270ddbfe5eb18837762': 'smashshape.com',
    '00ef251f6f49eb50f3300585c814910318e7f09864ed373ec4f078d2c1471d0e': 'redjaxfire.com',
}
ran = 0
if len(sys.argv) > 1:
    files = {}
    for r, _, fs in os.walk(sys.argv[1]):
        for f in fs:
            p = os.path.join(r, f)
            if 300_000 < os.path.getsize(p) < 600_000:
                files[hashlib.sha256(open(p, 'rb').read()).hexdigest()] = p
    for sha, host in EXP.items():
        if sha not in files:
            print(f'SKIP {sha[:12]} not provided')
            continue
        ran += 1
        r = subprocess.run([sys.executable, os.path.join(TOOL, 'legionloader_config.py'), files[sha]], capture_output=True, text=True)
        j = json.loads(r.stdout)
        check(j['c2_hosts'] == [host] and sorted(j['gate_paths']) == ['nback.php', 'nfront.php'], f'{sha[:12]} -> {host}')
else:
    print('SKIP real-sample regression (no sample directory given)')
print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED', f'(real samples tested: {ran})')
sys.exit(0 if ok else 1)
