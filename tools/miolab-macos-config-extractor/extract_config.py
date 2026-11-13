#!/usr/bin/env python3
"""Config extractor for the C1 'Setup Center' macOS stealer (C++ build, xorstr strings, rotating-XOR
config blob in __DATA,__data). Pure static: parses the Mach-O, decrypts the blob, parses fields.
Usage: extract_config.py <universal-or-thin-macho> [out.json]
Blob layout (arm64 + x86_64 __data start): u64 key | u32 size | u32 cursor | size bytes ciphertext.
Decrypt: for i: pt[i] = ct[i] ^ byte(i & 7) of key; key = ror64(key, 1) after every byte.
Plaintext: u32 user_id | u32 grab_mb | str build_tag | list hosts | list exts | list ? | 6 dialog strings | flags.
str = u16 len + bytes; list = u16 count + strs.
"""
import sys, json, struct, hashlib

def slices(data):
    magic = struct.unpack('>I', data[:4])[0]
    if magic == 0xcafebabe:
        n = struct.unpack('>I', data[4:8])[0]
        for i in range(n):
            ct, cs, off, sz, al = struct.unpack('>5I', data[8 + 20 * i: 28 + 20 * i])
            yield {0x1000007: 'x86_64', 0x100000c: 'arm64'}.get(ct, hex(ct)), data[off:off + sz]
    else:
        ct = struct.unpack('<I', data[4:8])[0]
        yield {0x1000007: 'x86_64', 0x100000c: 'arm64'}.get(ct, hex(ct)), data

def find_section(m, segname, sectname):
    ncmds = struct.unpack('<I', m[16:20])[0]
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack('<II', m[off:off + 8])
        if cmd == 0x19:  # LC_SEGMENT_64
            seg = m[off + 8:off + 24].rstrip(b'\0').decode()
            nsects = struct.unpack('<I', m[off + 64:off + 68])[0]
            for j in range(nsects):
                s = off + 72 + 80 * j
                sn = m[s:s + 16].rstrip(b'\0').decode(); sg = m[s + 16:s + 32].rstrip(b'\0').decode()
                addr, sz, foff = struct.unpack('<QQI', m[s + 32:s + 52])
                if sg == segname and sn == sectname:
                    return addr, foff, sz
        off += size
    return None

def ror64(x, n): return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def decrypt(blob):
    key = struct.unpack('<Q', blob[:8])[0]
    size = struct.unpack('<I', blob[8:12])[0]
    ct = blob[16:16 + size]
    out = bytearray()
    for i, c in enumerate(ct):
        out.append(c ^ ((key >> (8 * (i & 7))) & 0xff))
        key = ror64(key, 1)
    return blob[:8].hex(), size, bytes(out)

def parse(pt):
    o = 0
    def u16():
        nonlocal o; v = struct.unpack('<H', pt[o:o + 2])[0]; o += 2; return v
    def u32():
        nonlocal o; v = struct.unpack('<I', pt[o:o + 4])[0]; o += 4; return v
    def s():
        n = u16(); nonlocal o; v = pt[o:o + n]; o += n; return v.decode('utf-8', 'replace')
    def lst():
        return [s() for _ in range(u16())]
    cfg = {}
    cfg['user_id'] = u32()                 # sent as user_id=, written to ~/.hlpr/.ownrid
    cfg['filegrabber_max_mb'] = u32()      # '5 * 1024 * 1024' in the AppleScript filegrabber
    cfg['build_tag'] = s()                 # sent as build_tag=; also the ad-hoc signing identifier
    cfg['c2_hosts'] = lst()                # tried in order for upload, app-bundle and agent download
    cfg['filegrabber_extensions'] = lst()
    cfg['list3_unknown'] = lst()           # empty in this build (role not resolved)
    for k in ('fda_dialog_title', 'fda_dialog_text', 'password_dialog_title', 'password_dialog_text',
              'error_dialog_title', 'error_dialog_text'):
        cfg[k] = s()
    rest = pt[o:]
    cfg['flags_raw_hex'] = rest.hex()      # 6 x u8 toggles (all 1) + u16 (2 = password-dialog icon, inferred)
    return cfg

def extract(path):
    data = open(path, 'rb').read()
    res = {'file': path, 'sha256': hashlib.sha256(data).hexdigest(), 'slices': {}}
    for arch, m in slices(data):
        sec = find_section(m, '__DATA', '__data')
        if not sec:
            res['slices'][arch] = {'error': 'no __data'}; continue
        addr, foff, sz = sec
        blob = m[foff:foff + sz]
        key, size, pt = decrypt(blob)
        r = {'slice_sha256': hashlib.sha256(m).hexdigest(), 'data_va': hex(addr), 'key': key, 'size': size,
             'plaintext_hex': pt.hex()}
        try: r['config'] = parse(pt)
        except Exception as e: r['parse_error'] = repr(e)
        res['slices'][arch] = r
    return res

if __name__ == '__main__':
    r = extract(sys.argv[1])
    js = json.dumps(r, indent=1, ensure_ascii=False)
    if len(sys.argv) > 2: open(sys.argv[2], 'w').write(js)
    for arch, v in r['slices'].items():
        print(arch, json.dumps(v.get('config', v), ensure_ascii=False))
