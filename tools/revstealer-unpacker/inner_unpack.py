#!/usr/bin/env python3
"""REVSTEALER (Setup Center inner payload) static unpacker + config extractor.

Input : the inner x64 PE produced by sideload_extract.py (RC4-decrypted localdata.db),
        e.g. payload_decrypted.bin sha256 c6859833...
Output: <outdir>/config.json            C2 config + all decrypted strings
        <outdir>/inner_strings_decrypted.bin   same PE with every encrypted string patched to cleartext
        <outdir>/abe_helper.dll         embedded ChaCha20-encrypted App-Bound-Encryption helper DLL

Nothing is executed natively. String decryption runs the sample's own leaf decrypt routines
inside unicorn (pure CPU emulation: no OS layer, no API stubs, no network). Everything else
(ChaCha20, AES-256-CBC, watermark) is reimplemented in Python. Offsets are found by byte
signatures, so rebuilt variants with shifted addresses should still work.

usage: inner_unpack.py <inner_pe> <outdir>
deps : pefile capstone unicorn cryptography   (uv pip install --python .venv/bin/python ...)
"""
import sys, os, re, json, struct, hashlib, collections
import pefile, capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RAX
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sha = lambda b: hashlib.sha256(b).hexdigest()

# ---- signatures (REVSTEALER x64 build seen 2026-11, c6859833) ----
# string-descriptor dispatcher: mov rdi,[rcx]; lea rbx,[rcx+0xc]; mov eax,[rbx]; mov esi,2
SIG_STRDISP = re.compile(rb'\x48\x8b\x39\x48\x8d\x59\x0c\x8b\x03\xbe\x02\x00\x00\x00', re.S)
# ChaCha key/nonce setup: lea rcx,[rip+key]; mov r9d,0x20 ... lea r10,[rip+nonce] ... cmp rdx,0xc
SIG_CHACHA_KN = re.compile(rb'\x48\x8d\x0d(....)\x41\xb9\x20\x00\x00\x00.{12,24}?\x4c\x8d\x15(....)', re.S)
# chunk table: mov edx,total; mov rcx,rdi; call; mov rdx,[rdi]; lea r8,[rip+sizes]; lea r9,[rip+ptrs]; xor ebx,ebx; mov esi,count
SIG_CHUNKS = re.compile(rb'\xba(....)\x48\x8b\xcf\xe8....\x48\x8b\x17\x4c\x8d\x05(....)\x4c\x8d\x0d(....)\x33\xdb\xbe(....)', re.S)
# watermark check: mov al,[rcx+r15+K]; xor al,[rsp+rcx+0x40]; cmp al,[rcx+r15+V]
SIG_WMARK = re.compile(rb'\x42\x8a\x84\x39(....)\x32\x44\x0c\x40\x42\x3a\x84\x39(....)', re.S)
# chacha constant masking: mov dword [rsp+8], 0xa572f4db  (xor'd with 0xc4028cbe -> 'expa')
SIG_CHACHA_CONST = b'\xc7\x44\x24\x08\xdb\xf4\x72\xa5'


class Img:
    def __init__(self, path):
        self.raw = open(path, 'rb').read()
        self.pe = pefile.PE(data=self.raw)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img = bytearray(self.pe.get_memory_mapped_image())
        t = self.pe.sections[0]
        self.text = (t.VirtualAddress, t.VirtualAddress + t.Misc_VirtualSize)
        self.funcs = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                            for e in getattr(self.pe, 'DIRECTORY_ENTRY_EXCEPTION', []))

    def rip(self, m, grp):
        """RVA of a rip-relative disp32 captured in regex group grp (instruction ends 4 bytes after disp
        unless followed by an immediate; callers pass the right end via m.end(grp)+extra)."""
        disp = struct.unpack('<i', m.group(grp))[0]
        return m.end(grp) + disp

    def func_of(self, rva):
        for b, e in self.funcs:
            if b <= rva < e:
                return b
        return None


def find_decryptors(I):
    return sorted({I.base + I.func_of(m.start()) for m in SIG_STRDISP.finditer(I.img) if I.func_of(m.start()) is not None})


def find_sites(I, fns):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.skipdata = True
    last = None
    sites = collections.OrderedDict()
    lo, hi = I.text
    for ins in md.disasm(bytes(I.img[lo:hi]), I.base + lo):
        if ins.mnemonic == 'lea' and ins.op_str.startswith('rcx, [rip'):
            m = re.search(r'rip ([+-]) (0x[0-9a-f]+)', ins.op_str)
            off = int(m.group(2), 16) * (1 if m.group(1) == '+' else -1)
            last = (ins.address, ins.address + ins.size + off)
        elif ins.mnemonic in ('call', 'jmp') and ins.op_str.startswith('0x'):
            tgt = int(ins.op_str, 16)
            if tgt in fns and last and ins.address - last[0] < 0x20:
                sites.setdefault(last[1], {'fn': tgt, 'refs': []})['refs'].append(last[0])
    return sites


class Emu:
    STK, SENT = 0x7ff000000000, 0x7ff100000000

    def __init__(self, I):
        self.I = I
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        size = (len(I.img) + 0xfff) & ~0xfff
        self.mu.mem_map(I.base, size)
        self.mu.mem_write(I.base, bytes(I.img))
        self.mu.mem_map(self.STK, 0x100000)
        self.mu.mem_map(self.SENT, 0x1000)
        self.mu.mem_write(self.SENT, b'\xc3')

    def call(self, fn, rcx):
        rsp = self.STK + 0x80000
        self.mu.mem_write(rsp, struct.pack('<Q', self.SENT))
        self.mu.reg_write(UC_X86_REG_RSP, rsp)
        self.mu.reg_write(UC_X86_REG_RCX, rcx)
        self.mu.emu_start(fn, self.SENT, count=5_000_000)
        return self.mu.reg_read(UC_X86_REG_RAX)


def decrypt_strings(I):
    fns = find_decryptors(I)
    sites = find_sites(I, set(fns))
    emu = Emu(I)
    out = []
    votes = collections.defaultdict(lambda: [0, 0])
    for desc, info in sites.items():
        d = desc - I.base
        ptr, ln, tag = struct.unpack('<QHH', bytes(I.img[d:d + 12]))
        try:
            emu.call(info['fn'], desc)
        except UcError as e:
            out.append({'desc': hex(desc), 'error': str(e)})
            continue
        after = bytes(emu.mu.mem_read(ptr, ln * 2))
        votes[info['fn']][ln > 1 and after[1:ln * 2:2].count(0) == ln] += 1
        out.append({'desc': hex(desc), 'data': hex(ptr), 'len': ln, 'tag': tag, 'fn': hex(info['fn']),
                    'refs': [hex(r) for r in info['refs']], 'func': hex(I.base + (I.func_of(info['refs'][0] - I.base) or 0)),
                    '_after': after})
    wide_fns = {hex(f) for f, (n, w) in votes.items() if w > n}
    for s in out:
        if 'error' in s:
            continue
        s['wide'] = s['fn'] in wide_fns
        clear = s.pop('_after')[:s['len'] * (2 if s['wide'] else 1)]
        s['str'] = (clear.decode('utf-16le', 'replace') if s['wide'] else clear.decode('latin-1')).rstrip('\0')
        s['_bytes'] = clear
    return fns, out


def patch_pe(I, strings, path):
    raw = bytearray(I.raw)
    n = 0
    for s in strings:
        if 'error' in s:
            continue
        off = I.pe.get_offset_from_rva(int(s['data'], 16) - I.base)
        raw[off:off + len(s['_bytes'])] = s['_bytes']
        doff = I.pe.get_offset_from_rva(int(s['desc'], 16) - I.base)
        raw[doff + 12:doff + 16] = struct.pack('<I', 2)  # mark "already decrypted" so code keeps cleartext
        n += 1
    open(path, 'wb').write(raw)
    return n


def chacha20(key, nonce, data, ctr=0):
    def rotl(v, c): return ((v << c) | (v >> (32 - c))) & 0xffffffff

    def qr(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)
    out = bytearray()
    for bi in range(0, len(data), 64):
        st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack('<8I', key)) + \
             [(ctr + bi // 64) & 0xffffffff] + list(struct.unpack('<3I', nonce))
        w = st[:]
        for _ in range(10):
            qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
            qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
        ks = struct.pack('<16I', *[(w[j] + st[j]) & 0xffffffff for j in range(16)])
        out += bytes(x ^ y for x, y in zip(data[bi:bi + 64], ks))
    return bytes(out)


def extract_embedded_pe(I):
    m = SIG_CHACHA_KN.search(I.img, *I.text)
    c = SIG_CHUNKS.search(I.img, *I.text)
    if not m or not c:
        return None, {'error': 'chacha/chunk signature not found'}
    key_rva = I.rip(m, 1)
    nonce_rva = I.rip(m, 2)
    key, nonce = bytes(I.img[key_rva:key_rva + 32]), bytes(I.img[nonce_rva:nonce_rva + 12])
    total = struct.unpack('<I', c.group(1))[0]
    sizes_rva, ptrs_rva = I.rip(c, 2), I.rip(c, 3)
    count = struct.unpack('<I', c.group(4))[0]
    sizes = struct.unpack('<%dI' % count, bytes(I.img[sizes_rva:sizes_rva + 4 * count]))
    ptrs = struct.unpack('<%dQ' % count, bytes(I.img[ptrs_rva:ptrs_rva + 8 * count]))
    ct = b''.join(bytes(I.img[p - I.base:p - I.base + s]) for p, s in zip(ptrs, sizes))
    pt = chacha20(key, nonce, ct)
    meta = {'cipher': 'ChaCha20 (RFC 8439, counter 0; constants masked with 0xa572f4db in code)',
            'key': key.hex(), 'nonce': nonce.hex(), 'total': total, 'chunks': [[hex(p), s] for p, s in zip(ptrs, sizes)],
            'chacha_const_mask_present': SIG_CHACHA_CONST in I.img, 'mz': pt[:2] == b'MZ'}
    return pt, meta


def watermark(I):
    m = SIG_WMARK.search(I.img, *I.text)
    if not m:
        return {'found': False}
    k_rva, v_rva = struct.unpack('<i', m.group(1))[0], struct.unpack('<i', m.group(2))[0]
    k, v = bytes(I.img[k_rva:k_rva + 16]), bytes(I.img[v_rva:v_rva + 16])
    tail = I.raw[-16:]
    return {'found': True, 'xor_key': k.hex(), 'expected': v.hex(), 'file_tail16': tail.hex(),
            'raw_build_watermarked': bytes(a ^ b for a, b in zip(tail, k)) == v,
            'note': 'if the 16-byte EOF watermark is present the stealer shows a 6-char token prompt '
                    '(anti-sandbox / anti-leak); when hollowed into Installer.exe the check reads the host file and passes silently'}


def aes_cbc_dec(key, blob):
    d = Cipher(algorithms.AES(key), modes.CBC(blob[:16])).decryptor()
    p = d.update(blob[16:]) + d.finalize()
    pad = p[-1]
    if 1 <= pad <= 16 and p.endswith(bytes([pad]) * pad):
        p = p[:-pad]
    return p


def build_config(strings):
    S = [s for s in strings if 'error' not in s]
    txt = [s['str'] for s in S]
    hexes = [t for t in txt if re.fullmatch(r'[0-9a-fA-F]{64,}', t) and len(t) % 32 == 0]
    keys = collections.Counter(t for t in hexes if len(t) == 64)
    cfg = {}
    if keys:
        aes_key = keys.most_common(1)[0][0]
        cfg['aes_key'] = aes_key
        k = bytes.fromhex(aes_key)
        c2 = []
        for h in hexes:
            if h == aes_key:
                continue
            try:
                p = aes_cbc_dec(k, bytes.fromhex(h))
                if re.fullmatch(rb'[A-Za-z0-9.\-]+(:\d{1,5})?', p):
                    c2.append({'enc': h, 'host_port': p.decode()})
            except Exception:
                pass
        cfg['primary_c2'] = c2
    cfg['polygon_contract'] = [t for t in txt if re.fullmatch(r'0x[0-9a-fA-F]{40}', t)]
    cfg['contract_selector'] = [t for t in txt if re.fullmatch(r'0x[0-9a-fA-F]{8}', t)]
    cfg['rpc_endpoints'] = sorted({t for t in txt if re.fullmatch(r'[a-z0-9.\-]*(rpc|polygon|drpc|nodies|lava|pocket)[a-z0-9.\-]*\.[a-z]{2,}', t)})
    cfg['eth_call_template'] = [t for t in txt if 'eth_call' in t]
    tg = [s for s in S if 'telegra.ph/getPage' in s['str']]
    if tg:
        fn = tg[0]['func']
        slugs = [s['str'] for s in S if s['func'] == fn and re.fullmatch(r'[A-Za-z0-9]+(-[A-Za-z0-9]+)+', s['str'])]
        cfg['telegraph_dead_drop'] = [{'api': 'https://%s%s?return_content=false' % (tg[0]['str'], sl),
                                       'page': 'https://telegra.ph/%s' % sl, 'field': 'description (hex, AES-256-CBC with aes_key)'} for sl in slugs]
    cfg['gate_paths'] = sorted({t for t in txt if re.fullmatch(r'/[a-z]+(/[a-z]+)*\.[a-z]{2,5}', t)} | {t for t in txt if t == '/health'})
    cfg['user_agent'] = [t for t in txt if t.startswith('Mozilla/')]
    cfg['mutex'] = [t for t in txt if t.startswith('Global\\') or t.startswith('Local\\') and len(t) > 7]
    cfg['http_headers'] = [t for t in txt if t.startswith('Content-Type:')]
    cfg['cookie_names'] = [t for t in txt if t in ('__cf_bm', '_hjSession')]
    cfg['token_alphabet'] = [t for t in txt if re.fullmatch(r'[A-Z0-9]{32}', t)]
    cfg['c2_resolution_order'] = ['primary_c2 (GET /health must return "active")', 'telegraph_dead_drop',
                                  'polygon eth_call', 'sleep 20 s, repeat']
    return cfg


def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    I = Img(src)
    res = {'input': {'path': os.path.basename(src), 'sha256': sha(I.raw), 'size': len(I.raw),
                     'compile_ts': I.pe.FILE_HEADER.TimeDateStamp, 'imagebase': hex(I.base)}}
    res['watermark'] = watermark(I)
    fns, strings = decrypt_strings(I)
    res['string_decryptors'] = [hex(f) for f in fns]
    res['strings_decrypted'] = sum('error' not in s for s in strings)
    res['config'] = build_config(strings)
    pe2, meta = extract_embedded_pe(I)
    res['embedded_pe'] = meta
    if pe2:
        p = os.path.join(outdir, 'abe_helper.dll')
        open(p, 'wb').write(pe2)
        meta['sha256'] = sha(pe2)
        meta['size'] = len(pe2)
        try:
            ep = pefile.PE(data=pe2)
            meta['export_name'] = ep.DIRECTORY_ENTRY_EXPORT.name.decode() if hasattr(ep, 'DIRECTORY_ENTRY_EXPORT') else None
            meta['exports'] = [e.name.decode() for e in ep.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(ep, 'DIRECTORY_ENTRY_EXPORT') else []
            meta['compile_ts'] = ep.FILE_HEADER.TimeDateStamp
        except Exception as e:
            meta['pe_error'] = str(e)
    pd = os.path.join(outdir, 'inner_strings_decrypted.bin')
    res['patched_strings'] = patch_pe(I, strings, pd)
    res['inner_strings_decrypted_sha256'] = sha(open(pd, 'rb').read())
    res['strings'] = [{k: v for k, v in s.items() if k != '_bytes'} for s in strings]
    json.dump(res, open(os.path.join(outdir, 'config.json'), 'w'), indent=1, ensure_ascii=False)
    for p in (pd, os.path.join(outdir, 'abe_helper.dll')):
        if os.path.exists(p):
            os.chmod(p, 0o400)
    print(json.dumps({k: v for k, v in res.items() if k != 'strings'}, indent=1, ensure_ascii=False))


if __name__ == '__main__':
    main()
