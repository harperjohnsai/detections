#!/usr/bin/env python3
"""T0203: Remus per-build C2 table decryptor (static; no execution of the sample).

Layout found in 1ac2f1b0 (06.11.2026 build) by xref (blob_xrefs.py) + disassembly (disasm_at.py):
  init  fn @0x48e0(ctx, key=.rdata+0x344f0 (32 B), nonce=.rdata+0x34510 (8 B), counter=0)  -- 'expand 32-byte k'
        constants are built at run time (0x10a3b10f ^ 0x71d3c96a = 0x61707865), so no string in the file.
  use   0x7d61: entry = .rdata+0x34520 + idx*64; decrypt fn @0x4aa0(ctx, entry, out, len)  -- ChaCha20 (16/12/8/7)
Locating it in other builds: pattern 'lea rcx,[ctx]; lea rdx,[key]; lea r8,[nonce]; xor r9d,r9d; jmp init'.
Usage: remus_c2_table.py FILE...  -> prints per-file key/nonce RVAs and decrypted entries."""
import sys, struct, re, hashlib, json, pefile

def rotl(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))

def qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff; x[d] = rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff; x[b] = rotl(x[b] ^ x[c], 7)

def chacha_block(key, counter, nonce8, rounds=20):
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack('<8I', key)) + \
        [counter & 0xffffffff, counter >> 32] + list(struct.unpack('<2I', nonce8))
    x = s[:]
    for _ in range(rounds // 2):
        qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15)
        qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14)
    return struct.pack('<16I', *[(x[i] + s[i]) & 0xffffffff for i in range(16)])

def chacha_xor(key, nonce8, data, counter=0):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce8)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)

# 48 8d 0d rel32 | 48 8d 15 rel32 | 4c 8d 05 rel32 | 45 31 c9 | e9 rel32
PAT = re.compile(rb'\x48\x8d\x0d(.{4})\x48\x8d\x15(.{4})\x4c\x8d\x05(.{4})\x45\x31\xc9\xe9(.{4})', re.S)

def find_init(pe):
    text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    data = text.get_data()
    hits = []
    for m in PAT.finditer(data):
        rva = text.VirtualAddress + m.start()
        ctx = rva + 7 + struct.unpack('<i', m.group(1))[0]
        key = rva + 14 + struct.unpack('<i', m.group(2))[0]
        nonce = rva + 21 + struct.unpack('<i', m.group(3))[0]
        init = rva + 29 + struct.unpack('<i', m.group(4))[0]
        hits.append(dict(site=rva, ctx=ctx, key=key, nonce=nonce, init=init))
    return hits

def find_table_use(pe, ctx):
    """lea rdx,[table]; shl rax,6; add rdx,rax; lea rcx,[ctx] -> table RVA (64-byte entries)."""
    text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    data = text.get_data()
    out = []
    for m in re.finditer(rb'\x48\x8d\x15(.{4})\x48\xc1\xe0\x06\x48\x01\xc2\x48\x8d\x0d(.{4})', data, re.S):
        rva = text.VirtualAddress + m.start()
        tab = rva + 7 + struct.unpack('<i', m.group(1))[0]
        c = rva + 21 + struct.unpack('<i', m.group(2))[0]
        if c == ctx:
            out.append(dict(site=rva, table=tab))
    return out

def find_mask(pe, site):
    """After the decrypt call: call <mov dword [rcx],IMM1; ret> ... imul ecx,ecx,IMM2 ; xor ecx,[rsp+..].
    The loop runs once (i=1), so the 4-byte XOR mask = IMM1 ^ IMM2 (1ac2f1b0: 0x5f7721f7 ^ 0x18dc7118)."""
    win = pe.get_data(site, 0x80)
    for m in re.finditer(rb'\xe8(.{4})', win, re.S):
        tgt = site + m.start() + 5 + struct.unpack('<i', m.group(1))[0]
        if not (0x1000 <= tgt < 0x40000):
            continue
        f = pe.get_data(tgt, 7)
        if f[:2] == b'\xc7\x01' and f[6:7] == b'\xc3':
            imm1 = struct.unpack('<I', f[2:6])[0]
            rest = win[m.end():]
            k = re.search(rb'\x69\xc9(.{4})\x33\x4c\x84', rest, re.S)
            if k:
                imm2 = struct.unpack('<I', k.group(1))[0]
                return dict(mask=struct.pack('<I', imm1 ^ imm2), imm1=imm1, imm2=imm2, getter=tgt)
    return None

def unmask(b, mask):
    return bytes(x ^ mask[i % 4] for i, x in enumerate(b))

def printable(b):
    return b.split(b'\x00')[0]

def analyse(path, max_entries=3):  # table = 3 x 64 B (memset 0xc0 at 0x7f35 in 1ac2f1b0)
    pe = pefile.PE(data=open(path, 'rb').read())
    raw = open(path, 'rb').read()
    r = dict(file=path, sha256=hashlib.sha256(raw).hexdigest())
    inits = find_init(pe)
    if not inits:
        r['result'] = 'no-init-pattern'; return r
    best = None
    for h in inits:
        # init fn must hold the first obfuscated constant pair: mov eax,imm ... imul r10d,r10d,imm
        key = pe.get_data(h['key'], 32); nonce = pe.get_data(h['nonce'], 8)
        uses = find_table_use(pe, h['ctx'])
        if not uses:
            continue
        tab = uses[0]['table']
        rdata = next(s for s in pe.sections if s.Name.startswith(b'.rdata'))
        end = rdata.VirtualAddress + rdata.Misc_VirtualSize
        mk = find_mask(pe, uses[0]['site'])
        if not mk:
            # fallback: known plaintext 'http' on every entry; accepted only if all entries agree
            kps = {bytes(a ^ b for a, b in zip(chacha_xor(key, nonce, pe.get_data(tab + 64 * i, 64), i)[:4], b'http'))
                   for i in range(max_entries)}
            if len(kps) == 1:
                mk = dict(mask=kps.pop(), src='known-plaintext (code pattern not matched)')
        entries = []
        for i in range(max_entries):
            ct = pe.get_data(tab + 64 * i, 64)
            if len(ct) < 64 or tab + 64 * i + 64 > end:
                break
            # the sample copies the global ctx per call (memcpy 0x40 at 0x4ade), so every entry starts at counter 0
            # one ChaCha20 stream over the table (emu_c2.py: ctx counter 0 -> 3 after three 64 B calls)
            ptn = chacha_xor(key, nonce, ct, i)
            kp = bytes(a ^ b for a, b in zip(ptn[:4], b'http'))  # known-plaintext cross-check
            url = printable(unmask(ptn, mk['mask'])).decode('latin1') if mk else None
            entries.append(dict(idx=i, url=url, kp_mask=kp.hex()))
        best = dict(h, mask=(mk['mask'].hex() if mk else None), mask_src=(mk and {k: v for k, v in mk.items() if k != 'mask'}),
                    key_hex=key.hex(), nonce_hex=nonce.hex(), table=tab, use_sites=[u['site'] for u in uses],
                    entries=entries)
        break
    if not best:
        r['result'] = 'no-table-use'; r['inits'] = inits; return r
    r.update(best); r['result'] = 'ok'
    return r

if __name__ == '__main__':
    res = [analyse(f) for f in sys.argv[1:]]
    for r in res:
        print(r['sha256'][:12], r['result'], hex(r.get('key', 0)), hex(r.get('table', 0)))
        print('    mask', r.get('mask'), 'nonce', r.get('nonce_hex'))
        for e in r.get('entries', []):
            print('   ', e['idx'], repr(e['url']), 'kp', e['kp_mask'])
