#!/usr/bin/env python3
"""Static Xloader 8.x config decryptor (validated build: packed payload SHA-256 5547fa8c...84f1).

Input : a 32-bit Xloader stage image (0x46000 B, RVA == file offset; e.g. a sandbox dump of the RWX stage alloc in
        aspnet_compiler, tria `...-0x0000000000F00000-0x0000000000F46000-memory.dmp`) or the injected host payload
        (0x44000 B, e.g. tria newdev.exe `0x760000` region; stage RVA = dump offset + 0x1c91).
        The packed PE (MZER stub) itself is NOT accepted: its stage is produced by the packer at run time; unpack it
        first (emulate the packer, or take a sandbox stage dump).
Output: JSON (stdout or -o) with every decrypted string, all 65 C2 paths, the 64 decoy/C2 domains, the hard-coded
        "real C2" string, the keys, and the first check-in batch order.

Nothing is executed natively. Leaf routines of the sample (key builders, memcpy, string builders) run in bare unicorn
with no OS layer and no network; every key/constant is parsed from the input image's own code.
Scheme (stage RVAs of this build; finders are pattern-based, RVAs are only reported):
  PUSHEBP blobs  [M_s][body][M_e], M = 0x04ea77cc ^ c; body = D(D(body, K_ctx), K_fn)  (K_ctx = 0x3131 key ^ 0xfe)
                 K_fn is rebuilt from the consumer's own stack stores (disp8/disp32/byte-built, 1 unknown byte brute).
                 Consumed blobs (payload dumps): marker gone, [a, end) = D(plain, K_fn), end marker -> 90909090; plain = E(.)
  egg functions  thunk(E4c) -> key = K0(0x2d81) ^ (E4c ^ E88 ^ 0x839ade0e); eggs/body decrypted with D
  strings        ~175 builder fns: buf = imm bytes; D(buf, K_str ^ bl)       (decrypter 0xa3f1, K_str = 0x2e71())
  C2 path  idx   D(table[idx] (dword), K_path ^ idx)                          (dispatcher 0x36e1, mode 0xde)
  C2 host  idx   D(D(b64d(str[idx]), K1 ^ idx), K2)       K1 = ctx+0x4d84 = 0x3041() ^ 0x31,
                 K2 = 5 dwords ^ D (D = [cfg+0x20b8], stored by 0x10631 as mov [edi+0xb8], imm)
  real C2        D(D(b64d(str 0xa481), Kr), K4d24)        Kr = ((0x2fd1() ^ 0x19) ^ dword) ^ 0x73, K4d24 = 0x2f61() ^ 0xa4
                 it replaces the host of check-in slot [ctx+0xc30] (= 0) and keeps that slot's path.
D = Xloader custom RC4 (sub layer, RC4, sub layer) as in Zscaler ThreatLabz' public reimplementation.
"""
import argparse, base64, hashlib, json, re, struct, sys
import capstone
import unicorn as U
import unicorn.x86_const as R

STAGE_SIZE, PAYLOAD_SIZE, PAYLOAD_SHIFT = 0x46000, 0x44000, 0x1c91

# ---------------------------------------------------------------- crypto
def rc4(data, key):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff; s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray()
    for c in data:
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff; s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)

def _subs(d):
    d = bytearray(d); n = len(d)
    if n < 2: return bytes(d)
    for p in range(n - 2, -1, -1): d[p] = (d[p] - d[p + 1]) & 0xff
    for p in range(0, n - 1): d[p] = (d[p] - d[p + 1]) & 0xff
    return bytes(d)

def D(data, key):
    return _subs(rc4(_subs(data), key))

def inv_subs(d):
    d = bytearray(d); n = len(d)
    for p in range(n - 2, -1, -1): d[p] = (d[p] + d[p + 1]) & 0xff
    for p in range(0, n - 1): d[p] = (d[p] + d[p + 1]) & 0xff
    return bytes(d)

def E(data, key):
    """Inverse of D. A consumed blob in an injected-payload dump is stored as D(plain, K_fn) over [marker, end)."""
    return inv_subs(rc4(inv_subs(data), key))

def xb(key, b): return bytes(c ^ b for c in key)
def xd(key, d): return b''.join(struct.pack('<I', struct.unpack('<I', key[i:i + 4])[0] ^ d) for i in range(0, len(key), 4))
def k5(dws, x=0): return b''.join(struct.pack('<I', (v ^ x) & 0xffffffff) for v in dws)

# ---------------------------------------------------------------- image helpers
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); MD.skipdata = True

def load_image(path):
    d = open(path, 'rb').read()
    if d[:4] == b'MZER':
        sys.exit('packed PE (MZER stub): unpack to the stage image first (see module docstring)')
    if len(d) == STAGE_SIZE: return bytearray(d), 'stage', 0
    if len(d) == PAYLOAD_SIZE:
        return bytearray(b'\0' * PAYLOAD_SHIFT + d + b'\0' * (STAGE_SIZE - PAYLOAD_SHIFT - len(d))), 'payload', PAYLOAD_SHIFT
    sys.exit('unexpected size %#x (want stage 0x46000 or payload 0x44000)' % len(d))

def funcs(img): return [m.start() for m in re.finditer(rb'\x55\x8b\xec', img)]

def func_of(F, a):
    import bisect
    k = bisect.bisect_right(F, a) - 1
    return F[k] if k >= 0 else None

def calls(img):
    out = {}
    for m in re.finditer(rb'\xe8', img):
        i = m.start()
        if i + 5 > len(img): continue
        t = (i + 5 + struct.unpack('<i', img[i + 1:i + 5])[0]) & 0xffffffff
        if t < len(img): out.setdefault(t, []).append(i)
    return out

def dis(img, a, n):
    return list(MD.disasm(bytes(img[a:a + n]), a))

def body(img, f, limit=0x1800):
    """Disassemble a function linearly until its last `mov esp, ebp; pop ebp; ret` before the next prologue."""
    out = []
    for i in MD.disasm(bytes(img[f:f + limit]), f):
        if i.address > f and img[i.address:i.address + 3] == b'\x55\x8b\xec' and out and out[-1].mnemonic in ('ret', 'int3'):
            break
        out.append(i)
    return out

class Emu:
    """Bare unicorn: image mapped at BASE, no OS. Only for pure leaf routines."""
    BASE, STK, BUF, RET = 0x10000000, 0x20000000, 0x30000000, 0x40000000
    def __init__(self, img):
        self.u = U.Uc(U.UC_ARCH_X86, U.UC_MODE_32)
        self.u.mem_map(self.BASE, (len(img) + 0xfff) & ~0xfff); self.u.mem_write(self.BASE, bytes(img))
        for a in (self.STK, self.BUF): self.u.mem_map(a, 0x100000)
        self.u.mem_map(self.RET, 0x1000); self.u.mem_write(self.RET, b'\xc3')
        self.hooks = {}
        self.u.hook_add(U.UC_HOOK_CODE, self._hk, None, self.BASE, self.BASE + len(img))
    def _hk(self, u, addr, size, _):
        h = self.hooks.get(addr - self.BASE)
        if h: h(self)
    def call(self, rva, args=(), regs=None, maxins=3_000_000):
        u = self.u; u.mem_write(self.BUF, b'\0' * 0x1000)
        sp = self.STK + 0x80000
        st = struct.pack('<I', self.RET) + b''.join(struct.pack('<I', a) for a in args)
        sp -= len(st); u.mem_write(sp, st)
        for r in (R.UC_X86_REG_EAX, R.UC_X86_REG_EBX, R.UC_X86_REG_ECX, R.UC_X86_REG_EDX, R.UC_X86_REG_ESI, R.UC_X86_REG_EDI, R.UC_X86_REG_EBP):
            u.reg_write(r, 0)
        for k, v in (regs or {}).items(): u.reg_write(k, v)
        u.reg_write(R.UC_X86_REG_ESP, sp)
        u.emu_start(self.BASE + rva, self.RET, count=maxins)
    def ret_from_hook(self):
        sp = self.u.reg_read(R.UC_X86_REG_ESP)
        ret = struct.unpack('<I', self.u.mem_read(sp, 4))[0]
        self.u.reg_write(R.UC_X86_REG_ESP, sp + 4); self.u.reg_write(R.UC_X86_REG_EIP, ret)
    def args(self, n):
        sp = self.u.reg_read(R.UC_X86_REG_ESP)
        return struct.unpack('<%dI' % (n + 1), self.u.mem_read(sp, 4 * (n + 1)))[1:]
    def key_builder(self, rva):
        self.call(rva, (self.BUF,)); return bytes(self.u.mem_read(self.BUF, 20))

def plausible_code(b):
    if b[:2] == b'\x81\xec' and b[4:6] == b'\x00\x00' and b[6] in (0x53, 0x56, 0x57, 0x90): return True
    if b[:2] == b'\x83\xec' and b[3] in (0x53, 0x56, 0x57, 0x90): return True
    return False

# ---------------------------------------------------------------- stack-write interpreter (for consumer keys)
def stack_state(insns, stop):
    """Replay straight-line immediate stores to [ebp-X] up to address `stop`. Unknown bytes = None."""
    regs, mem = {}, {}
    R8 = {'al': 'eax', 'bl': 'ebx', 'cl': 'ecx', 'dl': 'edx'}
    def put(off, val, n):
        for k in range(n): mem[off + k] = None if val is None else (val >> (8 * k)) & 0xff
    for i in insns:
        if i.address >= stop: break
        m, o = i.mnemonic, i.op_str
        g = re.match(r'(e[a-d]x|e[sd]i), (0x[0-9a-f]+|\d+)$', o)
        if m == 'mov' and g: regs[g.group(1)] = int(g.group(2), 0); continue
        g = re.match(r'(e[a-d]x|e[sd]i), (e[a-d]x|e[sd]i)$', o)
        if m == 'xor' and g and g.group(1) == g.group(2): regs[g.group(1)] = 0; continue
        g = re.match(r'(byte|word|dword) ptr \[ebp - (0x[0-9a-f]+)\], (\S+)$', o)
        if m in ('mov', 'xor') and g:
            n = {'byte': 1, 'word': 2, 'dword': 4}[g.group(1)]; off = -int(g.group(2), 16); src = g.group(3)
            if re.match(r'(0x[0-9a-f]+|\d+)$', src): v = int(src, 0)
            elif src in regs: v = regs[src]
            elif src in R8: v = regs.get(R8[src])
            elif src in ('ax', 'bx', 'cx', 'dx'): v = regs.get('e' + src)
            else: v = None
            if m == 'mov': put(off, v, n)
            else:
                for k in range(n):
                    a = mem.get(off + k)
                    mem[off + k] = None if (a is None or v is None) else a ^ ((v >> (8 * k)) & 0xff)
            continue
        g = re.match(r'(e[a-d]x|e[sd]i), ', o)
        if g and m in ('mov', 'lea', 'add', 'sub', 'movzx', 'movsx', 'imul', 'pop', 'inc', 'dec', 'or', 'and', 'shl', 'shr'):
            regs.pop(g.group(1), None)
        if m == 'call': regs.pop('eax', None); regs.pop('ecx', None); regs.pop('edx', None)
    return mem


def key_builders(img):
    """Template key builders: `sub esp,0x24; ...; mov eax, X; 5x (mov [ebp-..], imm; xor [ebp-..], eax); memcpy 0x14`."""
    out = set()
    for f in funcs(img):
        b = bytes(img[f:f + 0x70])
        if b[3:6] == b'\x83\xec\x24' and b'\x6a\x14\x8d\x45\xdc' in b and b.count(b'\xc7\x45') >= 5: out.add(f)
    return out

def key_inits(img):
    """All `ctx+OFF = builder() ^ byte` inits: lea/add reg,[esi+OFF]; push; call KB; push XB; push reg; call XORB."""
    m = re.search(rb'\x30\x14\x08\x40\x83\xf8\x14', bytes(img))
    if not m: return {}
    F = funcs(img); xorb = func_of(F, m.start()); KB = key_builders(img)
    e = Emu(img); res = {}
    for site in calls(img).get(xorb, []):
        f = func_of(F, site)
        ins = [i for i in body(img, f, 0x2000) if i.address <= site]
        if not ins or ins[-1].address != site: continue
        win = ins[-12:]
        kb = xbv = off = None
        for i in reversed(win[:-1]):
            if i.mnemonic == 'push' and xbv is None and re.match(r'(0x[0-9a-f]+|\d+)$', i.op_str): xbv = int(i.op_str, 0)
            if i.mnemonic == 'call' and kb is None:
                try:
                    t = int(i.op_str, 16)
                    if t in KB: kb = t
                except ValueError: pass
            g = re.match(r'e[a-d]x|e[sd]i', i.op_str)
            gl = re.match(r'(e[a-d]x|e[sd]i), \[e[sd]i \+ (0x[0-9a-f]+)\]$', i.op_str)
            ga = re.match(r'(e[sd]i), (0x[0-9a-f]+)$', i.op_str)
            if off is None and i.mnemonic == 'lea' and gl: off = int(gl.group(2), 16)
            if off is None and i.mnemonic == 'add' and ga: off = int(ga.group(2), 16)
        if kb is not None and xbv is not None and off is not None:
            try: res[off] = xb(e.key_builder(kb), xbv & 0xff)
            except Exception: pass
    return res

# ---------------------------------------------------------------- layer 1: PUSHEBP blobs
def find_blob_sites(img, F, blob_fn):
    """Consumer call sites of the blob decrypter: returns [(consumer_fn, site, marker_consts...)]"""
    sites = []
    for site in calls(img).get(blob_fn, []):
        f = func_of(F, site)
        ins = body(img, f, 0x2000)
        consts = []
        for i in ins:
            if i.address >= site: break
            if i.mnemonic == 'xor' and re.match(r'eax, 0x[0-9a-f]{6,8}$', i.op_str): consts.append((i.address, int(i.op_str.split(', ')[1], 16)))
        sites.append((f, site, ins, consts))
    return sites

def decrypt_blobs(img, log):
    F = funcs(img)
    # marker base: consumers compute `add eax, BASE; je; xor eax, C` on a zeroed dword -> marker = BASE ^ C
    m = re.search(rb'\x05(....)\x74\x09\x35', bytes(img), re.S)
    base = struct.unpack('<I', m.group(1))[0] if m else 0x04ea77cc
    # identify the blob decrypter: function whose body scans `cmp dword ptr [eax + edi], edx` then calls the RC4 core
    cand = [f for f in F if bytes(img[f:f + 0x40]).find(b'\x39\x14\x38') > 0]
    blob_fn = cand[0] if cand else None
    # K_ctx: key builder whose 5 dwords ^ 0x57618200 ... is found as the builder used with `^ 0xfe` before the
    # injection copy; here derived by trying every 20-byte key builder ^ every byte: validated by the plain prologue.
    sites = find_blob_sites(img, F, blob_fn) if blob_fn else []
    # injection-time layer key: the consumer that passes `ctx + OFF` (add eax, OFF) as key; ctx+OFF is set by a
    # key-builder + xor-byte init (0x2dc11: ctx+0x394 = 0x3131() ^ 0xfe)
    kinits = key_inits(img)
    ctx_offs = set()
    for f, site, ins, consts in sites:
        for i in ins:
            if i.address >= site: break
            g = re.match(r'eax, (0x[0-9a-f]+)$', i.op_str)
            if i.mnemonic == 'add' and g and int(g.group(1), 16) < 0x1000: ctx_offs.add(int(g.group(1), 16))
    bkeys = {o: kinits[o] for o in ctx_offs if o in kinits}
    log['ctx_layer_key'] = {hex(o): k.hex() for o, k in bkeys.items()}
    done = {}
    fn_keys = set()
    for f, site, ins, consts in sites:
        if len(consts) < 1 or any(re.match(r'eax, 0x[0-9a-f]+$', i.op_str) and i.mnemonic == 'add' and int(i.op_str.split(', ')[1], 16) < 0x1000 for i in ins if i.address < site and i.address > site - 0x20): continue
        # last two marker constants before the call: (start, end) or reused start for the 2nd call
        cs = [c for a, c in consts]
        # end marker = last constant before the call; start = the closest earlier, different constant
        cands = [(c, cs[-1]) for c in reversed(cs[:-1]) if c != cs[-1]][:2]
        # the key: lea of the 2nd pushed arg; reconstruct the stack bytes
        pushes = []
        for i in ins:
            if i.address >= site: break
            if i.mnemonic == 'push': pushes.append(i)
        key_reg = pushes[-2].op_str if len(pushes) >= 2 else None
        lea = None
        for i in ins:
            if i.address >= site: break
            g = re.match(r'(e[a-d]x|e[sd]i), \[ebp - (0x[0-9a-f]+)\]$', i.op_str)
            if i.mnemonic == 'lea' and g and g.group(1) == key_reg: lea = -int(g.group(2), 16)
        if lea is None: continue
        mem = stack_state(ins, site)
        kb = [mem.get(lea + k) for k in range(20)]
        unknown = [k for k, v in enumerate(kb) if v is None]
        if len(unknown) > 1: continue
        if not unknown: fn_keys.add(bytes(kb))
        for ms, me in cands:
            M_s, M_e = struct.pack('<I', base ^ ms), struct.pack('<I', base ^ me)
            a = bytes(img).find(M_s)
            if a < 0 or str(ms) in done or bytes(img[a + 1:a + 4]) == b'\x55\x8b\xec': continue
            b = bytes(img).find(M_e, a + 4)
            if b < 0: continue
            ct = bytes(img[a + 4:b])
            hit = None
            for guess in (range(256) if unknown else [0]):
                kk = bytes(guess if v is None else v for v in kb)
                for kctx in [None] + list(bkeys.values()):
                    layers = [ct] if kctx is None else [D(ct, kctx)]
                    for l in layers:
                        o = D(l, kk)
                        if plausible_code(o): hit = (kk, o, kctx); break
                    if hit: break
                if hit: break
            if hit:
                kk, o, kctx = hit
                img[a + 4:b] = o; img[a + 1:a + 4] = b'\x55\x8b\xec'; img[b:b + 4] = b'\x90' * 4
                done[str(ms)] = {'rva': hex(a), 'len': hex(b - a - 4), 'marker': hex(ms), 'consumer': hex(site), 'key': kk.hex(),
                                 'ctx_layer': kctx is not None}
    # consumed blobs (injected-payload dumps): marker gone, [a, end) re-encrypted with D(., K_fn), end marker -> 90909090.
    # a = (egg-thunk target inside the blob) - 1; end = first 90909090 after it.
    for t in find_thunks(img):
        tgt = t['target']; a = tgt - 1
        if not (0 < a < len(img) - 0x40) or bytes(img[tgt:tgt + 3]) == b'\x55\x8b\xec': continue
        b = bytes(img).find(b'\x90\x90\x90\x90', a, a + 0x3000)
        if b < 0: continue
        for kk in fn_keys:
            o = E(bytes(img[a:b - 4]), kk)
            if o[1:4] == b'\x55\x8b\xec' and plausible_code(o[4:]):
                img[a:b - 4] = o
                done['c%x' % a] = {'rva': hex(a), 'len': hex(b - 4 - a), 'state': 'consumed (re-encrypted) blob', 'key': kk.hex()}
                break
    log.setdefault('blobs', []).extend(done.values())
    return img

# ---------------------------------------------------------------- layer 2: egg functions
def find_thunks(img):
    th = []
    for m in re.finditer(rb'\x55\x8b\xec\x81\xec\xac\x00\x00\x00', img):
        a = m.start(); info = {'addr': a, 'calls': []}
        for i in MD.disasm(bytes(img[a:a + 0x90]), a):
            o = i.op_str
            for key, pat in (('e4c', 'dword ptr [ebp - 0x60], 0x'), ('s_d', 'dword ptr [ebp - 0x2e], 0x'), ('s_w', 'word ptr [ebp - 0x30], 0x'),
                             ('e_w1', 'word ptr [ebp - 0x1c], 0x'), ('e_b1', 'byte ptr [ebp - 0x1a], 0x'), ('e_w2', 'word ptr [ebp - 0x19], 0x'),
                             ('e_b2', 'byte ptr [ebp - 0x17], 0x')):
                if i.mnemonic == 'mov' and o.startswith(pat): info[key] = int(o.split(', ')[1], 16)
            if i.mnemonic == 'mov' and re.match(r'byte ptr \[ebp - 0x1a\], (\d+)$', o): info['e_b1'] = int(o.split(', ')[1])
            if i.mnemonic == 'mov' and re.match(r'byte ptr \[ebp - 0x17\], (\d+)$', o): info['e_b2'] = int(o.split(', ')[1])
            if i.mnemonic == 'call':
                try: info['calls'].append(int(o, 16))
                except ValueError: pass
            if i.mnemonic == 'ret': break
        if {'e4c', 's_d', 's_w', 'e_w1', 'e_b1', 'e_w2', 'e_b2'} <= set(info) and len(info['calls']) >= 3:
            info['target'] = info['calls'][1]
            info['s_src'] = struct.pack('<HI', info['s_w'], info['s_d'])
            info['e_src'] = struct.pack('<H', info['e_w1']) + bytes([info['e_b1']]) + struct.pack('<H', info['e_w2']) + bytes([info['e_b2']])
            th.append(info)
    return th

def egg_slot(img, t):
    p = t + 3
    if img[p:p + 2] == b'\x81\xec': p += 6
    elif img[p:p + 2] == b'\x83\xec': p += 3
    while img[p] in (0x53, 0x56, 0x57): p += 1
    return p

def find_egg_key(img, th):
    """Egg key = KB() ^ (E4c ^ E88 ^ C) per dword. The hunter (thunk's 1st call -> its 1st call) does
    `xor ebx, C; call KB; xor [esi..], ebx` (here C = 0x839ade0e, KB = 0x2d81)."""
    KB = key_builders(img); e = Emu(img)
    for t in th:
        w = t['calls'][0]
        try: h = next(int(i.op_str, 16) for i in dis(img, w, 0x30) if i.mnemonic == 'call')
        except (StopIteration, ValueError): continue
        ins = dis(img, h, 0x200); C = None
        for i in ins:
            g = re.match(r'ebx, (0x[0-9a-f]+)$', i.op_str)
            if i.mnemonic == 'xor' and g: C = int(g.group(1), 16)
            if i.mnemonic == 'call' and C is not None:
                try: kb = int(i.op_str, 16)
                except ValueError: continue
                if kb in KB: return struct.unpack('<5I', e.key_builder(kb)), C, h, kb
    raise RuntimeError('egg hunter key not found')

def decrypt_eggs(img, log, K0, C, _tried={}):
    """E88 is a caller-side constant (the caller's arg struct): brute it over every imm32 stored by
    `mov [ebp-X], imm32` / `push imm32` in the (progressively decrypted) image, validated by the plaintext egg."""
    th = find_thunks(img)
    res = {}
    for rnd in range(10):
        prog = 0
        imms = set()
        for m in re.finditer(rb'\xc7\x45.(....)|\xc7\x85....(....)|\x68(....)', bytes(img), re.S):
            v = next(g for g in m.groups() if g is not None); imms.add(struct.unpack('<I', v)[0])
        for t in th:
            tgt = t['target']
            if tgt >= len(img) - 16: continue
            p = egg_slot(img, tgt); egg = bytes(img[p:p + 6])
            if egg == b'\x90' * 6:
                p += 6; egg = bytes(img[p:p + 6])
                if egg == b'\x90' * 6: continue
            new = imms - _tried.get((tgt, egg), set())
            _tried[(tgt, egg)] = _tried.get((tgt, egg), set()) | new
            for e88 in new:
                x = t['e4c'] ^ e88 ^ C
                k = b''.join(struct.pack('<I', kk ^ x) for kk in K0)
                if D(t['s_src'], k) == egg:
                    ee = D(t['e_src'], k); q = bytes(img).find(ee, p + 6)
                    if q < 0: break
                    img[p + 6:q] = D(bytes(img[p + 6:q]), k); img[p:p + 6] = b'\x90' * 6; img[q:q + 6] = b'\x90' * 6
                    res[hex(tgt)] = {'thunk': hex(t['addr']), 'e88': hex(e88), 'len': hex(q - p - 6)}
                    prog += 1; break
        print('[eggs] round %d +%d' % (rnd, prog), file=sys.stderr, flush=True)
        if not prog: break
    still = [hex(t['target']) for t in th if bytes(img[egg_slot(img, t['target']):egg_slot(img, t['target']) + 6]) != b'\x90' * 6
             and bytes(img[egg_slot(img, t['target']) + 6:egg_slot(img, t['target']) + 12]) != b'\x90' * 6]
    prev = log.get('eggs', {}).get('decrypted', {})
    prev.update(res)
    log['eggs'] = {'thunks': len(th), 'decrypted': prev, 'still_encrypted': still}
    return img

# ---------------------------------------------------------------- config
def find_string_decrypter(img, C):
    """The string decrypter: `call keybuilder; xor byte [ebp+eax-0x18], bl` loop, then the custom-RC4 struct call."""
    best = None
    for f, sites in C.items():
        if bytes(img[f:f + 3]) != b'\x55\x8b\xec': continue
        b = bytes(img[f:f + 0x90])
        if b'\x30\x5c\x05\xe8' in b and len(sites) > 50:
            if best is None or len(sites) > len(C[best]): best = f
    return best

def run_string_fns(img, sdec):
    ins = dis(img, sdec, 0x40)
    kb = next(int(i.op_str, 16) for i in ins if i.mnemonic == 'call')
    e = Emu(img)
    kstr = e.key_builder(kb)
    out = {}
    state = {}
    def hk(em):
        buf, ln = em.args(2); ln &= 0xff
        bl = em.u.reg_read(R.UC_X86_REG_EBX) & 0xff
        ct = bytes(em.u.mem_read(buf, ln)); pt = D(ct, xb(kstr, bl))
        em.u.mem_write(buf, pt); state['last'] = (bl, ln, ct, pt); em.ret_from_hook()
    e.hooks[sdec] = hk
    F = funcs(img)
    for f in sorted(set(func_of(F, x) for x in calls(img)[sdec])):
        state.clear()
        try: e.call(f, (e.BUF,))
        except Exception: continue
        if 'last' in state:
            bl, ln, ct, pt = state['last']; out[f] = {'xor': bl, 'len': ln, 'pt': pt}
    return kstr, kb, out

def parse_dispatcher(img):
    m = re.search(rb'\x81\x7d\x14\xde\x00\x00\x00', bytes(img))
    if not m: raise RuntimeError('C2 dispatcher (cmp [ebp+0x14], 0xde) not found - still encrypted in this snapshot?')
    F = funcs(img); f = func_of(F, m.start())
    ins = body(img, f, 0x900)
    stores = {}
    for i in ins:
        g = re.match(r'dword ptr \[ebp - (0x[0-9a-f]+)\], (0x[0-9a-f]+)$', i.op_str)
        if i.mnemonic == 'mov' and g: stores[int(g.group(1), 16)] = int(g.group(2), 16)
    # path key = 5 dwords at the highest offsets just below the frame top region (ebp-0x20..-0x10)
    pk_offs = sorted([o for o in stores if o <= 0x20], reverse=True)[:5]
    K_path = k5([stores[o] for o in pk_offs])
    tab_offs = sorted([o for o in stores if o > 0x40 and stores[o] > 0xffff], reverse=True)
    # the table is the longest run of consecutive dword slots
    runs, cur = [], []
    for o in tab_offs:
        if cur and cur[-1] - o != 4: runs.append(cur); cur = []
        cur.append(o)
    runs.append(cur)
    tab = max(runs, key=len)
    table = [stores[o] for o in tab]
    idx2fn, cur = {}, None
    for i in ins:
        g = re.match(r'bl, (0x[0-9a-f]+|\d+)$', i.op_str)
        if i.mnemonic == 'cmp' and g: cur = int(g.group(1), 0)
        elif i.mnemonic == 'call' and cur is not None:
            idx2fn[cur] = int(i.op_str, 16); cur = None
    off_k1 = None
    for i in ins:
        g = re.match(r'eax, (0x[0-9a-f]+)$', i.op_str)
        if i.mnemonic == 'add' and g and 0x1000 < int(g.group(1), 16) < 0x10000: off_k1 = int(g.group(1), 16)
    return f, K_path, table, idx2fn, off_k1

def find_builder_xor_after(img, ins, k, reg='esi'):
    """In `ins` find: <ptr = ctx+off>; push ptr; call KB; push XB; push ptr; call XORB  -> (KB, XB)."""
    for n in range(len(ins) - 4):
        a, b, c, d = ins[n:n + 4]
        if a.mnemonic == 'push' and b.mnemonic == 'call' and c.mnemonic == 'push' and d.mnemonic == 'push':
            try: kb = int(b.op_str, 16); xbv = int(c.op_str, 0)
            except ValueError: continue
            if d.op_str == a.op_str and ins[n + 4].mnemonic == 'call':
                yield n, kb, xbv

def extract_config(img):
    out = {}
    C = calls(img); F = funcs(img)
    sdec = find_string_decrypter(img, C)
    kstr, kstr_fn, S = run_string_fns(img, sdec)
    out['string_decrypter'] = {'rva': hex(sdec), 'key_builder': hex(kstr_fn), 'key': kstr.hex(), 'count': len(S)}
    disp, K_path, table, idx2fn, off_k1 = parse_dispatcher(img)
    out['dispatcher'] = {'rva': hex(disp), 'path_key': K_path.hex(), 'paths': len(table), 'domain_fns': len(idx2fn), 'k1_ctx_off': hex(off_k1 or 0)}
    paths = [D(struct.pack('<I', v), xb(K_path, i)).decode('latin1') for i, v in enumerate(table)]
    e = Emu(img)
    # K1: `add esi, off_k1; push esi; call KB; push XB; push esi; call XORB`
    K1 = None
    for m in re.finditer(rb'\x81\xc6' + struct.pack('<I', off_k1), bytes(img)):
        ins = dis(img, m.start(), 0x20)
        for n, kb, xbv in find_builder_xor_after(img, ins[1:], None):
            K1 = xb(e.key_builder(kb), xbv); out['K1'] = {'site': hex(m.start()), 'builder': hex(kb), 'xor_byte': hex(xbv), 'key': K1.hex()}
            break
        if K1: break
    # K2 + slot batch + real-C2 second layer: the check-in loop function (calls the dispatcher thunk twice, mode 0xde)
    loop = None
    for f in F:
        b = bytes(img[f:f + 0x800])
        if re.search(rb'\x8b\x87(..)\x00\x00\x31\x45', b, re.S) and b'\x81\xff\x40\x27\x00\x00' in b and b'\x68\xde\x00\x00\x00' in b:
            loop = f; break
    ins = body(img, loop, 0x800)
    st = stack_state(ins, ins[-1].address)
    m = re.search(rb'\x8b\x87(....)\x31\x45(.)', bytes(img[loop:loop + 0x200]), re.S)
    off2 = struct.unpack('<I', m.group(1))[0]; first = -(256 - m.group(2)[0])
    st0 = stack_state(ins, loop + m.start())          # stack before the 5 `xor [ebp-..], eax` with the cfg dword
    K2base = bytes(st0.get(first + k) or 0 for k in range(20))
    # D: the config dword is stored by the bot-info builder as `mov dword ptr [reg + off2 (-0x2000 base shift)], imm32`
    Dcands = []
    for delta in (0, 0x2000):
        for mm in re.finditer(rb'\xc7[\x80-\x87]' + re.escape(struct.pack('<I', off2 - delta)) + rb'(....)', bytes(img), re.S):
            Dcands.append((mm.start(), struct.unpack('<I', mm.group(1))[0]))
    # batch order of the first check-in round: 16 index bytes at [ebp-0x68]
    m2 = re.search(rb'\x0f\xb6\x44\x15(.)', bytes(img[loop:loop + 0x600]), re.S)
    batch = []
    if m2:
        boff = -(256 - m2.group(1)[0])
        batch = [st.get(boff + k) for k in range(16)]
    # real-C2 slot index [ctx+0xc30] = 0 at loop start; the slot whose host is replaced by the real C2 string
    real_slot = 0
    # second real-C2 layer (ctx+0x4d24): `lea ebx,[esi+off]; push ebx; call KB; push XB; push ebx; call XORB`
    Kr2 = None
    for n, kb, xbv in find_builder_xor_after(img, ins, None):
        Kr2 = xb(e.key_builder(kb), xbv); out['K_real2'] = {'builder': hex(kb), 'xor_byte': hex(xbv), 'key': Kr2.hex()}; break
    # domains
    domains = {}
    b64 = {i: S[fn]['pt'] for i, fn in idx2fn.items() if fn in S}
    layer1 = {i: D(base64.b64decode(s), xb(K1, i)) for i, s in b64.items()}
    def score(dom):
        return sum(all(32 < c < 127 for c in v) and b'.' in v for v in dom.values())
    bestD = None
    for site, dv in Dcands:
        K2 = xd(K2base, dv)
        dom = {i: D(v, K2) for i, v in layer1.items()}
        if bestD is None or score(dom) > bestD[0]: bestD = (score(dom), site, dv, K2, dom)
    if bestD is None: raise RuntimeError('config dword D not found (brute-force it with d_brute.c and a known host)')
    _, dsite, dv, K2, dom = bestD
    out['K2'] = {'base_dwords_at': hex(first), 'cfg_off': hex(off2), 'D': hex(dv), 'D_site': hex(dsite), 'key': K2.hex(),
                 'printable_domains': bestD[0]}
    # real C2: the string fn that is not reached from the dispatcher and whose b64 decodes to 23 bytes, consumed by the
    # init function: `lea ebx,[esi+off]; push ebx; call STRFN; ... call b64; lea edi,[esi+k]; push edi; call KB; push XB;
    # push edi; call XORB; mov eax, DW; xor [edi..]x5; ... xor byte [ebp+eax-0x60], XB2`
    real = None
    for fn, v in S.items():
        if fn in idx2fn.values(): continue
        s = v['pt']
        if not re.fullmatch(rb'[A-Za-z0-9+/=]{8,}', s): continue
        for site in C.get(fn, []):
            ins2 = dis(img, site, 0xc0)
            kb = xbv = dw = xb2 = None
            for n, kbb, xx in find_builder_xor_after(img, ins2, None):
                kb, xbv = kbb, xx
                tail = ins2[n + 5:n + 40]
                for t in tail:
                    g = re.match(r'eax, (0x[0-9a-f]+)$', t.op_str)
                    if t.mnemonic == 'mov' and g and dw is None: dw = int(g.group(1), 16)
                    g = re.match(r'byte ptr \[ebp \+ eax - 0x[0-9a-f]+\], (0x[0-9a-f]+)$', t.op_str)
                    if t.mnemonic == 'xor' and g: xb2 = int(g.group(1), 16)
                break
            if kb is None or dw is None or xb2 is None: continue
            Kr = xb(xd(xb(e.key_builder(kb), xbv), dw), xb2)
            l1 = D(base64.b64decode(s), Kr)
            pt = D(l1, Kr2) if Kr2 else l1
            real = {'string_fn': hex(fn), 'b64': s.decode(), 'key1': Kr.hex(), 'key2': (Kr2 or b'').hex(), 'host': pt.decode('latin1')}
            break
        if real: break
    out['real_c2'] = real
    table_rows = []
    for i in range(len(paths)):
        h = dom.get(i)
        table_rows.append({'idx': i, 'host': None if h is None else h.decode('latin1'), 'path': '/%s/' % paths[i],
                           'url': None if h is None else 'http://www.%s/%s/' % (h.decode('latin1'), paths[i])})
    out['c2_table'] = table_rows
    if batch and all(b is not None for b in batch):
        rows = []
        for slot, idx in enumerate(batch):
            host = dom[idx].decode('latin1')
            if slot == real_slot and real: host = real['host'][4:] if real['host'].startswith('www.') else real['host']
            rows.append({'slot': slot, 'idx': idx, 'url': 'http://www.%s/%s/' % (host, paths[idx]),
                         'note': 'host replaced by hard-coded real-C2 string' if slot == real_slot and real else ''})
        out['first_checkin_batch'] = rows
    out['strings'] = [{'rva': hex(f), 'xor': v['xor'], 'text': v['pt'].decode('latin1')} for f, v in sorted(S.items())]
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('image'); ap.add_argument('-o', '--out'); ap.add_argument('--dump-decrypted')
    a = ap.parse_args()
    img, kind, shift = load_image(a.image)
    log = {'input': a.image, 'sha256': hashlib.sha256(open(a.image, 'rb').read()).hexdigest(), 'kind': kind, 'rva_shift': hex(shift),
           'family': 'Xloader (Formbook successor), >= 8.1 obfuscation (struct-param RC4, out-of-order eggs)'}
    import math, collections
    seg = bytes(img[0x3000:0x40000]); cnt = collections.Counter(seg)
    ent = -sum(v / len(seg) * math.log2(v / len(seg)) for v in cnt.values())
    if ent > 7.9 or cnt.get(0, 0) == len(seg):
        sys.exit('snapshot not usable: image is %s (entropy %.2f): the dump was taken before the region was written or while '
                 'the image was encrypted around an API call; use another dump of the same region' % ('empty' if cnt.get(0, 0) == len(seg) else 'fully encrypted', ent))
    th = find_thunks(img)
    K0, C, hunter, kb = find_egg_key(img, th)
    log['egg_key'] = {'hunter': hex(hunter), 'builder': hex(kb), 'xor': hex(C), 'K0': k5(K0).hex()}
    for _ in range(4):
        decrypt_eggs(img, log, K0, C)
        decrypt_blobs(img, log)
    cfg = extract_config(img)
    log.update(cfg)
    if a.dump_decrypted: open(a.dump_decrypted, 'wb').write(bytes(img))
    js = json.dumps(log, indent=1)
    if a.out: open(a.out, 'w').write(js)
    else: print(js)

if __name__ == '__main__':
    main()
