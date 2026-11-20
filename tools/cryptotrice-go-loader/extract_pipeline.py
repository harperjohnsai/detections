#!/usr/bin/env python3
"""Build-independent pipeline extractor for the cryptotrice Go loader blob (static code, bare-unicorn loops).

1. Find the blob builder: `lea rsi,[rip+X]; mov ecx,N; rep movsq` after `call runtime.newobject`, with movabs
   immediates stored into the object head (`lea rdi,[rax+K]` gives the immediate-header length K).
2. Every later `mov rax, qword ptr [rsp+SLOT]` (SLOT = where newobject's result was saved) starts one in-place pass
   over the buffer. Each pass loop is run in bare unicorn (no OS, no Go runtime, no network): the code and .rdata are
   mapped, only the stack slot and buffer are provided; a block hook stops when control leaves the loop window.
   A pass that would reach runtime.panicIndex, or any call, is an error. The pass list ends at `ret`.
3. Output: header immediates, .rdata range, per-pass disassembly + effect, and the decrypted buffer.
No sample code runs natively; only the byte-transform loops run inside the emulator, on a copy of the blob.
Usage: extract_pipeline.py CORE.exe [OUT.bin]
"""
import sys, re, hashlib, json
import pefile, capstone
from capstone import x86
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_BLOCK
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP

WIN = 0x80          # max size of one pass loop window (bytes); larger loops are reported, not guessed
STACK, BUF = 0x10000000, 0x20000000


def load(path):
    d = open(path, 'rb').read()
    pe = pefile.PE(data=d, fast_load=True)
    return d, pe, pe.OPTIONAL_HEADER.ImageBase


def text_range(pe, base):
    s = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
    return base + s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData


def find_builder(d, pe, base, md):
    va0, fo, n = text_range(pe, base)
    code = d[fo: fo + n]
    for m in re.finditer(rb'\xf3\x48\xa5', code):          # rep movsq
        at = va0 + m.start()
        win = None
        for back in range(0x60, 0x30, -1):   # x86 is not self-synchronising: find a start that lands on rep movsq
            w = list(md.disasm(code[m.start() - back: m.start() + 3], at - back))
            if w and w[-1].address == at and sum(x.size for x in w) == back + 3:
                win = w; break
        if not win:
            continue
        ops = {}
        for ins in win:
            if ins.mnemonic == 'lea' and ins.op_str.startswith('rsi, [rip'):
                ops['src'] = ins.address + ins.size + ins.operands[1].mem.disp
            if ins.mnemonic == 'mov' and ins.op_str.startswith('ecx, '):
                ops['nq'] = ins.operands[1].imm
            if ins.mnemonic == 'movabs':
                ops.setdefault('imm', []).append(ins.operands[1].imm & (2 ** 64 - 1))
            if ins.mnemonic == 'lea' and ins.op_str.startswith('rdi, [rax +'):
                ops['hdr'] = ins.operands[1].mem.disp
            if ins.mnemonic == 'mov' and ins.op_str.startswith('qword ptr [rsp +') and ins.op_str.endswith(', rax'):
                ops['slot'] = ins.operands[0].mem.disp
        if {'src', 'nq', 'imm', 'hdr', 'slot'} <= ops.keys() and ops['nq'] > 0x1000:
            ops['at'] = at
            return ops
    raise SystemExit('no blob builder found')


def build_blob(d, pe, base, b):
    head = b''.join(x.to_bytes(8, 'little') for x in b['imm'])[:b['hdr']]
    off = pe.get_offset_from_rva(b['src'] - base)
    return head + d[off: off + b['nq'] * 8]


def passes(d, pe, base, md, b, length):
    va0, fo, n = text_range(pe, base)
    start = b['at'] - va0
    out = []
    for ins in md.disasm(d[fo + start: fo + n], b['at']):
        if ins.mnemonic == 'mov' and ins.op_str == f'rax, qword ptr [rsp + {b["slot"]:#x}]':
            body = list(md.disasm(d[fo + ins.address - va0: fo + ins.address - va0 + WIN], ins.address))
            if any(x.mnemonic == 'ret' for x in body[:8]):
                out.append({'site': ins.address, 'kind': 'return',
                            'len': next((x.operands[1].imm for x in body[:4] if x.op_str.startswith('ebx, ')), None)})
                break
            out.append({'site': ins.address, 'kind': 'pass',
                        'asm': [f'{x.mnemonic} {x.op_str}'.strip() for x in body if x.address < ins.address + 0x50]})
    return out


def emulate(d, pe, base, b, plist, blob):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff
    mu.mem_map(base, size)
    mu.mem_write(base, d[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    for s in pe.sections:
        mu.mem_write(base + s.VirtualAddress, d[s.PointerToRawData: s.PointerToRawData + min(s.SizeOfRawData, s.Misc_VirtualSize or s.SizeOfRawData)])
    mu.mem_map(STACK, 0x200000)
    mu.mem_map(BUF, (len(blob) + 0x1fff) & ~0xfff)
    mu.mem_write(BUF, blob)
    rsp = STACK + 0x100000
    mu.mem_write(rsp + b['slot'], BUF.to_bytes(8, 'little'))
    for p in plist:
        if p['kind'] != 'pass':
            continue
        site = p['site']; state = {}
        # loop window = site .. end of the last backward branch into the window (Go emits the loop condition last)
        body = list(md_.disasm(d[pe.get_offset_from_rva(site - base):][:WIN], site))
        back = [x for x in body if x.group(capstone.CS_GRP_JUMP) and x.operands[0].type == x86.X86_OP_IMM
                and site <= x.operands[0].imm < x.address]
        if not back:
            raise SystemExit(f'pass at {site:#x}: no loop found in {WIN:#x} bytes')
        loop_end = back[-1].address + back[-1].size
        p['loop'] = [hex(site), hex(loop_end)]

        def hook(uc, addr, sz, _):
            if not (site <= addr < loop_end):
                state['exit'] = addr; uc.emu_stop()
        h = mu.hook_add(UC_HOOK_BLOCK, hook)
        mu.reg_write(UC_X86_REG_RSP, rsp)
        before = bytes(mu.mem_read(BUF, len(blob)))
        mu.emu_start(site, site + WIN + 0x1000)
        mu.hook_del(h)
        p['exit'] = hex(state.get('exit', 0))
        nxt = list(md_.disasm(d[pe.get_offset_from_rva(state['exit'] - base):][:32], state['exit']))[:3]
        if any(x.mnemonic in ('call', 'ret', 'int3') for x in nxt):
            raise SystemExit(f'pass at {site:#x} left towards a call/ret at {state["exit"]:#x} (panic path?)')
        after = bytes(mu.mem_read(BUF, len(blob)))
        p['changed_bytes'] = sum(1 for x, y in zip(before[::997], after[::997]) if x != y)
    return bytes(mu.mem_read(BUF, len(blob)))


if __name__ == '__main__':
    d, pe, base = load(sys.argv[1])
    md_ = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md_.detail = True
    b = find_builder(d, pe, base, md_)
    blob = build_blob(d, pe, base, b)
    plist = passes(d, pe, base, md_, b, len(blob))
    out = emulate(d, pe, base, b, plist, blob)
    rep = {'builder_at': hex(b['at']), 'rdata_src': hex(b['src']), 'qwords': b['nq'], 'header_len': b['hdr'],
           'header_imm': [hex(x) for x in b['imm']], 'slot': hex(b['slot']), 'blob_len': len(blob),
           'blob_sha256': hashlib.sha256(blob).hexdigest(), 'out_sha256': hashlib.sha256(out).hexdigest(),
           'mz': out[:2] == b'MZ', 'passes': plist}
    if out[:2] == b'MZ':
        p2 = pefile.PE(data=out, fast_load=True)
        end = max(s.PointerToRawData + s.SizeOfRawData for s in p2.sections)
        rep['pe_len'] = end; rep['pe_sha256'] = hashlib.sha256(out[:end]).hexdigest(); rep['trailer_len'] = len(out) - end
        tr = out[end:]
        rep['trailer_alpha_frac'] = round(sum(1 for c in tr if 65 <= c <= 90 or 97 <= c <= 122) / max(1, len(tr)), 4)
    print(json.dumps(rep, indent=1))
    if len(sys.argv) > 2:
        open(sys.argv[2], 'wb').write(out)
