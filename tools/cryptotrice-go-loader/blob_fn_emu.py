#!/usr/bin/env python3
"""T0177: build-independent decryptor for the cryptotrice/NovaMetric Go reflective-loader blob (v2).

v1 (extract_pipeline.py) pattern-matched the builder and each pass loop; it decrypted 9/40 other builds because the
builder shape (immediate header or none, pointer spilled or kept in a register) and pass shapes vary per build.
v2 drops the per-pass patterns: it emulates the WHOLE blob-builder function in bare unicorn, from its entry to its
return, with every `call` patched to int3 and serviced by Python stubs:
  * runtime.newobject / makeslice / mallocgc / growslice -> bump allocator in emulator memory
  * runtime.memmove / memclrNoHeapPointers -> done in Python on emulator memory
  * runtime.panic* / throw / morestack -> abort (reported, never guessed)
  * any other callee (fmt/print/map/rand junk) -> skipped, returns a pointer to a zero scratch page
  * runtime.duffzero / duffcopy run as normal code (pure stores)
The function's return values (rax=ptr, rbx=len) give the decrypted buffer. Nothing runs natively, no OS layer, no
network, no Go runtime; only the sample's own arithmetic runs inside the emulator on a copy of its data.
Usage: blob_fn_emu.py SAMPLE.exe [OUT.bin]  -> JSON report on stdout
"""
import sys, re, json, hashlib, struct
import pefile, capstone
from unicorn import (Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_INTR, UC_HOOK_MEM_UNMAPPED, UC_PROT_ALL)
from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX,
                               UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_R14)
sys.path.insert(0, __file__.rsplit('/', 1)[0])
from gosyms import coff_symbols, SymIndex

STACK, STACK_SZ = 0x10000000, 0x400000
G, SCRATCH, SENTINEL = 0x18000000, 0x19000000, 0x1f000000
HEAP, HEAP_SZ = 0x40000000, 0x10000000
U64 = 2 ** 64 - 1


def builder_sites(d, pe, base, md):
    t = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
    code = d[t.PointerToRawData: t.PointerToRawData + t.SizeOfRawData]; va0 = base + t.VirtualAddress
    out = []
    for m in re.finditer(rb'\xf3\x48\xa5', code):
        at = va0 + m.start()
        for back in range(0x60, 0x08, -1):
            w = list(md.disasm(code[m.start() - back: m.start() + 3], at - back))
            if w and w[-1].address == at and sum(x.size for x in w) == back + 3:
                ecx = [x for x in w if x.mnemonic == 'mov' and x.op_str.startswith('ecx, 0x')]
                if ecx and ecx[-1].operands[1].imm > 0x1000:
                    out.append((at, ecx[-1].operands[1].imm))
                break
    return out


class Emu:
    def __init__(self, d, pe, base, syms):
        self.d, self.pe, self.base, self.syms = d, pe, base, syms
        self.rev = {v: k for k, v in syms.by_name.items()}
        mu = self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(base, (pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff)
        mu.mem_write(base, d[:pe.OPTIONAL_HEADER.SizeOfHeaders])
        for s in pe.sections:
            n = min(s.SizeOfRawData, s.Misc_VirtualSize or s.SizeOfRawData)
            mu.mem_write(base + s.VirtualAddress, d[s.PointerToRawData: s.PointerToRawData + n])
        for a, n in ((STACK, STACK_SZ), (G, 0x10000), (SCRATCH, 0x100000), (SENTINEL, 0x1000), (HEAP, HEAP_SZ)):
            mu.mem_map(a, n)
        mu.mem_write(SENTINEL, b'\xf4' * 16)          # hlt; never reached: emu_start stops at SENTINEL
        self.brk = HEAP; self.calls = {}; self.stubbed = {}; self.unmapped = 0; self.error = None
        mu.hook_add(UC_HOOK_INTR, self.on_int3)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.on_unmapped)

    def alloc(self, n):
        n = max(16, (n + 15) & ~15)
        if self.brk + n > HEAP + HEAP_SZ:
            raise RuntimeError('heap exhausted')
        p = self.brk; self.brk += n
        return p

    def on_unmapped(self, uc, access, addr, size, value, _):
        self.unmapped += 1
        if self.unmapped > 64:
            return False
        uc.mem_map(addr & ~0xfff, 0x1000); return True

    def patch_calls(self, lo, hi, md):
        code = bytes(self.mu.mem_read(lo, hi - lo))
        for ins in md.disasm(code, lo):
            if ins.mnemonic != 'call':
                continue
            tgt = None
            if ins.operands[0].type == capstone.x86.X86_OP_IMM:
                tgt = ins.operands[0].imm
                name = self.syms.at(tgt)[0] or ''
                if name in ('runtime.duffzero', 'runtime.duffcopy'):
                    continue
            self.calls[ins.address] = (tgt, ins.address + ins.size, f'{ins.mnemonic} {ins.op_str}')
            self.mu.mem_write(ins.address, b'\xcc' + b'\x90' * (ins.size - 1))

    def r(self, reg):
        return self.mu.reg_read(reg)

    def on_int3(self, uc, intno, _):
        rip = uc.reg_read(UC_X86_REG_RIP) - 1           # int3 is a trap: rip is past it
        if intno != 3 or rip not in self.calls:
            self.error = f'unexpected interrupt {intno} at {rip:#x}'; uc.emu_stop(); return
        tgt, nxt, txt = self.calls[rip]
        name = (self.syms.at(tgt)[0] if tgt else None) or txt
        rax, rbx, rcx, rdi, rsi = (self.r(x) for x in (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDI, UC_X86_REG_RSI))
        try:
            if name == 'runtime.newobject':
                size = struct.unpack('<Q', uc.mem_read(rax, 8))[0]
                uc.reg_write(UC_X86_REG_RAX, self.alloc(size))
            elif name == 'runtime.makeslice':
                es = struct.unpack('<Q', uc.mem_read(rax, 8))[0]
                uc.reg_write(UC_X86_REG_RAX, self.alloc(es * rcx))
            elif name == 'runtime.mallocgc':
                uc.reg_write(UC_X86_REG_RAX, self.alloc(rax))
            elif name == 'runtime.growslice':     # (oldPtr, newLen, oldCap, num, et) -> (ptr, newLen, newCap)
                es = struct.unpack('<Q', uc.mem_read(rsi, 8))[0]
                newcap = max(rbx, 2 * rcx, 4); old = rbx - rdi
                p = self.alloc(es * newcap)
                if old and rax:
                    uc.mem_write(p, bytes(uc.mem_read(rax, es * old)))
                uc.reg_write(UC_X86_REG_RAX, p); uc.reg_write(UC_X86_REG_RCX, newcap)
            elif name == 'runtime.memmove':
                if rcx:
                    uc.mem_write(rax, bytes(uc.mem_read(rbx, rcx)))
            elif name == 'runtime.memclrNoHeapPointers':
                if rbx:
                    uc.mem_write(rax, b'\0' * rbx)
            elif name.startswith(('runtime.panic', 'runtime.throw', 'runtime.morestack', 'runtime.goPanic')):
                self.error = f'{name} reached from {rip:#x}'; uc.emu_stop(); return
            else:
                self.stubbed[name] = self.stubbed.get(name, 0) + 1
                uc.reg_write(UC_X86_REG_RAX, SCRATCH); uc.reg_write(UC_X86_REG_RBX, 0)
        except Exception as e:  # noqa: BLE001
            self.error = f'stub {name} at {rip:#x}: {e}'; uc.emu_stop(); return
        uc.reg_write(UC_X86_REG_RIP, nxt)

    def run(self, fn, fn_end, md, timeout_s=240):
        self.patch_calls(fn, fn_end, md)
        rsp = STACK + STACK_SZ - 0x10000
        self.mu.mem_write(rsp, SENTINEL.to_bytes(8, 'little'))   # return address
        self.mu.reg_write(UC_X86_REG_RSP, rsp)
        self.mu.reg_write(UC_X86_REG_R14, G)                      # g with stackguard 0: prologue never grows
        try:
            self.mu.emu_start(fn, SENTINEL, timeout=timeout_s * 1_000_000)
        except UcError as e:
            self.error = self.error or f'UcError {e} at {self.mu.reg_read(UC_X86_REG_RIP):#x}'
        rip = self.mu.reg_read(UC_X86_REG_RIP)
        if rip != SENTINEL and not self.error:
            self.error = f'stopped at {rip:#x} (timeout?)'
        return self.r(UC_X86_REG_RAX), self.r(UC_X86_REG_RBX)


def analyse(path, out_path=None):
    d = open(path, 'rb').read()
    pe = pefile.PE(data=d, fast_load=True); base = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True
    t = [s for s in pe.sections if s.Name.startswith(b'.text')][0]
    syms = SymIndex(coff_symbols(d, pe), base + t.VirtualAddress, base + t.VirtualAddress + t.Misc_VirtualSize)
    rep = {'sha256': hashlib.sha256(d).hexdigest(), 'symbols': len(syms.addr), 'tries': []}
    if not syms.addr:
        rep['result'] = 'no COFF symbols (stripped build): v2 needs function bounds'; return rep
    seen = set()
    for at, nq in sorted(builder_sites(d, pe, base, md), key=lambda x: -x[1]):
        name, fn = syms.at(at)
        if fn in seen or not name or not name.startswith('main.'):
            continue
        seen.add(fn)
        emu = Emu(d, pe, base, syms)
        ptr, ln = emu.run(fn, syms.end_of(fn), md)
        tr = {'fn': name, 'fn_va': hex(fn), 'rep_movsq': hex(at), 'qwords': nq, 'calls_patched': len(emu.calls),
              'stubbed': sum(emu.stubbed.values()), 'stub_kinds': len(emu.stubbed), 'unmapped_pages': emu.unmapped,
              'error': emu.error, 'ret_len': ln}
        rep['tries'].append(tr)
        if emu.error or not (0 < ln < 0x4000000):
            continue
        out = bytes(emu.mu.mem_read(ptr, ln))
        tr['out_sha256'] = hashlib.sha256(out).hexdigest(); tr['mz'] = out[:2] == b'MZ'
        if tr['mz']:
            p2 = pefile.PE(data=out, fast_load=True)
            end = max(s.PointerToRawData + s.SizeOfRawData for s in p2.sections)
            rep.update(result='PE', fn=name, pe_len=end, pe_sha256=hashlib.sha256(out[:end]).hexdigest(),
                       trailer_len=len(out) - end, machine=hex(p2.FILE_HEADER.Machine),
                       file_layout=(len(out[:end]) != p2.OPTIONAL_HEADER.SizeOfImage))
            if out_path:
                open(out_path, 'wb').write(out[:end])
            return rep
    rep.setdefault('result', 'no MZ from any builder function')
    return rep


if __name__ == '__main__':
    print(json.dumps(analyse(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None), indent=1))
