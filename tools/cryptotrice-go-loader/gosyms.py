"""COFF symbol table reader for Go PEs (Go's linker writes one unless built with -s). Returns {name: va} and a
sorted list for address -> enclosing symbol lookups. Static only."""
import bisect, struct


def coff_symbols(d, pe):
    ptr, n = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
    if not ptr or not n:
        return {}
    strtab = ptr + n * 18
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = pe.sections
    out = {}
    i = 0
    while i < n:
        e = d[ptr + i * 18: ptr + i * 18 + 18]
        if len(e) < 18:
            break
        name, value, sec, typ, cls, naux = struct.unpack('<8sIhHBB', e)
        if name[:4] == b'\0\0\0\0':
            o = strtab + struct.unpack('<I', name[4:])[0]
            name = d[o: d.index(b'\0', o)]
        else:
            name = name.rstrip(b'\0')
        if 0 < sec <= len(secs):
            out[name.decode('latin1')] = base + secs[sec - 1].VirtualAddress + value
        i += 1 + naux
    return out


class SymIndex:
    def __init__(self, syms, text_lo, text_hi):
        items = sorted((v, k) for k, v in syms.items() if text_lo <= v < text_hi)
        self.addr = [a for a, _ in items]; self.name = [k for _, k in items]
        self.by_name = syms

    def at(self, va):
        i = bisect.bisect_right(self.addr, va) - 1
        return (self.name[i], self.addr[i]) if i >= 0 else (None, None)

    def end_of(self, va):
        i = bisect.bisect_right(self.addr, va)
        return self.addr[i] if i < len(self.addr) else None
