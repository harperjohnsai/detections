"""CNCMachineRMS / BabaDeda 'Storage' container: header scan + layer-1 (record tree) + layer-2 (blob XOR).

Format reconstructed from the loader shellcode routines (validated by emulating them in bare
unicorn, see emu_validate.py) and cross-checked with LevelBlue's published header equations.
All arithmetic is mod 2**64 unless noted.  K = per-build key, k = D[0] (per-file value).
"""
import struct
from dataclasses import dataclass, field

M = 1 << 64
INV3 = pow(3, -1, M)
HDR = 0x78
REC = 0x58


def header_key(q):
    """Return build key K if the 7 qwords satisfy the three header equations, else None."""
    k = q[0]
    K = ((q[1] - 7 * k) * INV3) % M
    if q[5] != (q[1] - 37 * (k + K)) % M:
        return None
    if q[6] != ((k + K + 1) * (q[5] + 1)) % M:
        return None
    return K


def _candidates(data, start, end):
    """Offsets where the three header equations hold (vectorised with numpy when available)."""
    try:
        import numpy as np
    except ImportError:
        unpack = struct.Struct('<7Q').unpack_from
        return [o for o in range(start, end + 1) if header_key(unpack(data, o)) is not None]
    out = []
    mv = memoryview(data)
    with np.errstate(over='ignore'):
        for r in range(8):
            n8 = (len(data) - r) // 8
            if n8 < 7:
                continue
            a = np.frombuffer(mv[r:r + n8 * 8], dtype='<u8')
            q0, q1, q5, q6 = a[:-6], a[1:-5], a[5:-1], a[6:]
            inv3 = np.uint64(INV3)
            K = (q1 - np.uint64(7) * q0) * inv3
            ok = (q5 == q1 - np.uint64(37) * (q0 + K)) & (q6 == (q0 + K + np.uint64(1)) * (q5 + np.uint64(1)))
            for j in np.nonzero(ok)[0]:
                o = r + 8 * int(j)
                if start <= o <= end:
                    out.append(o)
    return sorted(out)


def scan_headers(data, start=0, end=None, strict=True):
    """Yield (offset, K) for every Storage header in a buffer (unaligned byte scan).
    strict=True also requires that the parsed header describes a table that fits the buffer."""
    end = len(data) - HDR if end is None else min(end, len(data) - HDR)
    unpack = struct.Struct('<7Q').unpack_from
    for off in _candidates(data, start, end):
        K = header_key(unpack(data, off))
        if K is None:
            continue
        if strict:
            try:
                Storage(data, off, K)
            except ValueError:
                continue
        yield off, K


# Layer 2: XOR keystream  ks[i] = (k' + mult*i + c*2**i) & 0xff  (the c term only matters for i < 8)  with the record key byte k mapped to
#   k' = (a*k + b) & 0xff   if lo < k < hi        (small keys are remapped)
#   k' = (k + off) & 0xff   otherwise
# (mult, off, lo, hi, a, b, c) are build constants, different in every build we have seen:
#   loader3       ROMULUS/Stardock loader shellcode  - re-derived by emulating its own routine (emu_validate.py)
#   baba-loader   BabaDeda load.db blobs             - fitted from the data (key 14->68, 21->96, 25->112, 32->140, 36->156)
#   rat-embedded  config embedded in the payload     - fitted (key 6->25, 7->28, 25->82, 29->94)
#   off7          numeric-name MSI (K=0x4870ffc2)    - fitted: ks = k-7 + 238*i for every key
#   fi-loader     FilesInspectorX.msi (K=0x71f0b446) - fitted: like baba-loader with k' = 3k+8
#   (learned)     AllMyBasic.msi (K=0x32be4757)      - ks = k-8 + 30*2**i (c term), learned from the data
# Unknown builds: the parameters are learned from the data (strings/ints have a zero top byte), see learn_params().
# Canon-chain build (ISOSimple.msi, K=0x26ace8d1): keystream is non-linear, NOT reproduced (documented gap).
KNOWN = {'loader3': (3, 0, 5, 0x27, 2, 12, 0), 'baba-loader': (0, 0, 5, 0x27, 4, 12, 0),
         'rat-embedded': (0, 0, 5, 0x27, 3, 7, 0), 'off7': (238, 249, 5, 0x27, 1, 249, 0),
         'fi-loader': (0, 0, 5, 0x27, 3, 8, 0)}


def _kprime(k, p):
    mult, off, lo, hi, a, b = p[:6]
    return (a * k + b) & 0xFF if lo < k < hi else (k + off) & 0xFF


def dec_blob(buf, key, params=KNOWN['loader3']):
    """Layer 2 XOR keystream for one blob."""
    if not buf or not key:
        return bytes(buf)
    kp = _kprime(key & 0xFF, params)
    mult, c = params[0], (params[6] if len(params) > 6 else 0)
    out = bytes(x ^ ((kp + mult * i) & 0xFF) for i, x in enumerate(buf))
    if c:                                   # additive start-up transient c*2**i, zero from i = 8 on
        out = bytes(x ^ ((kp + mult * i + (c << i)) & 0xFF) for i, x in enumerate(buf[:8])) + out[8:]
    return out


def _top_zero_score(data, recs, params):
    """Fraction of small even-length blobs (ints / UTF-16 strings) whose last byte decrypts to 0."""
    n = ok = 0
    for r in recs:
        last = data[r.off + r.length - 1] ^ ((_kprime(r.key & 0xFF, params) + params[0] * (r.length - 1)) & 0xFF)
        n += 1
        ok += last == 0
    return ok / n if n else 0.0


def _plausible(b):
    """UTF-16 text after the 8-byte start-up transient (i >= 8), or x64 stub / PE at the start."""
    if b[:4] == b'\x48\x83\xec\x28' or b[:2] == b'MZ':
        return 1.0
    t = b[8:96]
    if len(t) >= 32 and not any(t[1::2]):
        return sum(32 <= c < 127 or c in (9, 10, 13) for c in t[0::2]) / len(t[0::2])
    return 0.0


SMALL = (4, 8, 16, 20, 26, 28, 36, 38, 40, 44, 46)


def learn_params(data, records):
    """Fit (mult, off, a, b) from the data: even-length small blobs have a zero top byte."""
    import numpy as np
    small = [r for r in records if r.enc and r.length in SMALL]
    out = [r for r in small if not 5 < r.key < 0x27]
    inn = [r for r in small if 5 < r.key < 0x27]
    long_out = [r for r in out if r.length >= 10]       # i = len-1 >= 9: the c*2**i start-up term has vanished
    if len(long_out) >= 20:
        out = long_out
    if not out:
        return None
    keys = np.array([r.key for r in out], dtype=np.int64)
    top = np.array([data[r.off + r.length - 1] for r in out], dtype=np.int64)
    li = np.array([r.length - 1 for r in out], dtype=np.int64)
    cands = []
    for mult in range(256):
        # top ^ ((k+off+mult*i)&255) == 0  <=>  off == (top - k - mult*i) & 255
        offs = (top - keys - mult * li) & 255
        cnt = np.bincount(offs, minlength=256)
        o = int(cnt.argmax())
        cands.append((cnt[o] / len(out), mult, o))
    cands.sort(reverse=True)
    bs = cands[0][0]
    if bs < 0.7:
        return None
    big = sorted((r for r in records if r.enc and r.length > 64 and not 5 < r.key < 0x27), key=lambda r: -r.length)[:6]
    best, bscore = None, -1.0
    for sc, mult, o in cands:
        if sc < bs * 0.95:
            break
        ps = sum(_plausible(dec_blob(data[r.off:r.off + 96], r.key, (mult, o, 5, 0x27, 1, o, 0))) for r in big)
        if ps > bscore:
            best, bscore = (mult, o), ps
    mult, off = best
    bs2, ab = -1.0, (1, off)
    if inn:
        long_inn = [r for r in inn if r.length >= 10]
        if len(long_inn) >= 10:
            inn = long_inn
        keys = np.array([r.key for r in inn], dtype=np.int64)
        top = np.array([data[r.off + r.length - 1] for r in inn], dtype=np.int64)
        li = np.array([r.length - 1 for r in inn], dtype=np.int64)
        for a in range(256):
            kb = (top - mult * li - a * keys) & 255   # required b per record
            cnt = np.bincount(kb, minlength=256)
            b = int(cnt.argmax())
            sc = cnt[b] / len(inn)
            if sc > bs2:
                bs2, ab = sc, (a, b)
        if bs2 < 0.6:
            return None
    p = (mult, off, 5, 0x27) + ab + (0,)
    return p[:6] + (_learn_c(data, records, p),)


def _learn_c(data, records, p):
    """Fit the c*2**i start-up transient: plaintext strings/ints have zero bytes at the odd positions 1,3,5,7."""
    cand = [r for r in records if r.enc and 8 <= r.length <= 200 and r.length % 2 == 0]
    best, bs = 0, -1
    for c in range(256):
        q = p[:6] + (c,)
        sc = sum(sum(dec_blob(data[r.off:r.off + 8], r.key, q)[1:8:2]) == 0 for r in cand)
        if sc > bs:
            best, bs = c, sc
    return best


@dataclass
class Record:
    index: int
    node: int       # node id
    parent: int
    prop: int       # property id (16001 = script, 16100 = payload ...)
    length: int     # blob length
    f20: int
    f21: int
    enc: int        # blob is layer-2 encrypted
    key: int        # layer-2 key byte
    f24: int
    f25: int
    off: int = 0    # absolute offset of the blob in the buffer
    blob: bytes = b''


class Storage:
    def __init__(self, data, off=0, K=None, variant=None):
        self.data, self.base = data, off
        if len(data) - off < HDR:
            raise ValueError('short')
        D = struct.unpack_from('<15Q', data, off)
        if K is None:
            K = header_key(D[:7])
        if K is None or header_key(D[:7]) != K:
            raise ValueError('header equations do not hold')
        self.K, self.D = K, D
        # header meta (version check), layer-1 table meta
        base = (D[0] * D[1]) % M
        self.version = (D[2] - (K - base + D[5])) & 0xFFFF
        T = D[10:15]
        self.n = (T[2] - K * T[1] - T[0]) % M
        n2 = (T[3] - K * T[0] + T[1]) % M
        if self.version != 1 or self.n != n2 or self.n == 0 or self.n > 1 << 20:
            raise ValueError('table meta inconsistent')
        self.blob_base = off + HDR + self.n * REC
        if self.blob_base > len(data):
            raise ValueError('table does not fit')
        self.records = []
        pos = self.blob_base
        for i in range(self.n):
            R = struct.unpack_from('<11Q', data, off + HDR + i * REC)
            x = R[0]
            rec = Record(
                i,
                (R[1] - K * x - x) % M,
                (R[2] - K + 3 * x) % M,
                (R[3] - K * (x + 5) + 2 * x) % M,
                (R[4] - K - 7 * x) % M,
                int((R[5] - 2 * K + 2 * x) % M != 0),
                (R[6] - K + 4 * x) & 0xFF,
                int((R[7] - 3 * K + 3 * x) % M != 0),
                (R[8] - K * x + 4 * x) & 0xFF,
                int((R[9] - 5 * K + x) % M != 0),
                (R[10] - K + 5 * x) & 0xFF,
            )
            rec.off = pos
            pos += rec.length
            self.records.append(rec)
        self.end = pos
        if self.end > len(data):
            raise ValueError('blobs exceed buffer')
        if isinstance(variant, tuple):
            self.variant, self.params = 'custom', variant
        elif variant:
            self.variant, self.params = variant, KNOWN[variant]
        else:
            self.variant, self.params = self._detect()
        self.layer2_ok = self.params is not None
        for r in self.records:
            raw = data[r.off:r.off + r.length]
            r.blob = dec_blob(raw, r.key, self.params) if (r.enc and self.params) else bytes(raw)

    def _detect(self):
        """Choose the layer-2 parameters: best of the known builds and the data-learned fit (ties -> known)."""
        small = [r for r in self.records if r.enc and r.length in SMALL]
        if sum(r.length >= 10 for r in small) >= 30:      # ignore 8-byte values: the start-up term can still act there
            small = [r for r in small if r.length >= 10]
        cands = [(n, p) for n, p in KNOWN.items()]
        learned = learn_params(self.data, self.records)
        if learned and learned not in KNOWN.values():
            cands.append(('learned', learned))
        best, bs = None, 0.0
        for n, p in cands:
            sc = _top_zero_score(self.data, small, p)
            if sc > bs + 1e-9:
                best, bs = (n, p), sc
        return best if best and bs >= 0.6 else ('unresolved', None)

    def by_prop(self, prop):
        return [r for r in self.records if r.prop == prop]
