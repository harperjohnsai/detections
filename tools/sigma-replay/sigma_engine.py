"""Small in-process Sigma matcher (no SQL backend) for replaying rules over normalised Windows events.

Supported: field modifiers contains/startswith/endswith/all/re(+i,m,s)/cidr/windash/base64/base64offset/
utf16le/utf16be/wide/lt/lte/gt/gte/exists/fieldref/cased, wildcards (* ?, backslash escapes), null values,
keyword searches, conditions with and/or/not/parentheses and "1 of x*" / "all of them" / "N of".
Not supported (rule is reported as skipped with a reason): aggregations (count/near/|), correlation rules,
`expand` placeholders, non-Windows log sources.
"""
from __future__ import annotations
import base64, ipaddress, re, pathlib
from dataclasses import dataclass, field
import yaml

DASHES = "-/\u2013\u2014\u2015"

# ---------------------------------------------------------------- logsource routing
# (kind, eids|None, extra predicate name|None)
CAT = {
    "process_creation": [("sysmon", {1}, None), ("security", {4688}, None)],
    "image_load": [("sysmon", {7}, None)],
    "registry_set": [("sysmon", {13}, None)],
    "registry_add": [("sysmon", {12}, "regadd")],
    "registry_delete": [("sysmon", {12}, "regdel")],
    "registry_event": [("sysmon", {12, 13, 14}, None)],
    "file_event": [("sysmon", {11}, None)],
    "file_change": [("sysmon", {2}, None)],
    "file_delete": [("sysmon", {23, 26}, None)],
    "network_connection": [("sysmon", {3}, None)],
    "dns_query": [("sysmon", {22}, None)],
    "create_remote_thread": [("sysmon", {8}, None)],
    "process_access": [("sysmon", {10}, None)],
    "pipe_created": [("sysmon", {17, 18}, None)],
    "driver_load": [("sysmon", {6}, None)],
    "raw_access_thread": [("sysmon", {9}, None)],
    "process_termination": [("sysmon", {5}, None)],
    "create_stream_hash": [("sysmon", {15}, None)],
    "wmi_event": [("sysmon", {19, 20, 21}, None)],
    "process_tampering": [("sysmon", {25}, None)],
    "ps_script": [("powershell", {4104}, None)],
    "ps_module": [("powershell", {4103}, None)],
    "ps_classic_start": [("powershell-classic", {400}, None)],
    "ps_classic_provider_start": [("powershell-classic", {600}, None)],
}
SERVICE = {
    "security": "security", "system": "system", "application": "application", "sysmon": "sysmon",
    "powershell": "powershell", "powershell-classic": "powershell-classic", "taskscheduler": "taskscheduler",
    "wmi": "wmi", "windefend": "windefend", "bits-client": "bits-client", "dns-server": "dns-server",
    "ntlm": "ntlm", "smbclient-security": "smbclient-security",
    "firewall-as": "firewall-as", "terminalservices-localsessionmanager": "terminalservices-localsessionmanager",
    "codeintegrity-operational": "codeintegrity-operational", 
    "applocker": "applocker",
}

# ---------------------------------------------------------------- value predicates
_tok = re.compile(r"\\\\|\\\*|\\\?|\*|\?")


def _parts(s: str):
    """split a sigma string into literal/wildcard tokens"""
    out, pos = [], 0
    lit = []
    i = 0
    while i < len(s):
        m = _tok.match(s, i)
        if m:
            t = m.group(0)
            if t == "\\\\":
                lit.append("\\")   # pySigma: an escaped backslash is one literal backslash
            elif t in ("\\*", "\\?"):
                lit.append(t[1])
            else:
                if lit: out.append(("l", "".join(lit))); lit = []
                out.append(("w", t))
            i = m.end()
        else:
            lit.append(s[i]); i += 1
    if lit: out.append(("l", "".join(lit)))
    return out


def _to_regex(parts, mod, windash=False):
    rx = []
    for k, v in parts:
        if k == "w":
            rx.append(".*" if v == "*" else ".")
        else:
            e = re.escape(v)
            if windash:
                e = re.sub(r"(?:(?<![A-Za-z0-9_])\\-|(?<![A-Za-z0-9_\\])-|(?<![A-Za-z0-9_])/)(?=[A-Za-z0-9_])", "[" + re.escape(DASHES) + "]", e)
            rx.append(e)
    body = "".join(rx)
    if mod == "contains": body = ".*" + body + ".*"
    elif mod == "startswith": body = body + ".*"
    elif mod == "endswith": body = ".*" + body
    return re.compile("^" + body + r"\Z", re.S)


def _b64_variants(raw: bytes, offset: bool):
    """base64 of the value; with offset: the 3 alignments, keeping only characters fully determined by the value
    (leading chars shared with the padding bytes and trailing chars shared with following bytes are cut)."""
    if not offset:
        return [base64.b64encode(raw).decode()]
    out = []
    for i, st in enumerate((0, 2, 3)):
        enc = base64.b64encode(b" " * i + raw).decode().rstrip("=")
        full = ((len(raw) + i) * 8) // 6
        out.append(enc[st:full])
    return out


class Unsupported(Exception):
    pass


def _value_preds(mods, values, cased):
    """return list of callables(str)->bool for the values"""
    base = [m for m in mods if m in ("contains", "startswith", "endswith")]
    mod = base[0] if base else "eq"
    windash = "windash" in mods
    enc = [m for m in mods if m in ("base64", "base64offset", "utf16le", "utf16be", "wide", "utf16")]
    if "expand" in mods:
        raise Unsupported("expand modifier")
    preds = []
    for v in values:
        if isinstance(v, bool) or v is None:
            v = str(v).lower() if v is not None else v
        if "re" in mods:
            fl = 0
            if "i" in mods: fl |= re.I
            if "m" in mods: fl |= re.M
            if "s" in mods: fl |= re.S
            rx = re.compile(str(v), fl)
            preds.append(lambda s, rx=rx: rx.search(s) is not None)
            continue
        if "cidr" in mods:
            net = ipaddress.ip_network(str(v), strict=False)
            def f(s, net=net):
                try: return ipaddress.ip_address(s.strip()) in net
                except ValueError: return False
            preds.append(f); continue
        if mods and any(m in ("lt", "lte", "gt", "gte") for m in mods):
            op = [m for m in mods if m in ("lt", "lte", "gt", "gte")][0]
            num = float(v)
            def f(s, op=op, num=num):
                try: x = float(s)
                except ValueError: return False
                return {"lt": x < num, "lte": x <= num, "gt": x > num, "gte": x >= num}[op]
            preds.append(f); continue
        sv = str(v)
        if enc:
            raw = sv.encode("utf-16le") if any(m in enc for m in ("utf16le", "wide", "utf16")) else (
                sv.encode("utf-16be") if "utf16be" in enc else sv.encode())
            if "base64" in enc or "base64offset" in enc:
                vs = _b64_variants(raw, "base64offset" in enc)
                rxs = [re.compile(re.escape(x)) for x in vs]
                preds.append(lambda s, rxs=rxs: any(r.search(s) for r in rxs))
            else:
                t = raw.decode("latin-1")
                if not cased: t = t.lower()
                preds.append(lambda s, t=t: t in s)
            continue
        parts = _parts(sv)
        has_wild = any(k == "w" for k, _ in parts)
        lit = "".join(x for k, x in parts)
        if not has_wild and not windash:
            if not cased: lit = lit.lower()
            if mod == "contains": preds.append(lambda s, l=lit: l in s)
            elif mod == "startswith": preds.append(lambda s, l=lit: s.startswith(l))
            elif mod == "endswith": preds.append(lambda s, l=lit: s.endswith(l))
            else: preds.append(lambda s, l=lit: s == l)
        else:
            parts = [(k, x if cased or k == "w" else x.lower()) for k, x in parts]
            rx = _to_regex(parts, mod, windash)
            preds.append(lambda s, rx=rx: rx.match(s) is not None)
    return preds


# ---------------------------------------------------------------- event accessors
def _str(v):
    if v is None: return None
    if isinstance(v, str): return v
    if isinstance(v, bool): return "true" if v else "false"
    return str(v)


class Ev:
    """event wrapper with lowercase cache"""
    __slots__ = ("d", "lc", "_all")

    def __init__(self, d):
        self.d = d if "EventID" in d or "_eid" not in d else dict(d, EventID=d["_eid"])   # rules select on EventID
        self.lc = {}; self._all = None

    def get(self, f, cased=False):
        v = self.d.get(f)
        if v is None:
            return None
        s = _str(v)
        if cased: return s
        l = self.lc.get(f)
        if l is None:
            l = s.lower(); self.lc[f] = l
        return l

    def alltext(self):
        if self._all is None:
            self._all = "\n".join(_str(v).lower() for k, v in self.d.items() if not k.startswith("_") and v is not None)
        return self._all


def _field_matcher(key, val):
    parts = key.split("|")
    fname, mods = parts[0], parts[1:]
    cased = any(m in mods for m in ("cased", "base64", "base64offset", "re"))
    if "exists" in mods:
        want = bool(val)
        return lambda ev: (ev.d.get(fname) is not None) == want
    vals = val if isinstance(val, list) else [val]
    if "fieldref" in mods:
        refs = [str(v) for v in vals]
        return lambda ev: any(ev.get(fname) is not None and ev.get(fname) == ev.get(r) for r in refs)
    has_null = any(v is None for v in vals)
    vals_nn = [v for v in vals if v is not None]
    preds = _value_preds(mods, vals_nn, cased) if vals_nn else []
    use_all = "all" in mods

    def m(ev):
        s = ev.get(fname, cased)
        if s is None or s == "":
            null_ok = has_null and not (use_all and preds)
            return null_ok or (s == "" and any(str(v) == "" for v in vals_nn))
        if not preds:
            return False
        if use_all:
            return all(p(s) for p in preds)
        for p in preds:
            if p(s): return True
        return False
    return m


def _keyword_matcher(vals):
    preds = _value_preds(["contains"], [str(v) for v in vals], False)
    return lambda ev: any(p(ev.alltext()) for p in preds)


def _keyword_field_matcher(mods, val):
    vals = val if isinstance(val, list) else [val]
    preds = _value_preds(["contains"] + [m for m in mods if m != "all"], [str(v) for v in vals], False)
    if "all" in mods:
        return lambda ev: all(p(ev.alltext()) for p in preds)
    return lambda ev: any(p(ev.alltext()) for p in preds)


def _compile_search(node):
    if isinstance(node, dict):
        ms = []
        for k, v in node.items():
            if k.split("|")[0] == "":      # keyword map such as {"|all": [...]} or {"|contains": [...]}
                ms.append(_keyword_field_matcher(k.split("|")[1:], v))
            else:
                ms.append(_field_matcher(k, v))
        return lambda ev: all(m(ev) for m in ms)
    if isinstance(node, list):
        if all(isinstance(x, dict) for x in node):
            subs = [_compile_search(x) for x in node]
            return lambda ev: any(s(ev) for s in subs)
        return _keyword_matcher([x for x in node])
    if isinstance(node, (str, int, float)):
        return _keyword_matcher([node])
    raise Unsupported("detection node type %s" % type(node))


# ---------------------------------------------------------------- condition parser
_ctok = re.compile(r"\s*(\(|\)|\||[^\s()|]+)")


def _tokenize(c):
    return _ctok.findall(c)


def _parse_condition(cond, names):
    toks = _tokenize(cond)
    if "|" in toks:
        raise Unsupported("aggregation/pipe in condition")
    pos = [0]

    def peek(): return toks[pos[0]] if pos[0] < len(toks) else None

    def eat(): pos[0] += 1; return toks[pos[0] - 1]

    def match_names(pat):
        if pat == "them":
            return [n for n in names if not n.startswith("_")]
        rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$")
        out = [n for n in names if rx.match(n)]
        if not out: raise Unsupported("no search matches %s" % pat)
        return out

    def p_or():
        l = p_and()
        while peek() and peek().lower() == "or":
            eat(); r = p_and(); l = (lambda a, b: lambda R: a(R) or b(R))(l, r)
        return l

    def p_and():
        l = p_not()
        while peek() and peek().lower() == "and":
            eat(); r = p_not(); l = (lambda a, b: lambda R: a(R) and b(R))(l, r)
        return l

    def p_not():
        if peek() and peek().lower() == "not":
            eat(); x = p_not(); return lambda R: not x(R)
        return p_atom()

    def p_atom():
        t = eat()
        if t == "(":
            x = p_or()
            if eat() != ")": raise Unsupported("paren")
            return x
        tl = t.lower()
        if (tl in ("all", "any") or tl.isdigit()) and peek() and peek().lower() == "of":
            eat(); pat = eat(); ns = match_names(pat)
            if tl == "all": return lambda R, ns=ns: all(R(n) for n in ns)
            k = 1 if tl == "any" else int(tl)
            return lambda R, ns=ns, k=k: sum(1 for n in ns if R(n)) >= k
        if t not in names:
            raise Unsupported("unknown search %s" % t)
        return lambda R, t=t: R(t)

    f = p_or()
    if pos[0] != len(toks): raise Unsupported("trailing tokens in condition")
    return f


# ---------------------------------------------------------------- rules
@dataclass
class Rule:
    path: str
    title: str
    id: str
    level: str
    status: str
    tags: list
    logsource: dict
    routes: list = field(default_factory=list)   # (kind, eids|None, pred|None)
    match: object = None
    skip_reason: str | None = None

    @property
    def techniques(self):
        out = []
        for t in self.tags or []:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", str(t).lower())
            if m: out.append(m.group(1).upper())
        return out

    @property
    def tactics(self):
        return [str(t)[7:] for t in (self.tags or []) if str(t).startswith("attack.") and not re.match(r"attack\.t\d{4}", str(t).lower())]


def _routes(ls):
    prod = str(ls.get("product", "")).lower()
    cat = ls.get("category"); svc = ls.get("service")
    if prod and prod != "windows":
        raise Unsupported("logsource product %s (no corpus)" % prod)
    if not prod:
        raise Unsupported("logsource without product (no corpus)")
    if cat:
        if cat not in CAT: raise Unsupported("logsource category %s (no corpus)" % cat)
        return list(CAT[cat])
    if svc:
        if svc not in SERVICE: raise Unsupported("logsource service %s (no corpus)" % svc)
        return [(SERVICE[svc], None, None)]
    return [("*", None, None)]


def load_rule(path: pathlib.Path, doc: dict, ignore_logsource: bool = False) -> Rule:
    r = Rule(str(path), doc.get("title", path.stem), str(doc.get("id", "")), doc.get("level", ""), doc.get("status", ""),
             doc.get("tags") or [], doc.get("logsource") or {})
    try:
        if "correlation" in doc: raise Unsupported("correlation rule")
        det = doc.get("detection")
        if not isinstance(det, dict): raise Unsupported("no detection")
        r.routes = [("*", None, None)] if ignore_logsource else _routes(r.logsource)
        cond = det.get("condition")
        conds = cond if isinstance(cond, list) else [cond]
        searches = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
        compiled = {k: _compile_search(v) for k, v in searches.items()}
        cfs = [_parse_condition(c, list(compiled)) for c in conds]

        def match(ev, compiled=compiled, cfs=cfs):
            memo = {}
            def R(n):
                v = memo.get(n)
                if v is None:
                    v = compiled[n](ev); memo[n] = v
                return v
            return any(cf(R) for cf in cfs)
        r.match = match
    except Unsupported as e:
        r.skip_reason = str(e)
    except (re.error, ValueError, TypeError) as e:
        r.skip_reason = "compile error: %s" % e
    return r


def load_rules(paths, only_windows=False):
    """paths: file or dir(s). returns list[Rule]"""
    files = []
    for p in paths:
        p = pathlib.Path(p)
        files += [p] if p.is_file() else sorted(list(p.rglob("*.yml")) + list(p.rglob("*.yaml")))
    rules = []
    for f in files:
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(encoding="utf-8")) if isinstance(d, dict)]
        except Exception as e:
            rules.append(Rule(str(f), f.stem, "", "", "", [], {}, skip_reason="yaml parse error: %s" % str(e)[:80]))
            continue
        for d in docs:
            if "detection" not in d and "correlation" not in d: continue
            rules.append(load_rule(f, d))
    return rules


# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, rules):
        self.rules = [r for r in rules if r.match]
        self.skipped = [r for r in rules if not r.match]
        self._idx = {}

    def candidates(self, kind, eid):
        k = (kind, eid)
        c = self._idx.get(k)
        if c is None:
            c = []
            for r in self.rules:
                for rk, eids, pred in r.routes:
                    if (rk == "*" or rk == kind) and (eids is None or eid in eids):
                        c.append((r, pred)); break
            self._idx[k] = c
        return c

    def run(self, d):
        """d: normalised event dict with _kind/_eid. Returns (matched_rules, evaluated_rules)."""
        ev = Ev(d)
        hit, seen = [], []
        for r, pred in self.candidates(d.get("_kind"), d.get("_eid")):
            if pred == "regadd" and d.get("EventType") != "CreateKey": continue
            if pred == "regdel" and d.get("EventType") not in ("DeleteKey", "DeleteValue"): continue
            seen.append(r)
            if r.match(ev): hit.append(r)
        return hit, seen
