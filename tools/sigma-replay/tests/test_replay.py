"""Replay-harness tests. Fixtures: two real Sysmon EID1 events from OTRF/Security-Datasets (MIT), see fixtures/."""
import json, pathlib, sys
import pytest
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import corpus, sigma_engine as se  # noqa: E402

FX = pathlib.Path(__file__).resolve().parent / "fixtures"


def events():
    out = {}
    for line in open(FX / "otrf_sample_events.jsonl"):
        o = json.loads(line)
        tag = o.pop("_fixture"); o.pop("_source_dataset"); o.pop("_attribution")
        eid = o.pop("EventID")
        out[tag] = corpus.finish(o, eid, o.get("Channel", "Microsoft-Windows-Sysmon/Operational"))
    return out


def run(rule_yaml, ev):
    import yaml
    r = se.load_rule(pathlib.Path("x.yml"), yaml.safe_load(rule_yaml))
    assert r.skip_reason is None, r.skip_reason
    hit, seen = se.Engine([r]).run(ev)
    return bool(hit), bool(seen)


def test_known_tp_fires_on_real_event_and_not_on_negative():
    ev = events()
    rules = se.load_rules([FX / "proc_creation_win_schtasks_create_demo.yml"])
    eng = se.Engine(rules)
    hit, seen = eng.run(ev["tp"])
    assert [r.title for r in hit] == ["Schtasks Create With Hidden PowerShell Payload (replay test fixture)"]
    hit, seen = eng.run(ev["neg"])
    assert hit == [] and len(seen) == 1   # evaluated (right logsource) but no match


def test_logsource_routing_skips_wrong_event_kind():
    ev = events()["tp"]
    ev2 = dict(ev, _eid=3)    # network connection: process_creation rule must not even be evaluated
    rules = se.load_rules([FX / "proc_creation_win_schtasks_create_demo.yml"])
    hit, seen = se.Engine(rules).run(ev2)
    assert hit == [] and seen == []


BASE = "title: t\nlogsource: {category: process_creation, product: windows}\ndetection:\n"


@pytest.mark.parametrize("det,cmd,expect", [
    ("  s: {CommandLine|contains: 'MiXeD'}\n  condition: s", "xx mixed yy", True),
    ("  s: {CommandLine|startswith: 'abc'}\n  condition: s", "abcdef", True),
    ("  s: {CommandLine|endswith: 'def'}\n  condition: s", "abcdef", True),
    ("  s: {CommandLine|contains|all: ['a1','b2']}\n  condition: s", "a1 b2", True),
    ("  s: {CommandLine|contains|all: ['a1','b2']}\n  condition: s", "a1 zz", False),
    ("  s: {CommandLine|contains: ['a1','b2']}\n  condition: s", "zz b2", True),
    ("  s: {CommandLine: 'ab*ef'}\n  condition: s", "abcdef", True),
    ("  s: {CommandLine: 'ab?def'}\n  condition: s", "abcdef", True),
    ("  s: {CommandLine|re: 'a.c+d'}\n  condition: s", "abccd", True),
    ("  s: {CommandLine|contains|windash: ' -enc'}\n  condition: s", "ps /enc xx", True),
    ("  s: {CommandLine|contains|windash: ' -enc'}\n  condition: s", "ps \u2013enc xx", True),
    ("  s: {Image: null}\n  condition: s", "x", True),      # null matches a missing field
    ("  a: {CommandLine|contains: 'x'}\n  b: {CommandLine|contains: 'y'}\n  condition: a and not b", "x", True),
    ("  a: {CommandLine|contains: 'x'}\n  b: {CommandLine|contains: 'y'}\n  condition: a and not b", "x y", False),
    ("  sel_a: {CommandLine|contains: 'x'}\n  sel_b: {CommandLine|contains: 'y'}\n  condition: 1 of sel_*", "y", True),
    ("  sel_a: {CommandLine|contains: 'x'}\n  sel_b: {CommandLine|contains: 'y'}\n  condition: all of them", "y", False),
    ("  kw: ['needle']\n  condition: kw", "has needle in it", True),
])
def test_modifiers_and_conditions(det, cmd, expect):
    ev = {"_eid": 1, "_kind": "sysmon", "Image": "C:\\a.exe" if "Image: null" not in det else "", "CommandLine": cmd}
    if "Image: null" in det: ev.pop("Image")
    assert run(BASE + det, ev)[0] is expect


def test_cidr_and_numeric():
    ev = {"_eid": 3, "_kind": "sysmon", "DestinationIp": "10.1.2.3", "DestinationPort": "445"}
    y = "title: t\nlogsource: {category: network_connection, product: windows}\ndetection:\n  s: {DestinationIp|cidr: 10.0.0.0/8, DestinationPort|gte: 400}\n  condition: s\n"
    y = y.replace("{DestinationIp|cidr: 10.0.0.0/8, DestinationPort|gte: 400}", "{DestinationIp|cidr: '10.0.0.0/8', DestinationPort|gte: 400}")
    assert run(y, ev)[0] is True


def test_aggregation_rules_are_skipped_not_misreported():
    import yaml
    d = yaml.safe_load(BASE + "  s: {CommandLine|contains: x}\n  condition: s | count() by Image > 5")
    r = se.load_rule(pathlib.Path("x.yml"), d)
    assert r.skip_reason and "aggregation" in r.skip_reason


def test_security_4688_is_mapped_to_sysmon_field_names():
    ev = corpus.finish({"NewProcessName": "C:\\Windows\\System32\\whoami.exe", "ParentProcessName": "C:\\x\\cmd.exe", "CommandLine": "whoami"}, 4688, "Security")
    y = BASE + "  s: {Image|endswith: '\\whoami.exe', ParentImage|endswith: '\\cmd.exe'}\n  condition: s"
    assert run(y, ev)[0] is True


@pytest.mark.skipif(not (ROOT / "src/sigmahq/rules/windows/process_creation").exists(), reason="SigmaHQ clone absent")
def test_sigmahq_rule_fires_on_real_event():
    ev = events()["tp"]
    rules = [r for r in se.load_rules([ROOT / "src/sigmahq/rules/windows/process_creation"]) if r.title == "Scheduled Task Creation Via Schtasks.EXE"]
    assert rules
    hit, _ = se.Engine(rules).run(ev)
    assert hit


def test_base64offset_matches_any_alignment():
    import base64
    y = BASE + "  s: {CommandLine|base64offset|contains: 'IEX ('}\n  condition: s"
    for pad in (b"", b"a", b"ab"):
        enc = base64.b64encode(pad + b"IEX (New-Object)").decode()
        ev = {"_eid": 1, "_kind": "sysmon", "Image": "C:\\a.exe", "CommandLine": "powershell -e " + enc}
        assert run(y, ev)[0] is True, pad
    assert run(y, {"_eid": 1, "_kind": "sysmon", "CommandLine": "powershell -e " + base64.b64encode(b"nothing here").decode()})[0] is False


def test_null_does_not_match_present_field():
    assert run(BASE + "  s: {Image: null}\n  condition: s", {"_eid": 1, "_kind": "sysmon", "Image": "C:\\a.exe"})[0] is False


def test_re_modifier_is_case_sensitive_unless_flagged():
    ev = {"_eid": 1, "_kind": "sysmon", "CommandLine": "C:\\Users\\a\\Temp\\x.msi"}
    assert run(BASE + "  s: {CommandLine|re: '\\\\Temp\\\\x'}\n  condition: s", ev)[0] is True
    assert run(BASE + "  s: {CommandLine|re: '\\\\temp\\\\x'}\n  condition: s", ev)[0] is False
    assert run(BASE + "  s: {CommandLine|re|i: '\\\\temp\\\\x'}\n  condition: s", ev)[0] is True


def test_eventid_selection_and_service_rules():
    y = "title: t\nlogsource: {product: windows, service: security}\ndetection:\n  s: {EventID: 4624}\n  condition: s\n"
    ev = corpus.finish({"TargetUserName": "x"}, 4624, "Security")
    assert run(y, ev)[0] is True
    assert run(y, corpus.finish({"TargetUserName": "x"}, 4625, "Security"))[0] is False


def test_escaped_backslash_is_one_backslash():
    ev = {"_eid": 1, "_kind": "sysmon", "CommandLine": "net use \\\\127.0.0.1\\c$"}
    assert run(BASE + "  s: {CommandLine|contains: '\\\\127.0.0.1\\c$'}\n  condition: s", ev)[0] is True
    # four backslashes in the rule file are two literal backslashes
    assert run(BASE + "  s: {CommandLine|contains: ' \\\\\\\\127'}\n  condition: s", {"_eid": 1, "_kind": "sysmon", "CommandLine": "x \\\\127"})[0] is True


def test_empty_string_matches_empty_field_and_null_matches_missing():
    ev = {"_eid": 1, "_kind": "sysmon", "ParentImage": "", "Image": "C:\\a.exe"}
    assert run(BASE + "  s: {ParentImage: ''}\n  condition: s", ev)[0] is True
    assert run(BASE + "  s: {Image: ''}\n  condition: s", ev)[0] is False
    assert run(BASE + "  s: {NoSuchField: ''}\n  condition: s", ev)[0] is False


def test_windash_only_touches_parameter_dashes():
    ev = lambda c: {"_eid": 1, "_kind": "sysmon", "CommandLine": c}
    y = BASE + "  s: {CommandLine|contains|windash: ' -foo-bar'}\n  condition: s"
    assert run(y, ev("x /foo-bar"))[0] is True
    assert run(y, ev("x -foo/bar"))[0] is False      # the mid-token dash stays a plain dash


def test_utf16_needle_is_case_insensitive_like_other_values():
    y = BASE + "  s: {CommandLine|wide|contains: 'AbC'}\n  condition: s"
    assert run(y, {"_eid": 1, "_kind": "sysmon", "CommandLine": "a\x00b\x00c\x00"})[0] is True


def test_keyword_map_with_all_modifier():
    y = BASE + "  kw:\n    '|all': ['foo', 'bar']\n  condition: kw"
    assert run(y, {"_eid": 1, "_kind": "sysmon", "CommandLine": "foo and bar"})[0] is True
    assert run(y, {"_eid": 1, "_kind": "sysmon", "CommandLine": "foo only"})[0] is False


def test_unparseable_yaml_is_reported_as_skipped(tmp_path):
    (tmp_path / "bad.yml").write_text("title: [unclosed\ndetection: {")
    rules = se.load_rules([tmp_path])
    assert len(rules) == 1 and rules[0].skip_reason.startswith("yaml parse error")
