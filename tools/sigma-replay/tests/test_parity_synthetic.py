"""Parity check: every hand-made event of the detections repo's own tests/test_sigma_synthetic.py must give the same
fire/silent verdict in this engine as in that file's tiny evaluator (logsource routing is bypassed: some of those
rules are proxy/macOS, which have no corpus). Skipped if the detections clone is absent."""
import glob, os, pathlib, sys
import pytest, yaml
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import sigma_engine as se  # noqa: E402

DET = ROOT.parent.parent
SRC = DET / "tests/test_sigma_synthetic.py"


def cases():
    text = SRC.read_text().split("for f, ev, exp, label in T:")[0]
    ns = {"__file__": str(SRC), "__name__": "synthetic_defs"}
    exec(compile(text, str(SRC), "exec"), ns)
    return ns["T"]


@pytest.mark.skipif(not SRC.exists(), reason="detections clone absent")
def test_engine_agrees_with_repo_synthetic_tests():
    bad, n = [], 0
    for f, ev, exp, label in cases():
        path = glob.glob(str(DET / "sigma/*" / f))[0]
        r = se.load_rule(pathlib.Path(path), yaml.safe_load(open(path)), ignore_logsource=True)
        assert r.match, (f, r.skip_reason)
        got = r.match(se.Ev(dict(ev)))
        n += 1
        if got != exp: bad.append((f, label, exp, got))
    assert n > 50
    assert not bad, bad
