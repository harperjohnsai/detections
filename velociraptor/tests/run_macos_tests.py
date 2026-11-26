#!/usr/bin/env python3
"""Regression test for the macOS artifacts in velociraptor/macos/ (Velociraptor v0.77.4).

Everything runs against SYNTHETIC fixtures (tests/fixtures/mac_fixtures.py): fake `/Users/...` and `/Applications/...`
trees in a temporary directory (JSON manifests, plists, small sqlite databases, a binary-plist BTM store with bookmark
blobs). Nothing is executed and no data from any device is used. The `Root` /
`IgnoreOSCheck` parameters of the artifacts are the test hooks that make a Linux runner read the fake tree.

  Custom.MacOS.Browser.Extensions   10 Chromium-family manifests (6 flagged, 4 clean), 2 native hosts, 3 Safari app
                                    extensions (+1 non-Safari appex that must be skipped), 5 Firefox add-ons (+1 theme)
  Custom.MacOS.TCC.Review           user + system TCC.db: 11 flagged grants, 4 clean, 1 denied row, installed-app join
  Custom.MacOS.Persistence.BTM      synthetic NSKeyedArchive store incl. NSData bookmark blobs and dict objects

Usage: VELOCIRAPTOR=/path/to/velociraptor python3 run_macos_tests.py   (exit 0 = all pass)
"""
import json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ART_DIR = os.path.join(HERE, "..", "macos")
FIX = os.path.join(HERE, "fixtures")
VELO = os.environ.get("VELOCIRAPTOR", "velociraptor")
ARTIFACTS = ["Custom.MacOS.Browser.Extensions", "Custom.MacOS.TCC.Review",
             "Custom.MacOS.Persistence.BTM"]
RESULTS = []


def check(name, ok, detail=""):
    print(("PASS" if ok else "FAIL"), name, detail)
    RESULTS.append(bool(ok))
    return ok


def collect(artifact, args=(), env=None):
    cmd = [VELO, "--definitions", ART_DIR, "artifacts", "collect", artifact, "--format", "jsonl"]
    for a in args:
        cmd += ["--args", a]
    e = dict(os.environ, **(env or {}))
    p = subprocess.run(cmd, capture_output=True, text=True, env=e)
    rows = [json.loads(l) for l in p.stdout.splitlines() if l.startswith("{")]
    errs = [l for l in p.stderr.splitlines() if "ERROR" in l]
    return rows, errs, p.returncode


def by_source(rows, name):
    return [r for r in rows if r.get("_Source", "").endswith("/" + name)]


def seeded(kind):
    root = tempfile.mkdtemp(prefix=f"macfix-{kind}-")
    subprocess.run([sys.executable, os.path.join(FIX, "mac_fixtures.py"), kind, root], check=True, stdout=subprocess.DEVNULL)
    return root


def cleanup(root):
    subprocess.run([sys.executable, os.path.join(FIX, "mac_fixtures.py"), "remove", root], check=True, stdout=subprocess.DEVNULL)


def has(reasons, *needles):
    return all(n in (reasons or "") for n in needles)


def read(name):
    with open(os.path.join(ART_DIR, name + ".yaml")) as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ tests
def test_verify_and_capabilities():
    for a in ARTIFACTS:
        p = subprocess.run([VELO, "artifacts", "verify", os.path.join(ART_DIR, a + ".yaml")], capture_output=True, text=True)
        check(f"verify {a}", p.returncode == 0 and "rror" not in p.stdout + p.stderr, (p.stdout + p.stderr).strip()[:200])
    # capability inventory: none executes a program, uploads, writes or talks to the network
    for a in ARTIFACTS:
        txt = re.sub(r"(?m)^\s*#.*$", "", read(a))
        body = txt.split("\nsources:", 1)[-1]
        execs = len(re.findall(r"\bexecve\(", body))
        others = re.findall(r"\b(upload|http_client|powershell|wmi|copy|rm|write_file|create_file)\(", body)
        want_exec = False
        declared = bool(re.search(r"(?m)^required_permissions:\s*\n\s*-\s*EXECVE\s*$", txt))
        check(f"capabilities {a}", (execs == 3 if want_exec else execs == 0) and declared == want_exec and not others,
              f"execve={execs} declared_EXECVE={declared} other={others}")


def test_extensions():
    root = seeded("extensions")
    try:
        rows, errs, rc = collect("Custom.MacOS.Browser.Extensions", [f"Root={root}", "IgnoreOSCheck=Y"])
    finally:
        cleanup(root)
    check("extensions: no VQL errors", rc == 0 and not errs, f"rc={rc} errors={errs[:1]}")
    ch = {r["ExtensionId"][0]: r for r in by_source(rows, "Chromium")}
    flagged = {k for k, r in ch.items() if r["Suspicious"]}
    check("chromium: 10 manifests, flagged b,c,e,f,h,j", len(ch) == 10 and flagged == set("bcefhj"),
          f"rows={len(ch)} flagged={sorted(flagged)}")
    check("chromium: clean store extensions a,d,g,i stay clean (Chrome, Brave, Edge store URLs)",
          all(not ch[k]["Suspicious"] and ch[k]["Reasons"] == "" for k in "adgi"))
    check("chromium: risky permissions + <all_urls> (b)", has(ch["b"]["Reasons"], "risky_permission:cookies,webRequest", "broad_host_access:<all_urls>"), ch["b"]["Reasons"])
    check("chromium: sideloaded + nativeMessaging + debugger (c)",
          has(ch["c"]["Reasons"], "risky_permission:nativeMessaging,debugger", "non_store_update_url:https://updates.example.invalid/crx"), ch["c"]["Reasons"])
    check("chromium: no update_url (e)", ch["e"]["Reasons"] == "no_update_url;", ch["e"]["Reasons"])
    check("chromium: unparseable manifest (f)", ch["f"]["Reasons"] == "unparseable_manifest;", ch["f"]["Reasons"])
    check("chromium: host wildcard only in optional_host_permissions/content_scripts (h)", has(ch["h"]["Reasons"], "broad_host_access:*://*/*"), ch["h"]["Reasons"])
    check("chromium: webRequestBlocking, proxy (j)", has(ch["j"]["Reasons"], "webRequestBlocking", "proxy"), ch["j"]["Reasons"])
    check("chromium: __MSG_appName__ resolved from _locales", ch["d"]["Name"] == "Localized Example", str(ch["d"]["Name"]))
    check("chromium: browser/profile parsed", (ch["g"]["Browser"], ch["i"]["Browser"], ch["i"]["Profile"], ch["a"]["Browser"]) == ("Brave", "Edge", "Profile 1", "Chrome"))
    nh = {r["Name"]: r for r in by_source(rows, "ChromiumNativeHosts")}
    check("native hosts: tmp/hidden path flagged, /Applications path clean",
          nh["com.example.badhost"]["Suspicious"] and not nh["com.example.goodhost"]["Suspicious"] and len(nh) == 2, str(sorted(nh)))
    sf = {r["BundleId"]: r for r in by_source(rows, "Safari")}
    check("safari: 3 web-extension appex (widget appex skipped)", set(sf) == {"com.example.tools.Extension", "com.example.reader.Extension", "com.example.dropped.Extension"}, str(sorted(sf)))
    check("safari: risky manifest flagged, clean one clean, downloads-folder app flagged",
          has(sf["com.example.tools.Extension"]["Reasons"], "risky_permission:cookies,nativeMessaging,webRequest", "broad_host_access")
          and not sf["com.example.reader.Extension"]["Suspicious"]
          and has(sf["com.example.dropped.Extension"]["Reasons"], "app_outside_applications:/Users/alice/Downloads/Dropped Helper.app"),
          f"{sf['com.example.tools.Extension']['Reasons']} | {sf['com.example.dropped.Extension']['Reasons']}")
    st = {r["Extension"]: r["Enabled"] for r in by_source(rows, "SafariEnabledState")}
    check("safari enabled state", st == {"com.example.tools.Extension (ABCDE12345)": True, "com.example.reader.Extension (ABCDE12345)": False}, str(st))
    ff = {r["ExtensionId"]: r for r in by_source(rows, "Firefox")}
    fflag = {k for k, r in ff.items() if r["Suspicious"]}
    check("firefox: 5 extensions (theme skipped); flagged pagetools, sideload, nosource; system add-on with broad perms clean",
          len(ff) == 5 and fflag == {"pagetools@example.org", "sideload@example.invalid", "nosource@example.invalid"}
          and not ff["system@mozilla.org"]["Suspicious"], f"rows={len(ff)} flagged={sorted(fflag)}")
    check("firefox: reasons", has(ff["sideload@example.invalid"]["Reasons"], "non_amo_source:", "unsigned_or_unknown_signature:0")
          and has(ff["pagetools@example.org"]["Reasons"], "risky_permission:webRequest,cookies,nativeMessaging", "broad_host_access:<all_urls>")
          and ff["nosource@example.invalid"]["Reasons"] == "no_source_uri;")


def test_tcc():
    root = seeded("tcc")
    try:
        rows, errs, rc = collect("Custom.MacOS.TCC.Review", [f"Root={root}", "IgnoreOSCheck=Y"])
        rows_d, _, _ = collect("Custom.MacOS.TCC.Review", [f"Root={root}", "IgnoreOSCheck=Y", "IncludeDenied=Y"])
    finally:
        cleanup(root)
    check("tcc: no VQL errors", rc == 0 and not errs, f"rc={rc} errors={errs[:1]}")
    acc = by_source(rows, "Access")
    key = lambda r: (r["Scope"], r["Service"].replace("kTCCService", ""), r["Client"])
    got = {key(r): r for r in acc}
    want_flag = {
        ("alice", "Accessibility", "com.splashtop.streamer"): ["remote_access_tool"],
        ("alice", "ScreenCapture", "com.philandro.anydesk"): ["remote_access_tool"],
        ("alice", "Accessibility", "com.connectwise.screenconnect.client"): ["remote_access_tool", "not_installed"],
        ("alice", "Accessibility", "com.example.GoneApp"): ["not_installed"],
        ("alice", "SystemPolicyAllFiles", "com.apple.Terminal"): ["terminal_or_shell"],
        ("alice", "ListenEvent", "/bin/bash"): ["terminal_or_shell"],
        ("alice", "AppleEvents", "com.googlecode.iterm2"): ["terminal_or_shell"],
        ("alice", "Accessibility", "/Applications/RustDesk.app/Contents/MacOS/RustDesk"): ["remote_access_tool"],
        ("alice", "PostEvent", "/Users/alice/bin/legacy-tool"): ["not_installed"],
        ("(system)", "SystemPolicyAllFiles", "com.splashtop.Splashtop-Streamer"): ["remote_access_tool", "not_installed"],
        ("(system)", "Accessibility", "/usr/libexec/sshd-keygen-wrapper"): ["terminal_or_shell"],
    }
    want_clean = [("alice", "Camera", "com.example.VideoCall"), ("alice", "Microphone", "com.apple.FaceTime"),
                  ("alice", "Calendar", "com.splashtop.streamer"), ("(system)", "ScreenCapture", "com.example.VideoCall")]
    flagged = {k for k, r in got.items() if r["Suspicious"]}
    check("tcc: 15 granted rows, exactly the 11 planted grants flagged", len(acc) == 15 and flagged == set(want_flag),
          f"rows={len(acc)} missing={sorted(set(want_flag) - flagged)} extra={sorted(flagged - set(want_flag))}")
    bad = {k: (got[k]["Reasons"], v) for k, v in want_flag.items() if k in got and sorted(r for r in got[k]["Reasons"].split(";") if r) != sorted(v)}
    check("tcc: reasons per flagged row", not bad, str(bad))
    check("tcc: clean rows stay clean (benign camera, Apple id without app on disk, non-sensitive service, other scope)",
          all(k in got and not got[k]["Suspicious"] for k in want_clean))
    check("tcc: limited grant (auth_value 3) counts; path client resolved to an existing file",
          got[("alice", "Accessibility", "/Applications/RustDesk.app/Contents/MacOS/RustDesk")]["Auth"] == "limited"
          and got[("alice", "Accessibility", "/Applications/RustDesk.app/Contents/MacOS/RustDesk")]["Installed"] is True)
    tv = got[("alice", "Accessibility", "com.splashtop.streamer")]
    check("tcc: join columns (installed app path, AppleEvents target, TCC last_modified)",
          tv["AppPath"] == "/Applications/Splashtop Streamer.app" and tv["Installed"] is True and tv["TCCLastModified"].startswith("2026-")
          and got[("alice", "AppleEvents", "com.googlecode.iterm2")]["AppleEventsTarget"] == "com.apple.finder")
    check("tcc: denied row hidden by default, shown with IncludeDenied=Y and never flagged",
          not any(r["Client"] == "com.philandro.anydesk" and r["Service"].endswith("Camera") for r in acc)
          and any(r["Client"] == "com.philandro.anydesk" and r["Service"].endswith("Camera") and not r["Suspicious"] and r["Auth"] == "denied"
                  for r in by_source(rows_d, "Access")) and len(by_source(rows_d, "Access")) == 16)
    inv = {r["BundleId"] for r in by_source(rows, "InstalledRemoteTools")}
    check("tcc: installed remote-tool inventory", inv == {"com.splashtop.streamer", "com.philandro.anydesk", "com.carriez.rustdesk"}, str(sorted(inv)))


def test_btm():
    root = seeded("btm")
    glob_ = "{%s/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm,%s/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/*.btm}" % (root, root)
    try:
        rows, errs, rc = collect("Custom.MacOS.Persistence.BTM", [f"BTMGlob={glob_}", "IgnoreOSCheck=Y"])
    finally:
        cleanup(root)
    check("btm: no VQL errors", rc == 0 and not errs, f"rc={rc} errors={errs[:1]}")
    vals = {r["Value"]: r for r in rows}
    sus = {v for v, r in vals.items() if r["Suspicious"]}
    check("btm: per-user and system store both read", {r["Store"].split(root, 1)[-1].split("/")[-1] for r in rows} == {"backgrounditems.btm", "BackgroundItems-v8.btm"})
    check("btm: bundle id / url / team id classified", vals["com.example.legit.helper"]["Kind"] == "bundle-id" and vals["ABCDE12345"]["Kind"] == "team-id"
          and vals["file:///Applications/Example.app/Contents/Library/LoginItems/Helper.app"]["Kind"] == "url")
    check("btm: bookmark blobs decoded to paths (bytes inside dict objects)",
          vals.get("/Applications/Example Updater.app", {}).get("Kind") == "bookmark-path"
          and vals.get("/private/tmp/.hidden/agent.sh", {}).get("Kind") == "bookmark-path",
          str([v for v in vals if v.startswith("UNPARSED")][:1]))
    check("btm: exactly 3 suspicious (user LaunchAgent named com.apple.*, tmp/hidden url, tmp/hidden bookmark path)",
          sus == {"/Users/alice/Library/LaunchAgents/com.apple.update.plist", "file:///private/tmp/.hidden/agent.sh", "/private/tmp/.hidden/agent.sh"}, str(sorted(sus)))


def main():
    for t in (test_verify_and_capabilities, test_extensions, test_tcc, test_btm):
        t()
    print(f"{sum(RESULTS)}/{len(RESULTS)} checks passed")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
