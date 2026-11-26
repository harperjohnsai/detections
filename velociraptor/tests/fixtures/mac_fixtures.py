#!/usr/bin/env python3
"""mac_fixtures.py <set> <root>  -- synthetic macOS fixture trees for the Velociraptor macOS artifact tests.

Everything is inert test data written under <root> (a scratch directory used as a fake filesystem root).
Nothing is executed; no data from any device is used. Sets:

  extensions  Chromium-family manifests (Chrome/Brave/Edge), native messaging hosts, Safari app extensions
              (.appex Info.plist + Resources/manifest.json), Firefox extensions.json
  tcc         user + system TCC.db (modern `access` schema) and installed-app Info.plists
  btm         synthetic NSKeyedArchive .btm (binary plist) incl. NSData bookmark blobs
"""
import json, os, plistlib, shutil, sqlite3, struct, sys

ROOT = sys.argv[2] if len(sys.argv) > 2 else ""
CMD = sys.argv[1] if len(sys.argv) > 1 else ""

STORE = "https://clients2.google.com/service/update2/crx"
EDGE_STORE = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
CH = "Users/alice/Library/Application Support/Google/Chrome/Default/Extensions"
BR = "Users/alice/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions"
ED = "Users/alice/Library/Application Support/Microsoft Edge/Profile 1/Extensions"


def p(rel):
    return os.path.join(ROOT, rel)


def wtext(rel, text):
    os.makedirs(os.path.dirname(p(rel)), exist_ok=True)
    with open(p(rel), "w") as f:
        f.write(text)


def wjson(rel, obj):
    wtext(rel, json.dumps(obj, indent=1))


def wbytes(rel, data):
    os.makedirs(os.path.dirname(p(rel)), exist_ok=True)
    with open(p(rel), "wb") as f:
        f.write(data)


def wplist(rel, obj, fmt=plistlib.FMT_XML):
    wbytes(rel, plistlib.dumps(obj, fmt=fmt))


def cid(c):  # 32 chars a-p like a real extension id
    return (c * 32)[:32]


# ----------------------------------------------------------------------------------------- extensions
def extensions():
    # --- Chromium family. E1..E8 flagged, D1..D4 decoys that must stay clean.
    wjson(f"{CH}/{cid('a')}/1.0.0_0/manifest.json", {          # D1 benign store extension
        "manifest_version": 3, "name": "Example Notes", "version": "1.0.0", "update_url": STORE,
        "permissions": ["storage", "alarms"]})
    wjson(f"{CH}/{cid('b')}/2.3.1_0/manifest.json", {          # E1 risky permissions, store update_url
        "manifest_version": 3, "name": "Example Page Tools", "version": "2.3.1", "update_url": STORE,
        "permissions": ["tabs", "cookies", "webRequest"], "host_permissions": ["<all_urls>"]})
    wjson(f"{CH}/{cid('c')}/0.9_0/manifest.json", {            # E2 sideloaded (non-store update_url) + nativeMessaging + debugger
        "manifest_version": 2, "name": "Example Document Viewer", "version": "0.9",
        "update_url": "https://updates.example.invalid/crx",
        "permissions": ["nativeMessaging", "debugger", "https://*/*"]})
    wjson(f"{CH}/{cid('d')}/1.2_0/manifest.json", {            # D2 localized name, specific hosts only
        "manifest_version": 3, "name": "__MSG_appName__", "default_locale": "en", "version": "1.2",
        "update_url": STORE, "permissions": ["storage"], "host_permissions": ["https://*.example.com/*"]})
    wjson(f"{CH}/{cid('d')}/1.2_0/_locales/en/messages.json", {"appName": {"message": "Localized Example"}})
    wjson(f"{CH}/{cid('e')}/3.0_0/manifest.json", {            # E3 no update_url at all (installed outside the store)
        "manifest_version": 3, "name": "Example Helper (no update url)", "version": "3.0",
        "permissions": ["storage"]})
    wtext(f"{CH}/{cid('f')}/1.0_0/manifest.json", "{ this is not json")   # E4 unparseable manifest
    wjson(f"{BR}/{cid('g')}/5.1_0/manifest.json", {            # D3 Brave, store, host permissions narrow
        "manifest_version": 3, "name": "Example Reader", "version": "5.1", "update_url": STORE,
        "permissions": ["storage", "tabs"], "host_permissions": ["https://example.org/*"]})
    wjson(f"{BR}/{cid('h')}/1.0_0/manifest.json", {            # E5 Brave, optional all_urls only in optional_host_permissions + content script
        "manifest_version": 3, "name": "Example Content Script", "version": "1.0", "update_url": STORE,
        "permissions": ["storage"], "optional_host_permissions": ["*://*/*"],
        "content_scripts": [{"matches": ["http://*/*", "https://*/*"], "js": ["a.js"]}]})
    wjson(f"{ED}/{cid('i')}/1.1_0/manifest.json", {            # D4 Edge store (Edge update url), clean
        "manifest_version": 3, "name": "Example Edge Add-on", "version": "1.1", "update_url": EDGE_STORE,
        "permissions": ["storage"]})
    wjson(f"{ED}/{cid('j')}/7.7_0/manifest.json", {            # E6 Edge, Chrome store url on Edge is fine, but webRequest+proxy
        "manifest_version": 2, "name": "Example Network Tool", "version": "7.7", "update_url": EDGE_STORE,
        "permissions": ["webRequest", "webRequestBlocking", "proxy", "<all_urls>"]})
    # native messaging hosts: N1 flagged (tmp, hidden), N2 clean
    wjson("Users/alice/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.example.badhost.json", {
        "name": "com.example.badhost", "description": "x", "path": "/private/tmp/.cache/host", "type": "stdio",
        "allowed_origins": [f"chrome-extension://{cid('c')}/"]})
    wjson("Library/Google/Chrome/NativeMessagingHosts/com.example.goodhost.json", {
        "name": "com.example.goodhost", "description": "x", "path": "/Applications/Example.app/Contents/MacOS/host",
        "type": "stdio", "allowed_origins": [f"chrome-extension://{cid('a')}/"]})

    # --- Safari app extensions. S1 risky, S2 clean, S3 non-Safari appex (decoy), S4 outside /Applications.
    def appex(app_rel, appex_name, bundle, point, manifest=None):
        base = f"{app_rel}/Contents/PlugIns/{appex_name}.appex/Contents"
        wplist(f"{base}/Info.plist", {
            "CFBundleIdentifier": bundle, "CFBundleName": appex_name, "CFBundleShortVersionString": "1.4",
            "NSExtension": {"NSExtensionPointIdentifier": point, "NSExtensionPrincipalClass": "Handler"}})
        if manifest is not None:
            wjson(f"{base}/Resources/manifest.json", manifest)
    appex("Applications/Example Browser Tools.app", "Example Tools Extension", "com.example.tools.Extension",
          "com.apple.Safari.web-extension",
          {"manifest_version": 3, "name": "Example Tools", "permissions": ["cookies", "nativeMessaging", "webRequest"],
           "host_permissions": ["<all_urls>"]})
    appex("Applications/Example Reader.app", "Reader Extension", "com.example.reader.Extension",
          "com.apple.Safari.web-extension",
          {"manifest_version": 3, "name": "Reader", "permissions": ["activeTab", "storage"]})
    appex("Applications/Example Widgets.app", "Widget Extension", "com.example.widgets.WidgetExtension",
          "com.apple.widgetkit-extension")
    appex("Users/alice/Downloads/Dropped Helper.app", "Dropped Extension", "com.example.dropped.Extension",
          "com.apple.Safari.web-extension",
          {"manifest_version": 2, "name": "Dropped", "permissions": ["<all_urls>"]})
    # enabled-state plist (layout inferred, not verified against a live system)
    wplist("Users/alice/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist", {
        "com.example.tools.Extension (ABCDE12345)": {"Enabled": True, "Allowed Domains": ["Always: all"]},
        "com.example.reader.Extension (ABCDE12345)": {"Enabled": False}})

    # --- Firefox. F1..F3 flagged, D5 clean, D6 system add-on with broad permissions (must stay clean), D7 theme.
    amo = "https://addons.mozilla.org/firefox/downloads/file/1/x.xpi"
    wjson("Users/alice/Library/Application Support/Firefox/Profiles/abc123.default-release/extensions.json", {
        "schemaVersion": 36, "addons": [
            {"id": "notes@example.org", "type": "extension", "version": "1.0", "active": True, "userDisabled": False,
             "location": "app-profile", "signedState": 2, "sourceURI": amo, "defaultLocale": {"name": "Example Notes FF"},
             "userPermissions": {"permissions": ["storage"], "origins": ["https://*.example.com/*"]}},
            {"id": "pagetools@example.org", "type": "extension", "version": "2.0", "active": True, "userDisabled": False,
             "location": "app-profile", "signedState": 2, "sourceURI": amo, "defaultLocale": {"name": "Example Page Tools FF"},
             "userPermissions": {"permissions": ["webRequest", "cookies", "nativeMessaging"], "origins": ["<all_urls>"]}},
            {"id": "sideload@example.invalid", "type": "extension", "version": "0.1", "active": True, "userDisabled": False,
             "location": "app-profile", "signedState": 0, "sourceURI": "https://downloads.example.invalid/x.xpi",
             "defaultLocale": {"name": "Example Sideload FF"}, "userPermissions": {"permissions": ["tabs"], "origins": []}},
            {"id": "nosource@example.invalid", "type": "extension", "version": "0.2", "active": False, "userDisabled": True,
             "location": "app-profile", "signedState": 2, "defaultLocale": {"name": "Example NoSource FF"},
             "userPermissions": {"permissions": [], "origins": []}},
            {"id": "system@mozilla.org", "type": "extension", "version": "1.0", "active": True, "location": "app-system-addons",
             "signedState": 3, "defaultLocale": {"name": "System Feature"},
             "userPermissions": {"permissions": ["webRequest", "cookies"], "origins": ["<all_urls>"]}},
            {"id": "theme@example.org", "type": "theme", "version": "1.0", "active": False, "location": "app-profile",
             "signedState": 2, "sourceURI": amo, "defaultLocale": {"name": "Example Theme"}},
        ]})


# ----------------------------------------------------------------------------------------- tcc
TCC_SCHEMA = """CREATE TABLE access (
  service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL,
  auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER,
  indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED',
  indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (service, client, client_type, indirect_object_identifier))"""


def tcc_db(rel, rows):
    os.makedirs(os.path.dirname(p(rel)), exist_ok=True)
    if os.path.exists(p(rel)):
        os.remove(p(rel))
    c = sqlite3.connect(p(rel))
    c.execute(TCC_SCHEMA)
    for service, client, ctype, auth, reason, target, ts in rows:
        c.execute("INSERT INTO access (service,client,client_type,auth_value,auth_reason,auth_version,"
                  "indirect_object_identifier,flags,last_modified) VALUES (?,?,?,?,?,1,?,0,?)",
                  (service, client, ctype, auth, reason, target, ts))
    c.commit()
    c.close()


def tcc():
    S = "kTCCService"
    t0 = 1795000000
    tcc_db("Users/alice/Library/Application Support/com.apple.TCC/TCC.db", [
        (S + "Accessibility", "com.splashtop.streamer", 0, 2, 2, "UNUSED", t0),       # T1 remote tool, allowed
        (S + "ScreenCapture", "com.philandro.anydesk", 0, 2, 2, "UNUSED", t0 + 10),      # T2 remote tool, allowed
        (S + "Camera", "com.philandro.anydesk", 0, 0, 2, "UNUSED", t0 + 11),            # D denied row (excluded by default)
        (S + "Accessibility", "com.connectwise.screenconnect.client", 0, 2, 2, "UNUSED", t0 + 20),  # T3 remote tool, NOT installed
        (S + "Accessibility", "com.example.GoneApp", 0, 2, 2, "UNUSED", t0 + 30),        # T4 not installed
        (S + "SystemPolicyAllFiles", "com.apple.Terminal", 0, 2, 2, "UNUSED", t0 + 40),  # T5 Terminal
        (S + "ListenEvent", "/bin/bash", 1, 2, 2, "UNUSED", t0 + 50),                    # T6 shell path
        (S + "AppleEvents", "com.googlecode.iterm2", 0, 2, 2, "com.apple.finder", t0 + 60),   # T7 iTerm AppleEvents -> Finder
        (S + "Camera", "com.example.VideoCall", 0, 2, 2, "UNUSED", t0 + 70),             # D sensitive, installed, benign
        (S + "Microphone", "com.apple.FaceTime", 0, 2, 2, "UNUSED", t0 + 80),            # D Apple, not on disk fixture: must not be 'not installed'
        (S + "Calendar", "com.splashtop.streamer", 0, 2, 2, "UNUSED", t0 + 90),       # D remote tool but not a sensitive service
        (S + "Accessibility", "/Applications/RustDesk.app/Contents/MacOS/RustDesk", 1, 3, 2, "UNUSED", t0 + 95),  # T8 limited(3) counts as granted, path client present
        (S + "PostEvent", "/Users/alice/bin/legacy-tool", 1, 2, 2, "UNUSED", t0 + 99),   # T9 path client that does not exist
    ])
    tcc_db("Library/Application Support/com.apple.TCC/TCC.db", [
        (S + "SystemPolicyAllFiles", "com.splashtop.Splashtop-Streamer", 0, 2, 4, "UNUSED", t0 + 100),  # T10 system DB, remote tool (not installed)
        (S + "Accessibility", "/usr/libexec/sshd-keygen-wrapper", 1, 2, 4, "UNUSED", t0 + 110),         # T11 sshd wrapper
        (S + "ScreenCapture", "com.example.VideoCall", 0, 2, 4, "UNUSED", t0 + 120),                    # D benign
    ])

    def app(rel, bundle, name):
        wplist(f"{rel}/Contents/Info.plist", {"CFBundleIdentifier": bundle, "CFBundleName": name, "CFBundleShortVersionString": "1.0"})
    app("Applications/Splashtop Streamer.app", "com.splashtop.streamer", "Splashtop Streamer")
    app("Applications/AnyDesk.app", "com.philandro.anydesk", "AnyDesk")
    app("Applications/Example Video Call.app", "com.example.VideoCall", "Example Video Call")
    app("Applications/iTerm.app", "com.googlecode.iterm2", "iTerm2")
    app("Applications/RustDesk.app", "com.carriez.rustdesk", "RustDesk")
    app("System/Applications/Utilities/Terminal.app", "com.apple.Terminal", "Terminal")
    wbytes("Applications/RustDesk.app/Contents/MacOS/RustDesk", b"#!/bin/sh\n")


# ----------------------------------------------------------------------------------------- btm
def bookmark(components):
    """Minimal NSURL bookmark-shaped blob: 'book' magic + length/type-prefixed UTF-8 path components.
    Not a faithful bookmark; it carries what the artifact's decoder reads (printable path components)."""
    out = b"book\x00\x00\x00\x00mark\x00\x00\x00\x00" + b"\x38\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 24
    for comp in components:
        raw = comp.encode()
        out += struct.pack("<II", len(raw), 0x0101) + raw + b"\x00" * (-len(raw) % 4)
    return out + b"\x00" * 16


def btm():
    objs = ["$null", "NSKeyedArchiver",
            "com.example.legit.helper",                                                       # bundle id
            "file:///Applications/Example.app/Contents/Library/LoginItems/Helper.app",       # url
            "/Users/alice/Library/LaunchAgents/com.apple.update.plist",                       # S: user LaunchAgent named com.apple.*
            "file:///private/tmp/.hidden/agent.sh",                                          # S: tmp + hidden
            "ABCDE12345",                                                                    # team id
            {"NS.objects": [1], "$class": 7, "name": "Example Corp"},                        # dict objects as in Apple's archives
            {"bookmark": bookmark(["Applications", "Example Updater.app"]), "type": 8},      # bookmark -> /Applications/Example Updater.app
            {"bookmark": bookmark(["private", "tmp", ".hidden", "agent.sh"]), "type": 8},    # bookmark -> S: /private/tmp/.hidden/agent.sh
            "NSDictionary", "$class"]
    wplist("Users/alice/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
           {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": 1}, "$objects": objs}, fmt=plistlib.FMT_BINARY)
    wplist("private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v8.btm",
           {"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": 1},
            "$objects": ["$null", "com.example.system.daemon", "file:///Library/LaunchDaemons/com.example.system.plist"]},
           fmt=plistlib.FMT_BINARY)


SETS = {"extensions": extensions, "tcc": tcc, "btm": btm}

if __name__ == "__main__":
    if CMD == "remove":
        shutil.rmtree(ROOT, ignore_errors=True)
        print("removed", ROOT, "exists_now=", os.path.exists(ROOT))
    elif CMD in SETS:
        SETS[CMD]()
        print("seeded", CMD, "under", ROOT)
    else:
        sys.exit("usage: mac_fixtures.py extensions|tcc|btm|remove ROOT")
