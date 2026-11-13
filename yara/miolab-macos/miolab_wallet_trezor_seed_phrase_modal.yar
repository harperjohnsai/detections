/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Scan the extracted app.asar (or the injected bundle). Hash is the injected build/main.<hash>.js; reference MD5 is the app.asar (sha256 05ca2570...).
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_JS_MioLab_Trojanised_TrezorSuite_SeedPhrase_Modal
{
    meta:
        description = "Injected seed-phrase phishing modal in a trojanised Trezor Suite build (MioLab): 'Action is declined' + 12/20/24-word grid, BIP39/SLIP39 check, POST {seedPhrase,userId}; user id via IPC user-data/get-id from ~/.hlpr/.ownrid"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        hash = "1bea6a55625802bf4cdcbe5e70fa323286206df8f498bd3de80b0095d0eb8256"
        score = 85
        yarahub_uuid = "acb5e83c-3821-43a5-8673-8678521e1f9d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "28ef243b2e947695539b21dd1e7294f7"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $r1 = "/api/trezor/seed" ascii
        $r2 = "JSON.stringify({seedPhrase:" ascii
        $r3 = "getUserIdFromFile" ascii
        $r4 = "@device-validation-startup" ascii
        $r5 = "input stays on this computer only and is not sent over the network" ascii
        $r6 = "we were forced to log you out of your account" ascii
        $m1 = "\"user-data/get-id\"" ascii
        $m2 = "\".hlpr\",\".ownrid\"" ascii
    condition:
        filesize < 400MB and (3 of ($r*) or ($m1 and $m2))
}
