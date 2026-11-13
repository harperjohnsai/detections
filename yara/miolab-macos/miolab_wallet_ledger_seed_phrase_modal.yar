/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Scan the extracted app.asar (or the renderer bundle): asar stores JS uncompressed, the zip does not. Hash is the injected renderer.bundle.js; reference MD5 is the app.asar (sha256 b6e9f449...).
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_JS_MioLab_Trojanised_LedgerLive_SeedPhrase_Modal
{
    meta:
        description = "Injected seed-phrase phishing modal in a trojanised Ledger Live / Ledger Wallet renderer bundle (MioLab): fake genuine-check dialog, 24-word grid, POST {seedPhrase,userId}, user id read from ~/.hlpr/.ownrid"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        hash = "979e1ba3034f153f2c0b3b91cdc027c281cecbd5234fa69f54ce716a6568dd6a"
        score = 85
        yarahub_uuid = "8ffee2c5-d924-4aee-8d39-f202920c3e12"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "c914a08a7796dd0c444626d202402669"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $m1 = "MODAL_SEED_PHRASE" ascii
        $m2 = "MODAL_GENUINE_CHECK" ascii
        $m3 = "genuineCheckDialogShown" ascii
        $m4 = "seedPhraseDialog.title" ascii
        $x1 = "Failed to send seed phrase:" ascii
        $x2 = "JSON.stringify({seedPhrase:" ascii
        $x3 = "\".hlpr\",\".ownrid\"" ascii
        $x4 = "/api/ledger/seed" ascii
    condition:
        filesize < 400MB and ($x4 or 3 of ($m*)) and 1 of ($x1, $x2, $x3)
}
