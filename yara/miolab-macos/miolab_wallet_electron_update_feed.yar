/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Reference file is the app-update.yml of the trojanised Ledger Wallet bundle. A rule on updater feeds is by nature narrow: it will not catch a feed hosted on a ledger.* name.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet
{
    meta:
        description = "Hunting: electron-updater app-update.yml inside a Ledger app bundle pointing at a non-Ledger generic feed (the MioLab trojan used a throwaway .online domain)"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        score = 60
        yarahub_uuid = "cc4e980f-f8ca-457e-a7fb-0710d09ac1c5"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "26c0e2570bee3b504a16c8d633f521ec"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $p = "provider: generic" ascii
        $c = "updaterCacheDirName: ledger-live-desktop-updater" ascii
        $ok1 = "ledger.com" ascii
        $ok2 = "ledger.app" ascii
    condition:
        filesize < 2KB and $p and $c and not any of ($ok*)
}
