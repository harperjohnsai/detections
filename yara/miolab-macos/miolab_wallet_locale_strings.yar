/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Matches inside the app.asar of the trojanised Ledger Wallet (reference MD5) and in the extracted locale JSON.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_MioLab_Trojanised_Wallet_Locale_Strings
{
    meta:
        description = "Locale JSON of the MioLab trojanised Ledger app: 'Action is declined / Suspicious activity ... log in back using your 24-word recovery phrase'"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        score = 75
        yarahub_uuid = "cd1159f0-1e4f-40c7-8da7-b31c984dc024"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "c914a08a7796dd0c444626d202402669"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $a = "\"genuineCheckDialog\"" ascii
        $b = "\"seedPhraseDialog\"" ascii
        $c = "we were forced to log you out of your account" ascii
        $d = "log in back using your 24-word recovery phrase" ascii
    condition:
        $a and $b and ($c or $d)
}
