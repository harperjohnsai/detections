/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Reference file is a list of public sandbox curl command lines of the agent.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule HUNT_MioLab_Agent_C2_Body
{
    meta:
        description = "HTTP POST body / curl argv of the MioLab agent beacon: custom-alphabet hex starting with a fixed obfuscated magic (OOzVBOVS)"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        score = 70
        yarahub_uuid = "d0dc4c92-9c07-4dbe-8509-fdce727d685f"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "916f51d51b410b0ed58be7ee3c11c61e"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $b = /--data "?OOzVBOVS[ptXQVlhBezPSEioO]{2,}/ ascii
    condition:
        $b
}
