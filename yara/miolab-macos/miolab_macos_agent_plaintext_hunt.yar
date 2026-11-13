/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Reference file is an analysis artefact (decoded strings of the agent arm64 slice).
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule HUNT_macOS_MioLab_Agent_Plaintext_Artifacts
{
    meta:
        description = "Decrypted strings / memory / EDR command lines of the MioLab .agnt agent"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        score = 60
        yarahub_uuid = "45aba368-f6c2-442d-a239-a2af3a287719"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "d18cd572397c2ccb266ad787037ffe0a"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $c2 = "/api/agnt" ascii
        $curl = "curl --fail --header \"Content-Type: text/plain\" --data \"" ascii
        $alph = "ptXQVlhBezPSEioO" ascii
        $r1 = "reverse shell already created" ascii
        $r2 = "failed to open reverse shell" ascii
        $r3 = "self-restart failed" ascii
        $f1 = ".hlpr" ascii
        $f2 = ".passwd" ascii
        $f3 = ".ownrid" ascii
        $sp = "system_profiler -json SPSoftwareDataType SPHardwareDataType" ascii
    condition:
        3 of them
}
