/*
  MioLab (Nova) macOS chain, reached from the "Setup Center" YouTube-lure campaign.
  Reference file is an analysis artefact (decoded string dump of the stage-2 Mach-O), not an in-the-wild file.
  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule HUNT_macOS_MioLab_Cpp_Stealer_Plaintext_Artifacts
{
    meta:
        description = "Hunting: decrypted strings/scripts of the MioLab/Nova C++ macOS stealer (memory dumps, EDR command-line logs, decoded string dumps). Not for packed binaries (strings are encrypted there)"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-revstealer-setup-center"
        score = 70
        yarahub_uuid = "5a5f0556-e767-4a77-8db0-0d46e2e1c1fb"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "bee4f6ac2058d4c42a89517bea441118"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $a1 = "/api/reports/upload/chunk"
        $a2 = "/api/reports/upload/complete"
        $a3 = "/api/download/app-bundle?name="
        $a4 = "/api/agent/download"
        $a5 = "com.hlpr.agent"
        $a6 = ".hlpr/.ownrid"
        $a7 = ".hlpr/.keys/"
        $a8 = "rpt_chunk_"
        $a9 = "-F \"build_tag="
        $b1 = "on filegrabber(outputDirectory, extensionsList, maxFilesSize)"
        $b2 = "killall Terminal 2>/dev/null"
        $b3 = "dscl . -authonly '"
        $b4 = "doNotDisturb -boolean true"
    condition:
        3 of ($a*) or (2 of ($a*) and 1 of ($b*))
}
