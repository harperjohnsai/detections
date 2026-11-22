/*
  Hunting: raw compiled AutoIt script (.a3x, AU3!EA06) of 1 to 20 MB. FluxEngine drops a 1.8 MB extensionless a3x next to a renamed AutoIt3.exe; the size comes from a hex-embedded DLL. Generic, low confidence: big a3x files of other loaders also match.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SUSP_AutoIt_A3X_Large_NoExt_Script
{
    meta:
        description = "Hunting: raw compiled AutoIt script (.a3x, AU3!EA06) of 1 to 20 MB. FluxEngine drops a 1.8 MB extensionless a3x next to a renamed AutoIt3.exe; the size comes from a hex-embedded DLL. Generic, low confidence: big a3x files of other loaders also match."
        author = "Harper Johns"
        date = "2026-11-22"
        hash = "4fc99727bbb91087a474126049ced32b69d252c5ed93e2b1fa40d8c13d10257e"
        family = "FluxEngine"
        score = 40
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "68c4ae32-58e7-47c9-8f95-a1b0f9ea9113"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "0230434cef5c8ab9a29303ca48642fa2"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        $magic = { A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D 41 55 33 21 45 41 30 36 }
    condition:
        $magic at 0 and filesize > 1MB and filesize < 20MB
}
