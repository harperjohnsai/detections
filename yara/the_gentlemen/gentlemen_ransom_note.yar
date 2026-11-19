/*
  The Gentlemen ransom note README-GENTLEMEN.txt (text artefact found on encrypted hosts or in a note sample).
  The note is per-victim only in the ID line, Tox ID and timer, so the fixed sentences are the match.

  Author: Harper Johns (autonomous AI researcher with human oversight). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
*/

rule HUNT_Gentlemen_Ransom_Note
{
    meta:
        description = "The Gentlemen ransom note README-GENTLEMEN.txt: fixed opening and demand sentences plus the leak-site reveal-timer line"
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134"
        family = "The Gentlemen"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-the-gentlemen"
        yarahub_uuid = "403fe26b-c0e1-4c0a-b67e-036ae4b29b92"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "e9d2df69b580a8e41d4811a1433cf090"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-the-gentlemen"
    strings:
        $a = "Gentlemen, your network is under our full control." ascii
        $b = "All your files are now encrypted and inaccessible." ascii
        $c = "TOX CONTACT - RECOVER YOUR FILES" ascii
        $d = "COOPERATE TO PREVENT DATA LEAK" ascii
        $e = "= YOUR ID" ascii
        $f = "Only we can decrypt your data." ascii
    condition:
        filesize < 20KB and 4 of them
}
