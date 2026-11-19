/*
  The Gentlemen (Storm-2697 / GOLD SHERWOOD / G1058) Go locker, Windows PE and Linux ELF builds.
  Header-agnostic on purpose: the Go build-info magic plus the locker's own flag, footer and worker strings also
  match an unpacked in-memory image or a process dump, not only a file on disk.

  Author: Harper Johns (autonomous AI researcher with human oversight). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.

  Known gap: the VMProtect-packed 2025-09 Windows build (51b9f246...) is NOT matched. Its Go image is encrypted and the
  packer stub is shared with unrelated Go malware (same imphash on SparkRAT, Sliver, Cobalt Strike, Laplas), so no
  family-specific packer rule exists. See yara/the_gentlemen/README.md.
*/

rule MAL_Gentlemen_Locker_Go
{
    meta:
        description = "The Gentlemen ransomware Go locker (Windows PE, Linux ELF, or an unpacked memory image): encrypted-file footer markers, LOCKER_BACKGROUND worker variable, note name and CLI strings"
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235"
        hash2 = "53d2484ae1ad6ff9547d90f5f5ccd6ae1dca8cb24e622a07dfc74c9593b2c3fa"
        family = "The Gentlemen"
        score = 85
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-the-gentlemen"
        yarahub_uuid = "37ed3423-8467-4ab8-84c3-0429d1f7bede"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "4200b46a93c6ab059e2b34ce200c4a5b"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-the-gentlemen"
    strings:
        $go = { FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A }   // "\xff Go buildinf:"
        $m1 = "--eph--" ascii
        $m2 = "--marker--" ascii
        $m3 = "LOCKER_BACKGROUND" ascii
        $m4 = "README-GENTLEMEN.txt" ascii
        $s1 = "[+] Encryption started. Going background..." ascii
        $s2 = "Silent mode (don't rename files)" ascii
        $s3 = "Wipe free space after encryption" ascii
        $s4 = "GENTLEMEN" ascii fullword
    condition:
        filesize < 100MB and $go and 3 of ($m*) and 1 of ($s*)
}
