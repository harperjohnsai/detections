/*
  Mispadu (URSA) payload build 108 (compiled 2026-09-24): encrypted IMG* resource loop and resource names (fake IBM
  Trusteer Rapport wait screens), or names plus build/protocol strings. Build-specific: later builds that rename the
  resources need an update.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_Mispadu_URSA_Payload_Build108
{
    meta:
        description = "Mispadu/URSA 2026 payload build artefacts: encrypted IMG* resources (Trusteer Rapport wait screens), config protocol, resource decrypt loop"
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "4f4129e8f79bde102875417f64a3258226ae93658776a416aaf4383698a6ea7d"
        family = "Mispadu"
        score = 75
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
        reference_eset = "https://www.welivesecurity.com/2019/11/19/mispadu-advertisement-discounted-unhappy-meal/"
        reference_ibm = "https://www.ibm.com/think/news/mispadu-ursa-c2c-communication-behind-scenes"
        yarahub_uuid = "a1a6594d-7346-4c15-9d2f-66141743c42b"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "97e42e50ecb6690f179b58c20f9de633"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
    strings:
        // resource decrypt loop (sub_6CBB0C): b - (k0 + j), j cycles 0..9
        $res = { 02 C3 0F B6 55 ?? E8 ?? ?? ?? ?? 88 45 ?? 83 FB 09 7C 04 33 DB EB 01 43 }
        $r1 = "IMGAGUARDE" wide
        $r2 = "IMGFAIXA" wide
        $r3 = "IMGCONF" wide
        $s1 = "_VS108_" wide
        $s2 = "qvar1=" wide
        $s3 = "qvar4=" wide
        $s4 = "<|TAMANHOKL|>" wide
        $s5 = "<|JKEYLOG|>" wide
        $s6 = "Alarme Bank Disparado" wide
        $s7 = "BTMemoryLoadLibary" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and
        ( ($res and 1 of ($r*)) or (2 of ($r*) and 3 of ($s*)) )
}
