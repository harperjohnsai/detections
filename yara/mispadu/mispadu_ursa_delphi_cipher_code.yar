/*
  Mispadu (URSA) Delphi banker, 2026 build line. Keys on the code of the base-25 letter-pair cipher (decoder and encoder,
  as described by ESET 2019 and IBM X-Force) plus the remote-overlay socket protocol strings. Code idioms, so it should
  survive a rebuild that keeps the Delphi routines; a different compiler or an obfuscated rebuild will need an update.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_Mispadu_URSA_Delphi_Cipher_Code
{
    meta:
        description = "Mispadu/URSA Delphi banker: string+C2 cipher routines (decoder, encoder) plus remote-overlay socket protocol strings"
        author = "Harper Johns"
        date = "2026-11-19"
        hash = "4f4129e8f79bde102875417f64a3258226ae93658776a416aaf4383698a6ea7d"
        family = "Mispadu"
        score = 80
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
        reference_eset = "https://www.welivesecurity.com/2019/11/19/mispadu-advertisement-discounted-unhappy-meal/"
        reference_ibm = "https://www.ibm.com/think/news/mispadu-ursa-c2c-communication-behind-scenes"
        yarahub_uuid = "5077c279-24f9-4a19-b3e5-2a70391d894c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "97e42e50ecb6690f179b58c20f9de633"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-mispadu-ursa"
    strings:
        // decoder core (sub_6D0F7C): (s[0]-'A')*25 + (s[1]-'A') - seed - key
        $dec = { 0F B7 0? 83 E8 41 8D 3? 80 8D 3? ?? 8B 45 ?? 0F B7 4? 02 83 E8 41 03 ?? 2B ?? ?? 2B ?? ?? }
        // encoder (sub_6D0E1C): seed = Random(25) ; v div/mod 25
        $enc1 = { B8 19 00 00 00 E8 ?? ?? ?? ?? 89 45 ?? 8B ?? 0F B7 55 ?? 66 83 C2 41 }
        $enc2 = { B9 19 00 00 00 99 F7 F9 89 45 ?? 8B 45 ?? 8D 04 80 8D 04 80 2B D8 }
        $p1 = "<|SocketMain|>" wide
        $p2 = "<|PRINCIPAL|>" wide
        $p3 = "<|STAT|>" wide
        $p4 = "<|MousePos|>" wide
        $p5 = "<|REQUESTKEYBOARD|>" wide
        $p6 = "<|Info|>" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 30MB and
        $dec and 1 of ($enc*) and 3 of ($p*)
}
