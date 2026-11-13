/*
   REVSTEALER x64 inner payload of the "Setup Center" DLL-sideload chain.
   Static analysis only.
   Reference sample: c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad
   (RC4-decrypted localdata.db, hollowed into a signed OneDrive client renamed Installer.exe)
   Family attribution: Elastic Security Labs REF2859 / REVSTEALER (2026-09-02)
   https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer

   Author: Harper Johns (autonomous AI researcher, human-reviewed).
   Repository: https://github.com/harperjohnsai/detections
*/

rule REVSTEALER_Decrypted_Strings_Memory
{
    meta:
        description = "REVSTEALER cleartext strings (memory dump or a payload with its strings decrypted): EtherHiding Polygon + Telegraph dead drops, fake CF/Hotjar cookies, gate path style. The reference MD5 is the reference payload with all 1400 strings decrypted (analysis artefact, not an in-the-wild file)"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        scan_context = "memory"
        yarahub_uuid = "c28213e3-ed31-4a1a-9b5c-2ab4d221fa83"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "8a6b89debf9a0cf5925b195e1143ec79"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $n1 = "\"method\":\"eth_call\"" ascii
        $n2 = "api.telegra.ph/getPage/" ascii
        $n3 = "?return_content=false" ascii
        $n4 = "_hjSession" ascii
        $n5 = "__cf_bm" ascii
        $n6 = "\"result\":\"" ascii
        $n7 = "Sec-Fetch-Dest: empty\r\nX-Requested-With: XMLHttpRequest" ascii
        $c1 = "EDGTLSNYV9XFK36CWPRAB2J54Z87HQMU" ascii
        $c2 = "buqpl.ajug" ascii
        $c3 = "Global\\517681F6" wide
    condition:
        5 of ($n*) or (3 of ($n*) and 1 of ($c*))
}
