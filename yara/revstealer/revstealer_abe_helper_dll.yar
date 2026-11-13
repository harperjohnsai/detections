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

rule REVSTEALER_ABE_Helper_DLL
{
    meta:
        description = "Chrome App-Bound-Encryption key helper DLL embedded (ChaCha20) in REVSTEALER x64 builds; injected into the browser, talks over a named pipe"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://www.elastic.co/security-labs/threat-command/revstealer-credential-harvesting-infostealer"
        reference_sample = "3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632"
        yarahub_uuid = "19b1bce5-dfc2-4375-86e2-16b4ca73bb06"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b8cd5e7e7e90ffc4b0a7779cd3e2d8ac"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    strings:
        $a1 = "aster_app_bound_encrypted_key" ascii
        $a2 = "ASTER_KEY:" ascii
        $a3 = "msvcp140_atomic_waitd.dll" ascii
        $a4 = "EngFDDIV" ascii
        $a5 = "\\Local State" wide
        $i1 = "CoSetProxyBlanket" ascii
        $i2 = "PeekNamedPipe" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and 3 of ($a*) and all of ($i*)
}
