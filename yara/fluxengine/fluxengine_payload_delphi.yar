/*
  FluxEngine client payload (the decrypted d3dx9_43.bin, builds 1.0.3.111 and 1.0.3.113). The payload is encrypted in transit, so this rule matches the decrypted file, a dump or a memory image, not the downloaded container.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule MAL_FluxEngine_Payload_Delphi
{
    meta:
        description = "FluxEngine client payload (the decrypted d3dx9_43.bin, builds 1.0.3.111 and 1.0.3.113). The payload is encrypted in transit, so this rule matches the decrypted file, a dump or a memory image, not the downloaded container."
        author = "Harper Johns"
        date = "2026-11-19"
        modified = "2026-11-22"
        hash1 = "c424a715e3861bc18e0c8223f3dfd909dc4a77a82b9c5a5a135b8d49bac7e8c6"
        hash2 = "c2225d927b1461354418ce8067574e2c48dcd19be9d5150b68a3bcfbdd0e5c25"
        family = "FluxEngine"
        score = 80
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
        yarahub_uuid = "2b1961d1-23bb-4577-a97a-bcf29fc07540"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "18a54b1573f23ccfb996536fb3e8d1f9"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-fluxengine"
    strings:
        // movzx edx,word[ebx]; movzx ecx,byte[ebp-5]; xor dx,cx; mov ecx,esi; dec ecx; movzx ecx,cl; xor dx,cx
        $dec = { 0F B7 13 0F B6 4D FB 66 33 D1 8B CE 49 0F B6 C9 66 33 D1 }
        $s1 = "UseCache[lurlsource] " wide
        $s2 = "FetchCF[lurlsource] " wide
        $s3 = "{\"action\":\"evento\",\"tipo\":\"dbg\",\"msg\":\"" wide
        $s4 = "CONTATOS_RESPONSE" wide
        $s5 = "REENVIO_RESPONSE" wide
        $s6 = "/template/source/" wide
        $s7 = "uReenvioExecutor" ascii
        $s8 = "uCloudflareDNS" ascii
        $s9 = "uExtrairContatos" ascii
        $s10 = "TFormCliente" ascii wide
        $s11 = "[TRAVA] HideFromTaskbar" wide
        $s12 = "X-Template-Owner-Id" wide
    condition:
        uint16(0) == 0x5A4D and #dec >= 5 and 4 of ($s*)
}
