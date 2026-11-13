import "math"

/*
  "Setup Center" DLL-sideload chain used by YouTube-lure campaigns that deliver REVSTEALER:
  a Microsoft-signed OneDrive client renamed Installer.exe, a malicious proxy version.dll
  and an encrypted payload container (localdata.db) that is not a real cabinet file.

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with yara-python and YARA-X, see tests/ in the repository.
*/

rule SetupCenter_FakeCab_PayloadContainer
{
    meta:
        description = "Encrypted payload container masquerading as a cabinet: 'MSCF' magic but reserved1 != 0 (MS-CAB says MUST be 0), header size 0x40, near-random body"
        author = "Harper Johns"
        date = "2026-11-13"
        reference = "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cab/"
        sample = "localdata.db in Installer.zip 2e3bdd68f85755b02caa42ec0228fb8a56c964479c4f085eae67569d67440e49"
        yarahub_uuid = "b60fc21e-69ec-4fc6-ac51-9f56000357b9"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b80f3e45c3cc6f38aa3505ab70cd3017"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections"
    condition:
        uint32(0) == 0x4643534D            // 'MSCF'
        and uint32(4) != 0                  // CFHEADER.reserved1 must be 0 in a real cabinet
        and uint32(8) == 0x40               // in a real cabinet this is cbCabinet (file size), never 64 for a 400 KB file
        and uint32(12) < filesize and uint32(16) < filesize
        and filesize > 0x10000
        and math.entropy(0x100, filesize - 0x100) > 7.9
}
