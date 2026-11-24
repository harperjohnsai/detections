/*
  CNCMachineRMS / BabaDeda "Storage" container file (build-key header equations).

  Author: Harper Johns (autonomous AI researcher, human-reviewed). Static analysis only.
  Repository: https://github.com/harperjohnsai/detections
  Tested with YARA-X, see tests/ in the repository.
*/

rule MAL_CNCMachineRMS_Storage_Container
{
    meta:
        description = "CNCMachineRMS (BabaDeda family) 'Storage' container file: 0x78-byte header whose first qwords obey the build-key equations published by LevelBlue (K = (q1 - 7*q0) / 3, q5 = q1 - 37*(q0 + K)); carries the loader script (class 16001) and the RAT shellcode (class 16100). Matches the container as a standalone file (execute_engine_disconnect.raw, load.db, monitor.raw, cab-extracted fil* files) at offset 0."
        author = "Harper Johns"
        date = "2026-11-24"
        hash = "d5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90"
        family = "CNCMachineRMS"
        score = 85
        reference = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
        yarahub_uuid = "4e7b5c11-edaa-4125-84c8-34e5d5e210dc"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:CLEAR"
        yarahub_rule_sharing_tlp = "TLP:CLEAR"
        yarahub_reference_md5 = "d8326e736280b2b73d1bb83bb9b56489"
        yarahub_reference_link = "https://github.com/harperjohnsai/detections/tree/main/iocs/2026-11-romulus-clickfix"
    condition:
        // qwords read as two uint32 halves so the rule also compiles with yara-python (no uint64() there)
        filesize > 0x80000 and filesize < 0x4000000 and
        (uint32(0) + (uint32(4) << 32)) > 0xFFFFFF and (uint32(0) + (uint32(4) << 32)) < 0x10000000000 and
        (uint32(8) + (uint32(12) << 32)) > 7*(uint32(0) + (uint32(4) << 32)) and
        ((uint32(8) + (uint32(12) << 32)) - 7*(uint32(0) + (uint32(4) << 32))) % 3 == 0 and
        ((uint32(8) + (uint32(12) << 32)) - 7*(uint32(0) + (uint32(4) << 32))) < 0x300000000000 and
        3*(uint32(40) + (uint32(44) << 32)) == 148*(uint32(0) + (uint32(4) << 32)) - 34*(uint32(8) + (uint32(12) << 32))
}
