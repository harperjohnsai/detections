rule MAL_SilentNet_Zig_Loader_InlineXorStrings
{
    meta:
        description = "SilentNet EXE loader written in Zig (fake game cheats/launchers that fetch the SilentNet Python stealer): Zig std.http client plus many compile-time inline XOR string-decrypt loops with a 16-byte repeating key (cmp idx,len / je / and idx,0xf / xor byte) over encrypted config blobs in .rdata"
        author = "Harper Johns"
        date = "2026-11-27"
        version = "1"
        reference = "https://www.malwation.com/blog/inside-silentnet-analysis-of-a-java-based-infostealer-with-blockchain-based-c2"
        reference_2 = "https://github.com/harperjohnsai/detections/tree/main/yara/silentnet"
        malware_family = "SilentNet"
        malware_type = "Loader"
        hash_sha256_1 = "dbe586b56376ac96097b76ed353b6ad89977d3345774d80fce846fe97370b86f"
        hash_sha256_2 = "0b9186fa35770dc3b4b121a35551d49c6d623c0cd8dafbc5bafbce2d5bdcd7f3"
        hash_sha256_3 = "2c252e7ec4f7b0ccb380bf58bce3fa1592f28fbf275eabb2fd29a3958fb11c95"
        score = 75
        license = "Detection Rule License (DRL) 1.1"
        note = "Every build we hold (two template versions, April-November 2026) has exactly 25 such loops; benign Zig programs (Zig compiler, ZLS, Bun, TigerBeetle) have none. A loader rebuilt without the string obfuscation would be missed."

    strings:
        $zig_ua = "user-agent: zig/" ascii
        $zig_http = " (std.http)" ascii
        // cmp rax|rcx.., imm8 ; je short ; mov r8d,eax | mov e?,e? ; and r?d,0x0f
        $loop = { 48 83 F? ?? 74 ?? ( 41 89 C? | 89 ?? ) ( 41 83 E? 0F | 83 E? 0F ) }

    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550
        and uint16(uint32(0x3c) + 4) == 0x8664
        and filesize < 8MB
        and 1 of ($zig_*)
        and #loop >= 12
}
