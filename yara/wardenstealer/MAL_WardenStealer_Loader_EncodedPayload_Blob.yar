import "pe"
import "math"

rule MAL_WardenStealer_Loader_EncodedPayload_Blob
{
    meta:
        description = "Warden Stealer loader (x64 EXE, or sideload DLL posing as jli.dll / mpclient.dll): the stealer image sits in .rdata as one long run of printable ASCII in a build-specific 32-, 64- or 65-symbol alphabet (no NUL, space or newline; 5-6 bits of entropy per byte). The builds we hold also share a tiny import table and a TLS directory (not tested by the rule). Covers the MSVC-linked August-September 2026 builds and the lld-linked October-November 2026 builds"
        author = "Harper Johns"
        date = "2026-11-27"
        version = "1.1"
        reference = "https://www.gendigital.com/blog/insights/research/warden-stealer-rust-infostealer-analysis"
        reference_2 = "https://github.com/harperjohnsai/detections/tree/main/yara/wardenstealer"
        malware_family = "WARDENStealer"
        malware_type = "Loader"
        hash_sha256_1 = "dcbb0f20d29ecc90db8c50ae5ee8d24a8faca5471725138786662aa9d2beecfd"
        hash_sha256_2 = "d76e906a18c04826996d1f30de248e7a0e50c48814c82e9583b36c91fdf66f00"
        hash_sha256_3 = "5d766bab63f8be7ae2e222402b364c18462ed545cc6898dbf9a0f32c289a90fa"
        score = 70
        license = "Detection Rule License (DRL) 1.1"
        note = "Structural rule: it tests an 8 KB window in the middle of .rdata, where the encoded payload lies in every build we hold. It does not match the unpacked stealer (use the YARAhub rules WardenStealer_Unpacked_AntiVM_CPUID_SMBIOS / WardenStealer_StringDecoder_Constants for that)."

    condition:
        uint16(0) == 0x5a4d
        and pe.is_64bit()
        and filesize < 6MB
        and for any s in pe.sections : (
            s.name == ".rdata" and s.raw_data_size > 150KB
            and math.count(0x00, s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) == 0
            and math.count(0x20, s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) == 0
            and math.count(0x0a, s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) == 0
            and math.mean(s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) > 60.0
            and math.mean(s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) < 100.0
            and math.deviation(s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192, 79.5) < 32.0
            and math.entropy(s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) > 4.8
            and math.entropy(s.raw_data_offset + s.raw_data_size \ 2 - 4096, 8192) < 6.2
        )
}
