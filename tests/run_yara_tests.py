#!/usr/bin/env python3
"""Compile and test the YARA rules in ../yara with yara-python and YARA-X.

Modes
  --compile-only            only check that every rule file compiles (used in CI, no samples needed)
  --samples DIR [DIR ...]   directories holding the real samples (identified by SHA-256, not by name)
  --negatives DIR [DIR ...] directories of benign files; every file there must produce 0 hits

Samples are malware and are NOT part of this repository. Get them from MalwareBazaar
(links in iocs/*/README.md) and put them in a directory of your own.
Static only: YARA reads bytes, nothing is executed.
"""
import argparse, glob, hashlib, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
YARA_DIR = os.path.join(HERE, '..', 'yara')

# sha256 -> rules that MUST match (and no others)
EXPECTED = {
    'b371d2e01562fc0d29072ac1a56969628b6408f2368c056c3158f4fe0c609960': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 27 (2026-11-05)
    '973ad2986d6eda8a8936342ba64fda6e2909cc8527a83bb2f474c13d76c0b6e7': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 25 (2026-10-28)
    '2903e5e3363c1c15725a5343d31429490ce662cdc3df3c1f0dbf8ba7863aa4c3': ['SetupCenter_ProxyVersionDll_Loader', 'SetupCenter_Loader_AntiVM_HashTables'],              # version.dll, build 26 (2026-11-02)
    '193f259776d345f42c7957b737c4ef2d72df5268eee1d12be0574e6f91469f62': ['SetupCenter_FakeCab_PayloadContainer'],           # localdata.db
    'b484561cc81da34990824452d4ce4002d0520c71c71e3eeb2f248e57e1f5bc3f': ['SetupCenter_FakeCab_PayloadContainer'],           # config.dat, build 25
    'ca82cb69da221788258d659b0eb8c84b7cfe0a99710037d40edd73e8ed330827': ['SetupCenter_FakeCab_PayloadContainer'],           # sync.dat, build 26
    'e472b895f15e4e17d3d35102ac6bc3eba9f707cb1da95df3ac2e7e9113825e81': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 25
    '673feccbcec6008354e4b3b7711de22953445d5314721097b041eb020e6cd231': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 26
    'c6859833796f682e3598f65865a2853c3ecc118d7f2fb01defc24cf328e3ecad': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],                # inner payload, build 27
    '3c6330d06b57d18026efd5745245cc19e1c67983d957f42ff6a821e2b7f71632': ['REVSTEALER_ABE_Helper_DLL'],                       # ABE helper DLL
    '0a48e7ed139a1cbe38c4ccb98edf2ff99bc53933f07942fa02fcf054dc14e0a6': ['REVSTEALER_Decrypted_Strings_Memory', 'REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact
    '5e3c4ef86cd0bb65f30fc919681a07126b8d3918419446b3c88d2ccbacf3dc86': ['REVSTEALER_Decrypted_Strings_Memory', 'REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact, build 25
    'c036690cb8e6965d3d2e1091d10ca78994e4440808813db032fa121fb0517ce9': ['REVSTEALER_x64_Core_SetupCenter', 'REVSTEALER_x64_Hashed_Evasion_Shapes'],  # strings-decrypted artefact, build 26
    # MioLab macOS chain (yara/miolab-macos)
    '2b4f61c274bf8e4a79cf77e7b36d18d1dd265e8e894f5f2b6d8babc6323d556a': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # stage-2 universal Mach-O
    '49de3b526ee449d9a28f73d85af2fb0b40d721b45693d80119f8db47d4bba51a': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # x86_64 slice
    'f9a80a964748880116c22e1353072b31a966a5744e930d7a1bd376cf75ba5532': ['MAL_macOS_MioLab_Cpp_Stealer_ConfigDecrypt'],  # arm64 slice
    '5a2bef675eae4b80db636a17f5a2ef1e67ee56c4b841ef995ce3ce52a739be5e': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent, universal
    '8281c8dc3f595064d5edad2ab479727358ac84af83ffb5604ab56929a5cd0c1b': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent arm64 slice
    '77a41f1a86f3bd778fd4febda4d2dc7ff77b53ec16f5e1ea52c29f2fc642d1ee': ['MAL_macOS_MioLab_Agent_Backdoor_Clipper'],      # agent x86_64 slice
    'b6e9f44926dda38bdd080e6cf23001546aee34f4b5f5eaf94e54ebcd73afa44a': ['MAL_JS_MioLab_Trojanised_LedgerLive_SeedPhrase_Modal', 'MAL_MioLab_Trojanised_Wallet_Locale_Strings'],  # Ledger app.asar
    '05ca25705ce7acffc20bbbf74ed4ec9fcd0b9a19307cb08f46e2d73d53b8802b': ['MAL_JS_MioLab_Trojanised_TrezorSuite_SeedPhrase_Modal'],  # Trezor app.asar
    'c383789cf9809290ae2a194ed44176e4fc36fbceb0260958e481a8562b0f16c9': ['SUSP_Electron_AppUpdate_Yml_NonVendor_Feed_Wallet'],  # Ledger app-update.yml
    '31a4f6a8aecd2b18107dfff5e68581804a68e9d61fc68e3ccf01d54225ae5cde': ['HUNT_macOS_MioLab_Cpp_Stealer_Plaintext_Artifacts'],  # decoded string dump (artefact)
    '978c98b401a6124e0522043b983911f7f57fc7b64868164cc158439ae5b07dd9': ['HUNT_macOS_MioLab_Agent_Plaintext_Artifacts'],       # decoded agent strings (artefact)
    '3bf97f7e851e3bfb9c16872a55364af1e6a95455d24b8d25e8dfc57e4c587a56': ['HUNT_MioLab_Agent_C2_Body'],                          # sandbox curl command lines (artefact)
    # Grandoreiro Delphi loader (yara/grandoreiro)
    '93845bd3c4d6cb0a15c75d82903a88776e07bf90634f8d794aca8fd476539a52': ['Grandoreiro_Loader_Delphi_BMP_Padding_Hunt', 'Grandoreiro_Loader_Delphi_StrCrypt_PortCalc'],  # loader EXE, 85.6 MB
    '29db0be6d95b24744259cba90c29fb34df596fb88d321dcc14e5873fd5a6ac6f': ['Grandoreiro_Loader_Delphi_StrCrypt_PortCalc'],  # same loader, padding resource stripped (derived test copy)
    # Mispadu (URSA) 2026 payload (yara/mispadu)
    '4f4129e8f79bde102875417f64a3258226ae93658776a416aaf4383698a6ea7d': ['MAL_Mispadu_URSA_Delphi_Cipher_Code', 'MAL_Mispadu_URSA_Payload_Build108'],  # payload EXE, build 108 (Delphi, 6.9 MB)
    '352c8d5d8cc824c41d143af2504d2cdf5d8a16e5f4df019032a5241859b1900b': ['MAL_Mispadu_URSA_Hook_DLL_pDLL'],  # pDLL keyboard-hook DLL extracted from the payload resources
    # FluxEngine (yara/fluxengine)
    'dc60f22fc59a7c3cb51b97661ad69f42d3028538c0044b248fc9681487c0b433': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, 2026-10-19 build
    '6a9ded132c050747ae5f233a91fc84c6bbee4e91950636f5fe077bf48acdca30': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    '7040370d8d09dc735d3ae9a77fe4b4c8e3f97c64efb60d4a962337fd6b16b114': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    '01af2f7049e1562023835ddcbffea76e265ed2906e140ba8a200eb41d37ebf8d': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll loader, Sep 2026
    'c424a715e3861bc18e0c8223f3dfd909dc4a77a82b9c5a5a135b8d49bac7e8c6': ['MAL_FluxEngine_Payload_Delphi'],  # decrypted payload (Delphi, 4.5 MB)
    '6e6d4084c6c2f3035c2fbda4daf4b705a06938d73bf91f402552b6d4ab522d9b': ['SUSP_FluxEngine_LNK_Squiblydoo_ADS'],  # stage-1 LNK
    # FluxEngine part 2 chain (2026-11-22)
    'c3dc04853487b4a8f0e25a9527c250c45de5f8ba8153ec5e0c83ad834a0c81de': ['MAL_FluxEngine_Loader_dhlib_DLL'],  # dhlib.dll Nov 2026 build (carved from the a3x)
    'c2225d927b1461354418ce8067574e2c48dcd19be9d5150b68a3bcfbdd0e5c25': ['MAL_FluxEngine_Payload_Delphi'],  # decrypted payload build 1.0.3.113
    'e683253477ca1b9b22c285cbc854a50284256b4d246b151e63dc171830bf7192': ['MAL_FluxEngine_VBS_Downloader'],  # stage-1 DOC-9CQC87.vbs
    '2ec8894d0cc8b092c5525a12254cad122d34933a349c3eff14f1af02836177ac': ['MAL_FluxEngine_SCT_Recon_Stage2'],  # stage-2 scriptlet
    'f32d6dc8c15efe4473e5a400cacb15cb28bcde2daf74fa2c99fa86d4936c7880': ['MAL_FluxEngine_SCT_Installer_Stage3'],  # stage-3 installer scriptlet
    '4fc99727bbb91087a474126049ced32b69d252c5ed93e2b1fa40d8c13d10257e': ['SUSP_AutoIt_A3X_Large_NoExt_Script'],  # compiled AutoIt script (raw a3x)
    'd8e0ac6e4300c5a2faa730aa45c7aa939c9232dcc4998d9122ecd4d37bc4c95e': ['MAL_FluxEngine_AU3_PELoader_Decompiled'],  # decompiled a3x text (artefact)
    'bdd2b7236a110b04c288380ad56e8d7909411da93eed2921301206de0cb0dda1': [],  # genuine signed AutoIt3.exe shipped renamed: must NOT hit
    'cd2f07e47e98e52472bd744912edc9e9e645b544f5e612e2f38f89b7acb1e064': [],  # genuine WebView2Loader.dll listed by the panel: must NOT hit
    '01b64c8943b71ef3a5c73de14269695a2c9c1fb15a97243abbe3a076a38993e8': [],  # <n>.ico of the install folder: no rule
    # Go reflective PE loader (yara/cryptotrice-go-loader): reference build and two builds with the same self-signed publisher name
    'b8c1d2399105a57046b24aeee74d2dea3250c8c8aa5502c448b8d954f1dcb17a': ['MAL_Go_Reflective_PE_Loader_Win64'],  # cryptotrice loader core (4,191,744 B, Go 1.21.1)
    '2b51009b5712d49af298d35b4fc22a014bb04575d7474f3b44fc6753720f39da': ['MAL_Go_Reflective_PE_Loader_Win64'],  # MalwareBazaar 2026-11-12, "Nova Metric Industries" signer, serial c8266838...
    '7a705f5b3959b9f56223cf93e68b1b0422959b7f9ca2e94ef0c30c8a050f793b': ['MAL_Go_Reflective_PE_Loader_Win64'],  # MalwareBazaar 2026-11-12, "Nova Metric Industries" signer, serial a3741edb...
    # The Gentlemen (yara/the_gentlemen)
    '3ab9575225e00a83a4ac2b534da5a710bdcf6eb72884944c437b5fbe5c5c9235': ['MAL_Gentlemen_Locker_Go'],  # Windows locker (Go, garbled), 2026-04
    '53d2484ae1ad6ff9547d90f5f5ccd6ae1dca8cb24e622a07dfc74c9593b2c3fa': ['MAL_Gentlemen_Locker_Go'],  # Linux ELF locker (Go), 2026-10
    '32ead708c8b0e5fcc61c224fb7e9e1b75a88f287d4c5d2867faacec310385134': ['HUNT_Gentlemen_Ransom_Note'],  # README-GENTLEMEN.txt (extracted from the note zip)
    '51b9f246d6da85631131fcd1fabf0a67937d4bdde33625a44f7ee6a3a7baebd2': [],  # DOCUMENTED MISS: VMProtect-packed Windows build, no family-specific rule possible (yara/the_gentlemen/README.md)
    'f8b07ce20ae77fec0905724a466196a5ba8281e9ba9534808ab7e7bf15f37516': [],  # DOCUMENTED MISS: the note zip (deflate container); the extracted note matches
    # ROMULUS ClickFix / CNCMachineRMS (yara/romulus-cncmachinerms)
    '29340068aa98c9720340fb1aa6f21f8314d939519db5e26cdd5e7d9c321816db': ['MAL_CNCMachineRMS_Core_Decrypted_x64'],  # decrypted RAT core
    '51c25fdf3a1aae25b7f489577f279839ec6c802ed3ba17b07d58c1fd055d7d70': ['MAL_CNCMachineRMS_Core_Decrypted_x64'],  # decrypted RAT core
    'ab65bbfc505dbe1cebe6021fb36e2011f6aa1d64f5d87cee1cbee3fc2a0c7907': ['MAL_CNCMachineRMS_Core_Decrypted_x64'],  # decrypted RAT core
    'd9274c98d7be30e6045e63d3acc190055a3849e2992b7382643c16a5aefa22dc': ['MAL_CNCMachineRMS_Core_Decrypted_x64'],  # decrypted RAT core
    '06b8adb4f361ba2cbcf35379e4dfd3d6291167bb987bd0b1817d3358c3e8fb5c': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    '4652fe86f16373375dbc84894917e34b4ea67b91a4b86d62c03fce96d9a985e8': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    '9a7ec20cfe939a0739819262c1e3ff0265c851136cc263597936773376a5d907': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    'd5acf44658f0dce90bd160f15d8e07a96938c81661d87dc7e9cb0107863bfb90': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    'd95a5e3447077a4cb0cad3110bf761b26270a140a4817744b9570e0887591e4c': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    'e614b7d5a7a363fb1b355a87e2e8d9e8a05bbbca08f2cee3d606bdb5015ac53b': ['MAL_CNCMachineRMS_Storage_Container'],  # Storage container
    '0187479bca5c3802c4ecc616ce610281cfa120448409dd9f0e9a01bd445a2e3c': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '01a1f73a1cf5f52ffe9c8091cc04d15c5cccaf67a8f66c56bf6b398303197d37': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '02da738af6d5faa9fb3bdb7c112e6fb0f16876e18edf2871566d14f0b0f6143a': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '04a6a5d6787196ae1851b3d031896953a8a72acde34580f8ce30e375a435e4d3': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '232a1639b1d70e7f4721b2811cb5dab3e096393d00a43bc46ba91cdcc36d9d84': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '37e56899fcfeeab953dd1c0804b59848f5cc66a0e47e2197e0e276dd032f30f7': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '3b39d6b14b99c0e1cf590a32635c77c31094cb2f48c916381df05fe3dc77ffe5': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '3cf6900cf7af81f4c5f3c41c96c6231f464646e89e427e25f83498667fe3247e': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '49c20202f1501b82dd1e87fbe63a0b1b066ad8a074f7d6a1b19b37cca09c735f': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '4a98be1541936632c91c83fc71d7626ea2f0fdc37ef2407f72879b9353d19af4': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '4cf4597ccacd6660d95e0f7630e69d0be81f98437d9c7970b24ac462fd821874': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '543c0336cabbab85a8cbaff437b8bb33fba4fda58763b1b00a948c7ebfcafbf4': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '5f36b4e8b71e2b12e542487ba0fd8b890abeb713297e103048b465e0e27db571': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '737690df6e6b5b05b295557e5da604116f46e42bb33b4b457a421c9af79d44a1': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '73d3bfae1717b01f021d88f9ae6a3628ae38013a50215de7de26905a6bb7746d': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '7c1c464de8a353bd5480e3de09ac36ad5cca6558e9c8adb9fe00b08ef7e76467': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '8f6f14485f0118637766e60a1382b5457d41056c60ac8783e8b5b82e9fd1faa5': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '920bc0ea1f58e06f4fa6e2038a62320dba36423e94bc169022cb125b84c6920a': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '9666fe7e1ff1f42bc8e9035cb54358dfeab009970ed005d3e2c9ecd1b54a40dc': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '9ae0f9d4338e4719d78a234a22c1ead941a66ed6b76d0ea4f4c332570788a74c': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'a93344d6a743979dd867d662a8572562bdfbe4bd16c0daa5dbdfa18c0e2ac985': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'b6769af4f9ed80121bd826e519e56dd57463f5688cc8c41287c43df2a86eeb88': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'cd0c4a46b163c5b6b2ee563be95328f57c627e2ba90bbbd4aa470765cd4849f6': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'd096a4ea41fe73b8c216e1058a1e895220dddc5f7218c3e603e3b18b2b3456f9': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'db2a4e300c9442b10840a790e93f7b99844d13e0305dd4ad052db62a379a1731': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'f205498b7aef46e722cc5fcc4ecfcdf2ae7407277c33351bd6c977416e2e3f2c': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'f3a8d40d9a7060bcad4444a7994c68d6d15ae556852d3324a125c55d56bb3702': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'f4c375f43b22056267ba4633c9e86a3120705f96cd053f2dbe629da09d63c318': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'f9440912b7f3a35c91ec7c9b98eaa9986733a60bb1be9e5a2591460dc135e9e8': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'faadf376cc6d2ff6dd56c814a99c4d3276bf10c843d04fb8fbd9b3ccedad428f': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    'fcbeea2c639ed7c3e8d7c2d78105c695e83f26ac62a6ba3c466b374a92393495': ['MAL_ROMULUS_MSI_Builder_Script_CustomAction'],  # MSI builder
    '7eb0d8e8f74b298885fa0ec0a0ee1e87b03e27fbff5fe41ae99edacfaac2d1a3': ['MAL_ROMULUS_PS_IntArray_CharOffset_Stager'],  # PowerShell stage
    'f1b38c9412a18eecc1e29bb058aa87bdbe41edac073c190aab517248cc68ad1d': ['MAL_ROMULUS_PS_IntArray_CharOffset_Stager'],  # PowerShell stage
    '98a1d42af78a82a61b1511479f7f8b3fb5f91bca8ff452cbf6576a32515c6b0d': ['MAL_ROMULUS_Script_Nibble_Base64_Decoders'],  # script stage
    'bb19340e9d9d29241321f3e8486901aaf130e65f809c67bf59eb5ae69f3cd304': ['MAL_ROMULUS_Script_Nibble_Base64_Decoders'],  # script stage
    '2108909c78bdf20abcbb092e1f72375d27d1ecc98d76312b33ead4ae3330a92e': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '32797a560b9a290e715cb5591e71dd9537d782862324906e1bb4652dd2366c9a': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '3bd4c0335342a0a68e535096e2c412d110b5d83ba6078ded762bb565fed96621': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '3cd1484cc5bf10e22d79784beba58a75d7b126c46efb5e1a85d6aab884447621': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '5cd20d86211ab3f4b8ab96a3efb296a069a600a3473d3548e1ed58a9d8c7062e': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '71b82aca5bf2b96a69dd4d4292a68b29e287bedd61d67414320dcfd899b00f08': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '727313a64de14972734375e50f5da5f01f1858de8d18bafbf372849b08d0aa39': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '8198d32ee695709cb1310b99a44db5bc70e6e3b3590394ad063f81ce544fdfae': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '9c615db040b88c18ce6b96f30d08797045b7d506f940bea452dc7a6992fdbb8d': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'a27cafb84876a3374ef4aba1062345def6cd0b029eaf8e0dc44fa24fc943f3c6': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'b59a21a8d4c0c11a9ecbbdbe2a2938499c99c5ebb210c9c6db9683c7ad19f4c4': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'b77575413c0f97eaf31e4a44c884c1ecdc0049ec89916ceb0bf3aaaedc0442fe': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'b962250b8eb977322899cbfd79e6adb6b3e6ac4fcef5cbdb724dde3ee203f1b7': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'bddc9f8116008c03cb90c2753eb85d6e264e80d64189c64e39706c8c989854d1': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'd7bcae4a915261ace7a845f8c1bb2a54ce918921805204125705bfae29656851': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    'eff5d63ddf1813962f0d8ad1250cea5486c8bb5dd27c3f432b43957a33e43764': ['MAL_ROMULUS_SideLoaded_Decoy_Loader_DLL'],  # decoy loader DLL
    '0457414c4504b70115798eee9c8384a8bf9e793461ffb2e0661a6dcc6ed4809f': ['MAL_ROMULUS_Stardock_DeElevator64_Patched_Import'],  # patched DeElevator64.dll
    '22869e3326fe1de011cd500e666769027126c5c440b76837baf55139f30094e4': [],  # genuine signed Stardock DeElevate64.exe (the host the chain abuses): must NOT hit
}
ok = True


def check(cond, msg):
    global ok
    print(('PASS ' if cond else 'FAIL ') + msg)
    ok &= bool(cond)


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def walk(dirs):
    for d in dirs:
        for r, _, fs in os.walk(d):
            for f in fs:
                yield os.path.join(r, f)


class Engines:
    def __init__(self):
        self.eng = {}
        files = sorted(glob.glob(os.path.join(YARA_DIR, '**', '*.yar'), recursive=True))
        self.files = files
        try:
            import yara
            self.eng['yara-python ' + yara.__version__] = self._py(yara, files)
        except ImportError:
            print('NOTE yara-python not installed, skipping')
        try:
            import yara_x
            self.eng['yara-x ' + __import__('importlib.metadata').metadata.version('yara-x')] = self._x(yara_x, files)
        except ImportError:
            print('NOTE yara-x not installed, skipping')

    def _py(self, yara, files):
        rules = yara.compile(filepaths={os.path.basename(f): f for f in files})
        return lambda p=None, data=None: sorted(r.rule for r in (rules.match(p) if p else rules.match(data=data)))

    def _x(self, yara_x, files):
        c = yara_x.Compiler()
        for f in files:
            c.add_source(open(f, encoding='utf-8').read(), origin=f)
        rules = yara_x.Scanner(c.build())
        def scan(p=None, data=None):
            res = rules.scan(data if data is not None else open(p, 'rb').read())
            return sorted(m.identifier for m in res.matching_rules)
        return scan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--compile-only', action='store_true')
    ap.add_argument('--samples', nargs='*', default=[])
    ap.add_argument('--negatives', nargs='*', default=[])
    a = ap.parse_args()
    E = Engines()
    check(E.eng, 'at least one YARA engine available')
    check(len(E.files) >= 17, f'{len(E.files)} rule files compiled together')
    for name in E.eng:
        print('ENGINE', name)
    if a.compile_only:
        print('COMPILE OK' if ok else 'COMPILE FAILED')
        return 0 if ok else 1

    seen = set()
    for p in walk(a.samples):
        h = sha256(p)
        if h in EXPECTED:
            seen.add(h)
            for name, scan in E.eng.items():
                check(scan(p) == sorted(EXPECTED[h]), f'[{name}] {h[:12]} -> {", ".join(sorted(EXPECTED[h]))}')
    for h in EXPECTED:
        if h not in seen:
            print(f'SKIP sample {h[:12]} not provided')

    negs = [p for p in walk(a.negatives) if os.path.isfile(p) and sha256(p) not in EXPECTED]  # known positives are never negatives
    for name, scan in E.eng.items():
        fp = [p for p in negs if scan(p)]
        check(not fp, f'[{name}] negative corpus: {len(negs)} files, 0 hits {[os.path.basename(x) for x in fp]}')

    # synthetic negatives: a real, spec-conformant cabinet must not trigger the fake-cab rule
    try:
        from cabarchive import CabArchive, CabFile
        arc = CabArchive(); arc['a.bin'] = CabFile(os.urandom(300000)); arc['b.txt'] = CabFile(b'hello ' * 5000)
        for comp in (False, True):
            cab = arc.save(compress=comp)
            for name, scan in E.eng.items():
                check(scan(data=cab) == [], f'[{name}] real CAB (compress={comp}) -> no hit')
    except ImportError:
        print('SKIP synthetic CAB test (pip install cabarchive)')
    print('ALL CHECKS PASS' if ok else 'SOME CHECKS FAILED')
    return 0 if ok else 1


sys.exit(main())
