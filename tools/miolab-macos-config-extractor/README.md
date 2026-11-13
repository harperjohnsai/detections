# miolab-macos-config-extractor

```bash
python3 extract_config.py <universal-or-thin-macho> [out.json]
```

Pure-Python static parser (standard library only). Walks the Mach-O load commands (fat or thin), finds `__DATA,__data`, decrypts the config blob and prints the parsed fields per architecture: affiliate `user_id`, `build_tag`, C2 host list, file-grabber extensions and the dialog texts. Nothing is executed. The decryption key is the first 8 bytes of the blob itself, read at run time.

Expected output for the reference stage-2 sample (SHA-256 `2b4f61c2...`, both slices): `user_id` 124, `build_tag` `ggggg`, four C2 hosts (see the case IOCs).
