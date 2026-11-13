# miolab-agent-wire-decoder

```bash
python3 agnt_wire_decode.py <body> [<body> ...]
```

Decodes the POST body that the MioLab macOS agent (`~/.hlpr/.agnt`) sends to its `/api/agnt` endpoint, as seen in curl command lines of public sandbox reports. Standard library only; takes text and prints bytes, nothing is executed or contacted. The obfuscation is keyless (fixed constants in the binary, also anchors of the YARA rule `MAL_macOS_MioLab_Agent_Backdoor_Clipper`), so the tool is for reading logged traffic, not for decrypting anything private.
