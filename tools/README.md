# tools/

Static helpers used to derive the rules. They parse and decrypt files only; nothing is executed natively. Handle the inputs as live malware.

| Tool | Purpose |
|---|---|
| [`setup-center-extractor/`](setup-center-extractor/) | recovers the config of the proxy `version.dll` from code patterns and RC4-decrypts `localdata.db` into the inner PE |
| [`revstealer-unpacker/`](revstealer-unpacker/) | decrypts REVSTEALER's strings (CPU emulation of its own leaf routines), the embedded helper DLL and the AES-256-CBC C2 config |
