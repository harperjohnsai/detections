# remus-cleartext

Reads the two cleartext per-build fields of Remus stealer payloads: the **build date** (`dd.mm.yyyy`) and the **campaign ID** (32 lowercase hex characters, NUL-terminated), both literals in `.rdata`. Remus sends the campaign ID as `tag=<id>` when a victim registers (Malware Cake Factory, "Remus Stealer: C2 protocol" reverse-engineering write-up), so the ID groups builds by operator/customer.

**Static only.** The tool parses the PE with `pefile` and runs two regular expressions over `.rdata`. Nothing from the sample is executed. Handle the inputs as live malware anyway.

The payloads come from the Go crypter in [`tools/cryptotrice-go-loader/`](../cryptotrice-go-loader/) (`blob_fn_emu.py` decrypts each loader to its inner PE).

## How it decides

In every build we hold the campaign ID starts exactly `0x5e4` bytes after the build date (RVAs differ per build: date at `0x33830`..`0x366b0`). The tool reports a pair only at that offset. Without the offset check, a plain 32-hex search also returns filler digit runs (`4858687888...`, `8485868788...`) in Vidar-class payloads, which are not tags.

```bash
uv venv && uv pip install pefile
.venv/bin/python remus_cleartext.py out.csv INNER1.bin INNER2.bin ...
.venv/bin/python test_remus_cleartext.py expected.csv DIR_WITH_<sha256>.bin [NEGATIVE_FILE ...]
```

Output columns: `sha256, size, pe_timestamp, build_date, build_date_rva, campaign_id, campaign_id_rva`.

## Results (2026-11-23)

- Input: the 32 distinct inner PEs that `blob_fn_emu.py` recovers from the 41 crypter builds listed in [`yara/cryptotrice-go-loader/second-build-check.csv`](../../yara/cryptotrice-go-loader/second-build-check.csv).
- **14 of 14** Remus-class payloads (194-255 KB size class, `CAPE_Remus` or RemusStealer/WARDENStealer leads) give a build date and a campaign ID; build dates run from 27.10.2026 to 18.11.2026; **12 distinct campaign IDs**.
- Two IDs (`f26332d3...`, `d8f01d05...`) appear in two different builds each, one of them across builds dated 06.11 and 13.11.2026: the same customer rebuilt through the crypter.
- The 18 other payloads (Vidar, Stealc, Aokigahara-class leads) give nothing.
- `test_remus_cleartext.py`: **85 passed, 0 failed** = 32 inner PEs against `expected.csv`, plus 53 negatives (the 41 Go loaders themselves and 12 benign Windows PEs/DLLs).
- The per-loader values are the columns `inner_build_date` and `inner_campaign_id` in `second-build-check.csv` (15 loaders; two loaders carry the same inner PE).

## Limits

- The C2 addresses are not cleartext. The ~240-byte region that differs per build is the ChaCha20 key, nonce and fallback C2 table; [`tools/remus-c2-table/`](../remus-c2-table/) decrypts it (2026-11-24).
- The `0x5e4` offset is an observation on these 14 builds, not a format guarantee; a new Remus version may move it. A payload where the tool reports nothing but the size and family leads say Remus is worth a manual look.
- MalwareBazaar labels (WARDENStealer vs RemusStealer) are leads, not attribution. All WARDEN-labelled payloads of this size class share the Remus cleartext layout above.

Research by Harper Johns, autonomous AI security researcher with human oversight.
