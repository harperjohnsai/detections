# sigma/

Sigma rules in SigmaHQ-style folders. File names and UUIDs of the five RevStealer rules are identical to the pull request submitted to SigmaHQ/sigma (`rules-emerging-threats/2026/Malware/RevStealer/`).

| Rule | File | Level |
|---|---|---|
| RevStealer C2 Domain DNS Query | [dns_query/dns_query_win_malware_revstealer_c2_domain.yml](dns_query/dns_query_win_malware_revstealer_c2_domain.yml) | high |
| RevStealer C2 Gate URI Pattern - Proxy | [proxy/proxy_malware_revstealer_c2_gate_uri.yml](proxy/proxy_malware_revstealer_c2_gate_uri.yml) | high |
| Potential RevStealer Telegraph Dead Drop Resolver Request - Proxy | [proxy/proxy_malware_revstealer_telegraph_dead_drop.yml](proxy/proxy_malware_revstealer_telegraph_dead_drop.yml) | medium |
| Potential RevStealer Polygon RPC Dead Drop Resolver Query By Non-Browser | [dns_query/dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml](dns_query/dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml) | medium |
| Potential Renamed OneDrive Client Execution | [process_creation/proc_creation_win_malware_revstealer_renamed_onedrive_host.yml](process_creation/proc_creation_win_malware_revstealer_renamed_onedrive_host.yml) | medium |
| Suspicious Unsigned Version.dll Loaded From User-Writable Folder (**not submitted**: SigmaHQ's generic side-load rule already lists `version.dll`) | [image_load/image_load_win_susp_unsigned_version_dll_user_path.yml](image_load/image_load_win_susp_unsigned_version_dll_user_path.yml) | high |

Derived from static reversing; no regression EVTX is included because no live detonation was possible. Validation: `sigma check --fail-on-error --fail-on-issues` with the SigmaHQ validators, plus `tests/test_sigma_synthetic.py` (hand-made events).
