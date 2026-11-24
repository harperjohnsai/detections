# sigma/

Sigma rules in SigmaHQ-style category folders. File names and UUIDs match the versions proposed upstream to SigmaHQ/sigma (`rules-emerging-threats/2026/Malware/RevStealer/`, `.../MioLab/`, `.../FluxEngine/` and `.../ROMULUS/`; rules marked "repository only" are not proposed upstream); see CHANGELOG.md for pull request links.

| Rule | File | Level |
|---|---|---|
| DNS Query To RevStealer C2 Domain | [dns_query/dns_query_win_malware_revstealer_c2_domain.yml](dns_query/dns_query_win_malware_revstealer_c2_domain.yml) | high |
| RevStealer C2 Gate URI Pattern - Proxy | [proxy/proxy_malware_revstealer_c2_gate_uri.yml](proxy/proxy_malware_revstealer_c2_gate_uri.yml) | high |
| Potential RevStealer Telegraph Dead Drop Resolver Request - Proxy | [proxy/proxy_malware_revstealer_telegraph_dead_drop.yml](proxy/proxy_malware_revstealer_telegraph_dead_drop.yml) | medium |
| Potential RevStealer Polygon RPC Dead Drop Resolver Query By Non-Browser | [dns_query/dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml](dns_query/dns_query_win_malware_revstealer_polygon_rpc_non_browser.yml) | medium |
| Renamed OneDrive Client Execution | [process_creation/proc_creation_win_renamed_onedrive.yml](process_creation/proc_creation_win_renamed_onedrive.yml) | medium |
| Suspicious MioLab Agent Process Activity | [process_creation/proc_creation_macos_malware_miolab_agent_activity.yml](process_creation/proc_creation_macos_malware_miolab_agent_activity.yml) | high |
| Suspicious MioLab LaunchAgent Or Staging File Creation | [file_event/file_event_macos_malware_miolab_persistence_indicators.yml](file_event/file_event_macos_malware_miolab_persistence_indicators.yml) | high |
| DNS Query To MioLab Stealer Domains | [dns/net_dns_miolab_stealer_c2_domains.yml](dns/net_dns_miolab_stealer_c2_domains.yml) | high |
| Potential MioLab Stealer C2 Communication | [proxy/proxy_malware_miolab_c2_communication.yml](proxy/proxy_malware_miolab_c2_communication.yml) | medium |
| Suspicious Unsigned Version.dll Loaded From User-Writable Folder (narrower hunting variant; SigmaHQ's generic side-load rule already lists `version.dll`, so it is not proposed upstream) | [image_load/image_load_win_susp_unsigned_version_dll_user_path.yml](image_load/image_load_win_susp_unsigned_version_dll_user_path.yml) | high |
| FluxEngine Banker Registry Key Write | [registry_set/registry_set_malware_fluxengine_desktop_key.yml](registry_set/registry_set_malware_fluxengine_desktop_key.yml) | high |
| FluxEngine Banker Fake HWiNFO32 Sensor Value Write | [registry_set/registry_set_malware_fluxengine_hwinfo_bsource_cache.yml](registry_set/registry_set_malware_fluxengine_hwinfo_bsource_cache.yml) | high |
| Potential FluxEngine Banker Run Key Persistence | [registry_set/registry_set_malware_fluxengine_run_key_root_folder.yml](registry_set/registry_set_malware_fluxengine_run_key_root_folder.yml) | medium |
| FluxEngine Banker Attrib.EXE Spawned By Renamed AutoIt Host | [process_creation/proc_creation_win_malware_fluxengine_attrib_from_autoit.yml](process_creation/proc_creation_win_malware_fluxengine_attrib_from_autoit.yml) | high |
| Potential FluxEngine Banker Cloudflare API Dead Drop Request - Proxy | [proxy/proxy_malware_fluxengine_cloudflare_api_dead_drop.yml](proxy/proxy_malware_fluxengine_cloudflare_api_dead_drop.yml) | medium |
| FluxEngine Banker Stage Download Request - Proxy | [proxy/proxy_malware_fluxengine_stage_url_msie8_ua.yml](proxy/proxy_malware_fluxengine_stage_url_msie8_ua.yml) | high |
| FluxEngine Banker Hollowed Attrib.EXE Network Connection (repository only) | [network_connection/net_connection_win_malware_fluxengine_attrib_network.yml](network_connection/net_connection_win_malware_fluxengine_attrib_network.yml) | high |
| Potential FluxEngine Banker Browser History Wipe From Scriptlet (repository only; script-host parents already covered upstream) | [process_creation/proc_creation_win_malware_fluxengine_clearmytracks_from_scriptlet.yml](process_creation/proc_creation_win_malware_fluxengine_clearmytracks_from_scriptlet.yml) | medium |
| Potential FluxEngine Banker Nested Regsvr32 Scriptlet Execution (repository only; `.sct` via regsvr32 already covered upstream) | [process_creation/proc_creation_win_malware_fluxengine_regsvr32_spawns_regsvr32_sct.yml](process_creation/proc_creation_win_malware_fluxengine_regsvr32_spawns_regsvr32_sct.yml) | medium |
| FluxEngine Banker Renamed AutoIt3 Execution From Root Folder (repository only; generic renamed AutoIt already covered upstream) | [process_creation/proc_creation_win_malware_fluxengine_renamed_autoit_root_folder.yml](process_creation/proc_creation_win_malware_fluxengine_renamed_autoit_root_folder.yml) | high |
| Potential FluxEngine Banker Script Host Regsvr32 Temp Scriptlet Execution (repository only; script host to regsvr32 already covered upstream) | [process_creation/proc_creation_win_malware_fluxengine_wscript_regsvr32_temp_sct.yml](process_creation/proc_creation_win_malware_fluxengine_wscript_regsvr32_temp_sct.yml) | medium |
| ROMULUS Silent MSI Install From PowerShell Staged In Temp | [process_creation/proc_creation_win_malware_romulus_msiexec_hex_temp_msi.yml](process_creation/proc_creation_win_malware_romulus_msiexec_hex_temp_msi.yml) | high |
| PowerShell Download From Decimal DWORD IP URL | [process_creation/proc_creation_win_powershell_download_decimal_dword_ip.yml](process_creation/proc_creation_win_powershell_download_decimal_dword_ip.yml) | high |
| Stardock DeElevate Binary Execution From Non-Standard Location | [process_creation/proc_creation_win_susp_stardock_deelevate_non_standard_location.yml](process_creation/proc_creation_win_susp_stardock_deelevate_non_standard_location.yml) | medium |
| Potential DeElevator64.DLL Sideloading | [image_load/image_load_side_load_stardock_deelevator64.yml](image_load/image_load_side_load_stardock_deelevator64.yml) | medium |
| ROMULUS Run Key Persistence Via DeElevate64.EXE | [registry_set/registry_set_malware_romulus_deelevate64_run_key.yml](registry_set/registry_set_malware_romulus_deelevate64_run_key.yml) | high |
| ROMULUS ClickFix Delivery Platform URL Patterns - Proxy | [proxy/proxy_malware_romulus_delivery_urls.yml](proxy/proxy_malware_romulus_delivery_urls.yml) | high |

Derived from static reversing; no regression EVTX is included because no live detonation was possible. Validation: `sigma check --fail-on-error --fail-on-issues` with the SigmaHQ validators, plus `tests/test_sigma_synthetic.py` (hand-made events).
