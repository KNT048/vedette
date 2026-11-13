# Deferred: feat/device-types-two-levels (item 25, D-511)

- [ ] Unknown devices still get only the one gentle scan (no -sV, D-84), so page titles, certificates and nmap's service device type arrive only after a person's "Scan now" pick (versions shape) or once the device has a kind. Decide (director/D-xx) whether an unknown, non-fragile device may get one versions scan automatically; today's rule is unchanged on purpose.
- [ ] 192.168.18.67 (HP card, ports 80/443/8000 only) gets no guess: not enough signal. Re-check on the N100 after a Scan now of it (title/certificate now kept).
- [ ] LLDP-MED Telephone bit → `ip_phone` instead of `iot` (sensor-passive `kindCap` + `engine.go`); same behaviour (acts as iot).
- [ ] More rule inputs: DHCP option 55 list and option 60 vendor class (parsed, not stored), more mDNS service types (`_airplay`, `_companion-link`, `_axis-video`, `_rtsp`…), SSDP deviceType. Needs a stored hint field per device.
- [ ] "Back to automatic" for a manual type, and picking "Unknown" pinning the device (v8 §6 gaps 1–2); catalog-guessed kinds stored as manual (gap 3).
- [ ] Catalog `kindHints` (Go `catalog.go` + FE twin `catalog.ts`): phone/mobile/android → `smartphone` instead of `iot` (same behaviour); kept for the golden search parity.
- [ ] MCP `list_assets` and AI `search_assets` filter by exact type: accept a category or acts-as kind too.
- [ ] Make / model / firmware split (item 25b): OUI maker vs device make, firmware field.
- [ ] Release note for the merge captain: inventory migration 0004 rebuilds `inv_asset` (not add-only, like findings 0005), so the release classifier flags it; a rollback to before it needs the backup.
