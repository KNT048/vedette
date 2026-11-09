# Deferred — feat/sensor-active (WP-12)

- [ ] SNMP (INV-10, the SNMP part of INV-8, `sa_snmp`): needs a story and a screen to enter community / v3 credentials first (gui-first, D-84 (3)); credentials go through `core/secrets` — kien / story first
- [ ] Move nmap from the core process into the `scan` container with `CAP_NET_RAW` and the sensor protocol (D-55, D-84 (5)); today `core/exec` runs `/usr/bin/nmap --privileged` in the core process, and the install must put the OS package nmap there — WP-08 / sensor protocol, same time as the sensor-passive capture
- [ ] Register the `scan_probes` export category in `/core/logs/export` once `logexport.Register` exists; the reader is `Service.Probes(since, limit)` — core logs WP
- [ ] Time zone: the window uses `time.Local` of the box (D-84 (6)); when core general settings get a time zone, switch `Service.local()` to it — core settings WP
- [ ] Hosts that answer a sweep but have no MAC (routed subnets) create no device: `core/observe` has no "seen this IP" field and `Record` needs a field to key a device on; add one (or a lightweight `Seen(ip)`) to `core/observe` + inventory — inventory/observe owner
- [ ] Devices the inventory knew before the module was turned on are never service-scanned again (only devices queued from `inventory.asset.discovered` are); decide a cadence for a periodic rescan (D-84 (6) names only the daily sweep) — kien
- [ ] CPE-derived vendor/product (`cpe:/a:apache:http_server` -> `apache` / `http server`) is matched to KEV by lower(vendor)|lower(product) only; a CPE-to-KEV-key table (the matching lib / Recog) would raise the match rate — matching WP
- [ ] Linux effect check on the lab VM with a real nmap against lab hosts only: `--privileged` with only `CAP_NET_RAW`, XML of nmap 7.94 parses, kill at window end leaves no child — WP-08 lab (never on a real network from a dev machine)
