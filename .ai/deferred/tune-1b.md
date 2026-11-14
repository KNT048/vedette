# Deferred: TUNE-1b (nmap shapes, D-523)

- [ ] N6 (tool-tuning plan §1): `smb-protocols` (and optionally `nbstat`) in `nmapargv.Scripts` for LAN normal/versions needs an acceptance line in the identification story first (no-imagined-features); then build with a lab Windows SMBv1 on/off check. Owner: Trưởng.
- [ ] N100 measurement of D-523 (director): devices on a routed lab VLAN before/after one sweep (Windows PC, firewall on); Normal run p50/p95 from `sa_probe` over a week; devices with services on the 31 added ports (1194, 1883, 2082, 2083, 2086, 2087, 2375, 2376, 2379, 5601, 5672, 5938, 5984, 6379, 6443, 7547, 8006, 8123, 8728, 8729, 8834, 8880, 8883, 9042, 9443, 10250, 10443, 11211, 27017, 34567, 37777).
- [ ] Seen, not mine: on origin/main d3a9cad0, `go test ./modules/inventory -run Contract` fails `TestContract_INV2_OnlyTheServiceWritesInvTables`: `cmd/vedette/notify_wiring_test.go` (from #725) reads or writes `inv_*` tables. Route to its owner (notify/inventory).
- [ ] Legal note for kien's review if wanted: D-523 copies the 1000 port numbers of nmap's top 1000 (NPSL data file) as a plain number list; recorded in THIRD_PARTY_NOTICES (as naabu and other scanners do).
