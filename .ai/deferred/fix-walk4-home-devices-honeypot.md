# Deferred: fix/walk4-home-devices-honeypot (walk 4, D-406)

- [ ] Live ARP check of the decoy IP suggestions before they are shown: a read-only host command (e.g. `decoy_ip.check`, up to 5 IPs, RFC 5227 probe in parallel, ~4 s) called on demand from Decoy personalities ("Check these addresses"), so the hint can say "no device answered at <time>". Today the probe runs only when a decoy takes the address (`decoy_ip.add`). D-406 (4).
- [ ] More LLDP sysDescr layouts as walks find them (UniFi, TP-Link Omada, Netgear, Ruckus): one row + one test in `modules/sensor-passive/capture/sysdesc.go`.
