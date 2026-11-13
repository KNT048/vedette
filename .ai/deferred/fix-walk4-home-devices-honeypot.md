# Deferred: fix/walk4-home-devices-honeypot (walk 4, D-406)

- [ ] Live ARP check of the decoy IP suggestions before they are shown: a read-only host command (e.g. `decoy_ip.check`, up to 5 IPs, RFC 5227 probe in parallel, ~4 s) called on demand from Decoy personalities ("Check these addresses"), so the hint can say "no device answered at <time>". Today the probe runs only when a decoy takes the address (`decoy_ip.add`). D-406 (4).
- [ ] More LLDP sysDescr layouts as walks find them (UniFi, TP-Link Omada, Netgear, Ruckus): one row + one test in `modules/sensor-passive/capture/sysdesc.go`.
- [ ] Model values stored before D-406 that hold a whole LLDP description stay the current model on boxes installed before it when the description's layout is unknown (no newer passive model replaces them). Test boxes only (pre-release); a one-off cleanup of passive `model` observations longer than 40 bytes if a released box ever has them. (Opus review LOW 3)
- [ ] SSDP `SERVER` header still becomes the passive model verbatim (≤ 200 bytes, e.g. "Linux/5.4 UPnP/1.0 MiniUPnPd/2.2"): same untrusted free text D-406 stopped for LLDP; parse it like sysdesc.go. (Opus review LOW 5)
