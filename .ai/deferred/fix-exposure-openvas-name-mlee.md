# Deferred — fix/exposure-openvas-name-mlee (PR #769)

- [ ] FULL-5 slice 3 (Mlee), from Opus r1 of #769 MEDIUM 2: D-567 (2) and plan §3.3 deep-scan every IP a name points to, CDN or hosting IPs included (all ports, exploit checks, OpenVAS on a provider's shared machines). Detectify works by name, and Cloudflare's policy forbids active exploitation. Before slice 3 merges, the testing-terms text must name the IP-level tools used on IPs that are not the box, and the supervisor/kien must give a legal OK. kien's decision stands, so this does not block #769.
- [ ] #779 LOW 1 (Trưởng's review): the probe-log "IP" column holds the domain for the `dns` probe row. The probe-log page and CSV are on the scan side, so it is Trưởng's call: rename the column to "IP or name", or add a docs note.
- [ ] Opus r1 #769 LOW: the swap note now also shows while the feed loads. Re-check on the N100 that it reads right once OpenVAS is on.
