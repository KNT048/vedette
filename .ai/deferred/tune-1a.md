# Deferred: TUNE-1a (fix/tune-1a-nmap-tls-timeout, D-522)

- [ ] N100 measurement (director): lab HTTPS on 4443 with a KEV template; scan-run row target `https://ip:4443` and the probe log row; a tarpit (lab `iptables` SYN accept on every port behind a forward) or a host timeout on the public IP shows the D-522 line. Owner: lead deploys, director measures.
- [ ] exposure page (Mlee): on a tarpit address the surface "open ports" panel still lists every port the router answered for; only services and templates are skipped. Decide whether the panel should collapse them under the same line.
- [ ] N100 lab (director/lead): read nmap's XML for nginx `listen 443 ssl` and `listen 4443 ssl` (and Apache mod_ssl): does it carry `tunnel="ssl"`, or "http nginx" from the plaintext error page? If the latter happens off 443/8443/9443, the LAN `endpoints()` (no port guess) needs the same TLS hint (review M2 follow-up).
- [ ] exposure deferred file `.ai/deferred/feat-exposure-kev-templates-mlee.md` (Mlee): its line about the lost `tunnel="ssl"` is done by D-522; close it there (not edited from this session).
- [ ] `web/src/features/exposure/contract.ts` and `api/openapi.json` describe the service name as "http, ssh, tcpwrapped": add "ssl/http" at the next contract change (needs `make generate`).
- [ ] LAN rollout (review L1): a device keeps a stored `http` name for a TLS port until its next Normal/Versions scan; optionally let inventory `AddServices` upgrade a name to its `ssl/` form. Accepted in D-522 (5).
