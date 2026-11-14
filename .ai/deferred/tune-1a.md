# Deferred: TUNE-1a (fix/tune-1a-nmap-tls-timeout, D-522)

- [ ] N100 measurement (director): lab HTTPS on 4443 with a KEV template; scan-run row target `https://ip:4443` and the probe log row; a tarpit (lab `iptables` SYN accept on every port behind a forward) or a host timeout on the public IP shows the D-522 line. Owner: lead deploys, director measures.
- [ ] exposure page (Mlee): on a tarpit address the surface "open ports" panel still lists every port the router answered for; only services and templates are skipped. Decide whether the panel should collapse them under the same line.
- [ ] exposure `zap.go` `isTLSService` (Mlee, #757): still treats any port 443/8443 as TLS even when nmap read plain "http" there; with D-522 the name is reliable, so the port guess can go.
- [ ] exposure deferred file `.ai/deferred/feat-exposure-kev-templates-mlee.md` (Mlee): its line about the lost `tunnel="ssl"` is done by D-522; close it there (not edited from this session).
- [ ] `web/src/features/exposure/contract.ts` and `api/openapi.json` describe the service name as "http, ssh, tcpwrapped": add "ssl/http" at the next contract change (needs `make generate`).
