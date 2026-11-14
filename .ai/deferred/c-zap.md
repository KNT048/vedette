# Deferred: c-zap (item 24 slice c, ZAP host op, D-521)

- [ ] Lab/N100: JVM peak with -Xmx512m inside --memory=1g (memory.peak of the libpod scope during a run on the forwarded test site); raise or lower -Xmx with the number.
- [ ] Lab/N100: ZAP 2.17.0 runs with --read-only, --tmpfs /home/zap (copy-up) and the bind-mounted /zap/wrk, as user 1000 under the vedette-container AppArmor profile; if not, adjust the mounts and record why in D-521.
- [ ] Lab/N100: the nft table inet vedette_zap loads next to netavark's tables (nft and iptables-nft backends) and drops DNS/zaproxy.org from vedette-zap0 (tcpdump); podman 4.9 accepts `network create --interface-name … --disable-dns` and `--dns none`.
- [ ] Docker boxes (DOCKER-USER, FORWARD DROP): vedette-zap0 is dropped by Docker's chain, so ZAP reaches no page. Add a per-run DOCKER-USER accept for vedette-zap0 -> ip:port (iptables, fixed shapes, removed after) or document the limit in the page text.
- [ ] Merge with slice b: keep b's `type exposureProbeLog` in cmd/vedette/exposureprobes.go and drop the type line of cmd/vedette/exposurewebprobe.go; b wires cfg.Probes, which then also implements exposure.WebProbeLog.
