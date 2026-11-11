# fix/docker-forward-drop (D-267)
- [ ] 2026-11-12 — Confirm on a real box (Mlee's .141) that the `<none>` image left by a failed on-box scan build carries `io.vedette.build=scan` (Containerfile LABEL after FROM), so uninstall removes it.
- [ ] 2026-11-12 — Check that `iptables -S DOCKER-USER` prints `--comment vedette-int` unquoted on Ubuntu 24.04, 26.04 and Debian 13 (`remove_forward_rules` matches it) and that `/usr/sbin/iptables` is the path on all three.
