# Deferred — feat/sensor-active (WP-12)

- [x] Move nmap from the core process into the `scan` container with `CAP_NET_RAW` and the sensor protocol (D-55, D-84 (5)); today `core/exec` runs `/usr/bin/nmap --privileged` in the core process, and the install must put the OS package nmap there — WP-08 / sensor protocol, same time as the sensor-passive capture — done: nmap runs in modules/sensor-active/worker (verified 2026-11-12)
- [x] Register the `scan_probes` export category in `/core/logs/export`: done in feat/logs-export (D-132), `sensoractive.ExportProbes`, registered in `cmd/vedette/logexport.go`
- [ ] Linux effect check on the lab VM with a real nmap against lab hosts only: `--privileged` with only `CAP_NET_RAW`, XML of nmap 7.94 parses, kill at window end leaves no child — WP-08 lab (never on a real network from a dev machine)
- [ ] The future `scan` module must treat the policy reason `first_gentle_scan` as a refusal (it only allows sensor-active's one gentle scan), see sensor-active CONTRACT PRE-2 — scan WP
