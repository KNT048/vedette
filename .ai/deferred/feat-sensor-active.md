# Deferred — feat/sensor-active (WP-12)

- [ ] Move nmap from the core process into the `scan` container with `CAP_NET_RAW` and the sensor protocol (D-55, D-84 (5)); today `core/exec` runs `/usr/bin/nmap --privileged` in the core process, and the install must put the OS package nmap there — WP-08 / sensor protocol, same time as the sensor-passive capture
- [x] Register the `scan_probes` export category in `/core/logs/export`: done in feat/logs-export (D-132), `sensoractive.ExportProbes`, registered in `cmd/vedette/logexport.go`
- [ ] Linux effect check on the lab VM with a real nmap against lab hosts only: `--privileged` with only `CAP_NET_RAW`, XML of nmap 7.94 parses, kill at window end leaves no child — WP-08 lab (never on a real network from a dev machine)
- [ ] Merge: this branch changes `inventory/scanpolicy.go` (unknown kind -> gentle, `ProtectedIPs`); the sensor-passive worktree changes `inventory/observe.go` (`observe.ErrRejected`): expect a conflict only in observe.go, not in scanpolicy.go — lead
- [ ] The future `scan` module must treat the policy reason `first_gentle_scan` as a refusal (it only allows sensor-active's one gentle scan), see sensor-active CONTRACT PRE-2 — scan WP
