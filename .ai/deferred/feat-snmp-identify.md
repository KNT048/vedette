# Deferred: feat/snmp-identify (item 26, D-512)

- [ ] Lab: run `~/vedette-wt/lab-scripts/snmp/drive-snmp.sh` (the lead; the agent does not run the lab). It proves v3 against a real net-snmp and the window's round on a real box; the unit tests use a fake agent built on gosnmp's own marshalling.
- [ ] Release: the sensor protocol is 5 (core takes 4). A release whose previous published release speaks 3 needs `min_upgrade_from` (`scripts/release/protoskew.go` says so at release time).
- [ ] findings reads the stated OS of Junos only (D-510); FortiOS ("FortiOS 7.2.5") and Cisco IOS stated over SNMP are recorded as the device's OS but raise no finding yet. A row in `findings.deviceOSes` each (FortiOS orders like SemVer; IOS does not, see the ponytail note there).
- [ ] SNMPv1, AES-192/256 (Cisco's and Blumenthal's variants differ), SHA-224/384/512: not offered (D-512); add when a customer's device needs one.
- [ ] Remember per device which credential answered last and try it first (Lansweeper's order); today every round tries a device's credentials in creation order (at most 4, 2 s x 2 each when they fail).
- [ ] The round reads every approved device once per window even when nothing changed; a device that never answers costs 4 s per credential each window. A "skip after N windows without an answer" rule waits for N100 numbers.
- [ ] Opus review of the security-sensitive parts (sensor protocol 5, worker, secrets) was not run inside this agent (no subagents for review): the lead's review round 1.
