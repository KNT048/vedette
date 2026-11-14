# fix/zap-tmpfs-owner (#770), deferred

- [ ] 2026-11-14 review r1 LOW: no unit test for lastLines/zapOutTail, nor that the failure path logs exit code and tails. Open.
- [ ] 2026-11-14 review r1 LOW: record in D-521 why the ZAP home tmpfs is mode=1777 (podman refuses uid=/gid=) and that ZAP runs in /zap/wrk; update the quoted argv in .ai/deferred/feat-exposure-zap-passive-mlee.md. Open.
