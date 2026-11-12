# fix-honeypot-decoy-truth (deferred)

- [ ] D-TBD: decision record for S-HP-1 "decoy state from the box" (clear decoy IP only when all traps off, state enum starting/stopping/failed, back-off 3 tries then 10 min) with sources (AWS Elastic IP, Azure public IP, Thinkst Canary console) in docs/DECISIONS.md.
- [ ] Finding 5 (partial): the off path already kicks Apply at once; the 1-2 min delay is an Apply still inside `container.start` (up to 5 min, holds the run loop). GUI now says "Turning off" until confirmed. Making a running start interruptible by a newer kick is not done.
- [ ] Finding 8: the MAC of a decoy added a moment ago shows after the adapter's state/net cache expires (up to 20 s, then the next Apply, up to 1 min). No adapter unit test for `honeypotHost.DecoyMACs`.
