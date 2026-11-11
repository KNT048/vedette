# fix/setup-scope-lan-ranges (#350) — deferred
- [ ] Flake seen once on the Mac (load ~15): `cmd/vedette` TestRunPurgeBringsBackAFreshBoxAndStops failed with `TempDir RemoveAll cleanup: unlinkat …/hp/config: directory not empty` (something still writes the honeypot config dir after the test ends); passed 5 runs after. Not this change; owner of the purge test / honeypot to look.
- [ ] Re-run of the WP-08h honeypot step on 192.168.18.141 after the rebuild proves the wizard's range reaches the honeypot (`lan` set, no `no_lan`).
