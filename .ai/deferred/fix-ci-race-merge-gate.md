# fix/ci-race-merge-gate (D-371), Opus review round 1, LOW

- [ ] An admin merge that bypasses the merge queue (`gh pr merge --admin`) lands with only the PR's non-race go-test; the next push run on main tests it with -race, after the fact. Known limit of D-245; the ruleset should keep bypass off for everyone but kien.
- [ ] `RACE` exported in a developer's shell (or `make -e`) changes a local `make test-go-shard`; the command line wins over the Makefile's `?=` only when given. Doc-level only: CI passes it explicitly.
