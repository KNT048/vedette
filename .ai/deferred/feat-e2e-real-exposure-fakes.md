# Deferred from feat/e2e-real-exposure-fakes (WP-30, #263)

- [ ] BUG (found, on main, not caused by this PR: it fails the same with the fakes off): `exposure.spec.ts:203` "domains as an administrator › add: the box asks for a DNS TXT proof…" fails the axe check at line 258: `color-contrast (serious)` on `div[data-title=""]`. Owner: Mlee (spec) / GUI owner (contrast). Per D-171 the spec stays red until fixed; file an issue.
