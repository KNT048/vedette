# feat-e2e-real-response-chains (WP-30 slice 9b)
Specs: `web/e2e-real/response-chain.global.spec.ts`. Known bugs are marked with `knownBug()` (the precondition stays a real assertion; the test fails the day the bug is fixed, so the marker gets removed).
- [ ] The response module has no `BaseURL` wired (`cmd/vedette/response.go`): the block list address in `GET /response/blocklist` is a relative path; the page must join it. Not a spec failure; check the Blocklist tab shows a full address on a box with a name.
