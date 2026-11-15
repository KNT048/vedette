# Deferred: fix/n55-feeds (PR #805, N55-1/N55-2), session fix-n55-feeds

From review 1 of #805 (supervisor 2026-11-15: deferred, rare / cosmetic):
- [ ] (r1 #2) The Feeds row and `/findings/plan` disagree in two edge states: (a) a done cursor for another address (an admin changed nvd-recent's URL): `TierStatus` says `ready` (it does not compare the URL) while the row says "Loading …" and the next check refills; fix: `TierStatus` treats `cur.URL != recent.URL` as `loading` (same address check as `recentComplete`). (b) a done cursor with 0 records (a source answering nothing): the plan says `loading` forever, the row says OK · 0, the feed waits its interval (ponytail in `recentComplete`); leave, or count it ready-but-empty.
- [ ] (r1 #6) During a refill the line counts the old rows ("Loading … 104,448 stored so far, published up to 15 Nov 2025" from the first minute; old rows stay until the final prune). Wording only: "Loading the 12 months again" would be clearer.
