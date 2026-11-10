# Deferred: feat/ai-activity (WP-25 slice 3)

- [ ] 2026-11-11 — A scheduled verify of the activity log that raises an incident when it breaks (S-AI-8 "alert on a broken chain") — vì sao để sau: needs the notify/incident port; verify on demand works — ở đâu: modules/ai/activity_read.go VerifyActivity
- [ ] 2026-11-11 — `GET /ai/activity` has no paging: the newest 1000 rows after the filters; `total` is the whole log — vì sao để sau: ponytail, the GUI has no "older" control; add a cursor when it gets one — ở đâu: modules/ai/activity_read.go MaxActivityItems
- [ ] 2026-11-11 — The newest activity row is never pruned (chainhead.Prune keeps the head's row), so a box that stops using AI keeps its last row past the retention — vì sao để sau: needs a change in core's helper (the head would have to be emptied); one row, no content — ở đâu: modules/ai/activity_api.go PruneActivity
