---
name: end-of-session
description: End-of-session handoff for the Vedette repo, run when kien says "doc" or a session is about to end.
disable-model-invocation: true
---

1. Every open item from this session is a GitHub issue labelled `v1` or `post-v1` (`gh issue create --label …`); nothing stays only in chat or a local file.
2. `docs/v1-journeys.json`: set `passes`/`evidence` only for journeys walked on a real box this session (box, build, what was seen).
3. New D-xx files only for decisions D-625 (2) covers; everything else is already in the PR descriptions.
4. `docs/USER_STORIES.md`: update a story's status only if this session verified it.
5. Supervisor only: rewrite (do not append to) the resume block in `/Users/kien/Desktop/vedette-wt/LEAD-STATE.md`, at most 40 lines: what is running, open PRs, next v1 issue, what waits on kien.
6. Build output cleaned (`make clean`); work committed on a branch; nothing pushed to `main`; no tag.
