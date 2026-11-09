<!-- Branch names: feat/..., fix/..., docs/.... Never push to main. See docs/ENGINEERING.md. -->

## What and why

<!-- One or two sentences. The "why" matters more than the "what". -->

## Trace

- Story ID(s): <!-- e.g. S-FEED-1 (docs/USER_STORIES.md). Docs/infra-only: write "none" and give the decision. -->
- Decision(s): <!-- e.g. D-18 (docs/DECISIONS.md), or "none" -->
- Module(s) touched: <!-- e.g. feeds -->

## Authorship

- [ ] Written (fully or partly) by an AI agent. A human has read the whole diff and approves it.

## Definition of Done

- [ ] Every feature, screen and button traces to a story ID above (no imagined features).
- [ ] `CONTRACT.md` and `IMPACT.md` read before, and updated after, any module change (or: no module touched).
- [ ] Unit tests added or updated. For module changes: `go test ./modules/<id>/... -run Contract` is green.
- [ ] Rebased on the latest `origin/main`, then `make verify` green on my machine; `make e2e` (or the affected specs) if `web/` changed. There is no CI (D-61): paste the results below.

## Local checks

<!-- Commit SHA checked, then the tail of `make verify` (and `make e2e`) output. New commits after this = run again. -->
- [ ] Deferred work recorded in `.ai/deferred/<session>.md` (or: none).
- [ ] Build output cleaned (`make clean`); no `bin/`, `web/dist/`, or reports committed.
- [ ] Nothing new in logs or UI exposes secrets; external input validated at the boundary.

## UI changes: follow docs/QA.md

Skip this section if no UI changed.

- [ ] Form matrix test added for every form with a selector that changes the meaning of other fields (QA.md step 2).
- [ ] Walkthrough scenario written per story, run step by step on desktop and phone, light and dark, with screenshots attached (QA.md step 3).
- [ ] Verified by someone other than the author, or an independent agent (QA.md step 1). Reviewer: <!-- name -->
- [ ] QA.md section 4 form catalogue updated in this PR.
- [ ] English-only copy (D-28); no emoji, no raw colour-only meaning (docs/FRONTEND.md section 4).

## Privacy and legal

- [ ] No new dependency, external tool, or data source. Or: `THIRD_PARTY_NOTICES.md` updated (licence and how it is used; no GPL/AGPL in the core).
- [ ] No new data leaving the box. Or: `PRIVACY.md` flow table and Settings -> Privacy UI updated in this PR.
- [ ] No new cookie, analytics, or CDN resource in the SPA.
- [ ] Active scanning stays inside verified, consented scope.

## Release notes

- [ ] User-visible change has a line under "Unreleased" in `CHANGELOG.md` (or: not user-visible).

## Screenshots / evidence

<!-- Before/after screenshots, test output, or the steps you ran. -->

<!-- If an AI agent opened this PR, add the attribution line it was told to use here. -->
