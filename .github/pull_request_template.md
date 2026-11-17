<!-- Branch names: feat/..., fix/..., docs/.... Never push to main. -->

## What and why

<!-- One or two sentences. The "why" matters more than the "what". -->

## Trace

- Issue(s): <!-- e.g. #123, or "none" -->
- Module(s) touched: <!-- e.g. feeds -->

## Definition of Done

- [ ] Every feature, screen and button traces to an issue or user story.
- [ ] `CONTRACT.md` and `IMPACT.md` read before, and updated after, any module change (or: no module touched).
- [ ] Unit tests added or updated. For module changes: `go test ./modules/<id>/... -run Contract` is green.
- [ ] `origin/main` merged in; the changed packages build and lint on my machine (gofmt/tsc included); CI green before merge. Paste the commands run below.

## Local checks

<!-- Commit SHA checked, then the build and lint commands run and their tail. -->
- [ ] Work left for later filed as a GitHub issue (or: none).
- [ ] Build output cleaned (`make clean`); no `bin/`, `web/dist/`, or reports committed.
- [ ] Nothing new in logs or UI exposes secrets; external input validated at the boundary.

## UI changes

Skip this section if no UI changed.

- [ ] Form matrix test added for every form with a selector that changes the meaning of other fields.
- [ ] Checked step by step on desktop and phone, light and dark, with screenshots attached.
- [ ] Verified by someone other than the author. Reviewer: <!-- name -->
- [ ] English-only copy; no emoji, no raw colour-only meaning (docs/FRONTEND.md section 4).

## Privacy and legal

- [ ] No new dependency, external tool, or data source. Or: `THIRD_PARTY_NOTICES.md` updated (licence and how it is used; no GPL/AGPL in the core).
- [ ] No new data leaving the box. Or: `PRIVACY.md` flow table and Settings -> Privacy UI updated in this PR.
- [ ] No new cookie, analytics, or CDN resource in the SPA.
- [ ] Active scanning stays inside verified, consented scope.

## Release notes

- [ ] User-visible change has a line under "Unreleased" in `CHANGELOG.md` (or: not user-visible).

## Screenshots / evidence

<!-- Before/after screenshots, test output, or the steps you ran. -->
