# fix/ci-static-speed (D-372), Opus review round 1, LOW

- [ ] go-release runs on a push to main too (Decide push → Go) and saves nothing there; it only takes one of the push run's jobs from the queue. Skip it on push if job capacity gets tight.
- [ ] go-release keeps setup-go's own cache (key by go.sum, saved once by whoever runs first): harmless while main holds that key, but the guard does not cover it.
- [ ] Cache quota: each main push now saves go-test (4 × ~400 MB), go-static and go-lint caches; check their sizes after the first pushes (`gh api repos/KNT048/vedette/actions/caches`) against the 10 GB limit.
- [ ] No guard reads verify-go-static's recipe: dropping generate-check or vet there would pass (gap from before this PR).
