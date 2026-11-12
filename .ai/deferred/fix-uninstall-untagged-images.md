# Deferred: fix/uninstall-untagged-images

- [ ] 2026-11-12 — retention (`host/ops/retain.go`) leaves nameless images alone by design and does not cover `vedette-scan-base`, so an upgrade that moves the tag leaves the old scan-base image nameless in root's podman (only --uninstall removes it, by label) — vì sao để sau: needs a rule for which nameless images with our source label retention may remove, and Podman is not available on the Mac to test it — ở đâu: `host/ops/retain.go` (#478)
