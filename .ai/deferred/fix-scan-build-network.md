# fix/scan-build-network (#467)
- [ ] 2026-11-12 — (Opus r1 LOW-2) `podman build --network <name> --cap-drop NET_RAW` is not yet proven on Podman 4.9 (Ubuntu 24.04, supported per D-267): check in the ubuntu2404 lab VM (slice/lab work); the real install retest on .141 (Podman 5.7) is the lead's.
