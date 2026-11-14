# Deferred: fix-deep-scan-openvas-first-start (PR #787, N42-3 + N42-4, D-590)

- [ ] userns for the Greenbone project (podman userns) so that container uid 1001 is not host uid 1001 — post-PR, owner Trưởng (review r1 M4: a host account with uid 1001 reads gvmd's environment and reaches its socket through /proc).
