# Deferred — feat/auth-oidc (WP-27 auth-oidc, session wp27-oidc)

- [x] PR 1 (#248): story, D-194..D-196, GUI on the mock. Merged.
- [ ] PR 2: backend `modules/auth-oidc` + `core/auth` (D-197). In review on `feat/auth-oidc-2`.
- [ ] `web/e2e-real/gaps.spec.ts` lists `GET /api/v1/core/oidc` as not wired; after PR 2 it answers (404 while the module is off, 200 when on). That file belongs to WP-30 (`wp30-s3`): tell that session when PR 2 merges, do not edit it here.
- [ ] IdP behind a private CA: the box trusts the system roots only, so an in-network Keycloak with an internal CA fails at discovery (`discovery_failed` says x509). Needs a story (upload a CA for the IdP, like a pinned certificate) and a D-number before code; until then the IdP must present a publicly trusted certificate or the box's OS trust store must hold the CA.
- [ ] e2e-real spec for SSO against a real IdP container (Keycloak or Dex) belongs to WP-30 (`make e2e-real`), not CI.
