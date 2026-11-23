# Auth-OIDC — Change Impact Map

> Package `modules/auth-oidc` (Go package `authoidc`). The GUI contract: `web/src/features/core/contract.ts`. Last verified: 2026-11-21 (every sentence checked against the code).

## Modifying: `Service.Store(ctx, actor, origin, Save)` / `View(ctx, origin)` (PUT/GET `/core/oidc`)
- **web/features/core (`UsersSection.tsx`)**: the SSO form; changing a field → regenerate `api/openapi.json` + `make generate-api` + fix the mock.
- **cmd/vedette/wiring.go `privacyFacts.OIDCConfigured`** reads `Service.Configured`; `modules/core/handlers_privacy.go` (flow 11 of Privacy) and `modules/core/handlers_session.go` (`GET /core/auth-options`, the SSO button) call it through `privacyFacts`. Changing the meaning of "configured" → the button and the Privacy page change with it.
- `Store` pins `redirect_uri` to the origin of the person who saved it (INV-6): changing how it is computed → every box must register the address again at the IdP.

## Modifying: `Service.Start` / `Service.Callback` (POST `/auth/oidc/start`, `/auth/oidc/callback`)
- **web/src/app/LoginPage.tsx**, **web/src/features/core/SsoCallbackPage.tsx**, **ssoFlow.ts** (sessionStorage `vedette-sso-flow`). Changing the field name `binding` or the path `/sso/callback` → the redirect URI registered at the customer's IdP no longer matches.
- **core/auth `SSOSignIn`**: Callback passes on (`iss`, `sub`, email, `email_verified`, name, role) after the ID token has been checked. Changing what is checked before the call → `core/auth` trusts unchecked data (INV-1).
- **modules/core codes/catalogue test**: a new error code must be in `docs/API_CONVENTIONS.md` (counted per status table).

## Modifying: `MapRole(groups, rows, def)` và `idClaims.groups(claim)`
- The role of every SSO account at the next sign-in; changing the rules (highest, exact name match, drop groups > 256 characters, the first 200 groups) → promotes/demotes in bulk and ends the sessions of people whose role changes.

## Modifying: `newClient` / `discover` / `clientFor` (every call to the IdP)
- INV-11: https, no redirects, 1 MiB, 10 s, an algorithm list. Loosening any of these → `TestContract_INV11_Discovery` and a security review.
- INV-12: `clientFor(ca_pem)` for discovery, JWKS (the provider holds the client) and the token exchange (`idp.client`). Using `s.client` directly in a new place → an IdP behind an internal CA breaks in that place. `parseCA` is the only gate into `oidc_config.ca_pem`; loosening it → a security review.
- **web/features/core (`OidcCaField.tsx`, the mock `caError`)**: the message `invalid_ca` and the "does not trust" sentence of `publicReason` are referred to in the GUI by the name of the field "Identity provider CA certificate".

## Depends on core (interface)
- `core/auth.SSOSignIn`, `RefuseSSO`, `CountSSOUsers`; `core/secrets` (purpose `oidc_config.client_secret`); `core/audit`; the columns `sso_issuer`/`sso_subject` of `core_user` (owned by core).

## Wiring
- `cmd/vedette/modules.go` (`Deps.OIDC`, migrations), `cmd/vedette/wiring.go` (`authoidc.New`), `cmd/vedette/handler.go` (`OIDCHandlers`); `core/server/modules.go` opens/closes the routes `/core/oidc`, `/auth/oidc` per module (SYS-5); `web/src/lib/modules.ts` and `web/src/features/core/ModulesSection.tsx` (the turn-off dialog reads `sso_users`). Changing a route path → change `core/server/modules.go`.

## Disabling this module
- The server returns 404 for `/auth/oidc/*`, `/core/oidc*` (SYS-5); `auth-options.oidc=false`; the IdP is not called. SSO accounts cannot get in until it is turned on again (the GUI names `sso_users` before turning off). `oidc_config` is kept as it is; `oidc_flow` expires and is cleaned at the next `start`.
