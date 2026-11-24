# Contributing

Start here. The [pull request template](.github/pull_request_template.md) holds the checklist every PR must complete; module rules are in each module's `CONTRACT.md` and `IMPACT.md`, and the architecture in `docs/`.

## The short version

1. Every change starts from an issue. If there is none, open one first (use the "Feature request / new user story" template: Trigger, See, Click, Get, plus acceptance criteria).
2. Branches: `feat/…`, `fix/…`, `docs/…`; open a pull request into `main`; `main` is protected and nobody pushes to it directly. PRs need a human review; code owners (`.github/CODEOWNERS`) review changes to their modules.
3. Modules: read `CONTRACT.md` and `IMPACT.md` before changing a module; update both and the tests.
4. Checks: `make verify` (type check, lint, unit tests, build) and `make e2e`; how to run them is under [Run it from source](#run-it-from-source). For UI changes, add a form matrix test for every form whose selector changes the meaning of other fields, and check the screen on desktop and phone, light and dark.
5. Commit messages: `scope: imperative summary` (for example `feeds: add EPSS delta`); the body says **why**.
6. Contributions are licensed under Apache-2.0. Do not add GPL/AGPL dependencies to the core (running them as separate processes or containers is fine). New dependency, external tool or data source: update `THIRD_PARTY_NOTICES.md`. New data leaving the box: update `PRIVACY.md` and the Settings -> Privacy UI. Same commit.
7. Product copy is English only.
8. Security vulnerabilities: do not open a public issue. Follow `SECURITY.md`.
9. Releases and git tags are made by the maintainer only.

## Run it from source

You need Go (the version in `go.mod`), pnpm (the version in `packageManager` of `web/package.json`; `corepack enable` provides it) and GNU make. pnpm fetches the Node.js version pinned in `web/package.json` by itself.

| Command | What it does |
|---|---|
| `make dev` | The web interface with a mock API at http://localhost:5173. On the Account step of the setup wizard choose **Use sample data** to sign in at once with 30 made-up devices and a few findings. |
| `make dev-api` | The real Go backend (127.0.0.1:8080) with the web interface; `REAL=core,inventory` picks the modules served by the backend, the rest stay mocked. Its state lives in `.dev/`. |
| `make help` | Every other target. |

Tests:

```sh
go test ./modules/<module>/... -run '^TestName$'     # one Go test
pnpm --dir web vitest run <file>                     # one web test file
pnpm --dir web exec tsc -b                           # web type check
make verify                                          # the full check: type check, lint, tests, contract drift, build
```

After you change `api/openapi.json` (generated from `web/src/features/*/contract.ts` by `pnpm --dir web openapi`), a sqlc query or a migration, run `make generate` and commit the result. Never edit `core/api/oas/`, `core/api/routes/routes_gen.go` or `core/store/coredb/` by hand. `make clean` removes build output and test reports.
