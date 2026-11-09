# Contributing

1. Every change starts from a user story (`docs/USER_STORIES.md`) or a decision (`docs/DECISIONS.md`). If there is none, open an issue first.
2. Branches: `feat/…`, `fix/…`, `docs/…`; open a pull request into `main`; `main` is protected.
3. Modules: read `CONTRACT.md` and `IMPACT.md` before changing a module; update both and the tests.
4. Checks: `make verify` (type check, lint, unit tests, build) and `make e2e`.
5. Commit messages: `scope: imperative summary` (for example `feeds: add EPSS delta`); the body says **why**.
6. Contributions are licensed under Apache-2.0. Do not add GPL/AGPL dependencies to the core (running them as separate processes or containers is fine; list them in `THIRD_PARTY_NOTICES.md`).
7. Product copy is English only.
