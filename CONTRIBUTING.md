# Contributing

Start here, then read the three documents linked below. They are the full rules; this page is the short version.

- **[docs/ENGINEERING.md](docs/ENGINEERING.md)**: Definition of Done, Go and TypeScript standards, branching and PRs, CODEOWNERS, release process, CI spec, and how to work with AI agents in this repo. (Written in Vietnamese; the checklist in the PR template is in English.)
- **[docs/QA.md](docs/QA.md)**: mandatory UI QA method (form matrix, step-by-step walkthrough, independent verification). Required for any new or changed screen.
- **[Pull request template](.github/pull_request_template.md)**: the checklist every PR must complete.

## The short version

1. Every change starts from a user story (`docs/USER_STORIES.md`) or a decision (`docs/DECISIONS.md`). If there is none, open an issue first (use the "Feature request / new user story" template: Trigger, See, Click, Get, plus acceptance criteria).
2. Branches: `feat/…`, `fix/…`, `docs/…`; open a pull request into `main`; `main` is protected and nobody pushes to it directly. PRs need a human review; code owners (`.github/CODEOWNERS`) review changes to their modules. A PR written by an AI agent must be read and approved by a human.
3. Modules: read `CONTRACT.md` and `IMPACT.md` before changing a module; update both and the tests.
4. Checks: `make verify` (type check, lint, unit tests, build) and `make e2e`. For UI changes, also follow `docs/QA.md`.
5. Commit messages: `scope: imperative summary` (for example `feeds: add EPSS delta`); the body says **why**.
6. Contributions are licensed under Apache-2.0. Do not add GPL/AGPL dependencies to the core (running them as separate processes or containers is fine). New dependency, external tool or data source: update `THIRD_PARTY_NOTICES.md`. New data leaving the box: update `PRIVACY.md` and the Settings -> Privacy UI. Same commit.
7. Product copy is English only.
8. Security vulnerabilities: do not open a public issue. Follow `SECURITY.md`.
9. Releases and git tags are made by the maintainer only.
