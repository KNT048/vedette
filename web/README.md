# web: the Vedette UI (React 19 + TypeScript)

Run with sample data (no backend needed): from the root folder run `make dev`, then open http://localhost:5173.
The first open goes to initial setup; choose "Use sample data" to get in at once. Sample accounts: `admin@congty.vn`, `it@congty.vn`, `giamdoc@congty.vn`, password `vedette-demo`.

- Architecture and conventions: `docs/FRONTEND.md`.
- The mock API (MSW) is the contract with the backend: handlers are in `src/features/<module>/mocks.ts`. Connect the real Go backend module by module: `make dev-api` (`REAL=core,inventory` picks the modules; see `docs/DEPLOYMENT.md` §13). A build connected to the whole backend: `VITE_API_MOCK=off pnpm build`.
- The hot board uses real CISA KEV/EPSS data: `make fixtures` (re-run every week).
- Checks: `make verify` (tsc + lint + vitest + build), `make e2e` (Playwright).
- Node is pinned by `devEngines.runtime` in `package.json`: pnpm downloads the right Node version by itself, no nvm needed.
