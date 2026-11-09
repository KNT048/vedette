# Third-party components

Updated whenever a dependency, external tool or data source is added (rule `.claude/rules/legal.md`).

## Libraries bundled in the web app (`web/`, measured with `pnpm --dir web licenses list --prod`)

The whole dependency tree that runs in the browser is MIT, ISC, Apache-2.0, 0BSD or OFL-1.1 (fonts). No GPL/AGPL. Direct dependencies:

| Package | License | Used for |
|---|---|---|
| react, react-dom, react-router | MIT | SPA framework, routing |
| @tanstack/react-query, @tanstack/react-table | MIT | API calls, tables |
| radix-ui (@radix-ui/*) | MIT | accessible primitives (dialogs, menus, switches) |
| i18next, react-i18next | MIT | UI strings |
| zod | MIT | API contract and validation (D-18) |
| lucide-react | ISC | icons |
| class-variance-authority | Apache-2.0 | button variants |
| clsx, tailwind-merge, sonner | MIT | CSS classes, notifications |
| @fontsource/be-vietnam-pro, @fontsource/jetbrains-mono | OFL-1.1 | self-hosted fonts (no CDN) |
| uqr | MIT | draws the two-step sign-in QR code locally in the SPA (bundled; no external QR service) |
| msw (+ `public/mockServiceWorker.js`) | MIT | mock API in the current build; removed when built with `VITE_API_MOCK=off` |

Build and test tools (not shipped): Vite, TypeScript, Tailwind CSS, vitest, Testing Library, axe-core (MPL-2.0, tests only), jsdom, oxlint, Playwright (Apache-2.0).

## Go libraries (generated automatically once the backend exists)

## Tools run as separate processes (not embedded, not redistributed)

| Component | License | How it is used |
|---|---|---|
| nmap | NPSL 0.95 | installed from the OS repository by the installer; invoked as a binary |
| OpenCanary | BSD-3 | installed by the installer; separate process |
| Zeek / Suricata (optional) | BSD / GPL-2 | separate processes |
| Greenbone CE (optional) | GPL-2 / AGPL-3 | separate container, unmodified |
| osquery (optional, on the user's Linux/Windows servers) | Apache-2.0 / GPL-2.0 (dual) | official release packages mirrored unmodified by the box for one-line install (D-34); license files shipped alongside |
| NXLog Community Edition (optional, on the user's Windows machines) | NXLog Public License | installed by the user to forward Windows Event Log as syslog; Vedette only shows a config snippet |

## Development and CI tools (not shipped in any image or binary)

Pinned in `tools/go.mod` (Go `tool` directives), run with `go tool -modfile=tools/go.mod <tool>` by `make verify-go` and CI. They only read the source tree; nothing from them is linked into Vedette.

| Tool | Version | License | How it is used |
|---|---|---|---|
| golangci-lint | v2.15.0 | GPL-3.0 | linter run on the source tree in dev and CI; separate process, never distributed |
| govulncheck (golang.org/x/vuln) | v1.9.0 | BSD-3-Clause | vulnerability scan of Go dependencies in dev and CI (daily on `main`) |
| GitHub Actions: actions/checkout, actions/setup-go, actions/upload-artifact, pnpm/action-setup | pinned by commit SHA in `.github/workflows/ci.yml` | MIT | CI runner steps; not distributed |

## Libraries planned for embedding (backend)

| Component | License |
|---|---|
| nuclei, httpx, naabu, subfinder, dnsx, nuclei-templates | MIT |
| recog / recog-go | BSD-2 |
| modernc.org/sqlite | BSD-3 |

## Data redistributed by the project's feed builder

| Source | License | Attribution |
|---|---|---|
| CISA KEV, vulnrichment | CC0 | "Source: CISA" (no logo) |
| CVE.org cvelistV5 | CVE Terms of Use | attribution |
| FIRST EPSS | attribution | "EPSS by FIRST" |
| GHSA | CC-BY 4.0 | attribution |
| OSV | Apache-2.0 | |
| nuclei-templates | MIT | |
| ET Open | BSD | |
| IPsum | Unlicense | |
| hagezi | GPL-3.0 | license included, unmodified |
| abuse.ch SSLBL / Feodo | CC0 | |
| Tor exit list | — | attribution: torproject |
| Team Cymru bogons | — | attribution |
| Cisco Umbrella top-1M, Majestic Million | — / CC-BY 3.0 | allow-lists |
| Spamhaus DROP | separate terms, **pending confirmation** | name not used in marketing |

Real data in the current build (`web/src/mocks/fixtures/`, `make fixtures`): CISA KEV (CC0), FIRST EPSS (attribution), the CVE list of nuclei-templates (MIT). Sources are shown on every screen.

## Data each box fetches with the user's own key (never through the project)

VulnCheck Community, AbuseIPDB, VirusTotal, GreyNoise, Shodan, AlienVault OTX, urlscan, OpenPhish, Censys, abuse.ch ThreatFox/URLhaus — under the terms of the user's own accounts.
