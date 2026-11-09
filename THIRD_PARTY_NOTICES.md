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

## Go libraries linked into the Vedette binary (backend)

Pure Go, no cgo. Versions pinned in `go.mod`/`go.sum`; licenses read from each module's LICENSE file (WP-03). Direct dependencies first, then what they pull in (`go list -deps ./core/... ./modules/...`). This table is replaced by a generated one with the WP-08 supply-chain job.

| Library | Version | License | How used |
|---|---|---|---|
| modernc.org/sqlite | v1.61.1 | BSD-3-Clause | embedded: SQLite engine transpiled to Go (database/sql driver) in `core/store`; also carries musl and SQLite's public-domain code, see the module's `LICENSE-3RD-PARTY.md` |
| github.com/pressly/goose/v3 | v3.29.0 | MIT | embedded: runs the embedded SQL migrations at start-up (`core/store.Migrate`); forward-only, no Down |
| modernc.org/libc, modernc.org/mathutil, modernc.org/memory | v1.79.0, v1.7.1, v1.12.1 | BSD-3-Clause | embedded: runtime of modernc.org/sqlite |
| github.com/ncruces/go-strftime | v1.1.0 | MIT | embedded: via modernc.org/sqlite |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause | embedded: via modernc.org/sqlite |
| github.com/dustin/go-humanize | v1.1.0 | MIT | embedded: via modernc.org/libc |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | embedded: via modernc.org/sqlite |
| github.com/mattn/go-isatty | v0.0.24 | MIT | embedded: via modernc.org/libc |
| github.com/mfridman/interpolate | v0.0.2 | MIT | embedded: via goose |
| github.com/sethvargo/go-retry | v0.5.0 | Apache-2.0 | embedded: via goose |
| go.uber.org/multierr | v1.11.0 | MIT | embedded: via goose |
| golang.org/x/sync, golang.org/x/sys | v0.24.0, v0.49.0 | BSD-3-Clause | embedded: via goose and modernc.org/sqlite |
| golang.org/x/crypto (package `argon2` only, with `blake2b` and `cpu` it uses) | v0.58.0 | BSD-3-Clause | embedded: argon2id password hashing in `core/auth` (WP-04b). Already in the module graph through goose and x/net; now a direct dependency |

### Generated API server (`core/api/oas`, ogen, D-60)

Pinned in `go.mod` and `go.sum`; licenses checked from the `LICENSE` files of each module (2026-11-09). Direct use is the generated API server (`core/api/oas`). Versions in the table are what `go list -deps ./core/api/...` resolved; `make verify-go` runs `govulncheck` on them.

| Library | Version | License | How it is used |
|---|---|---|---|
| github.com/ogen-go/ogen | v1.24.0 | Apache-2.0 | generates `core/api/oas` (`go tool ogen`, D-60); its runtime packages (router, request validation, JSON decode) are linked into the binary |
| github.com/go-faster/jx | v1.2.0 | MIT | JSON encode/decode in the generated server |
| github.com/go-faster/errors | v0.8.0 | BSD-3-Clause | error wrapping in ogen runtime |
| github.com/go-faster/yaml | v0.4.6 | Apache-2.0 and MIT | spec parser inside ogen's `jsonschema` package (linked, not used at run time) |
| github.com/dlclark/regexp2 | v1.12.0 | MIT | string `pattern` validation (ECMA-262 regexes from the contract) |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | UUID parameters in generated code |
| github.com/shopspring/decimal | v1.4.0 | MIT | number handling in ogen runtime |
| github.com/segmentio/asm | v1.2.1 | MIT-0 | base64 in ogen runtime |
| github.com/ghodss/yaml | v1.0.0 | MIT and BSD-3-Clause | YAML to JSON in ogen's spec package (linked, not used at run time) |
| gopkg.in/yaml.v2 | v2.4.0 | Apache-2.0 and MIT | YAML parsing used by `ghodss/yaml` |
| github.com/fatih/color, github.com/mattn/go-colorable, github.com/mattn/go-isatty | v1.19.0, v0.1.14, v0.0.24 | MIT | terminal colour in ogen's logger (linked, not used at run time) |
| go.uber.org/zap, go.uber.org/multierr | v1.28.0, v1.11.0 | MIT | logging inside ogen's spec packages (linked, not used at run time) |
| golang.org/x/net, golang.org/x/text, golang.org/x/sys, golang.org/x/sync, golang.org/x/exp | v0.62.0, v0.43.0, v0.49.0, v0.24.0, 2023-07-25 | BSD-3-Clause | HTTP header and IDNA checks, Unicode tables, system calls, errgroup, generic helpers; `golang.org/x/net/publicsuffix` (embedded Public Suffix List) refuses IOC domains that are public suffixes such as `com.vn` or `github.io` (`modules/feeds`, issue #29) |

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

Pinned in `tools/go.mod` (Go `tool` directives), run with `go tool -modfile=tools/go.mod <tool>` by `make verify-go` and `make audit` on the developer's machine (no hosted CI, D-61). They only read the source tree; nothing from them is linked into Vedette.

| Tool | Version | License | How it is used |
|---|---|---|---|
| golangci-lint | v2.15.0 | GPL-3.0 | linter run on the source tree on the developer's machine; separate process, never distributed |
| govulncheck (golang.org/x/vuln) | v1.9.0 | BSD-3-Clause | vulnerability scan of Go dependencies (`make verify-go`, `make audit`) |
| sqlc (github.com/sqlc-dev/sqlc) | v1.31.1 | MIT | generates the typed query code in `core/store/coredb` from SQL files (`make generate`); the generated code is committed, sqlc itself is never linked |

## Libraries planned for embedding (backend)

| Component | License |
|---|---|
| nuclei, httpx, naabu, subfinder, dnsx, nuclei-templates | MIT |
| recog / recog-go | BSD-2 |

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

### Module registry (`core/modreg`, WP-04a)

| Library | Version | License | How it is used |
|---|---|---|---|
| go.yaml.in/yaml/v3 | v3.0.5 | MIT and Apache-2.0 | embedded: parses each module's `MANIFEST.yaml` (embedded in the binary by `modules/manifests.go`) when the process starts; no input from the network |

### Passive sensor (`modules/sensor-passive`, WP-11)

No third-party library: the pcap/pcapng readers and the ARP, DHCP, DNS/mDNS, SSDP, LLDP, TLS ClientHello and HTTP Host parsers are written in Go on the standard library (`syscall` for the Linux AF_PACKET socket). The IEEE OUI registry is **not** shipped: its public page states no redistribution licence (D-80).
