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
| golang.org/x/sync, golang.org/x/sys | v0.24.0, v0.49.0 | BSD-3-Clause | embedded: via goose and modernc.org/sqlite; golang.org/x/sys/unix is also used directly by `modules/sensor-passive` (AF_PACKET promiscuous membership, Linux), `host/peer` (Linux only, `vedette-host`: `SO_PEERPIDFD` and `SO_PEERCRED` of the socket peer) and, from WP-07b part 3, `host/ops` (Linux only: the `AF_PACKET` socket that sends and reads fixed 42-byte ARP frames, D-101) |
| golang.org/x/crypto (packages `argon2` and `ssh`, with what they use) | v0.58.0 | BSD-3-Clause | embedded: argon2id password hashing in `core/auth` (WP-04b); `ssh` reads and fingerprints the private key of an SSH connection in `core/conn` (WP-13b slice 4: key must parse, no passphrase, SHA256 fingerprint of the public half), and opens the SSH session itself since slice 13b-5 (D-94): `ssh.NewClientConn` over a connection from the policy dialer, a pseudo-terminal session, host key pinned on first use, only the library's secure algorithm lists (`ssh.SupportedAlgorithms`), in the `core` process; no new module and no change to `go.mod`. Already in the module graph through goose and x/net; a direct dependency, version unchanged. From WP-07b part 3, `blake2b` is also used directly by `internal/release` (minisign prehashed `ED` signatures, D-103), in `core` and `vedette-host` |
| golang.org/x/mod (package `semver` only) | v0.42.0 | BSD-3-Clause | embedded from WP-07b part 3 (slice 3-2): SemVer precedence for downgrade and rollback rules in `internal/release` (D-104), in `core` and `vedette-host`. Was an indirect requirement; now direct (same version) through `internal/release` |
| github.com/coder/websocket | v1.8.15 | ISC | embedded: outward WebSocket client for notify approvals: Slack Socket Mode (D-38) and the Zalo personal reply-code listener (D-46); no dependencies of its own. Added for issue #43; the first importer (WP-22) turns the `// indirect` mark into a direct requirement |

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

## Protocol knowledge re-implemented in Go (no third-party code linked)

| Source | License | How it is used |
|---|---|---|
| zca-js v2.2.0 (github.com/RFS-ADRENO/zca-js, copyright 2024-2025 RFS-ADRENO, truong9c2208, JustKemForFun) | MIT | The unofficial Zalo personal-account protocol (sign-in request, parameter encryption and signature, message send, and the WebSocket listener notes in `modules/notify/IMPACT.md`) was read from its source and re-implemented in Go in `modules/notify/channel/zalopersonal*.go` (D-46), the same protocol the n8n Zalo community node uses through that library. Not a dependency: no code or package is linked, the logic is rewritten with the Go standard library. The test vectors were produced by running its algorithms on crypto-js 4.2.0 (MIT) outside the repository. |

## Tools run as separate processes (not embedded, not redistributed)

| Component | License | How it is used |
|---|---|---|
| nmap | NPSL 0.95 | installed from the OS package repository (Debian trixie, `deb.debian.org`) into the `scan` image that vedette-host builds on the box (`deploy/containers/scan/Containerfile.onbox`, carried in `host/ops/scanbuild.go`, D-147); not distributed by Vedette (in no image the project builds or publishes); invoked as a binary |
| nuclei (projectdiscovery) v3.11.1 | MIT | shipped in the signed `scan` base image (`deploy/containers/scan-base/Containerfile`, D-146): the release binary pinned by version and SHA-256 (checked on the zip before unpacking and on the binary after), at `/usr/local/bin/nuclei`, run as its own process in the `scan` container with `-duc -ni` and an empty tmpfs home. Not linked into any Vedette binary. Its licence file is in the image at `/usr/local/share/vedette/licenses/nuclei-LICENSE.md` |
| The safe nuclei-templates pack (projectdiscovery/nuclei-templates 10.5.1, `kev,vkev` only, D-125, D-146) | MIT | data: built by `make scan-pack` (`scripts/scanpack`) from the pinned release archive (SHA-256 checked before reading), copied unmodified, only the templates that pass the filter; shipped in the `scan` base image at `/usr/share/vedette/nuclei-templates` with its index and licence (`/usr/local/share/vedette/licenses/nuclei-templates-LICENSE.md`); its index only (template ids, CVEs, paths, hashes, tags, the first request line) is also committed at `content/nucleipack/index.json` by the same `make scan-pack` and embedded in `core` (scan S5), so core plans jobs against the pack of the image |
| Base images: Debian 13 "trixie" slim (`scan` base), distroless `static-debian13` (`sensor`, `core`), Go 1.26 build image (build stage only, not shipped) | various free software licences (Debian packages keep their own; distroless: Apache-2.0 and the licences of its Debian packages) | container base layers pinned by digest in `deploy/containers/pins.env`; the licence texts are inside the layers (`/usr/share/doc/*/copyright`). The Debian slim layer of the published `scan` base carries GPL userland (bash, coreutils, util-linux, apt, dpkg and others) and distroless carries glibc-free static files and Debian copyright data: each is a separate program shipped as part of the base file system, **mere aggregation** (GPL-2 section 2), not linked into any Vedette binary and not modified. Source: the exact packages of the pinned base digest are on https://snapshot.debian.org at the digest's build date (and `apt-get source` on the same release), and the Debian source packages are at https://sources.debian.org |
| OpenCanary | BSD-3 | runs from the signed `honeypot` container image (D-123, D-146); separate process, not embedded |
| Zeek / Suricata (optional) | BSD / GPL-2 | separate processes |
| Greenbone CE (optional) | GPL-2 / AGPL-3 | separate container, unmodified |
| osquery (optional, on the user's Linux/Windows servers) | Apache-2.0 / GPL-2.0 (dual) | official release packages mirrored unmodified by the box for one-line install (D-34); license files shipped alongside |
| NXLog Community Edition (optional, on the user's Windows machines) | NXLog Public License | installed by the user to forward Windows Event Log as syslog; Vedette only shows a config snippet |
| Podman (with Quadlet) | Apache-2.0 | appliance only: installed from the OS repository by the installer; `vedette-host` runs `podman` (pull by digest, inspect, tag, rmi) with fixed argv and writes Quadlet unit files from constant templates (D-105) |
| netplan (`netplan.io`) | GPL-3.0 | appliance only: OS package (installed by the installer on Debian 13); `vedette-host` writes its single YAML file and runs `netplan apply` (D-99) |
| iproute2 (`ip`) | GPL-2.0 | appliance only: OS package; `vedette-host` runs `ip` with fixed argv to build the decoy namespace `vedette-hp` and its macvlan links (D-102) |
| nftables (`nft`) | GPL-2.0 (some files GPL-2.0-or-later) | appliance only: OS package; `vedette-host` loads one constant ruleset inside `vedette-hp` and lists it to check the effect (D-102) |
| procps (`sysctl`) | GPL-2.0-or-later (`sysctl`), LGPL-2.1-or-later (library) | appliance only: OS package; `vedette-host` runs `sysctl -w` with constant keys and values inside `vedette-hp` (D-102) |
| chrony (`chronyd`, `chronyc`) | GPL-2.0 | appliance only: installed by the installer, which owns `chrony.conf`; `vedette-host` writes `/etc/chrony/sources.d/vedette.sources` and runs `chronyc` (D-106) |

The GPL tools above are separate programs from the distribution, run through `core/exec` with fixed argv; nothing from them is linked into or redistributed with Vedette (rule `legal.md`: GPL/AGPL is never embedded). Licences checked from the Debian copyright files (`metadata.ftp-master.debian.org/changelogs/main/…/stable_copyright`) on 2026-11-10.

## Development and CI tools (not shipped in any image or binary)

Pinned in `tools/go.mod` (Go `tool` directives), run with `go tool -modfile=tools/go.mod <tool>` by `make verify-go` and `make audit` on the developer's machine (no hosted CI, D-61). They only read the source tree; nothing from them is linked into Vedette.

| Tool | Version | License | How it is used |
|---|---|---|---|
| golangci-lint | v2.15.0 | GPL-3.0 | linter run on the source tree on the developer's machine; separate process, never distributed |
| govulncheck (golang.org/x/vuln) | v1.9.0 | BSD-3-Clause | vulnerability scan of Go dependencies (`make verify-go`, `make audit`) |
| nfpm (github.com/goreleaser/nfpm/v2) | v2.43.0 | MIT | the maintainer's build tool for the `vedette-host` `.deb` (`make host-deb`, D-155); a separate process on the maintainer's and CI machine, never shipped or linked into Vedette; its Go dependency graph was checked for GPL/AGPL (none) |
| sqlc (github.com/sqlc-dev/sqlc) | v1.31.1 | MIT | generates the typed query code in `core/store/coredb` from SQL files (`make generate`); the generated code is committed, sqlc itself is never linked |
| GitHub Actions in `.github/workflows/ci.yml`: `actions/checkout`, `actions/setup-go`, `pnpm/action-setup`, `actions/cache` | pinned by commit SHA (cache v6.1.0) | MIT | run on GitHub's runners only (D-63); `actions/cache` keeps the golangci-lint cache between runs (D-140). Change detection uses no third-party action |

Release signing tools (maintainer's machine only, not in `tools/go.mod`, never shipped): minisign (ISC) signs `index.json` and release manifests; cosign (Apache-2.0), pinned, signs images in the legacy format with `--new-bundle-format=false --use-signing-config=false` (D-103). minisign 0.12 was also run once to produce the committed signature test vectors of `internal/release` (D-107; throwaway test keys, commands in `internal/release/testdata/README.md`). cosign was not run: its legacy signature format is built by a committed Go generator, and two payload strings are copied from the test file of github.com/sigstore/sigstore `pkg/signature/payload` (Apache-2.0, source and commit in that README); no cosign or sigstore code is linked.

## Libraries planned for embedding (backend)

| Component | License |
|---|---|
| httpx, naabu, subfinder, dnsx | MIT |
| recog / recog-go | BSD-2 |

## Data redistributed by the project's feed builder

| Source | License | Attribution |
|---|---|---|
| CISA KEV, vulnrichment | CC0 | "Source: CISA" (no logo); the same KEV file is also read from CISA's own GitHub mirror (`cisagov/kev-data`) when cisa.gov is blocked (D-91) |
| CVE.org cvelistV5 | CVE Terms of Use | attribution |
| FIRST EPSS | attribution | "EPSS by FIRST" |
| GHSA | CC-BY 4.0 | attribution |
| OSV | Apache-2.0 | |
| nuclei-templates | MIT | |
| ET Open | BSD | |
| IPsum | Unlicense | |
| hagezi | GPL-3.0 | license included, unmodified |
| abuse.ch Feodo Tracker | CC0 | |
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

No third-party library: the pcap/pcapng readers and the ARP, DHCP, DNS/mDNS, SSDP, LLDP, TLS ClientHello and HTTP Host parsers are written in Go on the standard library (`syscall` for the Linux AF_PACKET socket).

| Data | License | How it is used |
|---|---|---|
| runZero mac-tracker (`data/macs.json`), copyright runZero Inc., HD Moore and dutchcoders; the data is from the IEEE Registration Authority registries (oui, mam, oui36, iab, cid) | MIT (runZero's compilation); the IEEE data itself carries no copyright claim: Debian's `ieee-data` copyright file quotes "IEEE does not assert any copyright in the OUI Public Listing or attempt to restrict distribution of the listing in any way" ([source](https://metadata.ftp-master.debian.org/changelogs/main/i/ieee-data/unstable_copyright)); IEEE "strongly encourages" getting the listing from IEEE regularly, which `make oui` does indirectly (rebuilt from runZero, which tracks IEEE twice a day) | bundled: `make oui` reads it at build time, from a pinned commit whose SHA-256 is checked, and writes `content/oui/oui.tsv.gz`, embedded in the binary (D-83); the MIT notice is kept next to it in `content/oui/LICENSE.mac-tracker`. Nothing is downloaded at run time, so PRIVACY.md is unchanged. The GPL/NPSL lists of Wireshark and Nmap are not used |

