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
| github.com/ledongthuc/pdf | v0.0.0-20261020125853-5e46805f718e | BSD-3-Clause | embedded, but run only in a child process: reads the text of a PDF that an administrator adds to the AI knowledge base (`core/pdftext`, started by `vedette pdftext` through `core/exec`, D-264); a fork of `rsc.io/pdf`, no dependency of its own; the file is read in memory, never run; the child has RLIMIT_AS (start-up size + 512 MiB), RLIMIT_CPU 60 s, a 60 s wall-clock kill and capped output, because the library has fatal errors and endless loops that `recover()` cannot stop |
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
| github.com/coreos/go-oidc/v3 (package `oidc`) | v3.21.0 | Apache-2.0 | embedded: OpenID Connect discovery and ID-token verification for SSO sign-in (`modules/auth-oidc`, D-194, D-197): issuer match, signature with the issuer's JWKS, alg allowlist, aud, exp |
| github.com/go-jose/go-jose/v4 | v4.1.4 | Apache-2.0 | embedded: via go-oidc, JWS parsing and signature checks of the ID token (also used by the tests' fake identity provider) |
| golang.org/x/oauth2 | v0.37.0 | BSD-3-Clause | embedded: the authorization-code request and token exchange with PKCE S256 of SSO sign-in (`modules/auth-oidc`, D-197) |
| github.com/coder/websocket | v1.8.15 | ISC | embedded: outward WebSocket client for notify approvals: Slack Socket Mode (D-38) and the Zalo personal reply-code listener (D-46); no dependencies of its own. Added for issue #43; a direct requirement since the Slack Socket Mode listener (notify slice 3) |

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
| github.com/shopspring/decimal | v1.5.0 | MIT | number handling in ogen runtime |
| github.com/segmentio/asm | v1.2.1 | MIT-0 | base64 in ogen runtime |
| github.com/ghodss/yaml | v1.0.0 | MIT and BSD-3-Clause | YAML to JSON in ogen's spec package (linked, not used at run time) |
| gopkg.in/yaml.v2 | v2.4.0 | Apache-2.0 and MIT | YAML parsing used by `ghodss/yaml` |
| github.com/fatih/color, github.com/mattn/go-colorable, github.com/mattn/go-isatty | v1.19.0, v0.1.14, v0.0.24 | MIT | terminal colour in ogen's logger (linked, not used at run time) |
| go.uber.org/zap, go.uber.org/multierr | v1.28.0, v1.11.0 | MIT | logging inside ogen's spec packages (linked, not used at run time) |
| golang.org/x/net, golang.org/x/text, golang.org/x/sys, golang.org/x/sync, golang.org/x/exp | v0.62.0, v0.43.0, v0.49.0, v0.24.0, v0.0.0-20261011100332-faecfb24eb49 | BSD-3-Clause | HTTP header and IDNA checks, the HTML tokenizer of `golang.org/x/net/html` (text of the vendor pages read for CVE news, D-281), Unicode tables, system calls, errgroup, generic helpers; `golang.org/x/net/publicsuffix` (embedded Public Suffix List) refuses IOC domains that are public suffixes such as `com.vn` or `github.io` (`modules/feeds`, issue #29) |

## Protocol knowledge re-implemented in Go (no third-party code linked)

| Source | License | How it is used |
|---|---|---|
| zca-js v2.2.0 (github.com/RFS-ADRENO/zca-js, copyright 2024-2025 RFS-ADRENO, truong9c2208, JustKemForFun) | MIT | The unofficial Zalo personal-account protocol (sign-in request, parameter encryption and signature, message send, and the WebSocket listener notes in `modules/notify/IMPACT.md`) was read from its source and re-implemented in Go in `modules/notify/channel/zalopersonal*.go` (D-46), the same protocol the n8n Zalo community node uses through that library. Not a dependency: no code or package is linked, the logic is rewritten with the Go standard library. The test vectors were produced by running its algorithms on crypto-js 4.2.0 (MIT) outside the repository. |

## Tools run as separate processes (not embedded, not redistributed)

| Component | License | How it is used |
|---|---|---|
| nmap | NPSL 0.95 | installed from the OS package repository (Debian trixie, `deb.debian.org`) into the `scan` image that vedette-host builds on the box (`deploy/containers/scan/Containerfile.onbox`, carried in `host/ops/scanbuild.go`, D-147); not distributed by Vedette (in no image the project builds or publishes); invoked as a binary |
| nuclei (projectdiscovery) v3.11.1 | MIT | shipped in the signed `scan` base image (`deploy/containers/scan-base/Containerfile`, D-146, D-319): **built from source**, not the upstream release binary. The tag archive `v3.11.1.tar.gz` is pinned by SHA-256 (`NUCLEI_SRC_SHA256`, checked before it is unpacked); the image build compiles `./cmd/nuclei` with the pinned Go toolchain (`GOLANG_IMAGE`, `CGO_ENABLED=0`, `-trimpath`) and our patched `go.mod`/`go.sum` (`deploy/containers/scan-base/nuclei/`, only dependency versions raised to the fixed releases of the vulnerabilities reported by trivy; `go.sum` verifies every module, as in Debian, Alpine and Wolfi rebuilds of upstream Go programs). The Go source files are unmodified; `go.mod`/`go.sum` are ours (newer patched module versions). At `/usr/local/bin/nuclei`, run as its own process in the `scan` container with `-duc -ni` and an empty tmpfs home. Not linked into any Vedette binary. Its licence file is in the image at `/usr/local/share/vedette/licenses/nuclei-LICENSE.md`; the licences of its Go dependencies are not yet listed in the image (`.ai/deferred/fix-nuclei-rebuilt-patched.md`) |
| The safe nuclei-templates pack (projectdiscovery/nuclei-templates 10.5.1, `kev,vkev` only, D-125, D-146) | MIT | data: built by `make scan-pack` (`scripts/scanpack`) from the pinned release archive (SHA-256 checked before reading), copied unmodified, only the templates that pass the filter; shipped in the `scan` base image at `/usr/share/vedette/nuclei-templates` with its index and licence (`/usr/local/share/vedette/licenses/nuclei-templates-LICENSE.md`); its index only (template ids, CVEs, paths, hashes, tags, the first request line) is also committed at `content/nucleipack/index.json` by the same `make scan-pack` and embedded in `core` (scan S5), so core plans jobs against the pack of the image |
| Base images: Debian 13 "trixie" slim (`scan` base), distroless `static-debian13` (`sensor`, `core`), Go 1.26 build image (build stage only, not shipped) | various free software licences (Debian packages keep their own; distroless: Apache-2.0 and the licences of its Debian packages) | container base layers pinned by digest in `deploy/containers/pins.env`; the licence texts are inside the layers (`/usr/share/doc/*/copyright`). The Debian slim layer of the published `scan` base carries GPL userland (bash, coreutils, util-linux, apt, dpkg and others) and distroless carries glibc-free static files and Debian copyright data: each is a separate program shipped as part of the base file system, **mere aggregation** (GPL-2 section 2), not linked into any Vedette binary and not modified. Source: the exact packages of the pinned base digest are on https://snapshot.debian.org at the digest's build date (and `apt-get source` on the same release), and the Debian source packages are at https://sources.debian.org |

Every container image carries its third-party license file at a standard path (D-155 (10)): `/usr/share/doc/vedette/third-party-licenses` in `core`, `sensor`, `scan` base and `honeypot` is the Go license plus the license file of every Go module linked into the binary of that image (made at build time by `scripts/hostlicenses` over the image's own main package, the same tool as the `vedette-host` .deb; a linked module with no license file fails the build). Added there: `core` has `osquery/` (see the osquery row); `scan` base has `nuclei-LICENSE.md` and `nuclei-templates-LICENSE.md` (MIT, also at `/usr/local/share/vedette/licenses/`); `honeypot` has `python-licenses`, the licence files of OpenCanary and every Python package gathered from their dist-info (a package that ships none is named in the file), while each Debian package keeps `/usr/share/doc/<package>/copyright`. Not covered yet: the JavaScript libraries inside the web interface embedded in `core` (see the table of the web app above).
| OpenCanary | BSD-3 | runs from the signed `honeypot` container image (D-123, D-146); separate process, not embedded; the image's components are listed in the section "Components of the `honeypot` container image" below (WP-08e, D-162) |
| Zeek / Suricata (optional) | BSD / GPL-2 | separate processes |
| Greenbone CE (optional) | GPL-2 / AGPL-3 | separate container, unmodified |
| osquery 5.12.1 (optional, on the user's Linux/Windows servers) | Apache-2.0 / GPL-2.0 (dual; offered here under Apache-2.0) | the three official release files for the endpoint (`osquery_5.12.1-1.linux_amd64.deb`, `osquery-5.12.1-1.linux.x86_64.rpm`, `osquery-5.12.1.msi`) are shipped **unmodified** in the `core` image under `/usr/share/vedette/osquery/` and served by the box for the one-line install (D-34, D-169 (10)); they run on the customer's servers only and are **not linked into or run by Vedette**. The version and the SHA-256 of each file are pinned in `deploy/osquery/PINS`; the image build downloads them from the official release and fails on any mismatch; nothing is downloaded at run time. Source: https://github.com/osquery/osquery/tree/5.12.1 (licence texts: the three files `LICENSE`, `LICENSE-Apache-2.0`, `LICENSE-GPL-2.0` of that tree, kept unmodified in `deploy/osquery/`, SHA-256 pinned in `PINS` and checked by the core build; shipped in the image at `/usr/share/doc/vedette/osquery/`, next to the packages' own copies; the package contents were not opened, the texts come from the tag the packages are built from) |
| NXLog Community Edition (optional, on the user's Windows machines) | NXLog Public License | installed by the user to forward Windows Event Log as syslog; Vedette only shows a config snippet |
| Podman (with Quadlet) | Apache-2.0 | appliance only: installed from the OS repository by the installer; `vedette-host` runs `podman` (pull by digest, inspect, tag, rmi) with fixed argv and writes Quadlet unit files from constant templates (D-105) |
| netplan (`netplan.io`) | GPL-3.0 | appliance only: OS package (installed by the installer on Debian 13); `vedette-host` writes its single YAML file and runs `netplan apply` (D-99) |
| iproute2 (`ip`) | GPL-2.0 | appliance only: OS package; `vedette-host` runs `ip` with fixed argv to build the decoy namespace `vedette-hp` and its macvlan links (D-102) |
| nftables (`nft`) | GPL-2.0 (some files GPL-2.0-or-later) | appliance only: OS package; `vedette-host` loads one constant ruleset inside `vedette-hp` and lists it to check the effect (D-102) |
| procps (`sysctl`) | GPL-2.0-or-later (`sysctl`), LGPL-2.1-or-later (library) | appliance only: OS package; `vedette-host` runs `sysctl -w` with constant keys and values inside `vedette-hp` (D-102) |
| chrony (`chronyd`, `chronyc`) | GPL-2.0 | appliance only: installed by the installer only when missing, with the distribution's own `chrony.conf` left as it is (D-166); `vedette-host` writes `/etc/chrony/sources.d/vedette.sources` and runs `chronyc` (D-106) |
| conntrack-tools (`conntrack`) | GPL-2.0-or-later | appliance only: system package `conntrack`, separate process (not linked), installed by the installer when missing; `vedette-host` runs one fixed command, `conntrack -D -f ipv4 -p udp --orig-port-dst 514`, after core runs again, to delete stale UDP entries of the syslog port (D-268) |

Packages that `install.sh` asks apt for when they are missing (WP-08h, D-166). All come from the distribution's own repository, run as separate processes, are never redistributed by the project, and are removed again by `install.sh --uninstall` when nothing else needs them:

| Component | License | How it is used |
|---|---|---|
| iptables | GPL-2.0-or-later | appliance only: OS package; netavark (Podman's network backend, Ubuntu 24.04) programs the container firewall through it; Vedette never runs it |
| conntrack (conntrack-tools) | GPL-2.0-or-later | appliance only: OS package, separate process; `vedette-host` runs the one fixed delete of the stale UDP syslog entries after core runs again (D-268); see its row above |
| netavark | Apache-2.0 | appliance only: OS package; Podman's container network backend, creates the `vedette-int` network and the port forwards of core |
| aardvark-dns | Apache-2.0 | appliance only: OS package; Podman's DNS for container networks (netavark companion) |
| catatonit | GPL-2.0-or-later | appliance only: OS package; the init process Podman runs for the `scan` container (`--init`, D-113) |
| unattended-upgrades | GPL-2.0-or-later | appliance only: OS package (a dependency of the `vedette-host` package); `vedette-host` writes its apt configuration (D-53) |
| curl | curl license (MIT-style) | appliance only: OS package; `install.sh` downloads the release files and waits for core with it |
| ca-certificates | GPL-2.0-or-later (scripts), MPL-2.0 (the Mozilla certificate bundle) | appliance only: OS package; the trust roots for the downloads of `install.sh` and Podman |
| passwd (`useradd`, `groupadd`) | BSD-3-Clause / GPL-2.0-or-later (shadow) | appliance only: OS package; the `vedette-host` package's postinst makes the users `vedette` and `vedette-sensor` with it |

The GPL tools above are separate programs from the distribution, run through `core/exec` with fixed argv; nothing from them is linked into or redistributed with Vedette (rule `legal.md`: GPL/AGPL is never embedded). Licences checked from the Debian copyright files (`metadata.ftp-master.debian.org/changelogs/main/…/stable_copyright`) on 2026-11-10.

## Components of the `honeypot` container image (WP-08e, D-162)

The `honeypot` image (`deploy/containers/honeypot/Containerfile`) is a separate container the unit runs in its own network namespace; none of this is linked into, or loaded by, a Vedette binary (`core`, `vedette-host`, `vedette-sensor` are static Go with no cgo; `deploy/containers/honeypot_test.go` reads the licence file of every Go module they link and fails on a GPL, LGPL or AGPL text). The image's own list of added components is `/usr/share/vedette/honeypot-inventory.txt`; each Debian package's licence text is in `/usr/share/doc/<package>/copyright`, each Python package's in its `*.dist-info`. The image keeps every notice and licence file of what it ships, unmodified except where stated. Licences below are as the packages declare them (read from the built image on 2026-11-11).

| Component | Version | License | How used |
|---|---|---|---|
| OpenCanary | 0.9.10 | BSD-3-Clause | the trap engine, started by `init.py` as `twistd`; pinned in `requirements.in`, hash-locked in `requirements.txt` |
| Samba (`samba`, `samba-libs`, `samba-common`, `samba-common-bin`, `libldb2`, `libtdb1`, `libtalloc2`, `libtevent0t64`, `libwbclient0`) | Debian 13 package, floor `2:4.22` (`SAMBA_MIN_VERSION`) | GPL-3.0-or-later (the libraries LGPL-3.0-or-later) | **separate process** (`smbd`, started by `init.py` with exec, a read-only guest share of planted bait files, every open audited); never linked into a Vedette binary; taken unmodified from the Debian repository at build time, so its source is Debian's. Exact version of the check run of 2026-11-11: `samba` 2:4.22.11+dfsg-0+deb13u1; every release records its own list (`honeypot-inventory.txt`) for the source offer (WP-08k) |
| Python 3.13 (`python3`, `python3.13`, `libpython3.13-*`, `python3-minimal`) and its Debian libraries (ICU, readline, ncurses, libffi, expat, GnuTLS, Kerberos, LDAP and others the Samba and Python packages depend on, listed in the inventory file) | Debian 13 packages | PSF-2.0 for Python; the libraries keep their own free licences (Debian copyright files) | runs OpenCanary and `init.py` |
| Twisted 26.4.0, attrs, Automat, constantly, Incremental, hyperlink, zope.interface (ZPL-2.1), service-identity, pyasn1 and pyasn1-modules, six, typing-extensions (PSF-2.0), packaging 26.3 (Apache-2.0 OR BSD-2-Clause) | pinned in `requirements.txt` | MIT, BSD-2-Clause, ZPL-2.1, PSF-2.0, Apache-2.0 | OpenCanary's network stack |
| cryptography 50.0.2, pyOpenSSL 26.4.0, cffi, pycparser, bcrypt 3.2.0, passlib | pinned in `requirements.txt` | Apache-2.0 OR BSD-3-Clause; Apache-2.0; MIT-0; BSD-3-Clause; BSD | SSH trap keys, TLS |
| requests 2.33.0, urllib3, idna, certifi (MPL-2.0, unmodified), charset-normalizer, redis, GitPython 3.2.1 (BSD-3-Clause), gitdb, smmap, Jinja2 3.1.6, MarkupSafe | pinned in `requirements.txt` | Apache-2.0, MIT, BSD, MPL-2.0 | OpenCanary's declared dependencies (most are imported but unused with the five traps Vedette turns on) |
| ntlmlib 0.72 (Apache-2.0), simplejson 3.16.0 (MIT or AFL), ordereddict 1.1 (MIT, text in its source header; the package declares no licence), setuptools 83.0.0 (MIT) | pinned in `requirements-sdist.txt` / `requirements.txt`; the first three built from hash-checked source archives | as stated | pure Python, no compiler |
| hpfeeds 3.0.0 (GPL-3.0) | **not shipped** | GPL-3.0 (its `LICENSE`; PyPI says "GPL") | OpenCanary imports it at the top of `opencanary/logger.py` (`import hpfeeds`) and calls it only for an hpfeeds logger, which Vedette's configuration never names. The image therefore holds **a stub** (`deploy/containers/honeypot/hpfeeds_stub.py`, no imports, `new()` raises) at `/opt/opencanary/lib/hpfeeds.py`; `lock.py` leaves hpfeeds out of the hash-locked install, tests keep it out of `requirements*.txt` and out of the rendered config, and `make honeypot-check` fails on a GPL Python package in the inventory (D-162) |
| Debian 13 "trixie" slim | by digest in `pins.env` | Debian packages keep their own licences | base layers |
| the core binary at `/vedette` | this project | Apache-2.0 | only so the unit's `HealthCmd` (`/vedette honeypot healthcheck`, D-137) runs; static, no cgo |

## Development and CI tools (not shipped in any image or binary)

Pinned in `tools/go.mod` (Go `tool` directives), run with `go tool -modfile=tools/go.mod <tool>` by `make verify-go` and `make audit` on the developer's machine (no hosted CI, D-61). They only read the source tree; nothing from them is linked into Vedette.

| Tool | Version | License | How it is used |
|---|---|---|---|
| golangci-lint | v2.15.0 | GPL-3.0 | linter run on the source tree on the developer's machine; separate process, never distributed |
| govulncheck (golang.org/x/vuln) | v1.9.0 | BSD-3-Clause | vulnerability scan of Go dependencies (`make verify-go`, `make audit`) |
| nfpm (github.com/goreleaser/nfpm/v2) | v2.43.0 | MIT | the maintainer's build tool for the `vedette-host` `.deb` (`make host-deb`, D-155); a separate process on the maintainer's and CI machine, never shipped or linked into Vedette; its Go dependency graph was checked for GPL/AGPL (none) |
| sqlc (github.com/sqlc-dev/sqlc) | v1.31.1 | MIT | generates the typed query code in `core/store/coredb` from SQL files (`make generate`); the generated code is committed, sqlc itself is never linked |
| GitHub Actions in `.github/workflows/ci.yml`: `actions/checkout`, `actions/setup-go`, `pnpm/action-setup`, `actions/cache` | pinned by commit SHA (cache v6.1.0) | MIT | run on GitHub's runners only (D-63); `actions/cache` keeps the golangci-lint cache between runs (D-140). Change detection uses no third-party action |

Release supply-chain scanner (D-159, maintainer's machine only, never shipped, not a Go dependency): **trivy** (aquasecurity/trivy, Apache-2.0), run from its official container image pinned by digest in `deploy/tools.env`. `make sbom` writes the CycloneDX SBOMs (`dist/sbom/`) and `make vuln-scan` gates the release on fixable HIGH/CRITICAL vulnerabilities. It downloads its own vulnerability database (`ghcr.io/aquasecurity/trivy-db`, built by Aqua Security from public advisories; used only to scan, not redistributed) into the maintainer's cache; nothing of Vedette's, and no data of a customer, leaves the machine.

Release signing tools (maintainer's machine only, not in `tools/go.mod`, never shipped): minisign (ISC) signs `index.json` and release manifests; cosign (Apache-2.0), pinned, signs images in the legacy format with `--new-bundle-format=false --use-signing-config=false` (D-103). minisign 0.12 was also run once to produce the committed signature test vectors of `internal/release` (D-107; throwaway test keys, commands in `internal/release/testdata/README.md`). cosign was not run: its legacy signature format is built by a committed Go generator, and two payload strings are copied from the test file of github.com/sigstore/sigstore `pkg/signature/payload` (Apache-2.0, source and commit in that README); no cosign or sigstore code is linked.

Lab VMs (D-315, `scripts/dev/lab-vm.sh`, developer's machine only, never shipped or linked): **QEMU** (`qemu-system-x86`, `qemu-utils`; GPL-2.0), **passt** (GPL-2.0-or-later), **cloud-image-utils** (`cloud-localds`; GPL-3.0), installed from the OS repository by `lab-vm.sh setup` and run as separate processes. Guest images: the Ubuntu 24.04 cloud image (Canonical, free software under their own licenses; image terms at cloud-images.ubuntu.com) and the Debian 13 generic cloud image (Debian, DFSG-free), downloaded by the developer into `~/.cache/vedette-lab/` and never redistributed. Nothing of Vedette's leaves the machine.

Release builder (WP-08f, D-164, maintainer's machine only, never shipped): `scripts/release` is Vedette's own Go code and adds no dependency (it uses `golang.org/x/crypto` and `golang.org/x/mod`, already listed above, through `internal/release`). It runs the **minisign** command line tool (jedisct1/minisign, ISC) as a separate process to sign `index.json` and `release-manifest.json`: release 0.12, the official static binary, pinned by the SHA-256 of the tarball and of the binary for each architecture in `deploy/tools.env` and fetched by `scripts/release/minisign.sh` into `~/.cache/vedette-minisign` (nothing of Vedette's leaves the machine; the download is the maintainer's own, from `github.com/jedisct1/minisign/releases`). `make release-interop` also runs it to check that its signatures and the box's verifier agree. It prints the `cosign sign` commands for the maintainer to run; it does not run cosign. **cosign** (sigstore/cosign, Apache-2.0) release v2.6.5, the official binary for each OS and architecture, is pinned by SHA-256 in `deploy/tools.env` and fetched by `scripts/release/cosign.sh` into `~/.cache/vedette-cosign` (D-257; the download is the maintainer's own, from `github.com/sigstore/cosign/releases`); `scripts/release/keygen.sh` runs it and minisign to make the release keys (D-256). Nothing of Vedette's leaves the machine.

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
| Spamhaus DROP | not used in v1 (D-367) | name not used in marketing |

Real data in the current build (`web/src/mocks/fixtures/`, `make fixtures`): CISA KEV (CC0), FIRST EPSS (attribution), the CVE list of nuclei-templates (MIT). Sources are shown on every screen.

## Public pages each box reads for CVE news (only when a person presses the button; S-AI-3, D-280, D-281)

Read on the box, never stored or redistributed as they are: the box keeps only the AI's summary and the links. No library added; `golang.org/x/net/html` (already linked, row above) reads the advisory pages.

| Source | Terms | How it is used |
|---|---|---|
| NVD CVE API 2.0 (`services.nvd.nist.gov`) | NVD terms of use; NVD data is in the public domain | data: one record per CVE, no key; the source row carries the notice the terms require: "This product uses the NVD API but is not endorsed or certified by the NVD." |
| GitHub REST API, repository search (`api.github.com`) | GitHub Terms of Service (API) | data: names, descriptions, stars and dates of public repositories that name the CVE; no token, no code downloaded |
| Vendor advisory pages (the 16 hosts in PRIVACY.md flow 8) | each vendor's site terms | data: the visible text of one advisory page the CVE links to, cut to 6000 bytes |
| Feeds of watchTowr Labs, GreyNoise, SANS Internet Storm Center, Rapid7, Unit 42, Google Project Zero | each site's terms; public RSS/Atom | data: the posts that name the CVE (title, date, link, text around the mention) |

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

