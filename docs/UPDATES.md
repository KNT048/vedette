# Updates

A security product must be easy to keep current. This page is the overview; the exact formats, signatures and rules are in
[`specs/update-manifest.md`](specs/update-manifest.md), the steps on the box in [DEPLOYMENT.md](DEPLOYMENT.md) §9, and the release keys
in [RELEASE_KEYS.md](RELEASE_KEYS.md).

## 1. What is updated, and how

| What | Where it comes from | How the box trusts it |
|---|---|---|
| Feed data (exploited lists, CVE records, fixed versions, signals, indicators) | each publisher directly, on the feed's own schedule ([DATA_PIPELINE.md](DATA_PIPELINE.md)) | the parser fails closed; no data goes through the project |
| Vedette software: the `core`, `sensor`, `scan` and `honeypot` images | GitHub Releases (the signed `index.json` and `release-manifest.json`) and `ghcr.io` (the images, by digest) | minisign signatures on the index and the manifest, checked by `core` and again by `vedette-host`; a cosign signature on every image |
| `vedette-host` itself | the `.deb` of the release, its SHA-256 in the signed manifest | installed by the running `vedette-host` as the first step of a software run (`host.self_update`), or by `install.sh` |
| Content that ships with the software: confirmed recommendation packs, the product catalogue, device types, safe-check packs, log parsers | inside the signed `core` image | the image's signature |
| Operating system packages | the distribution's apt mirrors, through `vedette-host` | apt's own signatures |
| Product advisories (flaws in Vedette itself) | the `advisories` of the signed index | the index's signature |

The public keys are compiled into the binaries (`internal/release/keys.go`). A file that is unsigned or wrongly signed is refused
wherever it comes from; TLS only protects the transfer.

## 2. Software updates on the appliance

- **Check**: every 6 hours (± 30 minutes) and when someone presses Check, while update checks are on under Settings → Privacy (PRIVACY
  flow 6). The box sends only its current version.
- **Channels**: `stable` and `beta` (Settings → Updates → Software channel). A box installed from a beta release follows the beta
  channel.
- **Rollout**: each channel of the index names a rollout percentage; a box is offered the release, by hand or automatically, only when
  its cohort is inside it. Until then the Updates page says the box is not in the rollout yet.
- **Mode**: manual (the default: the page offers the release and asks before it starts) or automatic (installs inside the maintenance
  window, never while another run is busy).
- **Run**: `vedette-host` updates itself first, then backs up the database, pulls each image by digest after checking its signature,
  and replaces the containers with `core` first; a health gate follows. A failure returns to the previous images within the same run.
- **Rollback**: Settings → Updates → History → Roll back, to the previous release (one generation is kept). When the release is marked
  `rollback.safe=false`, the page asks to confirm the data loss and the database backup taken just before the update is restored.
  `vedette-host` has no manual rollback; it goes back to its previous package by itself after a failed start.
- **Revocation**: the index can withdraw a release or a key; a box never installs a withdrawn release.
- **Advisories**: an advisory in the index is shown on every box's Updates page.

A **container-only** install has no `vedette-host`: it does not update itself. Settings → Updates names the new release and shows the
`pull` and `up -d` commands with the release's image digests ([INSTALL-CONTAINER.md](INSTALL-CONTAINER.md)).

The **offline bundle** for air-gapped networks is not in v1: the interface does not offer it, and `/core/updates/bundle` answers 501.

## 3. Operating system updates

Settings → Updates checks the operating system first: release, kernel, packages with security fixes, whether a restart is needed, end
of support. `vedette-host` runs a fixed list of apt commands with checked parameters: install the security fixes or everything,
unattended-upgrades, a schedule inside the maintenance window, restart now or later. A distribution release upgrade is guidance only,
never done automatically. The database is backed up first and the health gate runs after.

## 4. Making a release

Releases are built and signed on the maintainer's machine with the `make release-*` targets (`make help` lists them; the flow is in
the comment above them in the `Makefile`), not by CI. In short:

1. The maintainer tags `v<version>` by hand, then builds the multi-architecture images (`make images`) and the `vedette-host` package
   (`make host-deb`) from a clean clone at that tag. Builds are reproducible (`-trimpath`, `CGO_ENABLED=0`, amd64 and arm64 without
   emulation).
2. Supply chain: `make sbom` writes a CycloneDX SBOM for each image and architecture plus the source tree; `make vuln-scan` refuses any
   HIGH or CRITICAL vulnerability that already has a fix, except the dated, reasoned entries of `.trivyignore.yaml`; `make
   notices-check` compares `THIRD_PARTY_NOTICES.md` with what is actually linked.
3. The release gates rebuild the package at the tag and check every artifact; the images are pushed by digest, signed with cosign (the
   SBOMs attached as attestations), and the index and manifest are signed with minisign and checked with the box's own verifier.
4. The GitHub release is published with the index last. Test releases go to the `beta` channel first.

## 5. Flaws in Vedette itself

- Report them privately as described in [SECURITY.md](../SECURITY.md).
- CI runs `govulncheck` on Go changes and daily, and `pnpm audit` daily; Dependabot proposes dependency updates.
- A fixed flaw gets an advisory, delivered through the index and shown in the app.
