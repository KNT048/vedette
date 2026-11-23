# Updates: designed in from day one

A security product must be updated often; the place for that must be in the original design.

> **Data and content packs:** GitHub now publishes only **signed software updates**. The channel "1. Data" below no longer goes through GitHub/the builder: the box pulls each feed from its source itself (`docs/DATA_PIPELINE.md` §0). The channel "2. Content packs" (skills, confirmed recommendation packs, log parsers...) is now **packaged with the software update**. A staged rollout (§2) applies to software updates. The feed safety test (§5) runs on the box before the data is used.

> **A container-based appliance:** the box is an appliance that runs containers. The channel "3. Software" is now a **cosign-signed OCI image** (a pinned digest, a staged release, a rollback with the old tag), **replacing the A/B slot mechanism for the binary**; the box's **operating system update** goes through `vedette-host` (replacing `vedette-updater`). Operating detail: `docs/DEPLOYMENT.md` §9. The *Container only* install type has no `vedette-host`: it does not update itself, the GUI announces the new version and shows the command.

## 0. Updates on the appliance: software and operating system

| Layer | What is updated | Mechanism | Rollback |
|---|---|---|---|
| Vedette software | the images `core`, `sensor`, `honeypot`, `scan` (+ the digest of `greenbone`) | `vedette-host` fetches `release.json` (minisign-signed, verifiable offline) listing each image digest, the channel, the rollout %, the minimum host version, `revoked[]`; pulls by digest; **cosign is mandatory** (a policy on the host, fail closed); backs up the DB; replaces containers in the order `core` → `sensor`/`scan` → `honeypot` → `greenbone` (a sensor/worker is never newer than `core`, `core` accepts sensor protocol N and N-1, `specs/sensor-protocol.md` §10; a rollback goes the other way, `core` last); a health gate | go back to the previous digest/tag (1 generation kept); migrations are expand-only so the previous version can run |
| Operating system | apt packages, kernel, reboot (S-CORE-7) | `vedette-host` runs a fixed list of apt commands, scheduled by a maintenance window | back up the DB first, a health gate after; upgrading the OS release is guidance only |
| `vedette-host` | itself | a `.deb` package with its SHA-256 in the signed manifest, installed by the old `vedette-host` (`host.self_update`, the first step of the software run) or `install.sh`; detail in `specs/host-api.md` §6.14 | automatic: the previous package is kept, if the new one is not healthy the old one is installed again; no manual rollback |

Cohort, `beta` → `stable` ≥ 7 days, the revocation list, the offline bundle: unchanged as in §1-§3. A cohort blocks only **automatic** updates (when a user clicks by hand: see `DEPLOYMENT.md` question B6).

The rest of this document describes the data/content/advisory channels and the CI release; wherever it mentions "binary", "slot A/B", "minisign + cosign for the binary", read it according to the table above.

## 1. Four channels

| Channel | Content | Interval | Mechanism | Rollback |
|---|---|---|---|---|
| **1. Data** | `feeds/*` (vuln, hot, ioc, slug) | 30-60 minutes | a signed `index.json`; ETag; delta | the previous version is kept; `revoked[]` withdraws a bad file |
| **2. Content packs** (mitigation packs: shipped inside the signed `core` image) | skills, mitigation packs, a nuclei subset, the recog DB, log parsers, rule packs, Vietnamese sentence templates | daily | a signed `content-packs/<name>-<semver>.tar.zst`; the manifest lists files + sha256 | N-1 is kept; back in 1 click |
| **3. Software** | OCI images `core`/`sensor`/`honeypot`/`scan` (the SPA is embedded in `core`); ~~binary + A/B slot~~ | per release; channels `stable`/`beta` | a minisign-signed `release.json`; pull images by digest, cosign mandatory; replace containers, a health gate; fail → back to the previous digest | the old tag/digest (1 generation kept); a Rollback button; see §0 |
| **4. Product advisories** | flaws in Vedette itself, dependencies | when there is one | `security.json` in the index; a UI banner; mail/Telegram to the admin | none |

Every channel: a signature is mandatory, the public keys are in the binary (2 keys: `builder-vn`, `builder-gh`, + a separate software release key), a **revocation list** in `index.json`.

## 2. Rollout in batches

- Each box has `cohort = hash(install_id) mod 100`. `index.json` records `rollout: {content-pack X: 10}` → only boxes with cohort <10 receive it; it grows 10 → 50 → 100 after 24 hours with no error report (an anonymous opt-in hit or an issue). Software: `beta` before `stable` by ≥ 7 days.
- Never switch on a data/rule change globally (the Cloudflare lesson of 2025-12-05).

## 3. The Updates page (S-CORE-2)

Shows: the software/data/content pack version, "updated at", the channel, the history of the last 20 updates, the signature state, a check-now button, a rollback button per channel, automatic/manual mode, the **offline bundle** (postponed until after v1: the GUI does not offer it, `/core/updates/bundle` returns 501) (`vedette bundle export/import` for air-gapped networks), the state of product advisories.

## 4. Release process (CI, GitHub Actions)

1. Test (Go, FE), lint, `govulncheck`, `trivy fs`, licence check (no GPL/AGPL in the core).
2. Reproducible builds (`-trimpath`, `CGO_ENABLED=0`), multi-architecture (amd64/arm64: `make images`, one manifest list per image, cross-compiled without qemu; `make host-deb VERSION=<x.y.z> RELEASE_PREV_INDEX=<folder of the published index>` sets the `sequence` floor of the index inside `vedette-host` to the sequence of that index; a real build without `RELEASE_PREV_INDEX` is refused, except `MIN_SEQUENCE=0` for the first release; a real build is also refused when the git tree is dirty or `GOFLAGS` has `-overlay`/`-tags`, and the finished binary must carry exactly the bytes of the real public key), an **OCI image** for each container and a `.deb` package for `vedette-host` (`make host-deb`, nfpm; package parameters in `DEPLOYMENT.md` §3.1).
3. A CycloneDX SBOM and vulnerability scanning with a single tool, **trivy** (no syft/grype): `make sbom` writes the SBOM for each image and each architecture plus the source tree into `dist/sbom/`; `make vuln-scan` stops when there is a HIGH/CRITICAL flaw that already has a fix, with exceptions only through `.trivyignore.yaml` with a reason and an expiry date; `make notices-check` compares `THIRD_PARTY_NOTICES.md` with the Go modules actually linked and the web dependencies. This step runs on the maintainer's machine, in the same pass as step 2, and needs no key (attaching the SBOM to the image with `cosign attest` belongs to step 4).
4. Signing: **cosign** for each image (the box verifies when pulling); **minisign** for `release.json` and the `vedette-host` package (verifiable offline). Whether cosign is key-based or keyless: open question A3 in `ARCHITECTURE.md`.
5. A changelog from commits; a GitHub Release; `index.json` updated through the builder; `beta` first.
6. The tag is created by hand by a maintainer.

## 5. Flaws in the product itself

- `SECURITY.md`: a private reporting channel, SLA 2/14/30 days.
- Dependencies: Renovate weekly, pinned versions; a serious CVE in a dependency → a fix release within 7 days.
- Malicious feed data (an IOC that "blocks Google", a dangerous Nuclei template): the builder has a **safety test** before signing: the top-10k-domain whitelist must not appear in the block list; the nuclei subset only has safe tags; log parsers run a 60-second fuzz.
- The box keeps an update log (who, when, sha256) in `core_audit`.

## 6. When the free infrastructure changes

Every URL is in one (signed) `channels.json` file → changing the host = changing one file. A second mirror (Releases ↔ R2) always exists; the box tries them in turn.
