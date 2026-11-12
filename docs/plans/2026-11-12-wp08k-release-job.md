# WP-08k: the release job, end to end (D-457)

The first real release (v1) is built, signed and published from the maintainer's Mac (kien), by `make` targets, in the order below.
Nothing here runs in CI: CI holds no key and no publishing token (D-63, D-82). The AI writes the tools and this plan; it never
creates a tag, never pushes to ghcr.io and never creates a GitHub release.

Parts of WP-08k: **A** `release-bake-install` and **B** `release-gates` and **C** the `cosign attest` lines of `release-cosign-plan` are
built on the Mac side; `release-push`, `release-in`, `release-publish` and this plan are the lead's (this branch).

## 1. Order

`<v>` is the release version, SemVer without `v` (for example `1.0.0`). Run everything from a full git clone (not a worktree: Go records
no VCS information there, `check-binaries -release` refuses) at kien's tag, with `RELEASE=1` so `release-verify` keeps `dist/release`.

| # | Step | Who | Reads | Writes | Key / token |
|---|---|---|---|---|---|
| 0 | `git tag -s v<v>` on the release commit, `git push origin v<v>` | **kien, by hand** | | tag | git signing key (optional), GitHub push |
| 1 | `make images IMAGE_TAG=<v> IMAGE_VERSION=<v> RELEASE_PREV_INDEX=<published index dir>` (or `MIN_SEQUENCE=0` for the very first) | maintainer | tree at the tag, `pins.env` | 4 local podman manifest lists `localhost/vedette-{core,sensor,scan-base,honeypot}:<v>`, amd64 + arm64 | none |
| 2 | `make host-deb VERSION=<v> ARCH=amd64` and `ARCH=arm64` (same `RELEASE_PREV_INDEX`) | maintainer | tree | `dist/vedette-host_<v>_<arch>.deb` | none |
| 3 | **[B]** `release-gates`: `make vuln-scan`, `notices-check`, `check-binaries -release`, image version label = `<v>`, `MIN_SEQUENCE` floor | maintainer | lists, `.deb`, previous index | `dist/sbom`, `dist/vuln` (RELEASE=1) | none |
| 4 | **`make release-push VERSION=<v>`** | maintainer | the 4 local lists | ghcr.io: `vedette-{core,sensor,scan,honeypot}` by digest (+ tag `<v>`); `dist/release/images.json` | **ghcr token** (`podman login ghcr.io`, `write:packages`) |
| 5 | **`make release-in RELEASE_CHANNEL=stable RELEASE_ROLLBACK_SAFE=false`** (+ `RELEASE_ROLLBACK_MIN`, `RELEASE_MIN_UPGRADE_FROM` when wanted), then write the notes into `release.in.json` | maintainer | `images.json`, the two `.deb`, local lists (sizes) | `release.in.json` | none |
| 6 | **[C]** `make release-cosign-plan COSIGN_KEY=…` (sign lines + `cosign attest --type cyclonedx` lines from `images.json`) | maintainer | `release.in.json`, `images.json`, `dist/sbom` | printed commands | none |
| 7 | run the printed cosign commands | **kien** | | `dist/release/cosign/<service>.{payload.json,sig}`; attestations in ghcr | **cosign key** + `COSIGN_PASSWORD`, ghcr token (attest uploads) |
| 8 | `make release-manifest RELEASE_PREV_INDEX=…` | maintainer | `release.in.json`, cosign files, git at `v<v>`, previous index | `release-manifest.json`, `index.json` (unsigned) | none |
| 9 | `make release-container-assets` | maintainer | git at `v<v>`, `release.in.json` | the four container-only files | none |
| 10 | **[A]** `release-bake-install` | maintainer | `install.sh` at the tag, the `.deb` | `dist/release/install.sh` (3 baked lines), `install.sh.minisig` | **minisign active key** |
| 11 | `make release-sign MINISIGN_KEY=…` (active), then `RELEASE_SLOT=backup` with the offline key | **kien** | `dist/release` | `.minisig` files; `index.json.backup.minisig` | **minisign active**, then **backup** (USB) |
| 12 | `make release-verify RELEASE=1 RELEASE_PREV_INDEX=…` | maintainer | `dist/release` | nothing (kept) | none |
| 13 | **`make release-publish`** (prints), then **`make release-publish PUBLISH=1`** | **kien** | `dist/release`, `release.in.json` | GitHub release `v<v>` and the fixed release `index` | **gh token** (`repo` scope) |
| 14 | archive `index.json` + `.minisig` (+ SHA-256 noted) as the next `RELEASE_PREV_INDEX`; `make clean`; remove the local lists | kien | | | |

The weekly index refresh (D-150) is `release-refresh` → `release-sign` (+ backup) → `release-verify RELEASE=1` → `release-publish`: on an
index-only directory publish uploads only the index.

### What each new step does

**`release-push`** (`scripts/release` `push`, podman only). For each of `core`, `sensor`, `scan-base` (published as **`vedette-scan`**:
the manifest, the cosign identity and `vedette.env` all call it `scan`, and the box builds its scan image FROM it, D-147) and `honeypot`:

1. `podman manifest exists` + `inspect` of `localhost/vedette-<image>:<v>`: it must be a manifest list holding exactly the platforms of
   `PLATFORMS` (default linux/amd64 + linux/arm64).
2. `podman manifest push --all --quiet --digestfile <tmp> <local> docker://ghcr.io/knt048/vedette-<service>:<v>`. The digest podman
   writes is the index digest **as pushed** (layers are compressed on push, so the per-platform digests differ from the local ones;
   measured).
3. `podman manifest inspect ghcr.io/knt048/vedette-<service>@<digest>`: podman refuses a manifest whose bytes do not hash to the
   digest asked for ("Manifest does not match provided manifest digest", measured with podman 5.7 against a fake registry serving other
   bytes), so the list read back is the one the boxes will pull. Its platforms must again be exactly `PLATFORMS`; their digests go to
   `images.json`.
4. `podman manifest inspect …:<v>`: the version tag must name the same per-platform digests. The tag is for people; nothing
   downstream reads it.

Refused: a registry other than `ghcr.io/knt048` unless it is on 127.0.0.1/::1/localhost (a rehearsal: TLS verification, the `-test.`
refusal and the git checks are off there); a non-SemVer or `-test.` version; uncommitted changes to tracked files; HEAD not equal to
tag `v<v>`; `CONTAINER=docker` (see §4). `images.json` is written only after all four are pushed and read back:

```json
{"version":"X.Y.Z","images":[{"service":"core","repo":"ghcr.io/knt048/vedette-core","index_digest":"sha256:<64hex>",
  "platforms":[{"platform":"linux/amd64","digest":"sha256:<64hex>"},{"platform":"linux/arm64","digest":"sha256:<64hex>"}]}, …]}
```

Services in order core, sensor, scan, honeypot; platforms sorted. Part C reads it for `cosign attest` (per-platform SBOMs
`dist/sbom/<image>-<arch>.cdx.json` attach to the platform digests; the local name `scan-base` maps to service `scan`).

**`release-in`** (`in`): reads `images.json` strictly (four services, each once, repo `ghcr.io/knt048/vedette-<service>`: a rehearsal's
file is refused), and writes `release.in.json`: images (`digest` = index digest, `platforms`, `size` = the largest unpacked size among
the platforms of the local list, used by the box only for its free-space check, D-104), host = the two
`<deb-dir>/vedette-host_<v>_<amd64|arm64>.deb` (checked by the same `buildHostPart` the manifest uses), `install_modes`
`["appliance","container"]` (D-451), `released_at` empty, `content`/`bundled` empty, `sbom` null. `channel` and `rollback.safe` must
be given (`stable|beta`, `true|false`); `rollback.min_version` and `min_upgrade_from` only when given. It refuses to overwrite an
existing `release.in.json` (it may hold notes). The result is parsed back with `ParseInputs`, and a test runs it through
`BuildManifest`.

**`release-publish`** (`publish`): verifies `dist/release` again with the box's verifier (`VerifyDir`), checks each `.deb` named in
`release.in.json` against the SHA-256 and size of the **signed** manifest, requires `install.sh` + `install.sh.minisig` (part A), the
container assets when the manifest lists `container`, and that tag `v<v>` exists. Default: prints the commands. `PUBLISH=1`:

1. `gh release view v<v>`; if absent `gh release create v<v> --verify-tag --draft --title "Vedette <v>" --notes <manifest notes>`
   (`--prerelease` for channel beta or a SemVer prerelease). `--verify-tag` aborts when the tag is not on GitHub.
2. `gh release upload v<v> --clobber` of: `release-manifest.json(.minisig)`, `install.sh(.minisig)`, `compose.yaml`,
   `compose.sensors.yaml`, `compose.syslog.yaml`, `vedette.env` (each `.minisig`), `vedette-host_<v>_amd64.deb`,
   `vedette-host_<v>_arm64.deb`.
3. Read back (`gh release view --json assets`): every asset `uploaded`, same size, same `sha256:` digest when GitHub reports one, and
   nothing else on the release.
4. `gh release edit v<v> --draft=false`, read back: published.
5. **Last:** `gh release upload index --clobber index.json index.json.minisig` (+ any `index.v<N>.json` pair, D-108), read back.

`index.json.backup.minisig`, `images.json`, `release.in.json` and the cosign files are not uploaded (the box never fetches them); kien
keeps them with the archived index.

## 2. Why this order: a half-published release

The boxes and `install.sh` read only two places: the fixed release `index` (`…/releases/download/index/index.json` + `.minisig`, D-341)
and, from the version it announces, `…/releases/download/v<v>/{release-manifest.json,.minisig,install.sh,vedette-host_<v>_<arch>.deb,…}`.
Images are pulled by digest from ghcr. So:

- **Images before documents.** A manifest names digests that are already in the registry and readable (step 4 before step 8); a box
  never verifies a manifest whose images 404.
- **The version release is a draft until every asset is there and checked.** Draft assets are not public, so a box or customer
  following `v<v>` either sees nothing (404, retried later) or all of it. This is what `gh release create` itself does when given
  assets, and what GitHub's immutable-release guidance prescribes (draft, attach, publish).
- **The index goes up last**, after `v<v>` is published and read back: no box is ever told about a release whose files are missing.
- **A published version is never changed.** A re-run compares a published `v<v>` with the directory and only proceeds to the index
  when they match; any difference stops with "release the next version". Version tags in ghcr are never pushed twice for different
  content (step 4 refuses when the tag names another list).

Failure at each point and what to do:

| Fails at | State | Recovery |
|---|---|---|
| push (4) | some images in ghcr, nothing references them | fix, run `release-push` again (same digests if the lists did not change). Unreferenced digests are harmless; delete the packages' versions by hand only if a tag must be reused |
| 5–12 | nothing public references anything | fix and re-run the step |
| publish 1–3 | a draft `v<v>`, maybe partial | `release-publish PUBLISH=1` again: the draft is filled (`--clobber`) and checked |
| publish 4 | `v<v>` published, index old | run again: published assets are compared, then the index goes up. Boxes still see the previous release: correct |
| publish 5 | index half replaced (`--clobber` deletes then uploads; a box may fetch the new `index.json` with the old signature) | boxes fail closed (signature check), keep their stored index and retry later; run again at once |
| a bad release found after publishing | | never delete or edit `v<v>`: publish `v<v+1>`, and revoke `<v>` through the index (`revoked[]` kind `release`, D-108) |

The two `--clobber` windows (index file and signature are two uploads, GitHub has no atomic replace) are a known limit: the box treats
a mismatched pair as a failed check and keeps what it has (D-104, D-341), so the window costs a delay, never a wrong update.

## 3. One-time manual steps for kien

1. A GitHub token for `gh` with `repo` scope; a ghcr token (classic PAT `write:packages`, or `gh auth token` with that scope) for
   `podman login ghcr.io -u kiennt048`. Neither goes into the repo or argv; podman and gh keep them.
2. Create the fixed release `index` once (it creates the lightweight tag `index`, which only kien may do):
   `gh release create index --repo KNT048/vedette --title "Update index" --notes "Signed update index (D-150). Do not delete." --latest=false`
   and upload the first `index.json` + `.minisig` with the first release. `release-publish` refuses until it exists.
3. **After the first push, make the four ghcr packages public** (GitHub → Packages → `vedette-core`, `-sensor`, `-scan`, `-honeypot` →
   Package settings → Change visibility → Public) and link them to the repository. New packages are private; boxes pull anonymously.
   Do it before step 13, or `install.sh` on a customer box fails at the pull.
4. Leave GitHub **immutable releases off** for this repository: they would also lock the fixed release `index`, which must be replaced
   every week (D-150). The tool keeps version releases unchanged instead (§2).

## 4. Not done here / open

- `CONTAINER=docker`: `make images` writes OCI archives under `dist/images/` (not run yet, `.ai/deferred/feat-multiarch-images.md`);
  pushing those needs `skopeo copy --all oci-archive:` or `regctl`, a new dependency. `release-push` refuses docker until someone needs it.
- Prerelease `.deb` names: nfpm writes `~` for a SemVer prerelease (`1.0.0~beta.1`); `release-in` needs the SemVer spelling, so for a
  prerelease the rename (part A) must happen **before** step 5, not after. A plain `1.0.0` needs no rename.
- `sbom` of the manifest stays null; the SBOMs travel as cosign attestations (part C). `bundled` (nuclei, OpenCanary versions for the
  Managed packages view) stays empty; filling it from `pins.env` is a follow-up if the GUI should show it for v1.
- Release notes: written by hand into `release.in.json` after step 5 (they are signed in the manifest and reused as the GitHub notes).
