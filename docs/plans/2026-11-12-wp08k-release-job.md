# WP-08k: the release job, end to end (D-457)

The first real release (v1) is built, signed and published from the maintainer's Mac (kien), by `make` targets, in the order below.
Nothing here runs in CI: CI holds no key and no publishing token (D-63, D-82). The AI writes the tools and this plan; it never
creates a tag, never pushes to ghcr.io and never creates a GitHub release.

Parts of WP-08k: **A** `release-bake-install` and **B** `release-gates` and **C** the `cosign attest` lines of `release-cosign-plan` are
built on the Mac side; `release-push`, `release-in`, `release-publish` and this plan are the lead's (branch `feat/release-push`).

## 1. Order

`<v>` is the release version, SemVer without `v` (for example `1.0.0`). Run everything from a full git clone (not a worktree: Go records
no VCS information there, `check-binaries -release` refuses) at kien's tag, with `RELEASE=1` so `release-verify` keeps `dist/release`.
`<prev>` is kien's saved copy of the published index (`index.json` + `.minisig`, step 14 of the previous release); the first release
has none.

| # | Step | Who | Reads | Writes | Key / token |
|---|---|---|---|---|---|
| 0 | `git tag -s v<v>` on the release commit, `git push origin v<v>` | **kien, by hand** | | tag | git signing key (optional), GitHub push |
| 1 | `make images IMAGE_TAG=<v> IMAGE_VERSION=<v> RELEASE_PREV_INDEX=<prev>` (or `MIN_SEQUENCE=0` for the very first) | maintainer | tree at the tag, `pins.env` | 4 local podman manifest lists `localhost/vedette-{core,sensor,scan-base,honeypot}:<v>`, amd64 + arm64 | none |
| 2 | `make host-deb VERSION=<v> ARCH=amd64` and `ARCH=arm64` (same `RELEASE_PREV_INDEX`), then **[A]** `make release-deb-name VERSION=<v>` (a prerelease: nfpm's `~` name → SemVer; a plain `<v>` needs nothing) | maintainer | tree | `dist/vedette-host_<v>_<arch>.deb` | none |
| 3 | **[B]** `make release-gates VERSION=<v> RELEASE_PREV_INDEX=<prev>` (or `MIN_SEQUENCE=0` for the very first): `make vuln-scan`, `sbom`, `notices-check`, `check-binaries -release`, image version label = `<v>`, `MIN_SEQUENCE` floor (D-401) | maintainer | lists, `.deb`, `<prev>` | `dist/sbom`, `dist/vuln` (RELEASE=1); `dist/release/gates.json` (only when all passed) | none |
| 4 | **`make release-push VERSION=<v>`** | maintainer | the 4 local lists, `gates.json` | ghcr.io: `vedette-{core,sensor,scan,honeypot}` by digest (+ tag `<v>`); `dist/release/images.json` | **ghcr token** (`podman login ghcr.io`, `write:packages`) |
| 5 | **`make release-in RELEASE_CHANNEL=stable RELEASE_ROLLBACK_SAFE=false`** (+ `RELEASE_ROLLBACK_MIN`, `RELEASE_MIN_UPGRADE_FROM` when wanted), then write the notes into `release.in.json` | maintainer | `images.json`, `gates.json`, the two `.deb`, local lists (sizes) | `release.in.json` | none |
| 6 | **[C]** `make release-cosign-plan COSIGN_KEY=…` (sign lines + `cosign attest --type cyclonedx` lines from `images.json`; each SBOM's trivy `ImageID` must be the platform's `config` in `images.json`) | maintainer | `release.in.json`, `images.json`, `dist/sbom` | printed commands | none |
| 7 | run the printed cosign commands | **kien** | | `dist/release/cosign/<service>.{payload.json,sig}`; attestations in ghcr | **cosign key** + `COSIGN_PASSWORD`, ghcr token (attest uploads) |
| 8 | `make release-manifest RELEASE_PREV_INDEX=<prev>` | maintainer | `release.in.json`, cosign files, git at `v<v>`, `<prev>` | `release-manifest.json`, `index.json` (unsigned) | none |
| 9 | `make release-container-assets` | maintainer | git at `v<v>`, `release.in.json` | the four container-only files | none |
| 10 | **[A]** `make release-bake-install MINISIGN_KEY=…` (active; the backup key only for a rescue) | maintainer | `install.sh` at the tag, `release-manifest.json`, the `.deb` | `dist/release/install.sh` (3 baked lines), `install.sh.minisig` with the trusted comment `file:install.sh version:<v>` | **minisign active key** |
| 11 | `make release-sign MINISIGN_KEY=…` (active), then `RELEASE_SLOT=backup` with the offline key | **kien** | `dist/release` | `.minisig` files; `index.json.backup.minisig` | **minisign active**, then **backup** (USB) |
| 12 | `make release-verify RELEASE=1 RELEASE_PREV_INDEX=<prev>` | maintainer | `dist/release` | nothing (kept) | none |
| 13 | **`make release-publish RELEASE_PREV_INDEX=<prev>`** (prints), then the same with **`PUBLISH=1`** (the first release: `FIRST_RELEASE=1` and no `RELEASE_PREV_INDEX`) | **kien** | `dist/release`, `release.in.json`, `<prev>`, the live index, ghcr anonymously | GitHub release `v<v>` and the fixed release `index` | **gh token** (`repo` scope) |
| 14 | archive, before `make clean`: `dist/release/index.json`, `.minisig`, `.backup.minisig` (its SHA-256 noted: the next `<prev>`), `release-manifest.json(.minisig)`, `gates.json`, `images.json`, `release.in.json`, `dist/release/cosign/`; then `make clean` and remove the local lists | kien | | archive | |

The weekly index refresh (D-150) is `release-refresh RELEASE_PREV_INDEX=<prev>` → `release-sign` (+ backup) → `release-verify RELEASE=1
RELEASE_PREV_INDEX=<prev>` → `release-publish RELEASE_PREV_INDEX=<prev> PUBLISH=1`: on an index-only directory publish uploads only the
index, after the same live-index check; then archive the new index as the next `<prev>`.

### What each new step does

**`release-gates`** (D-401; `release gates` after three make targets). Stops at the first failure: VERSION SemVer and not `-test.`, the
tree clean and HEAD = tag `v<v>`; `make vuln-scan` and `make sbom` of the lists tagged `<v>` with `RELEASE=1` (dist/vuln, dist/sbom for
part C); `make notices-check`; `check-binaries -release` on the `vedette-host` read out of each `.deb`; the version label of every platform
of the four lists, and core's `io.github.knt048.vedette.min-sequence` label = the floor; each `.deb` built again with
`make host-deb … MIN_SEQUENCE=<floor>` into a temporary directory and compared byte for byte (the package is reproducible; a stripped
binary does not show its floor). The floor is the verified sequence of `RELEASE_PREV_INDEX` (checked by the Go step too, since an
environment `MIN_SEQUENCE` would win in make), so images and packages must have been
built with that same `<prev>`. `host-deb` pins `GOAMD64=v1` and `GOARM64=v8.0` on its `go build`, so a package built with another CPU
level in the environment (one an older box cannot run) is not rebuilt the same way and is refused.

Only when every check passed does the final run write **`dist/release/gates.json`** (`-out`, atomically, mode 0644): the version, the
floor, per `.deb` arch its file name, SHA-256 and size (of the bytes compared with the rebuild), and per image and platform the
**config digest** (podman's image ID) of the platform image it read. The config digest is the identity the rest of the chain already
uses (push compares it with a list already in the registry, `images.json` records it, part C requires each SBOM's trivy `ImageID` to
equal it); a re-read of the same list gives the same one, any rebuild another (a bit-for-bit identical rebuild is the same image). A
final run removes an earlier `gates.json` first, so a failed run never leaves a previous pass; `-preflight` writes and removes nothing.
Steps 4 and 5 read it strictly (known fields only, both packages and the four images once each) and refuse when it is missing, of
another version, or names other bytes: "run make release-gates again". A `make images` or `make host-deb` between step 3 and steps
4–5 is therefore caught, not shipped.

**`release-push`** (`scripts/release` `push`, podman only). For each of `core`, `sensor`, `scan-base` (published as **`vedette-scan`**:
the manifest, the cosign identity and `vedette.env` all call it `scan`, and the box builds its scan image FROM it, D-147) and `honeypot`:

1. `podman manifest exists` + `inspect` of `localhost/vedette-<image>:<v>`: a manifest list holding exactly the platforms of `PLATFORMS`
   (default linux/amd64 + linux/arm64); `podman images --all --format json` gives each platform image's ID (its config digest), size
   and labels, and every platform must carry `org.opencontainers.image.version=<v>` and have the config digest `gates.json` records
   (`-gates`, default `<out>/gates.json`; a missing record or one of another version is refused). All four lists are read and compared
   before anything is pushed. A rehearsal needs a `gates.json` too.
2. Refuses when a **local** image is named `ghcr.io/knt048/vedette-<service>:<v>`: podman resolves a name in local storage first and
   has no `docker://` form for `manifest inspect` (measured, podman 5.7), so the read-back below would read the local copy.
3. Is `…:<v>` already in the registry (`podman manifest inspect`, with podman's login)? "manifest unknown" → push. Present → read it
   anonymously over the registry API and compare each platform's **config digest** with the local image ID: the same → reused, not
   pushed again (a re-run after a failure); different → refused ("a pushed version is never replaced"); not readable anonymously →
   refused until the package is public or that version deleted. Any other error → refused.
4. `podman manifest push --all --quiet --compression-format=gzip --digestfile <tmp> <local> docker://ghcr.io/knt048/vedette-<service>:<v>`:
   gzip whatever the build machine's `containers.conf` says (every podman and Docker on a box pulls it). The digest podman writes is
   the index digest **as pushed** (layers are compressed on push, so per-platform digests differ from the local ones; measured).
5. `podman manifest inspect ghcr.io/knt048/vedette-<service>@<digest>`: podman refuses a manifest whose bytes do not hash to the
   digest asked for ("Manifest does not match provided manifest digest", measured with podman 5.7 against a fake registry serving
   other bytes), so the list read back is the one boxes will pull; its platforms must again be exactly `PLATFORMS`.
6. `podman manifest inspect …:<v>`: the version tag must name the same per-platform digests. The tag is for people; nothing
   downstream reads it.

Also refused: a registry other than `ghcr.io/knt048` unless it is on 127.0.0.1/[::1]/localhost (a **rehearsal**: TLS verification, the
`-test.` refusal and the git checks are off; Linux only, because podman on macOS runs in a VM whose 127.0.0.1 is not the Mac's); a
non-SemVer or `-test.` version; uncommitted changes to tracked files; HEAD not equal to tag `v<v>`; `CONTAINER=docker` (§4).
The git check proves the **tree** is the tag, not that the images were built from it: untracked files are not looked at, and the images
are only tied to `<v>` by their version label (and B's gates); build them from the tag in the same session.
`images.json` is written only after all four are in the registry and read back:

```json
{"version":"X.Y.Z","images":[{"service":"core","repo":"ghcr.io/knt048/vedette-core","index_digest":"sha256:<64hex>",
  "platforms":[{"platform":"linux/amd64","digest":"sha256:<64hex>","config":"sha256:<64hex>"},{"platform":"linux/arm64",…}]}, …]}
```

Services in order core, sensor, scan, honeypot; platforms sorted; `config` is the config digest of the platform image pushed (the
local image ID, which a push does not change). Part C reads it for `cosign attest` (per-platform SBOMs
`dist/sbom/<image>-<arch>.cdx.json` attach to the platform digests; the local name `scan-base` maps to service `scan`).

**`release-deb-name`** (`deb-name`, part A): renames `<deb-dir>/vedette-host_<debian version>_<arch>.deb` (nfpm turns the first `-`
of a SemVer prerelease into `~`) to `vedette-host_<v>_<arch>.deb` for amd64 and arm64. Nothing to do for a version without a prerelease;
a package already renamed is left; both names present (a rebuild next to a renamed package) or neither is refused.

**`release-bake-install`** (`bake-install`, part A): reads `install.sh` from git at `v<v>` (`RELEASE_REF`), never the working tree, and
`release-manifest.json` (unsigned at this step); hashes the two `.deb` of `release.in.json` again and refuses when they are not the ones
the manifest names. Each of the three lines `VEDETTE_VERSION=""`, `VEDETTE_DEB_SHA256_AMD64=""`, `VEDETTE_DEB_SHA256_ARM64=""` must be
there once, empty, and be the only line that can set its variable (the rule `release-publish` applies, shared code); they become the
manifest's version and package SHA-256s, nothing else changes. Refused: a `-test.` version, a manifest without both packages, a value
outside SemVer / 64 lower-case hex. The pinned minisign signs `dist/release/install.sh` (fixed argv, the passphrase on the terminal or
stdin) with the trusted comment `file:install.sh version:<v>`; the signature is then verified with the release keys (`RELEASE_KEYS`, else
the compiled-in ones) and its comment read back. On any failure neither `install.sh` nor its `.minisig` is left in `dist/release`.

**`release-in`** (`in`): reads `images.json` strictly (four services, each once, repo `ghcr.io/knt048/vedette-<service>`: a rehearsal's
file is refused), and writes `release.in.json`: images (`digest` = index digest, `platforms`, `size` = the largest unpacked size among
the platforms of the local list, used by the box only for its free-space check, D-104), host = the two
`<deb-dir>/vedette-host_<v>_<amd64|arm64>.deb` (checked by the same `buildHostPart` the manifest uses), `install_modes`
`["appliance","container"]` (D-451), `released_at` empty, `content`/`bundled` empty, `sbom` null. It reads `gates.json` (`-gates`,
default next to `-images`) and refuses another version, a `.deb` whose SHA-256 or size is not the recorded one, and a platform config
digest, in `images.json` or in the local lists it takes the sizes from, that is not the recorded one. `channel` and `rollback.safe` must
be given (`stable|beta`, `true|false`); `rollback.min_version` and `min_upgrade_from` only when given. It refuses to overwrite an
existing `release.in.json` (it may hold notes). The result is parsed back with `ParseInputs`, and a test runs it through
`BuildManifest`.

**`release-publish`** (`publish`). Before anything (both modes):

- `VerifyDir` (the box's verifier) on `dist/release`, then every file listed below is recorded once (name → SHA-256, size), `VerifyDir`
  runs again and the files are compared with the record, so the record is of verified bytes. A symlink or non-regular file is refused.
- A `-test.` version is refused.
- **install.sh** must pass `release.VerifyContent`, be signed by the key that signed the manifest, carry the trusted comment exactly
  `file:install.sh version:<v>`, and have each baked line (`VEDETTE_VERSION`, `VEDETTE_DEB_SHA256_AMD64`, `VEDETTE_DEB_SHA256_ARM64`)
  exactly once, equal to the signed manifest's version and package SHA-256s.
- Each `.deb` named in `release.in.json` must have the SHA-256 and size of the **signed** manifest; tag `v<v>` must exist.
- With `PUBLISH=1`: the manifest and index signers must be the keys **compiled into this build** (active; the backup key only for a
  rescue), never test keys. The signer is found by key id in the keys verify used and its **whole** public key compared (an id is 8
  bytes anyone can copy), and every cosign key verify used must be a compiled-in one. `-keys-dir` changes what verify reasons with (a
  rescue checks against the keys installed boxes trust), never which signer may be published.
- install.sh is recorded from the very bytes `checkInstaller` verified; any line that can set a baked variable (indented,
  `export`/`readonly`/`local`, `+=`, `${X=…}`/`${X:=…}`, after another command, a BOM or CR) must be exactly the baked line, and a
  manifest without both packages is refused (an empty checksum would be baked).

Default: prints the commands (the notes go to `dist/release/release-notes.md`). `PUBLISH=1` runs:

1. The **live index**: the release `index` must exist and be published. If it has `index.json`, it is downloaded and verified. When it
   is byte-identical (with its `.minisig`) to this run's own index, an earlier run already uploaded it: the steps below only check
   (nothing is uploaded). Otherwise it must be byte-identical to `RELEASE_PREV_INDEX`, which is then mandatory; with no live index only
   `FIRST_RELEASE=1` without `RELEASE_PREV_INDEX` proceeds. Either way a release built on a stale index is refused before anything is
   uploaded; a live index that does not verify points at row "publish 7" of §2.
2. `gh release view v<v>`; if absent `gh release create v<v> --verify-tag --draft --title "Vedette <v>" --notes-file <temp file with the
   manifest notes>` (`--prerelease` for channel beta or a SemVer prerelease). `--verify-tag` aborts when the tag is not on GitHub.
3. Files re-hashed against the record, then `gh release upload v<v> --clobber` of: `release-manifest.json(.minisig)`, `install.sh(.minisig)`,
   `compose.yaml`, `compose.sensors.yaml`, `compose.syslog.yaml`, `vedette.env` (each `.minisig`), `vedette-host_<v>_amd64.deb`,
   `vedette-host_<v>_arm64.deb`.
4. Read back (`gh release view --json assets`): every asset `uploaded`, the recorded size and `sha256:` digest; when GitHub reports no
   digest the asset is downloaded and hashed; an asset that is not part of the release is refused (remove it with
   `gh release delete-asset v<v> <name>`).
5. **Anonymous pull**: for every image of the manifest, `GET https://ghcr.io/token?scope=repository:knt048/vedette-<service>:pull` then
   `HEAD /v2/knt048/vedette-<service>/manifests/<digest>` with the OCI index and Docker list Accept types, as a box does. Denied →
   "make the package public"; the release stays a draft.
6. `gh release edit v<v> --draft=false`, read back: published.
7. **Last:** anonymous pull checked again, the live index read again (it must not have moved since step 1), the index files re-hashed,
   then `gh release upload index --clobber index.json index.json.minisig` (+ any `index.v<N>.json` pair, D-108), read back.

`index.json.backup.minisig`, `gates.json`, `images.json`, `release.in.json` and the cosign files are not uploaded (the box never fetches them); kien
keeps them in the archive of step 14.

## 2. Why this order: a half-published release

The boxes and `install.sh` read only two places: the fixed release `index` (`…/releases/download/index/index.json` + `.minisig`, D-341)
and, from the version it announces, `…/releases/download/v<v>/{release-manifest.json,.minisig,install.sh,vedette-host_<v>_<arch>.deb,…}`.
Images are pulled by digest from ghcr, anonymously. So:

- **Images before documents.** A manifest names digests that are already in the registry and readable (step 4 before step 8), and
  publish proves them pullable anonymously before `v<v>` and the index go public.
- **The version release is a draft until every asset is there and checked.** Draft assets are not public, so a box or customer
  following `v<v>` either sees nothing (404, retried later) or all of it. This is what `gh release create` itself does when given
  assets, and what GitHub's immutable-release guidance prescribes (draft, attach, publish).
- **The index goes up last**, after `v<v>` is published and read back, and only onto the index it was built on: no box is ever told
  about a release whose files are missing, and a concurrent publish is not overwritten.
- **A published version is never changed.** A re-run compares a published `v<v>` with the record and only proceeds to the index when
  they match; any difference stops with "release the next version". In ghcr, a version tag that already exists is reused only when its
  images are the local ones (same config digests); other images under that tag are refused.

Failure at each point and what to do:

| Fails at | State | Recovery |
|---|---|---|
| push (4) | some images in ghcr, nothing references them | fix, run `release-push` again: images already there with the same content are reused, the rest pushed (if a re-run is refused because the package is private, make it public first, §3). Different content under `<v>` is refused: delete that package version by hand only if `<v>` was never published, else release `<v+1>` |
| 5–12 | nothing public references anything | fix and re-run the step |
| publish 2–5 | a draft `v<v>`, maybe partial | `release-publish PUBLISH=1` again: the draft is filled (`--clobber`) and checked |
| publish 6 | `v<v>` published, index old | run again: published assets are compared, then the index goes up. Boxes still see the previous release: correct |
| publish 7 | index half replaced (`--clobber` deletes then uploads; a box may fetch the new `index.json` with the old signature) | boxes fail closed (signature check), keep their stored index and retry later; fix at once by hand ("Row publish 7, by hand" below) |
| a bad release found after publishing | | never delete or edit `v<v>`: publish `v<v+1>`, and revoke `<v>` through the index (`revoked[]` kind `release`, D-108) |

The two `--clobber` windows (index file and signature are two uploads, GitHub has no atomic replace) are a known limit: the box treats
a mismatched pair as a failed check and keeps what it has (D-104, D-341), so the window costs a delay, never a wrong update.

**Row "publish 7", by hand.** A run stopped during the index upload leaves `index.json` and `index.json.minisig` of two different
indexes on the release `index`; `release-publish` then refuses (the live index does not verify, or is neither this run's nor
`-prev-index`). Download both (`gh release download index --repo KNT048/vedette -p 'index.json*' -D /tmp/live`), check that each file is
byte-identical either to `dist/release/` (this run) or to `<prev>` (nothing else may be there), then upload this run's pair with the
printed `gh release upload index … --clobber` command and run `release-publish PUBLISH=1` once more: it finds its own index live and
only checks the assets. A live index that is neither: stop, someone else published.

**A rescue (D-258, D-259) is published by hand.** When the leaked active key's holder has replaced the live index, it is neither the
rescue's own index nor `-prev-index` (kien's archived copy, RELEASE_KEYS.md "Bản cứu" step 3), so `PUBLISH=1` refuses before uploading
anything, by design. Path: verify the live index with the old keys and confirm it is not one kien published (signed by the leaked key,
not in the archive); run `release-publish` without `PUBLISH` to print the commands; run them one by one, checking after the upload
that every asset of `v<v>` has the SHA-256 of `dist/release/` (`gh release view v<v> --json assets`); upload the rescue index last.
`-keys-dir` is the old keys for verify; the signers must still be the compiled-in production keys (the backup key for a rescue).

## 3. One-time manual steps for kien

1. A GitHub token for `gh` with `repo` scope; a ghcr token (classic PAT `write:packages`, or `gh auth token` with that scope) for
   `podman login ghcr.io -u kiennt048`. Neither goes into the repo or argv; podman and gh keep them.
2. Create the fixed release `index` once (it creates the lightweight tag `index`, which only kien may do):
   `gh release create index --repo KNT048/vedette --title "Update index" --notes "Signed update index (D-150). Do not delete." --latest=false`.
   The first `release-publish PUBLISH=1 FIRST_RELEASE=1` uploads the first `index.json` + `.minisig`; `release-publish` refuses until the
   release exists.
3. **After the first push, make the four ghcr packages public** (GitHub → Packages → `vedette-core`, `-sensor`, `-scan`, `-honeypot` →
   Package settings → Change visibility → Public) and link them to the repository. New packages are private; boxes pull anonymously,
   and `release-publish` refuses until they are pullable that way.
4. Leave GitHub **immutable releases off** for this repository: they would also lock the fixed release `index`, which must be replaced
   every week (D-150). The tool keeps version releases unchanged instead (§2).
5. `release-bake-install` (part A) signs `install.sh.minisig` with the trusted comment exactly `file:install.sh version:<v>`: give it
   the key that signs the manifest in step 11 (`MINISIGN_KEY`, the active key; the backup key only for a rescue).

## 4. Not done here / open

- `CONTAINER=docker`: `make images` writes OCI archives under `dist/images/` (not run yet, `.ai/deferred/feat-multiarch-images.md`);
  pushing those needs `skopeo copy --all oci-archive:` or `regctl`, a new dependency. `release-push` refuses docker until someone needs it.
- Prerelease `.deb` names: nfpm writes `~` for a SemVer prerelease (`1.0.0~beta.1`); `release-in` needs the SemVer spelling, so for a
  prerelease the rename (part A) must happen **before** step 5, not after. A plain `1.0.0` needs no rename. Done by
  `make release-deb-name` in step 2; `release-in` still refuses a `~` name.
- `sbom` of the manifest stays null; the SBOMs travel as cosign attestations (part C). `bundled` (nuclei, OpenCanary versions for the
  Managed packages view) stays empty; filling it from `pins.env` is a follow-up if the GUI should show it for v1.
- Release notes: written by hand into `release.in.json` after step 5 (they are signed in the manifest and reused as the GitHub notes).
- Only a loopback registry, a fake registry (`httptest`) and fakes of `gh` were used: the first real ghcr push and publish are kien's
  (`.ai/deferred/feat-release-push.md`).
