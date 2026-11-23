# Khoá ký phát hành

Three keys sign everything a Vedette box trusts when it updates. The public half is embedded in the binary (`internal/release/keys.go`); the private half lives only where the maintainer keeps it, never in the repository, on a box, in a log or in a PR.

| Key | ID | Signs what | Private file | Password (Keychain, service) |
|---|---|---|---|---|
| minisign **in use** | `7B78764E550D48D0` | `index.json` and every `release-manifest.json` | `~/.vedette-release-keys/minisign.key` | `vedette-release-minisign` |
| minisign **backup** (offline) | `8DD38917AD864FAE` | the index that revokes a key, and a rescue release after the key in use leaks; does not sign ordinary releases | `~/.vedette-release-keys/minisign-backup.key` | `vedette-release-minisign-backup` |
| cosign (ECDSA P-256) | SHA-256 PKIX `CosignKeyID` | images (the old format) | `~/.vedette-release-keys/cosign.key` | `vedette-release-cosign` |

The account of a Keychain entry is the maintainer's macOS user name (`$USER`). Each entry **trusts no application** (`-T ""`): every read, by any program, shows a macOS dialog that needs the login password, so a process running under that account (a script, a package installer) cannot get the password silently. Click **Allow**, never **Always Allow** (it adds that program to the trust list). The public half sits next to it (`*.pub`, exactly the names that `RELEASE_KEYS` reads); if `RELEASE_KEYS` is not set, `scripts/release` uses the compiled-in keys, which are these same three keys.

## Key generation ceremony (2026-11-11)

`scripts/release/keygen.sh` on the maintainer's Mac (macOS only because the password goes into Keychain):

0. Try once first: `security dump-keychain -a ~/Library/Keychains/login.keychain-db > /dev/null` must exit 0 (it only reads the access list, with no password). The script uses this command to check that the entry just created trusts no application; if this command fails the script stops.
1. Check that `minisign` in PATH is the version in `deploy/tools.env` (0.12; on macOS the Homebrew build, only the version is checked, the hash is not pinned: the pinned binary of `minisign.sh` exists only for Linux) and fetch cosign v2.6.5 pinned by SHA-256 with `scripts/release/cosign.sh`.
2. Refuse if a key file or a Keychain entry of the same name already exists (a key is never overwritten).
3. For each key: a random 256-bit password (`openssl rand -hex 32`) into a shell variable, written straight into Keychain through `security -i` reading from stdin (not in argv, shell history or a file, not printed), the entry trusting no application; create the key, encrypt it with that password (minisign: scrypt; cosign: scrypt + secretbox; cosign takes the password through `COSIGN_PASSWORD`, which a process of the same account can see while cosign runs); the folder `0700`, the file `0600`.
4. Self-check: read the password back from Keychain (one dialog per key), compare it with what was just written, then each key signs a throwaway file and the signature is checked with the public half (proving that the Keychain entry, the private key and the public key are one set); the throwaway file is deleted.
5. Only the public half is printed. If it breaks midway the script says which files and Keychain entries are left, which must be deleted before running again.

The three real keys were created with the first version of the script (the Keychain entries then trusted the `security` tool); after a review the same day, the three entries were created again with the same passwords and `-T ""` (the application list of the `decrypt` permission is empty, checked with `security dump-keychain -a`).

After that each key signs `internal/release/testdata/prod/proof.txt` (proof of possession, not a release document). `TestProductionKeysProofOfPossession` checks those three signatures with the embedded constants, so a constant altered by one character or pasted into the wrong cell goes red on CI and not at the first release.

## Signing a release

Before signing:

- [ ] The maintainer tags `v<v>` **first**, and only then builds the images and the `.deb` from a clean clone at exactly that tag: a `.deb` built before the tag carries a different commit and version, `release-gates` rebuilds at the tag and refuses (the v0.1.0-beta.1 release had to rebuild the `.deb`).
- [ ] `podman login ghcr.io` (a `write:packages` token); `gh auth refresh -s read:packages` so `gh` can list packages.
- [ ] The KNT048 organisation allows Public packages (Settings → Packages); after the first `release-push`, the four packages `vedette-core`, `-sensor`, `-scan`, `-honeypot` are set to Public and linked to the repo.

The password is never an argument; each command below shows one Keychain dialog:

```bash
security find-generic-password -s vedette-release-minisign -a "$USER" -w | make release-sign MINISIGN_KEY=$HOME/.vedette-release-keys/minisign.key MINISIGN_BIN=$(command -v minisign) PASSPHRASE_STDIN=1
```

```bash
make -s release-cosign-plan COSIGN_KEY=$HOME/.vedette-release-keys/cosign.key > dist/cosign-plan.sh && less dist/cosign-plan.sh   # prints the commands only (cosign pinned); read them again
COSIGN_PASSWORD=$(security find-generic-password -s vedette-release-cosign -a "$USER" -w) scripts/release/cosign-auth.sh sh -eu dist/cosign-plan.sh
```

The plan starts with a `cd` to the repo root, then `cosign sign` for each image (writing `dist/release/cosign/<service>.{payload.json,sig}` for `release-manifest`), then `cosign attest --type cyclonedx` for each per-architecture SBOM (`dist/sbom` of `make sbom RELEASE=1 IMAGE_TAG=<v>`), uploaded to ghcr next to the digest of that architecture. Each SBOM must be the SBOM of exactly the image that was pushed: trivy's `aquasecurity:trivy:ImageID` must equal the config digest that `release-push` recorded for that architecture in `images.json` (if the image is rebuilt after pushing, the new SBOM is refused). cosign needs the ghcr login and reads it like Docker (`$DOCKER_CONFIG/config.json`, then `~/.docker/config.json`; only when both are missing does it read podman's `auth.json`), so a `~/.docker/config.json` with no ghcr hides `podman login ghcr.io`: `scripts/release/cosign-auth.sh` points `DOCKER_CONFIG` at a temporary folder (0700) whose `config.json` is a link to podman's `auth.json` (`$REGISTRY_AUTH_FILE`, or `~/.config/containers/auth.json` on macOS), runs the plan, then deletes the folder; it copies and prints no credentials. Re-running after a failure: `--replace` replaces the old CycloneDX attestation of the same digest (not measured on ghcr) (part C).

The backup key is taken out only when the revocation index must be signed (`RELEASE_SLOT=backup`) or for a rescue release.

## What the maintainer must do (once, **now**)

1. Copy `~/.vedette-release-keys/` (three encrypted `.key` files and three `.pub`) to **two different offline places**, for example two USB sticks stored in two places.
2. Copy the **three passwords** from Keychain (Keychain Access → search `vedette-release` → Show password, or `security find-generic-password -s vedette-release-<name> -a "$USER" -w` in your own terminal) onto **paper**, stored apart from the USB sticks. An encrypted key without its password is useless; a password without the key file is useless too; with the two kept apart, losing one place does not expose the key.
3. **The backup key leaves the Mac at once** after the two offline copies exist: delete `minisign-backup.key` and the Keychain entry `vedette-release-minisign-backup` (`security delete-generic-password -s vedette-release-minisign-backup -a "$USER"`). The point of the backup key is that an attacker who takes over the machine does not have it; and since it alone can sign the index and manifest that a box accepts, leaving it on the Mac puts both keys in one place. The key in use and the cosign key may stay on the Mac for releasing; optionally delete them too and plug in the USB stick only when releasing.
4. Re-check one copy by signing a test file from the USB stick (`minisign -S -s <usb>/minisign.key -m <file>` then `minisign -Vm <file> -p <usb>/minisign.pub`).
5. **Time Machine**: it backs up both `~/.vedette-release-keys` and `login.keychain-db`, so whoever has the backup disk needs only the maintainer's login password in addition. Either exclude the key folder from Time Machine (`tmutil addexclusion ~/.vedette-release-keys`; the two USB sticks are already copies), or use only an encrypted Time Machine disk.

The key folder sits in the home folder, outside iCloud Drive.

## Key rotation and revocation

- **The key in use leaks or is lost:** installed boxes trust only the two embedded keys, so a rescue release must go through the **backup** key. The steps are in "Rescue release" just below.
- **The cosign key leaks:** revoke `kind=key` by `CosignKeyID` in an index signed by the backup key, and release a binary with the new cosign key. The verifier accepts 1-2 cosign keys (`Trust.Cosign`), but `Embedded()` today is built from a single constant `prodCosign`: embedding two keys during a transition needs a code change.
- **The backup key leaks:** as serious as both leaking: it alone can sign the index and manifest a box accepts, and can permanently revoke the key in use. No index can revoke the backup key (by design). Response: at once release, with the key in use, a binary with a new backup key, before the holder of the key can revoke the key in use; a box that has already accepted that person's revocation index can be rescued only by reinstalling. Both minisign keys leaking together is a recorded limit (update-manifest §13 (b)).
- Losing the password or every copy of the key in use while the backup key remains: treat as "leaked" above. Losing both minisign keys: installed boxes accept no more updates; users must reinstall with a new `install.sh`.

## Rescue release after the key in use leaks

**Where the box looks for the signature.** The box receives **one** signature per document, in exactly the same place as for every release: `index.json.minisig` and `release-manifest.json.minisig` (`container.pull` has `index_sig`/`manifest_sig`; the first install uses `-index-sig`/`-manifest-sig`). The box's verifier accepts a signature of **any** of the two embedded keys. So a rescue release publishes the **backup** key's signature in those very two files, and publishes no signature of the key in use (the box would refuse it because that key has been revoked). The box-side code does not change a line. `<file>.backup.minisig` (`-slot backup`) is still only an extra signature for `verify` to check; the box never downloads it.

**Steps** (the maintainer's machine, the backup key taken from the USB stick):

1. Keep a folder with the three **old** public halves (`minisign.pub` is the key that just leaked, `minisign-backup.pub`, `cosign.pub`): this is what installed boxes trust. Every command below runs with `-keys-dir` pointing there, because the compiled-in key in the rescue release is already the new key.
2. Create a new key in use: move the old pair into `retired/`, `scripts/release/keygen.sh minisign`. Change `prodMinisignActive`, move the old line into `prodMinisignRetired`, write the new key, merge, build the images and the `.deb` of the rescue release.
3. **The base index is the maintainer's own saved copy**, not downloaded again from GitHub: the holder of the leaked key may have published an index of their own, and everything in `-prev-index` (channels, advisories, revocations, `keys`) goes into the index the backup key is about to sign. Use the copy of the last index you published (compare its SHA-256 with the one recorded when it was published), and re-read the carried-over part before signing.
4. `release manifest` like every release (`-prev-index` is that saved copy, `-keys-dir` the old one).
5. `release index … -prev-index <saved copy> -keys-dir <old keys> -revoke-key <ID of the leaked key> -revoke-reason "<reason>"`: adds a `kind=key` revocation row (`-revoke-key` does not run without `-prev-index`: an index with no base would lose the existing channels, advisories and revocations). A key revocation is kept forever; a box accepts it only when the index is signed by the backup key, and then `sequence` is allowed to be lower than the index the holder of the leaked key may have given the box.
6. `release sign -slot rescue -key <usb>/minisign-backup.key -prev-index <saved copy> -keys-dir <old keys> …` (or `make release-sign RELEASE_SLOT=rescue RELEASE_PREV_INDEX=… RELEASE_KEYS=…`): the backup key signs `index.json` (with every `index.v<N>.json`) **and** `release-manifest.json` into `<file>.minisig`. The tool refuses when the manifest is missing, when the folder already has a signature from another run, when the index does not revoke the key in use of the old key set, or when the base index has already revoked that key (each leaked key gets only one rescue). After signing it runs `verify`; if the result is not `RESCUE` (for example signed by mistake with another key) it deletes all the signatures of that run.
7. `release verify -dir … -prev-index <saved copy> -keys-dir <old keys>`: runs exactly the box's verifier, the result line says `RESCUE`. A manifest signed by the backup key passes only when the index is also signed by the backup key, revokes the key in use of the checked key set, and the base index has not revoked it yet. Checking with the new compiled-in key is refused.
8. **Container-only customers**: the four files `vedette.env`, `compose*.yaml` of the old rescue release are also signed by the backup key, and customers who have only `vedette.pub` (the key that just leaked) will see `FAILED`. The release notes and the GitHub release page must say "rescue release" and tell them to verify with `vedette-backup.pub` (the public half of the backup key, `8DD38917AD864FAE`, from the repository: `docs/INSTALL-CONTAINER.md` §1 already preserves it, §5 says how to use it). `cosign.pub` does not change unless the cosign key itself leaks.
9. Publish, then put the backup key back offline. The next ordinary release uses the new key, `-prev-index` is the rescue release's index, the new compiled-in key; revoking the old key carries on in every later index.

**The rescue window.** A box downloads the current `index.json`. A box that still has the old binary can read only an index signed by the backup key; the next index (the weekly refresh, or an ordinary release) signed by the new key is refused by an old box, which then cannot reach the rescue manifest. So any box that has not received the rescue release (powered off, a network error) before the next index must reinstall with a new `install.sh`. To make the window longest: the rescue index `-valid-days 14`, and publish no other index for 14 days unless there is an urgent fix (an expired index only warns, so an old box still accepts the rescue index afterwards). Not chosen: having the backup key also sign the refreshes for a while (the offline key would have to come out many times).

The rule "the backup key signs only the rescue release" lives in the tool (`sign`, `verify`), not in the box: the box accepts a manifest signed by the backup key because that key is never revoked. That is why it must be offline.

Source: `docs/specs/update-manifest.md` §5, §8, §13.
