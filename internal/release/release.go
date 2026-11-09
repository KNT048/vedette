// Package release verifies what the box downloads before it acts on it: the release index, the
// release manifest, and the cosign signature of each container image. It is pure (no files, no
// network, no clock: callers pass bytes and, where it matters, the time) and is shared by
// vedette-host, which verifies again on its own and does not trust core, and by core, which
// verifies to show the result (docs/specs/update-manifest.md §5, D-103, D-104).
//
// # Trust model
//
// The root of trust is a set of public keys compiled into the binary (Embedded). Nothing the
// network delivers can add, replace or widen it; the keys listed in index.json are informational.
//
//   - index.json and release-manifest.json carry a detached minisign signature (prehashed "ED"
//     only; the legacy "Ed" is refused; the global signature over signature || trusted comment is
//     checked). Two minisign keys are embedded: the active key, and an offline backup key that
//     exists so a leaked active key can be revoked without trusting the leaked key.
//   - Each image in the manifest carries a cosign simple-signing payload and an ECDSA P-256 over
//     SHA-256 signature (the legacy cosign format, verified offline; no Rekor). The signature travels
//     inside the minisign-signed manifest, so image trust is exactly manifest trust plus a second,
//     separate key. The payload's critical.image.docker-manifest-digest must equal images[].digest.
//   - Revocation lives in the newest index the box has accepted (the "stored" index). A revoked
//     signing key, release version or image digest is refused. Authority rules: an index may
//     revoke an embedded key only when the backup key signed it, and never the backup key itself;
//     revocations of embedded keys are sticky (carried into every later index), so a later index
//     cannot quietly un-revoke a leaked key. The sequence number never goes back (equal is fine).
//   - JSON is decoded strictly (internal/jsonstrict): unknown fields, repeated keys and keys that
//     differ only by case are refused, sizes are capped, and every schema check fails closed.
//
// A binary built without real keys has none embedded: Embedded returns ErrNoTrustKeys and every
// verification that uses it refuses. Test-only keys exist only in builds made with the
// releasetestkeys tag, and Trust.TestOnly says so.
package release

import (
	"errors"
	"fmt"
)

// Limits (update-manifest.md §12, SYS-6).
const (
	MaxDocBytes      = 256 << 10 // index.json and release-manifest.json
	MaxSigBytes      = 2 << 10   // a .minisig
	MaxImages        = 16
	maxCosignPayload = 4 << 10
	maxCosignSig     = 96 // a P-256 DER signature is at most 72 bytes
)

// Errors. Callers test with errors.Is; the host maps them to the codes of host-api.md §11.
var (
	ErrNoTrustKeys         = errors.New("release: no trusted keys embedded in this build") // every check refuses
	ErrTooLarge            = errors.New("release: input too large")
	ErrBadSignature        = errors.New("release: bad signature")        // signature_invalid
	ErrMalformed           = errors.New("release: malformed document")   // invalid_args or signature_invalid
	ErrUnknownSchema       = errors.New("release: unknown schema")       // "update the box through a bundle or reinstall"
	ErrIndexRequired       = errors.New("release: an index is required") // pull without an index
	ErrKeyNotAuthorised    = errors.New("release: index may not revoke that key")
	ErrSequenceRegress     = errors.New("release: index sequence went backwards")                  // sequence_regress
	ErrDowngrade           = errors.New("release: version is lower than the running one")          // downgrade_not_allowed
	ErrUpgradePath         = errors.New("release: running version is below min_upgrade_from")      // upgrade_path_required
	ErrRollbackNotAllowed  = errors.New("release: previous version is below rollback.min_version") // rollback_not_allowed
	ErrPlatform            = errors.New("release: no image for this platform")                     // platform_mismatch
	ErrInstallMode         = errors.New("release: install mode not supported by this release")
	ErrRegistryNotAllowed  = errors.New("release: image ref is not the fixed registry ref") // registry_not_allowed
	ErrDigestNotInManifest = errors.New("release: digest is not in the manifest")           // digest_not_in_manifest
	ErrManifestHash        = errors.New("release: manifest sha256 differs from the index")

	// ErrRevoked is matched by errors.Is for both of the following.
	ErrRevoked        = errors.New("release: revoked")
	ErrKeyRevoked     = &revokedError{"release: signing key revoked"}                     // key_revoked
	ErrReleaseRevoked = &revokedError{"release: release version or image digest revoked"} // release_revoked
)

type revokedError struct{ msg string }

func (e *revokedError) Error() string        { return e.msg }
func (e *revokedError) Is(target error) bool { return target == ErrRevoked }

// wrap adds a short detail to a sentinel. Details never carry more than a clipped piece of input.
func wrap(base error, format string, a ...any) error {
	return fmt.Errorf("%w: %s", base, fmt.Sprintf(format, a...))
}

// clip cuts attacker-supplied text so an error message stays small and printable.
func clip(s string) string {
	const n = 48
	out := make([]rune, 0, n)
	for _, r := range s {
		if len(out) == n {
			return string(out) + "..."
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		out = append(out, r)
	}
	return string(out)
}
