package release

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"testing"
)

// logger carries the one message that says why a build refuses everything.
var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

// The real release public keys, in the form minisign and cosign print them: compile-time constants of
// a production build, made by the key ceremony of 2026-11-11 (D-256, scripts/release/keygen.sh). The
// private halves are encrypted, outside the repo and every box, with the maintainer (docs/RELEASE_KEYS.md).
// A constant left empty makes Embedded refuse everything (fail closed). Rotating a key changes its
// constant here and moves the old minisign line to prodMinisignRetired (D-130). Never put a private key
// or a test key here (TestProductionConstantsAreNotTestKeys).
const (
	// minisign public key 7B78764E550D48D0, the active key: signs index.json and every release manifest
	prodMinisignActive = "RWTQSA1VTnZ4e4eM2iBmUKE1/t5l9pmrScK2+wR/EohjSfFEZQ8VwT/m"
	// minisign public key 8DD38917AD864FAE, the offline backup key: signs the index that revokes a key (D-108) and the rescue release after one (D-258)
	prodMinisignBackup = "RWSuT4atF4nTjejJTNkQcFCkxroGAm0jmVNBd0gvgVoNNpP3n1mSe//r"
	// cosign key (ECDSA P-256), signs the images (legacy format, D-103)
	prodCosign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm91vgScv6zgXXBX6iJP5qaqydWIx
KTprVWOY3EIHh6AAysr2ncwvWLztYFqP1hoFK19WWSnT+svtyjSBL+2HZA==
-----END PUBLIC KEY-----
`
)

// prodMinisignRetired lists the minisign public keys that signed in the past and no longer do ("RWQ…"
// lines). They only re-verify the stored index (Trust.Retired). Empty until the first key rotation.
var prodMinisignRetired []string

// MinSequenceText is the minimum index sequence of this build, a decimal number. The release job sets it
// with -ldflags "-X github.com/knt048/vedette/internal/release.MinSequenceText=<n>" (a linker can only
// set strings) to the sequence of the index current at build time; the default 0 sets no floor.
var MinSequenceText = "0"

func parseMinSequence(s string) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("MinSequenceText is not a plain decimal number")
	}
	return n, nil
}

var logOnce sync.Once

// syncOnce is for tests that want the "why" log line again.
func syncOnce() sync.Once { return sync.Once{} }

// Embedded returns the keys compiled into this build. With no real keys (and no test keys) it
// returns ErrNoTrustKeys and logs why, once.
func Embedded() (Trust, error) { return embeddedTrust(testing.Testing()) }

// embeddedTrust is Embedded with the "inside a test binary" fact passed in, so a test can prove
// that test-only keys are refused everywhere else.
func embeddedTrust(inTest bool) (Trust, error) {
	active, backup, cosign, testOnly := embeddedKeys()
	t, err := parseTrust(active, backup, cosign)
	if err == nil && testOnly && !inTest {
		err = errors.New("test-only keys outside a test binary")
	}
	if err == nil {
		for _, k := range prodMinisignRetired {
			rk, kerr := ParseMinisignPublicKey(k)
			if kerr != nil {
				err = kerr
				break
			}
			t.Retired = append(t.Retired, rk)
		}
	}
	if err == nil {
		t.MinSequence, err = parseMinSequence(MinSequenceText)
	}
	if err == nil {
		err = t.validate()
	}
	if err != nil {
		logOnce.Do(func() {
			logger.Error( //nolint:sloglint // the one package logger is swapped by the test; there is no caller to pass one
				"release: no usable trusted keys are embedded in this build; every update check, pull and start will be refused until a build with the real release keys is installed", "reason", err.Error())
		})
		return Trust{}, wrap(ErrNoTrustKeys, "%v", err)
	}
	t.TestOnly = testOnly
	return t, nil
}
