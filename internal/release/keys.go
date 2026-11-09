package release

import (
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
)

// logger carries the one message that says why a build refuses everything.
var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

// The real public keys, in the form minisign and cosign print them. They are compile-time constants
// of a production build; until kien makes the offline keys they are empty, and then Embedded
// refuses (fail closed). Replacing them is the only change needed to go live
// (.ai/deferred/feat-host-net-containers.md). Never put a private key or a test key here.
const (
	prodMinisignActive = "" // "RWQ…" line of the active key's .pub
	prodMinisignBackup = "" // "RWQ…" line of the offline backup key's .pub
	prodCosign         = "" // PEM "PUBLIC KEY" of the cosign key (ECDSA P-256)
)

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
