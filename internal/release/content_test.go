package release_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

func TestVerifyContent(t *testing.T) {
	active, backup, other := releasetest.NewMinisign(t), releasetest.NewMinisign(t), releasetest.NewMinisign(t)
	cs := releasetest.NewCosign(t)
	trust, err := release.NewTrust(active.PubLine(), backup.PubLine(), cs.PubPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("vedette mitigation packs v1\nversion 1\n")
	for name, sig := range map[string][]byte{"active": active.Sign(msg), "backup": backup.Sign(msg)} {
		if err := release.VerifyContent(msg, sig, trust); err != nil {
			t.Errorf("%s key: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		msg, sig []byte
		want     error
	}{
		"other key":    {msg, other.Sign(msg), release.ErrBadSignature},
		"changed text": {append(append([]byte{}, msg...), 'x'), active.Sign(msg), release.ErrBadSignature},
		"no signature": {msg, nil, release.ErrBadSignature},
		"huge message": {[]byte(strings.Repeat("a", release.MaxDocBytes+1)), active.Sign(msg), release.ErrTooLarge},
		"huge sig":     {msg, make([]byte, release.MaxSigBytes+1), release.ErrTooLarge},
	} {
		if err := release.VerifyContent(c.msg, c.sig, trust); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	if err := release.VerifyContent(msg, active.Sign(msg), release.Trust{}); !errors.Is(err, release.ErrNoTrustKeys) {
		t.Errorf("no keys: %v", err)
	}
}
