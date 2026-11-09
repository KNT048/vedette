//go:build !releasetestkeys

package release

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
)

// A production build (no releasetestkeys tag) embeds no real key yet: it must refuse everything,
// say why, and never hold a test key.
func TestProductionBuildFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	old := logger
	logger = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { logger = old })
	logOnce = syncOnce() // log again in this test

	tr, err := Embedded()
	if !errors.Is(err, ErrNoTrustKeys) {
		t.Fatalf("Embedded() = %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("no usable trusted keys")) {
		t.Fatalf("not logged: %q", buf.String())
	}
	if tr.TestOnly || len(tr.Cosign) != 0 {
		t.Fatalf("%+v", tr)
	}
	// With the zero Trust Embedded hands back, every entry point refuses, even for correctly signed data.
	e := newEnv(t)
	raw, sig := e.signedIndex(e.active, e.indexMap(1))
	if _, err := VerifyIndex(raw, sig, tr, nil); !errors.Is(err, ErrNoTrustKeys) {
		t.Errorf("VerifyIndex: %v", err)
	}
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mraw := js(t, e.manifestMap())
	if _, err := VerifyManifest(mraw, e.active.sign(mraw), tr, idx); !errors.Is(err, ErrNoTrustKeys) {
		t.Errorf("VerifyManifest: %v", err)
	}
	mf := e.verifiedManifest(e.manifestMap(), idx)
	if err := VerifyImage(mf, "core", digestCore, tr); !errors.Is(err, ErrNoTrustKeys) {
		t.Errorf("VerifyImage: %v", err)
	}
}

// The production constants must never be the test keys (the test keys live only under testdata and
// in keys_testonly.go, which is not compiled into a production build).
func TestProductionConstantsAreNotTestKeys(t *testing.T) {
	for _, c := range []struct{ name, prod, file string }{
		{"active", prodMinisignActive, "minisign/test.pub"},
		{"backup", prodMinisignBackup, "minisign/backup.pub"},
		{"cosign", prodCosign, "cosign/cosign.pub"},
	} {
		if c.prod != "" && bytes.Contains(td(t, c.file), []byte(c.prod)) {
			t.Errorf("%s constant is a test key", c.name)
		}
	}
	if a, b, c, testOnly := embeddedKeys(); testOnly || a != prodMinisignActive || b != prodMinisignBackup || c != prodCosign {
		t.Error("production build embeds something else")
	}
}
