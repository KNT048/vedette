//go:build releasetestkeys

package release

import (
	"bytes"
	"errors"
	"testing"
)

// With -tags releasetestkeys the embedded keys are the throwaway testdata keys, flagged TestOnly.
func TestTestKeysBuild(t *testing.T) {
	tr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if !tr.TestOnly {
		t.Fatal("test keys must be flagged TestOnly")
	}
	want := tdTrust(t)
	if tr.Active.ID != want.Active.ID || tr.Backup.ID != want.Backup.ID || CosignKeyID(tr.Cosign[0]) != CosignKeyID(want.Cosign[0]) {
		t.Fatal("embedded test keys differ from testdata")
	}
	if !bytes.Contains(td(t, "minisign/test.pub"), []byte(testMinisignActive)) {
		t.Fatal("constant is not testdata's key")
	}
	// and the real vectors verify against the embedded trust
	idx, err := VerifyIndex(td(t, "release/index.json"), td(t, "release/index.json.minisig"), tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := VerifyManifest(td(t, "release/release-manifest.json"), td(t, "release/release-manifest.json.minisig"), tr, idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyImage(mf, "core", mf.Images[0].Digest, tr); err != nil {
		t.Fatal(err)
	}
}

// Test-only keys are refused unless the binary is a test binary (Embedded passes testing.Testing()).
func TestTestKeysRefusedOutsideTests(t *testing.T) {
	if _, err := embeddedTrust(false); !errors.Is(err, ErrNoTrustKeys) {
		t.Fatalf("test-only keys accepted outside a test binary: %v", err)
	}
	if _, err := embeddedTrust(true); err != nil {
		t.Fatal(err)
	}
}
