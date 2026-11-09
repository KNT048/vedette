package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

// The committed vectors end to end: index and manifest signed by the real minisign tool, image
// signatures in the cosign legacy format.
func TestRealVectorsEndToEnd(t *testing.T) {
	tr := tdTrust(t)
	iraw, isig := td(t, "release/index.json"), td(t, "release/index.json.minisig")
	idx, err := VerifyIndex(iraw, isig, tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Sequence != 7 || idx.KeyID != tr.Active.KeyID() || idx.Expired(t0.Add(13*24*time.Hour)) || !idx.Expired(t0.Add(15*24*time.Hour)) {
		t.Fatalf("%+v", idx)
	}
	// the backup key's signature over the same index
	if x, err := VerifyIndex(iraw, td(t, "release/index.json.backup.minisig"), tr, nil); err != nil || x.KeyID != tr.Backup.KeyID() {
		t.Fatal(x, err)
	}
	mraw, msig := td(t, "release/release-manifest.json"), td(t, "release/release-manifest.json.minisig")
	if err := CheckManifestSHA256(idx, "stable", mraw); err != nil {
		t.Fatal(err)
	}
	mf, err := VerifyManifest(mraw, msig, tr, idx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"core", "sensor"} {
		im, _ := mf.Image(s)
		if err := VerifyImage(mf, s, im.Digest, tr); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if err := mf.CheckPlatform("core", "linux/arm64"); err != nil {
		t.Error(err)
	}
	if err := CheckUpgrade(mf, "1.3.0"); err != nil {
		t.Error(err)
	}
	// each tampered file fails
	if _, err := VerifyManifest(bytes.Replace(mraw, []byte("1.4.0"), []byte("1.4.1"), 1), msig, tr, idx); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
	if _, err := VerifyIndex(bytes.Replace(iraw, []byte(`"sequence": 7`), []byte(`"sequence": 8`), 1), isig, tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
	// a manifest signature is not an index signature, and vice versa (different documents)
	if _, err := VerifyIndex(iraw, msig, tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Error(err)
	}
	// the index hash in the vectors matches the manifest
	s := sha256.Sum256(mraw)
	if idx.Channels["stable"].ManifestSHA256 != hex.EncodeToString(s[:]) {
		t.Error("vector index does not match vector manifest")
	}
	// the index in the vectors revokes 1.3.2, so a manifest for that version would be refused
	if idx.revoked(KindRelease, "1.3.2") == nil {
		t.Error("vector index lost its revocation")
	}
}

// A vector signed by a key that is trusted only as "other" must not pass as active or backup.
func TestRealVectorWrongTrust(t *testing.T) {
	tr := tdTrust(t)
	tr.Active, tr.Backup = tr.Backup, tr.Active // swapped roles: still the same two keys, still valid
	if _, err := VerifyIndex(td(t, "release/index.json"), td(t, "release/index.json.minisig"), tr, nil); err != nil {
		t.Fatal(err)
	}
	other, err := ParseMinisignPublicKey(string(td(t, "minisign/other.pub")))
	if err != nil {
		t.Fatal(err)
	}
	tr.Active, tr.Backup = other, other // same id twice is not a valid trust
	if _, err := VerifyIndex(td(t, "release/index.json"), td(t, "release/index.json.minisig"), tr, nil); !errors.Is(err, ErrNoTrustKeys) {
		t.Fatal(err)
	}
}
