//go:build !releasetestkeys

package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// The ids of the release keys made at the ceremony of 2026-11-11 (D-256), as minisign prints them and as
// index.json revocations name them. A change here is a key rotation: it needs a decision, not a test fix.
const (
	prodActiveID = "7B78764E550D48D0"
	prodBackupID = "8DD38917AD864FAE"
)

// A production build (no releasetestkeys tag) embeds the real release keys, and only them.
func TestProductionBuildEmbedsTheReleaseKeys(t *testing.T) {
	tr, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded() = %v", err)
	}
	if tr.TestOnly || len(tr.Retired) != 0 || tr.MinSequence != 0 {
		t.Fatalf("%+v", tr)
	}
	if tr.Active.KeyID() != prodActiveID || tr.Backup.KeyID() != prodBackupID {
		t.Fatalf("active %s backup %s", tr.Active.KeyID(), tr.Backup.KeyID())
	}
	if len(tr.Cosign) != 1 {
		t.Fatalf("%d cosign keys", len(tr.Cosign))
	}
	if got, err := ParseCosignPublicKey(prodCosign); err != nil || CosignKeyID(got) != CosignKeyID(tr.Cosign[0]) {
		t.Fatal(err)
	}
}

// The private halves exist and match the constants: at the ceremony each key signed testdata/prod/proof.txt
// (scripts/release/keygen.sh made the keys; the proof was signed right after). A constant edited by one
// character, or a key pasted into the wrong slot, fails here instead of in the first release.
func TestProductionKeysProofOfPossession(t *testing.T) {
	tr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	proof := td(t, "prod/proof.txt")
	res, err := verifyMinisign(proof, td(t, "prod/proof.txt.minisig"), tr)
	if err != nil || res.backup || res.key.KeyID() != prodActiveID {
		t.Fatalf("active: %+v %v", res, err)
	}
	res, err = verifyMinisign(proof, td(t, "prod/proof.txt.backup.minisig"), tr)
	if err != nil || !res.backup || res.key.KeyID() != prodBackupID {
		t.Fatalf("backup: %+v %v", res, err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(td(t, "prod/proof.txt.cosign.sig"))))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(proof)
	if !ecdsa.VerifyASN1(tr.Cosign[0], h[:], der) {
		t.Fatal("cosign: the embedded key does not verify the ceremony's signature")
	}
	// the same signatures over one changed byte are refused
	bad := bytes.Clone(proof)
	bad[0] ^= 1
	if _, err := verifyMinisign(bad, td(t, "prod/proof.txt.minisig"), tr); !errors.Is(err, ErrBadSignature) {
		t.Errorf("active over a changed file: %v", err)
	}
	if _, err := verifyMinisign(bad, td(t, "prod/proof.txt.backup.minisig"), tr); !errors.Is(err, ErrBadSignature) {
		t.Errorf("backup over a changed file: %v", err)
	}
	h = sha256.Sum256(bad)
	if ecdsa.VerifyASN1(tr.Cosign[0], h[:], der) {
		t.Error("cosign over a changed file")
	}
	// the proof is not a release document
	if _, err := VerifyIndex(proof, td(t, "prod/proof.txt.minisig"), tr, nil); err == nil {
		t.Error("the proof verified as an index")
	}
}

// What the throwaway test keys sign is refused by a production build, at every entry point.
func TestProductionBuildRefusesTestKeySignatures(t *testing.T) {
	tr, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	raw, sig := e.signedIndex(e.active, e.indexMap(1))
	if _, err := VerifyIndex(raw, sig, tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifyIndex: %v", err)
	}
	braw, bsig := e.signedIndex(e.backup, e.indexMap(1))
	if _, err := VerifyIndex(braw, bsig, tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifyIndex (test backup key): %v", err)
	}
	idx := e.verifiedIndex(e.active, e.indexMap(1))
	mraw := js(t, e.manifestMap())
	if _, err := VerifyManifest(mraw, e.active.sign(mraw), tr, idx); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifyManifest: %v", err)
	}
	mf := e.verifiedManifest(e.manifestMap(), idx)
	if err := VerifyImage(mf, "core", digestCore, tr); !errors.Is(err, ErrBadSignature) {
		t.Errorf("VerifyImage: %v", err)
	}
	// and the committed vectors the real minisign signed with the test keys
	if _, err := VerifyIndex(td(t, "release/index.json"), td(t, "release/index.json.minisig"), tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("committed vector: %v", err)
	}
}

// A build whose trust does not validate still fails closed and says why, once.
func TestProductionBuildFailsClosed(t *testing.T) {
	var buf bytes.Buffer
	old, oldSeq := logger, MinSequenceText
	logger = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { logger, MinSequenceText = old, oldSeq })
	logOnce = syncOnce() // log again in this test
	t.Cleanup(func() { logOnce = syncOnce() })

	MinSequenceText = "not a number" // what a broken -ldflags would set
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
	e := newEnv(t)
	raw, sig := e.signedIndex(e.active, e.indexMap(1))
	if _, err := VerifyIndex(raw, sig, tr, nil); !errors.Is(err, ErrNoTrustKeys) {
		t.Errorf("VerifyIndex: %v", err)
	}
	// an empty constant is refused too (what a build had before the ceremony)
	for _, k := range [][3]string{{"", prodMinisignBackup, prodCosign}, {prodMinisignActive, "", prodCosign}, {prodMinisignActive, prodMinisignBackup, ""}} {
		if _, err := parseTrust(k[0], k[1], k[2]); err == nil {
			t.Errorf("empty constant accepted: %q", k)
		}
	}
}

// The production constants are never a test key, and the test data never holds a production key except the
// ceremony's proof under testdata/prod (the test keys live only under testdata and in keys_testonly.go, which a
// production build does not compile).
func TestProductionConstantsAreNotTestKeys(t *testing.T) {
	for _, c := range []struct{ name, prod, file string }{
		{"active", prodMinisignActive, "minisign/test.pub"},
		{"backup", prodMinisignBackup, "minisign/backup.pub"},
		{"cosign", prodCosign, "cosign/cosign.pub"},
	} {
		if c.prod == "" || bytes.Contains(td(t, c.file), []byte(strings.TrimSpace(c.prod))) {
			t.Errorf("%s constant is empty or a test key", c.name)
		}
	}
	if a, b, c, testOnly := embeddedKeys(); testOnly || a != prodMinisignActive || b != prodMinisignBackup || c != prodCosign {
		t.Error("production build embeds something else")
	}
	err := filepath.WalkDir("testdata", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasPrefix(p, filepath.Join("testdata", "prod")+string(filepath.Separator)) {
			return err
		}
		b := td(t, strings.TrimPrefix(p, "testdata"+string(filepath.Separator)))
		for _, k := range []string{prodMinisignActive, prodMinisignBackup, strings.Split(prodCosign, "\n")[1]} {
			if bytes.Contains(b, []byte(k)) {
				t.Errorf("%s holds a production key", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
