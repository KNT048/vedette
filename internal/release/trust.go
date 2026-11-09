package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

// Trust is the set of keys a verification trusts. In production it comes from Embedded; tests (and
// the host's test seam, D-107) build it from the keys under testdata.
type Trust struct {
	Active, Backup MinisignKey        // the signing key and the offline recovery key
	Cosign         []*ecdsa.PublicKey // one key, or two during a rotation (update-manifest.md §5.2)
	TestOnly       bool               // set by a build with the releasetestkeys tag; callers should refuse it in production
}

func (t Trust) validate() error {
	if len(t.Active.Key) != 32 || len(t.Backup.Key) != 32 {
		return errors.New("a minisign key is missing")
	}
	if t.Active.ID == t.Backup.ID || bytes.Equal(t.Active.Key, t.Backup.Key) {
		return errors.New("the two minisign keys are the same key")
	}
	if len(t.Cosign) == 0 || len(t.Cosign) > 2 {
		return errors.New("need one or two cosign keys")
	}
	for _, k := range t.Cosign {
		if k == nil || k.Curve != elliptic.P256() {
			return errors.New("cosign key is not ECDSA P-256")
		}
	}
	return nil
}

// NewTrust builds a Trust from the printed forms of the keys.
func NewTrust(minisignActive, minisignBackup string, cosignPEM ...string) (Trust, error) {
	var t Trust
	var err error
	if t.Active, err = ParseMinisignPublicKey(minisignActive); err != nil {
		return Trust{}, err
	}
	if t.Backup, err = ParseMinisignPublicKey(minisignBackup); err != nil {
		return Trust{}, err
	}
	for _, p := range cosignPEM {
		k, err := ParseCosignPublicKey(p)
		if err != nil {
			return Trust{}, err
		}
		t.Cosign = append(t.Cosign, k)
	}
	return t, t.validate()
}

func parseTrust(active, backup, cosign string) (Trust, error) {
	if active == "" || backup == "" || cosign == "" {
		return Trust{}, errors.New("a key constant is empty")
	}
	return NewTrust(active, backup, cosign)
}

// ParseCosignPublicKey reads a PEM "PUBLIC KEY" block holding an ECDSA P-256 key (what cosign
// generate-key-pair writes to cosign.pub).
func ParseCosignPublicKey(p string) (*ecdsa.PublicKey, error) {
	if len(p) > 1024 {
		return nil, errors.New("cosign public key: too long")
	}
	blk, rest := pem.Decode([]byte(p))
	if blk == nil || blk.Type != "PUBLIC KEY" || len(bytesTrim(rest)) != 0 {
		return nil, errors.New("cosign public key: not a single PEM PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("cosign public key: not PKIX")
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("cosign public key: not ECDSA P-256")
	}
	return ek, nil
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[0] == '\n' || b[0] == ' ' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}

// CosignKeyID names a cosign key in index.json revocations: lower-case hex SHA-256 of its
// PKIX (DER) encoding.
func CosignKeyID(k *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}
