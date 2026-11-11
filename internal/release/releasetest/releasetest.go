// Package releasetest holds the throwaway signers that the tests of internal/release and of the release
// builder (scripts/release) share: a minisign signer (the prehashed "ED" format, what the minisign tool writes)
// and a cosign signer (ECDSA P-256 over SHA-256, ASN.1 DER, the legacy simple-signing format). The keys are made
// in memory from crypto/rand when a test starts and never written anywhere; nothing here can sign for a real
// release, and nothing in a production binary imports this package.
//
// The package does not import internal/release (its own tests import it, which would be a cycle), so keys are
// handed out as plain crypto types and as the text lines the real tools print.
package releasetest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// Minisign is a throwaway minisign key pair.
type Minisign struct {
	ID   [8]byte // the key id as stored in the files (little-endian)
	Priv ed25519.PrivateKey
}

// NewMinisign makes a random key pair.
func NewMinisign(t testing.TB) *Minisign {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Minisign{Priv: priv}
	if _, err := rand.Read(s.ID[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

// Public is the public key.
func (s *Minisign) Public() ed25519.PublicKey { return s.Priv.Public().(ed25519.PublicKey) }

// PubLine is the one-line "RWQ..." public key as minisign prints it.
func (s *Minisign) PubLine() string {
	b := append(append([]byte("Ed"), s.ID[:]...), s.Public()...)
	return base64.StdEncoding.EncodeToString(b)
}

// SigFile builds a .minisig from parts, so tests can break each part separately.
func SigFile(alg string, id [8]byte, sig []byte, trustedComment string, global []byte) []byte {
	raw := append(append([]byte(alg), id[:]...), sig...)
	return []byte("untrusted comment: test\n" + base64.StdEncoding.EncodeToString(raw) + "\ntrusted comment: " +
		trustedComment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

// Sign signs msg (prehashed "ED") with the trusted comment "t".
func (s *Minisign) Sign(msg []byte) []byte { return s.SignComment(msg, "t") }

// SignComment signs msg with the given trusted comment.
func (s *Minisign) SignComment(msg []byte, tc string) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.Priv, h[:])
	return SigFile("ED", s.ID, sig, tc, ed25519.Sign(s.Priv, append(append([]byte{}, sig...), tc...)))
}

// Cosign is a throwaway cosign key pair (ECDSA P-256).
type Cosign struct{ Priv *ecdsa.PrivateKey }

// NewCosign makes a random key pair.
func NewCosign(t testing.TB) *Cosign {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Cosign{k}
}

// Public is the public key.
func (c *Cosign) Public() *ecdsa.PublicKey { return &c.Priv.PublicKey }

// PubPEM is the PEM "PUBLIC KEY" file that `cosign generate-key-pair` writes.
func (c *Cosign) PubPEM(t testing.TB) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(c.Public())
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// SignRaw is ECDSA P-256 over SHA-256 of payload, ASN.1 DER, as sigstore's signer does.
func (c *Cosign) SignRaw(t testing.TB, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, c.Priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// Sign returns the base64 payload and the base64 signature, the two halves of images[].cosign.
func (c *Cosign) Sign(t testing.TB, payload []byte) (payloadB64, sigB64 string) {
	t.Helper()
	return base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(c.SignRaw(t, payload))
}

// Payload is the simple-signing document exactly as `cosign sign <repo>@<digest>` emits it: dockerRef is the
// repository without tag or digest.
func Payload(dockerRef, digest string) []byte {
	return []byte(`{"critical":{"identity":{"docker-reference":"` + dockerRef + `"},"image":{"docker-manifest-digest":"` +
		digest + `"},"type":"cosign container image signature"},"optional":null}`)
}

// FlipS returns sig with S replaced by N-S (the other, equally valid form), and whether it is now high.
func FlipS(t testing.TB, sig []byte) (out []byte, high bool) {
	t.Helper()
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) != 0 {
		t.Fatal("bad der", err)
	}
	n := elliptic.P256().Params().N
	rs.S = new(big.Int).Sub(n, rs.S)
	b, err := asn1.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	return b, rs.S.Cmp(new(big.Int).Rsh(n, 1)) > 0
}
