package release

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

// ---- a minisign signer for tests (the verifier is checked against the real tool in vectors_test.go) ----

type msigner struct {
	id   [8]byte
	priv ed25519.PrivateKey
}

func newMsigner(t testing.TB) *msigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &msigner{priv: priv}
	if _, err := rand.Read(s.id[:]); err != nil {
		t.Fatal(err)
	}
	_ = pub
	return s
}

func (s *msigner) key() MinisignKey {
	return MinisignKey{ID: s.id, Key: s.priv.Public().(ed25519.PublicKey)}
}

// sigFile builds a .minisig from parts, so tests can break each part separately.
func sigFile(alg string, id [8]byte, sig []byte, trustedComment string, global []byte) []byte {
	raw := append(append([]byte(alg), id[:]...), sig...)
	return []byte("untrusted comment: test\n" + base64.StdEncoding.EncodeToString(raw) + "\ntrusted comment: " +
		trustedComment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

func (s *msigner) sign(msg []byte) []byte { return s.signC(msg, "t") }

func (s *msigner) signC(msg []byte, tc string) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, h[:])
	return sigFile("ED", s.id, sig, tc, ed25519.Sign(s.priv, append(append([]byte{}, sig...), tc...)))
}

// ---- a cosign signer for tests ----

type csigner struct{ priv *ecdsa.PrivateKey }

func newCsigner(t testing.TB) *csigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &csigner{k}
}

func (c *csigner) pub() *ecdsa.PublicKey { return &c.priv.PublicKey }

func (c *csigner) signRaw(t testing.TB, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func (c *csigner) sign(t testing.TB, payload []byte) CosignSig {
	return CosignSig{base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(c.signRaw(t, payload))}
}

func payloadFor(service, digest string) []byte {
	return []byte(`{"critical":{"identity":{"docker-reference":"` + RegistryPrefix + service + `"},"image":{"docker-manifest-digest":"` +
		digest + `"},"type":"cosign container image signature"},"optional":null}`)
}

// flipS returns sig with S replaced by N-S (the other, equally valid form), and whether it is now high.
func flipS(t testing.TB, sig []byte) (out []byte, high bool) {
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

// ---- a whole signing environment ----

const digestCore = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestSensor = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

var t0 = time.Date(2026, 12, 2, 8, 0, 0, 0, time.UTC)

type env struct {
	t              testing.TB
	active, backup *msigner
	cosign         *csigner
	trust          Trust
}

func newEnv(t testing.TB) *env {
	t.Helper()
	e := &env{t: t, active: newMsigner(t), backup: newMsigner(t), cosign: newCsigner(t)}
	e.trust = Trust{Active: e.active.key(), Backup: e.backup.key(), Cosign: []*ecdsa.PublicKey{e.cosign.pub()}}
	if err := e.trust.validate(); err != nil {
		t.Fatal(err)
	}
	return e
}

type m = map[string]any

func (e *env) indexMap(seq uint64) m {
	return m{
		"schema": 1, "sequence": seq,
		"generated_at": t0.Format(time.RFC3339), "expires_at": t0.Add(14 * 24 * time.Hour).Format(time.RFC3339),
		"channels": m{"stable": m{"latest": "1.4.0", "manifest": "https://github.com/knt048/vedette/releases/download/v1.4.0/release-manifest.json",
			"manifest_sha256": hex.EncodeToString(make([]byte, 32)), "rollout": m{"percent": 100}}},
		"revoked": []any{}, "advisories": []any{}, "keys": []any{},
	}
}

func revocation(kind, id string) m {
	return m{"kind": kind, "id": id, "reason": "test", "since": t0.Format(time.RFC3339), "action": "block_install"}
}

func (e *env) image(service, version, digest string) m {
	return m{"service": service, "ref": ImageRef(service, version), "digest": digest, "size": 1000,
		"platforms": []string{"linux/amd64"}, "cosign": e.cosign.sign(e.t, payloadFor(service, digest))}
}

func (e *env) manifestMap() m {
	const version = "1.4.0"
	return m{
		"schema": 1, "version": version, "channel": "stable", "released_at": t0.Format(time.RFC3339),
		"min_upgrade_from": "1.2.0", "db_schema": 14, "rollback": m{"safe": true, "min_version": "1.3.0"},
		"install_modes": []string{"appliance", "container"},
		"images":        []any{e.image("core", version, digestCore), e.image("sensor", version, digestSensor)},
		"notes":         "n",
	}
}

func js(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *env) signedIndex(s *msigner, x m) (raw, sig []byte) {
	raw = js(e.t, x)
	return raw, s.sign(raw)
}

func (e *env) verifiedIndex(s *msigner, x m) *Index {
	e.t.Helper()
	raw, sig := e.signedIndex(s, x)
	idx, err := VerifyIndex(raw, sig, e.trust, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return idx
}

func (e *env) verifiedManifest(x m, idx *Index) *Manifest {
	e.t.Helper()
	raw := js(e.t, x)
	mf, err := VerifyManifest(raw, e.active.sign(raw), e.trust, idx)
	if err != nil {
		e.t.Fatal(err)
	}
	return mf
}

// ---- testdata ----

func td(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", rel)) //nolint:gosec // fixed test fixture names
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// tdTrust is the trust of the committed vectors: test key 1 active, test key 3 backup, the vector cosign key.
func tdTrust(t testing.TB) Trust {
	t.Helper()
	tr, err := NewTrust(string(td(t, "minisign/test.pub")), string(td(t, "minisign/backup.pub")), string(td(t, "cosign/cosign.pub")))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}
