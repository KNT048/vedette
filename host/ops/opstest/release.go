package opstest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/internal/release"
)

// A signing environment for the tests of container.pull: throwaway minisign keys (active and backup)
// and a cosign key made when the test starts, a release.Trust built from their public halves
// (Deps.Keys), and builders for index.json, release-manifest.json and the container.pull args.
// The private keys live only in the test process. The committed vectors of internal/release/testdata
// (made with the real minisign) are used by the tests that want a real tool's signatures.

// Release is the signing environment.
type Release struct {
	Trust release.Trust

	t      testing.TB
	active msigner
	backup msigner
	cosign *ecdsa.PrivateKey
}

type msigner struct {
	id   [8]byte
	priv ed25519.PrivateKey
}

func newMsigner(t testing.TB) msigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := msigner{priv: priv}
	if _, err := rand.Read(s.id[:]); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s msigner) key() release.MinisignKey {
	return release.MinisignKey{ID: s.id, Key: s.priv.Public().(ed25519.PublicKey)}
}

// sign writes a .minisig in the prehashed "ED" form (BLAKE2b-512 of the message) with a trusted comment.
func (s msigner) sign(msg []byte) []byte {
	const tc = "t"
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(s.priv, h[:])
	global := ed25519.Sign(s.priv, append(append([]byte{}, sig...), tc...))
	raw := append(append([]byte("ED"), s.id[:]...), sig...)
	return []byte("untrusted comment: test\n" + base64.StdEncoding.EncodeToString(raw) + "\ntrusted comment: " + tc + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

// NewRelease makes the keys and the trust of a test.
func NewRelease(t testing.TB) *Release {
	t.Helper()
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := &Release{t: t, active: newMsigner(t), backup: newMsigner(t), cosign: ck}
	r.Trust = release.Trust{Active: r.active.key(), Backup: r.backup.key(), Cosign: []*ecdsa.PublicKey{&ck.PublicKey}}
	return r
}

// Keys is the Deps.Keys of this environment.
func (r *Release) Keys() (release.Trust, error) { return r.Trust, nil }

// ActiveKeyID is the minisign key id of the active key as index.json revocations name it.
func (r *Release) ActiveKeyID() string { return r.active.key().KeyID() }

// BackupKeyID is the same for the offline backup key.
func (r *Release) BackupKeyID() string { return r.backup.key().KeyID() }

// Sign signs with the active key.
func (r *Release) Sign(raw []byte) []byte { return r.active.sign(raw) }

// SignBackup signs with the offline backup key.
func (r *Release) SignBackup(raw []byte) []byte { return r.backup.sign(raw) }

// CosignSig signs an image the way the release job does: simple-signing payload, ECDSA P-256 over SHA-256.
func (r *Release) CosignSig(service, digest string) release.CosignSig {
	r.t.Helper()
	payload := []byte(`{"critical":{"identity":{"docker-reference":"` + release.RegistryPrefix + service + `"},"image":{"docker-manifest-digest":"` +
		digest + `"},"type":"cosign container image signature"},"optional":null}`)
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, r.cosign, h[:])
	if err != nil {
		r.t.Fatal(err)
	}
	return release.CosignSig{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)}
}

// Doc is a JSON document a test may change before it is signed.
type Doc = map[string]any

var docTime = time.Date(2026, 12, 2, 8, 0, 0, 0, time.UTC)

// IndexDoc is a valid index.json with the given sequence: one channel whose latest is 9.9.9 (so no
// manifest hash applies to the releases of a test), nothing revoked.
func (r *Release) IndexDoc(seq uint64) Doc {
	return Doc{
		"schema": 1, "sequence": seq,
		"generated_at": docTime.Format(time.RFC3339), "expires_at": docTime.Add(14 * 24 * time.Hour).Format(time.RFC3339),
		"channels": Doc{"stable": Doc{
			"latest": "9.9.9", "manifest": "https://github.com/knt048/vedette/releases/download/v9.9.9/release-manifest.json",
			"manifest_sha256": hex.EncodeToString(make([]byte, 32)), "rollout": Doc{"percent": 100},
		}},
		"revoked": []any{}, "advisories": []any{}, "keys": []any{},
	}
}

// Revocation is an entry of index.json "revoked" that blocks installs.
func Revocation(kind, id string) Doc {
	return Doc{"kind": kind, "id": id, "reason": "test", "since": docTime.Format(time.RFC3339), "action": "block_install"}
}

// Img says which image a manifest holds.
type Img struct {
	Service, Digest string
	Size            int64
}

// ImageDoc is one images[] entry of a manifest for linux/amd64, with a cosign signature made by this
// environment.
func (r *Release) ImageDoc(version string, im Img) Doc {
	return Doc{
		"service": im.Service, "ref": release.ImageRef(im.Service, version), "digest": im.Digest, "size": im.Size,
		"platforms": []string{"linux/amd64"}, "cosign": r.CosignSig(im.Service, im.Digest),
	}
}

// ManifestDoc is a valid release-manifest.json for version holding the images.
func (r *Release) ManifestDoc(version string, imgs ...Img) Doc {
	var images []any
	for _, im := range imgs {
		images = append(images, r.ImageDoc(version, im))
	}
	return Doc{
		"schema": 1, "version": version, "channel": "stable", "released_at": docTime.Format(time.RFC3339),
		"min_upgrade_from": "", "db_schema": 14, "rollback": Doc{"safe": true, "min_version": ""},
		"install_modes": []string{"appliance", "container"}, "images": images, "notes": "n",
	}
}

// JSON marshals a document.
func JSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Args builds the container.pull args for raw documents: the index and manifest signed by the active key.
func (r *Release) Args(service, version string, indexRaw, manifestRaw []byte) api.ContainerPullArgs {
	return r.ArgsSig(service, version, indexRaw, r.Sign(indexRaw), manifestRaw, r.Sign(manifestRaw))
}

// ArgsSig is Args with the signatures given.
func (r *Release) ArgsSig(service, version string, indexRaw, indexSig, manifestRaw, manifestSig []byte) api.ContainerPullArgs {
	b := base64.StdEncoding.EncodeToString
	return api.ContainerPullArgs{
		Service: service, Version: version, Source: api.PullSourceRegistry,
		Index: b(indexRaw), IndexSig: b(indexSig), Manifest: b(manifestRaw), ManifestSig: b(manifestSig),
	}
}
