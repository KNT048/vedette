// Command testchannel makes the TEST release that `make install-artifacts` hands to `install.sh --test-artifacts`
// (WP-08h, D-166). The real release keys do not exist yet (08k), so a test install needs a release signed with
// throwaway keys, and a vedette-host that trusts exactly those keys.
//
//	keys   makes the throwaway keys (private halves stay in -out, mode 0600, never committed; a folder that already holds keys
//	       keeps them, so a later build is trusted by a box installed from the first, #469) and a Go build overlay that
//	       replaces internal/release/keys_prod.go of ONE build of vedette-host with their public halves. The source tree is
//	       never changed and the production guard (test-only keys are refused outside a test binary) is not weakened:
//	       the test host is simply a different build with other production-style keys.
//	sign   builds index.json and release-manifest.json for the images found under -blobs and signs them (minisign
//	       format and the legacy cosign payload) with those keys; every document is checked back with internal/release.
//	serve  a read-only registry for the blobs of those images, bound to loopback: install.sh points podman's mirror for
//	       ghcr.io/knt048 at it, so `vedette-host -bootstrap` pulls by digest exactly as in production. With -releases it also
//	       serves the documents and the host package under /release/, the update source of a test box (docs/INSTALL-TEST.md).
//
// Nothing here runs on a customer box: the customer path has no test keys, no mirror and no registry.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/knt048/vedette/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "testchannel:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: testchannel keys|sign|serve (see the header of main.go)")
	}
	switch args[0] {
	case "keys":
		return cmdKeys(args[1:])
	case "sign":
		return cmdSign(args[1:])
	case "serve":
		return cmdServe(args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

// ---- keys ------------------------------------------------------------------------------------------------------------

// keySet is what `keys` writes into its directory: seeds and a cosign key, all private, all throwaway.
type keySet struct {
	active, backup ed25519.PrivateKey
	activeID       [8]byte
	backupID       [8]byte
	cosign         *ecdsa.PrivateKey
}

func minisignPub(id [8]byte, pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), id[:]...), pub...))
}

func newKeySet() (*keySet, error) {
	ks := &keySet{}
	var err error
	for _, k := range []struct {
		priv *ed25519.PrivateKey
		id   *[8]byte
	}{{&ks.active, &ks.activeID}, {&ks.backup, &ks.backupID}} {
		if _, *k.priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			return nil, err
		}
		if _, err = rand.Read(k.id[:]); err != nil {
			return nil, err
		}
	}
	ks.cosign, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return ks, err
}

func (ks *keySet) cosignPEM() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&ks.cosign.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func (ks *keySet) save(dir string) error {
	der, err := x509.MarshalPKCS8PrivateKey(ks.cosign)
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"minisign-active.seed": []byte(base64.StdEncoding.EncodeToString(append(ks.activeID[:], ks.active.Seed()...))),
		"minisign-backup.seed": []byte(base64.StdEncoding.EncodeToString(append(ks.backupID[:], ks.backup.Seed()...))),
		"cosign.key":           pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func loadKeySet(dir string) (*keySet, error) {
	ks := &keySet{}
	for _, k := range []struct {
		name string
		priv *ed25519.PrivateKey
		id   *[8]byte
	}{{"minisign-active.seed", &ks.active, &ks.activeID}, {"minisign-backup.seed", &ks.backup, &ks.backupID}} {
		raw, err := os.ReadFile(filepath.Join(dir, k.name)) //nolint:gosec // the tool's own key folder, named on its command line
		if err != nil {
			return nil, err
		}
		b, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil || len(b) != 8+ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a key made by testchannel keys", k.name)
		}
		copy(k.id[:], b[:8])
		*k.priv = ed25519.NewKeyFromSeed(b[8:])
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cosign.key")) //nolint:gosec // same folder
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, errors.New("cosign.key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("cosign.key is not an ECDSA key")
	}
	ks.cosign = ec
	return ks, nil
}

func (ks *keySet) trust() (release.Trust, error) {
	pem, err := ks.cosignPEM()
	if err != nil {
		return release.Trust{}, err
	}
	return release.NewTrust(
		minisignPub(ks.activeID, ks.active.Public().(ed25519.PublicKey)),
		minisignPub(ks.backupID, ks.backup.Public().(ed25519.PublicKey)), pem)
}

// keysProd is the replacement of internal/release/keys_prod.go: the same function, other keys, testOnly false.
const keysProd = `//go:build !releasetestkeys

// Code generated by scripts/testchannel keys. DO NOT COMMIT: it exists only inside one test build of vedette-host (go build -overlay).

package release

func embeddedKeys() (active, backup, cosign string, testOnly bool) {
	return %q, %q, %q, false
}
`

func cmdKeys(args []string) error {
	fs := flag.NewFlagSet("keys", flag.ContinueOnError)
	out := fs.String("out", "", "empty folder for the private keys, the generated source and overlay.json")
	root := fs.String("repo", "", "repository root (absolute)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || !filepath.IsAbs(*root) {
		return errors.New("keys: -out and an absolute -repo are required")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	// A folder that already holds keys (KEYS=<dir> of make install-artifacts) keeps them: the second build is trusted by a box
	// installed from the first. The generated source and overlay are rewritten each time (their paths belong to this checkout).
	var ks *keySet
	var err error
	if _, serr := os.Stat(filepath.Join(*out, "minisign-active.seed")); serr == nil {
		ks, err = loadKeySet(*out)
	} else if ks, err = newKeySet(); err == nil {
		err = ks.save(*out)
	}
	if err != nil {
		return err
	}
	cos, err := ks.cosignPEM()
	if err != nil {
		return err
	}
	src := fmt.Sprintf(keysProd, minisignPub(ks.activeID, ks.active.Public().(ed25519.PublicKey)),
		minisignPub(ks.backupID, ks.backup.Public().(ed25519.PublicKey)), cos)
	gen := filepath.Join(*out, "keys_prod.go")
	if err := os.WriteFile(gen, []byte(src), 0o600); err != nil {
		return err
	}
	absOut, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	overlay, err := json.Marshal(map[string]map[string]string{"Replace": {
		filepath.Join(*root, "internal", "release", "keys_prod.go"): filepath.Join(absOut, "keys_prod.go"),
	}})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*out, "overlay.json"), overlay, 0o600)
}

// ---- minisign and cosign signing -------------------------------------------------------------------------------------

// minisign signs msg in the format internal/release accepts: prehashed "ED" (BLAKE2b-512), then the trusted comment.
func minisign(priv ed25519.PrivateKey, id [8]byte, msg []byte, trustedComment string) []byte {
	h := blake2b.Sum512(msg)
	sig := ed25519.Sign(priv, h[:])
	global := ed25519.Sign(priv, append(append([]byte(nil), sig...), trustedComment...))
	file := base64.StdEncoding.EncodeToString(append(append([]byte("ED"), id[:]...), sig...))
	return []byte("untrusted comment: vedette TEST-ONLY signature, throwaway key\n" + file +
		"\ntrusted comment: " + trustedComment + "\n" + base64.StdEncoding.EncodeToString(global) + "\n")
}

// cosignSig is the legacy simple-signing payload of one image and its ECDSA P-256 / SHA-256 / ASN.1 signature
// (internal/release/testdata/README.md).
func cosignSig(k *ecdsa.PrivateKey, service, digest string) (release.CosignSig, error) {
	payload, err := json.Marshal(map[string]any{
		"critical": map[string]any{
			"identity": map[string]string{"docker-reference": release.RegistryPrefix + service},
			"image":    map[string]string{"docker-manifest-digest": digest},
			"type":     "cosign container image signature",
		},
		"optional": nil,
	})
	if err != nil {
		return release.CosignSig{}, err
	}
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		return release.CosignSig{}, err
	}
	return release.CosignSig{Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// ---- sign ------------------------------------------------------------------------------------------------------------

type imageFlag []string

func (f *imageFlag) String() string     { return strings.Join(*f, ",") }
func (f *imageFlag) Set(s string) error { *f = append(*f, s); return nil }

func fileSHA256(path string) (string, int64, error) {
	b, err := os.ReadFile(path) //nolint:gosec // an artifact named on the command line
	if err != nil {
		return "", 0, err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), int64(len(b)), nil
}

type signSpec struct {
	keys       *keySet
	version    string
	platform   string
	blobs      string
	deb        string
	images     map[string]string // service -> sha256:<hex> of its manifest list
	now        time.Time
	releaseURL string
}

// build returns the four documents: index, its signature, manifest, its signature.
func (s signSpec) build() (index, indexSig, manifest, manifestSig []byte, err error) {
	m := release.Manifest{
		Schema: 1, Version: s.version, Channel: "beta", ReleasedAt: s.now, DBSchema: 0,
		Rollback:     release.Rollback{Safe: false},
		InstallModes: []string{"appliance"},
		Content:      []release.Content{}, Bundled: []release.Bundled{},
		Notes: "TEST CHANNEL: signed with throwaway keys, not a release.",
	}
	for _, svc := range release.Services {
		d, ok := s.images[svc]
		if !ok {
			continue
		}
		_, size, ferr := fileSHA256(filepath.Join(s.blobs, strings.TrimPrefix(d, "sha256:")))
		if ferr != nil {
			return nil, nil, nil, nil, fmt.Errorf("the manifest list of %s is not in -blobs: %w", svc, ferr)
		}
		cs, cerr := cosignSig(s.keys.cosign, svc, d)
		if cerr != nil {
			return nil, nil, nil, nil, cerr
		}
		m.Images = append(m.Images, release.Image{Service: svc, Ref: release.ImageRef(svc, s.version), Digest: d, Size: size, Platforms: []string{s.platform}, Cosign: cs})
	}
	if s.deb != "" {
		sum, size, ferr := fileSHA256(s.deb)
		if ferr != nil {
			return nil, nil, nil, nil, ferr
		}
		m.Host = &release.HostPart{Version: s.version, Files: []release.HostFile{{Name: filepath.Base(s.deb), SHA256: sum, Size: size}}}
	}
	if manifest, err = json.MarshalIndent(m, "", "  "); err != nil {
		return nil, nil, nil, nil, err
	}
	manifest = append(manifest, '\n')
	msum := sha256.Sum256(manifest)
	x := release.Index{
		Schema: 1, Sequence: uint64(s.now.Unix()), //nolint:gosec // a Unix time after 1970 is positive
		GeneratedAt: s.now, ExpiresAt: s.now.Add(13 * 24 * time.Hour),
		Channels: map[string]release.Channel{"beta": {
			Latest: s.version, Manifest: s.releaseURL + "/release-manifest.json", ManifestSHA256: hex.EncodeToString(msum[:]),
			Rollout: &release.Rollout{Percent: 100},
		}},
		Revoked: []release.Revocation{}, Advisories: []release.Advisory{}, Keys: []release.KeyInfo{},
	}
	if index, err = json.MarshalIndent(x, "", "  "); err != nil {
		return nil, nil, nil, nil, err
	}
	index = append(index, '\n')
	k := s.keys
	indexSig = minisign(k.active, k.activeID, index, fmt.Sprintf("file:index.json sequence:%d TEST-ONLY", x.Sequence))
	manifestSig = minisign(k.active, k.activeID, manifest, "file:release-manifest.json version:"+s.version+" TEST-ONLY")
	return index, indexSig, manifest, manifestSig, nil
}

// check reads the documents back with the production verifiers and the trust of the throwaway keys.
func (s signSpec) check(index, indexSig, manifest, manifestSig []byte) error {
	t, err := s.keys.trust()
	if err != nil {
		return err
	}
	idx, err := release.VerifyIndex(index, indexSig, t, nil)
	if err != nil {
		return fmt.Errorf("index does not verify: %w", err)
	}
	if err := release.CheckManifestSHA256(idx, "beta", manifest); err != nil {
		return fmt.Errorf("index and manifest disagree: %w", err)
	}
	m, err := release.VerifyManifest(manifest, manifestSig, t, idx)
	if err != nil {
		return fmt.Errorf("manifest does not verify: %w", err)
	}
	for svc, d := range s.images {
		if err := release.VerifyImage(m, svc, d, t); err != nil {
			return fmt.Errorf("image %s does not verify: %w", svc, err)
		}
	}
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keys := fs.String("keys", "", "folder made by `keys`")
	out := fs.String("out", "", "folder for index.json, release-manifest.json and their .minisig")
	version := fs.String("version", "", "release version, SemVer without v")
	platform := fs.String("platform", "linux/amd64", "platform of the images")
	blobs := fs.String("blobs", "", "folder of blobs named by their sha256 hex (what `serve` serves)")
	deb := fs.String("deb", "", "the vedette-host package (its sha256 goes into the manifest)")
	var images imageFlag
	fs.Var(&images, "image", "service=sha256:<hex> of the image's manifest list (repeat)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keys == "" || *out == "" || *version == "" || *blobs == "" || len(images) == 0 {
		return errors.New("sign: -keys -out -version -blobs and at least one -image are required")
	}
	ks, err := loadKeySet(*keys)
	if err != nil {
		return err
	}
	spec := signSpec{keys: ks, version: *version, platform: *platform, blobs: *blobs, deb: *deb, images: map[string]string{}, now: time.Now().UTC().Truncate(time.Second),
		releaseURL: "https://github.com/KNT048/vedette/releases/download/v" + *version}
	for _, im := range images {
		svc, d, ok := strings.Cut(im, "=")
		if !ok {
			return fmt.Errorf("-image %q is not service=digest", im)
		}
		spec.images[svc] = d
	}
	index, indexSig, manifest, manifestSig, err := spec.build()
	if err != nil {
		return err
	}
	if err := spec.check(index, indexSig, manifest, manifestSig); err != nil {
		return err
	}
	for name, b := range map[string][]byte{"index.json": index, "index.json.minisig": indexSig, "release-manifest.json": manifest, "release-manifest.json.minisig": manifestSig} {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil { //nolint:gosec // public documents of a test release
			return err
		}
	}
	return nil
}
