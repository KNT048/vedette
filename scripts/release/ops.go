package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

const (
	indexFile    = "index.json"
	manifestFile = "release-manifest.json"
	maxDoc       = release.MaxDocBytes
)

func readDoc(p string) ([]byte, error) { return readSmall(p, int64(maxDoc)) }

// LoadTrust reads the public keys from dir (minisign.pub, minisign-backup.pub, cosign.pub: the files `minisign -G` and
// `cosign generate-key-pair` write). An empty dir means the keys compiled into this build, which are empty until the
// real release keys exist (08l) and then refuse, so a build without keys cannot pass a release.
func LoadTrust(dir string) (release.Trust, error) {
	if dir == "" {
		return release.Embedded()
	}
	read := func(n string) (string, error) {
		b, err := readSmall(filepath.Join(dir, n), 2<<10)
		return string(b), err
	}
	a, err := read("minisign.pub")
	if err != nil {
		return release.Trust{}, err
	}
	b, err := read("minisign-backup.pub")
	if err != nil {
		return release.Trust{}, err
	}
	c, err := read("cosign.pub")
	if err != nil {
		return release.Trust{}, err
	}
	return release.NewTrust(a, b, c)
}

// LoadPrev reads and verifies the previous release held in dir (index.json and release-manifest.json with their .minisig).
// Both are verified with the verifier of internal/release; the builder never builds on a file that does not verify.
func LoadPrev(dir string, trust release.Trust) (*Prev, error) {
	idx, err := verifyIndexFile(dir, trust, nil)
	if err != nil {
		return nil, fmt.Errorf("previous release: %w", err)
	}
	raw, sig, err := readSigned(filepath.Join(dir, manifestFile))
	if err != nil {
		return nil, fmt.Errorf("previous release: %w", err)
	}
	m, err := release.VerifyManifest(raw, sig, trust, idx)
	if err != nil {
		return nil, fmt.Errorf("previous release manifest: %w", err)
	}
	return &Prev{Manifest: m, Index: idx}, nil
}

func readSigned(p string) (raw, sig []byte, err error) {
	if raw, err = readDoc(p); err != nil {
		return nil, nil, err
	}
	if sig, err = readSmall(p+".minisig", release.MaxSigBytes); err != nil {
		return nil, nil, err
	}
	return raw, sig, nil
}

func verifyIndexFile(dir string, trust release.Trust, stored *release.Index) (*release.Index, error) {
	raw, sig, err := readSigned(filepath.Join(dir, indexFile))
	if err != nil {
		return nil, err
	}
	return release.VerifyIndex(raw, sig, trust, stored)
}

// SignRelease signs the documents of dir with s: index.json and any index.v<N>.json always, release-manifest.json only for the
// active key. The backup slot (the offline key, D-103) signs indexes only, into <file>.backup.minisig; it exists to revoke a
// leaked active key, never to sign a release. It returns the signature files written.
func SignRelease(ctx context.Context, s Signer, dir string, backup bool) ([]string, error) {
	names, err := filepath.Glob(filepath.Join(dir, "index*.json"))
	if err != nil {
		return nil, err
	}
	var docs []string
	for _, n := range names {
		if b := filepath.Base(n); b == indexFile || (strings.HasPrefix(b, "index.v") && strings.HasSuffix(b, ".json")) {
			docs = append(docs, n)
		}
	}
	if !slices.Contains(docs, filepath.Join(dir, indexFile)) {
		return nil, errors.New("no index.json to sign: run release index first")
	}
	slices.Sort(docs)
	if !backup {
		docs = append(docs, filepath.Join(dir, manifestFile))
	}
	var written []string
	for _, p := range docs {
		raw, err := readDoc(p)
		if err != nil {
			return written, err
		}
		tc, err := trustedComment(filepath.Base(p), raw)
		if err != nil {
			return written, err
		}
		sigPath := p + ".minisig"
		if backup {
			sigPath = p + ".backup.minisig"
		}
		if err := s.SignFile(ctx, p, sigPath, tc); err != nil {
			return written, err
		}
		written = append(written, sigPath)
	}
	return written, nil
}

// trustedComment says what a signature is for: the file name and the sequence or version (a signature over an index is not
// mistaken for one over a manifest when the files are later listed side by side).
func trustedComment(name string, raw []byte) (string, error) {
	var d struct {
		Sequence uint64 `json:"sequence"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	if name == manifestFile {
		return "file:" + name + " version:" + d.Version, nil
	}
	return fmt.Sprintf("file:%s sequence:%d", name, d.Sequence), nil
}

// Summary is what VerifyDir found.
type Summary struct {
	Sequence   uint64
	Version    string
	Channel    string
	IndexKeyID string
	Images     []string // service@digest, each cosign signature verified
	BackupSig  bool     // the backup key's index signature was present and verified
}

// VerifyDir is the check before anything is published: it runs the box-side verifier of internal/release over the output,
// with the keys of trust. The index (against the previous index when prevDir is given, so a sequence that goes back is
// refused), the manifest (signature, revocation, refs), the manifest's hash in the index, the index's latest for the
// manifest's channel, and every image's cosign signature against its digest.
func VerifyDir(dir, prevDir string, trust release.Trust) (*Summary, error) {
	var stored *release.Index
	if prevDir != "" {
		p, err := LoadPrev(prevDir, trust)
		if err != nil {
			return nil, err
		}
		stored = p.Index
	}
	idx, err := verifyIndexFile(dir, trust, stored)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	s := &Summary{Sequence: idx.Sequence, IndexKeyID: idx.KeyID}
	if bsig, err := readSmall(filepath.Join(dir, indexFile+".backup.minisig"), release.MaxSigBytes); err == nil {
		raw, err := readDoc(filepath.Join(dir, indexFile))
		if err != nil {
			return nil, err
		}
		bx, err := release.VerifyIndex(raw, bsig, trust, stored)
		if err != nil {
			return nil, fmt.Errorf("index backup signature: %w", err)
		}
		if bx.KeyID != trust.Backup.KeyID() {
			return nil, errors.New("index.json.backup.minisig is not signed by the backup key")
		}
		s.BackupSig = true
	}
	mraw, msig, err := readSigned(filepath.Join(dir, manifestFile))
	if err != nil {
		return nil, err
	}
	m, err := release.VerifyManifest(mraw, msig, trust, idx)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	s.Version, s.Channel = m.Version, m.Channel
	if m.KeyID != trust.Active.KeyID() {
		return nil, errors.New("the manifest is not signed by the active key")
	}
	if err := release.CheckManifestSHA256(idx, m.Channel, mraw); err != nil {
		return nil, fmt.Errorf("index does not describe this manifest: %w", err)
	}
	if idx.Channels[m.Channel].Latest != m.Version {
		return nil, fmt.Errorf("index says channel %s is at %s, the manifest is %s", m.Channel, idx.Channels[m.Channel].Latest, m.Version)
	}
	for _, im := range m.Images {
		if err := release.VerifyImage(m, im.Service, im.Digest, trust); err != nil {
			return nil, fmt.Errorf("image %s: %w", im.Service, err)
		}
		s.Images = append(s.Images, im.Service+"@"+im.Digest)
	}
	return s, nil
}
