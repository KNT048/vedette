package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
// `cosign generate-key-pair` write). An empty dir means the keys compiled into this build: the real release keys (D-256)
// in a normal build, the throwaway ones with the releasetestkeys tag; a build whose keys do not validate refuses.
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

// LoadPrevIndex reads and verifies the published index held in dir (index.json and its .minisig) with the verifier of
// internal/release. It is the one thing a new release builds on besides the git trees: its sequence, revocations, advisories and
// channels carry over. No previous manifest is read or needed, so a revoked or withdrawn release cannot block the next one.
func LoadPrevIndex(dir string, trust release.Trust) (*release.Index, error) {
	idx, err := verifyIndexFile(dir, trust, nil)
	if err != nil {
		return nil, fmt.Errorf("published index: %w", err)
	}
	return idx, nil
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

// SignRelease signs the documents of dir with s: index.json and any index.v<N>.json always, and release-manifest.json when there
// is one (a weekly refresh of the index, D-150, has none) and only for the active key. The backup slot (the offline key, D-103)
// signs indexes only, into <file>.backup.minisig; it exists to revoke a leaked active key. Signing the rescue manifest after such a
// leak (D-258) is not supported yet. It returns the
// signature files written. When anything fails, every signature written in this run is removed: a directory holds either all the
// signatures of the run or none of them.
func SignRelease(ctx context.Context, s Signer, dir string, backup bool) (written []string, err error) {
	defer func() {
		if err != nil {
			for _, w := range written {
				_ = os.Remove(w)
			}
			written = nil
		}
	}()
	names, err := filepath.Glob(filepath.Join(dir, "index*.json"))
	if err != nil {
		return nil, err
	}
	var docs []string
	for _, n := range names {
		if b := filepath.Base(n); b == indexFile || isLegacyIndex(b) {
			docs = append(docs, n)
		}
	}
	if !slices.Contains(docs, filepath.Join(dir, indexFile)) {
		return nil, errors.New("no index.json to sign: run release index first")
	}
	slices.Sort(docs)
	if m := filepath.Join(dir, manifestFile); !backup {
		if _, err := os.Stat(m); err == nil {
			docs = append(docs, m)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
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
		written = append(written, sigPath) // before the call: a signer that fails half way may have left the file
		if err := s.SignFile(ctx, p, sigPath, tc); err != nil {
			return written, err
		}
	}
	return written, nil
}

func isLegacyIndex(base string) bool {
	return strings.HasPrefix(base, "index.v") && strings.HasSuffix(base, ".json") && !strings.Contains(base, ".minisig")
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
	Version    string // empty for an index-only directory
	Channel    string
	IndexKeyID string
	Images     []string // service@digest, each cosign signature verified
	BackupSig  bool     // the backup key's index signature was present and verified
	IndexOnly  bool     // no manifest in the directory: a refresh of the index
}

// legacyVerifiers check an index.v<N>.json and its signature. A legacy index is a document of a schema this build cannot
// parse, so there is nothing to check it with until the schema moves on: the entry for schema N is added together with
// legacyWriters[N] (index.go). Until then VerifyDir refuses a directory that holds one, instead of passing a file nobody verified.
var legacyVerifiers = map[int]func(raw, sig []byte, trust release.Trust) error{}

// VerifyDir is the check before anything is published: it runs the box-side verifier of internal/release over the output,
// with the keys of trust. stored is the published index the box holds now (prevDir, verified first): the new index must not go
// back in sequence, and a channel that stays at the same version must keep the same manifest. Then the manifest (signature,
// revocation, refs), its hash in the index, the index's latest for its channel, and every image's cosign signature against its
// digest. A directory without a manifest is a refresh of the index (D-150): the index is checked against stored, the channels
// must be unchanged apart from the sequence and dates, and nothing else exists to check.
func VerifyDir(dir, prevDir string, trust release.Trust) (*Summary, error) {
	var stored *release.Index
	if prevDir != "" {
		p, err := LoadPrevIndex(prevDir, trust)
		if err != nil {
			return nil, err
		}
		stored = p
	}
	idx, err := verifyIndexFile(dir, trust, stored)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	if stored != nil {
		if err := checkChannelsStable(stored, idx); err != nil {
			return nil, err
		}
	}
	s := &Summary{Sequence: idx.Sequence, IndexKeyID: idx.KeyID}
	raw, err := readDoc(filepath.Join(dir, indexFile))
	if err != nil {
		return nil, err
	}
	switch bsig, err := readSmall(filepath.Join(dir, indexFile+".backup.minisig"), release.MaxSigBytes); {
	case err == nil:
		bx, err := release.VerifyIndex(raw, bsig, trust, stored)
		if err != nil {
			return nil, fmt.Errorf("index backup signature: %w", err)
		}
		if bx.KeyID != trust.Backup.KeyID() {
			return nil, errors.New("index.json.backup.minisig is not signed by the backup key")
		}
		s.BackupSig = true
	case !errors.Is(err, os.ErrNotExist): // an unreadable or oversized file is not an absent one
		return nil, fmt.Errorf("index backup signature: %w", err)
	}
	if err := verifyLegacyIndexes(dir, trust); err != nil {
		return nil, err
	}
	mraw, msig, err := readSigned(filepath.Join(dir, manifestFile))
	if errors.Is(err, os.ErrNotExist) {
		if _, serr := os.Stat(filepath.Join(dir, manifestFile)); serr == nil {
			return nil, fmt.Errorf("manifest: %w", err) // the manifest is there and its signature is not
		}
		if stored == nil {
			return nil, errors.New("a directory without a manifest is a refresh of the index: give the published index (-prev-index) to check it against")
		}
		for name, c := range idx.Channels {
			if old, ok := stored.Channels[name]; !ok || old.Latest != c.Latest || old.Rollout == nil || c.Rollout == nil || *old.Rollout != *c.Rollout {
				return nil, fmt.Errorf("channel %s differs from the published index, and no manifest is here to announce it", name)
			}
		}
		for name := range stored.Channels {
			if _, ok := idx.Channels[name]; !ok {
				return nil, fmt.Errorf("channel %s is gone from the refreshed index", name)
			}
		}
		s.IndexOnly = true
		return s, nil
	}
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

// verifyLegacyIndexes refuses an index.v<N>.json that has no verifier (see legacyVerifiers) or does not pass its verifier.
func verifyLegacyIndexes(dir string, trust release.Trust) error {
	names, err := filepath.Glob(filepath.Join(dir, "index.v*.json"))
	if err != nil {
		return err
	}
	for _, n := range names {
		var schema int
		if _, err := fmt.Sscanf(filepath.Base(n), "index.v%d.json", &schema); err != nil {
			return fmt.Errorf("%s: not an index.v<N>.json name", filepath.Base(n))
		}
		verify, ok := legacyVerifiers[schema]
		if !ok {
			return fmt.Errorf("%s is a legacy index (D-108) and this build has no verifier for schema %d: do not publish a file nobody verified", filepath.Base(n), schema)
		}
		raw, sig, err := readSigned(n)
		if err != nil {
			return err
		}
		if err := verify(raw, sig, trust); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(n), err)
		}
	}
	return nil
}
