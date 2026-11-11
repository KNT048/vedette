package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// manifestURL is where a release's manifest is published (D-150: GitHub Releases of the repository).
func manifestURL(version string) string {
	return "https://github.com/knt048/vedette/releases/download/v" + version + "/release-manifest.json"
}

// indexSchema is the schema of the index the builder writes; it is the schema internal/release verifies.
var indexSchema = 1

// legacyWriters turn the index being published into the document of an older schema (D-108: the previous schema's index keeps
// being published beside the new one for at least 12 months, so boxes that cannot read the new schema still see revocations).
// Schema 1 is the first schema, so there is nothing to write yet. When indexSchema becomes 2, add legacyWriters[1] here: until
// then BuildIndex refuses to publish, instead of publishing an index no old box can read.
var legacyWriters = map[int]func(release.Index) ([]byte, error){}

// IndexFile is one file of the output: index.json, or index.v<N>.json for a legacy schema.
type IndexFile struct {
	Name string
	Data []byte
}

// IndexParams says what changes in the index. A zero Manifest only refreshes it (the weekly re-sign, D-150).
type IndexParams struct {
	Now      time.Time
	ValidFor time.Duration // expires_at = generated_at + ValidFor; 0 = 14 days, the maximum
	Sequence uint64        // 0 = the previous sequence + 1 (1 for the first index)
	Rollout  int           // percent for the channel of a new manifest; -1 = unset (100)

	Channel         string // channel of the manifest
	ManifestVersion string // empty: no new manifest
	ManifestRaw     []byte // the signed bytes of that manifest: the index carries their SHA-256
}

// BuildIndex builds index.json (unsigned) from the previous verified index and the new manifest. Revocations, advisories and
// the other channel carry over unchanged, so a chain of indexes never forgets a revocation. It refuses a sequence that does not
// go up, a channel whose latest version would go down, and an expiry past the 14-day maximum.
func BuildIndex(prev *release.Index, p IndexParams) ([]IndexFile, error) {
	x := release.Index{
		Schema: indexSchema, GeneratedAt: p.Now.UTC().Truncate(time.Second),
		Channels: map[string]release.Channel{}, Revoked: []release.Revocation{}, Advisories: []release.Advisory{}, Keys: []release.KeyInfo{},
	}
	valid := p.ValidFor
	if valid == 0 {
		valid = 14 * 24 * time.Hour
	}
	if valid < 0 || valid > 14*24*time.Hour {
		return nil, errors.New("an index may be valid for at most 14 days (update-manifest.md 4.1)")
	}
	x.ExpiresAt = x.GeneratedAt.Add(valid)
	var prevSeq uint64
	if prev != nil {
		prevSeq = prev.Sequence
		for k, v := range prev.Channels {
			x.Channels[k] = v
		}
		x.Revoked = append(x.Revoked, prev.Revoked...)
		x.Advisories = append(x.Advisories, prev.Advisories...)
		x.Keys = append(x.Keys, prev.Keys...)
	}
	x.Sequence = p.Sequence
	if x.Sequence == 0 {
		x.Sequence = prevSeq + 1
	}
	if x.Sequence <= prevSeq {
		return nil, fmt.Errorf("sequence %d is not above the previous index's %d", x.Sequence, prevSeq)
	}
	if p.ManifestVersion != "" {
		if _, err := release.CompareVersions(p.ManifestVersion, p.ManifestVersion); err != nil {
			return nil, fmt.Errorf("manifest version %q is not SemVer", p.ManifestVersion)
		}
		if p.Channel != "stable" && p.Channel != "beta" {
			return nil, fmt.Errorf("channel must be stable or beta, got %q", p.Channel)
		}
		if len(p.ManifestRaw) == 0 {
			return nil, errors.New("a new manifest needs its bytes (the index carries their SHA-256)")
		}
		if old, ok := x.Channels[p.Channel]; ok {
			c, err := release.CompareVersions(p.ManifestVersion, old.Latest)
			if err != nil {
				return nil, err
			}
			if c < 0 {
				return nil, fmt.Errorf("channel %s would go from %s down to %s; withdraw a release with a revocation, not by lowering latest", p.Channel, old.Latest, p.ManifestVersion)
			}
		}
		rollout := p.Rollout
		if rollout < 0 {
			rollout = 100
		}
		if rollout > 100 {
			return nil, errors.New("rollout percent is above 100")
		}
		sum := sha256.Sum256(p.ManifestRaw)
		x.Channels[p.Channel] = release.Channel{
			Latest: p.ManifestVersion, Manifest: manifestURL(p.ManifestVersion), ManifestSHA256: hex.EncodeToString(sum[:]),
			Rollout: &release.Rollout{Percent: rollout},
		}
	}
	if len(x.Channels) == 0 {
		return nil, errors.New("an index needs at least one channel: give the manifest of the first release")
	}
	cur, err := marshal(x)
	if err != nil {
		return nil, err
	}
	files := []IndexFile{{"index.json", cur}}
	for s := 1; s < indexSchema; s++ {
		w, ok := legacyWriters[s]
		if !ok {
			return nil, fmt.Errorf("no writer for the schema %d index: D-108 requires publishing it beside schema %d for at least 12 months", s, indexSchema)
		}
		b, err := w(x)
		if err != nil {
			return nil, fmt.Errorf("legacy schema %d index: %w", s, err)
		}
		files = append(files, IndexFile{fmt.Sprintf("index.v%d.json", s), b})
	}
	return files, nil
}
