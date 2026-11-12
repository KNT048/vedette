package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	// MinSequence is the floor compiled into the vedette-host of this release (MIN_SEQUENCE, the sequence of the index current at
	// build time): the new index must be numbered above it, or boxes running that host would refuse it. 0 = none.
	MinSequence uint64

	Channel         string // channel of the manifest
	ManifestVersion string // empty: no new manifest
	ManifestRaw     []byte // the signed bytes of that manifest: the index carries their SHA-256

	// RevokeKeys are key ids (minisign: 16 upper-case hex; cosign: CosignKeyID) to revoke, with RevokeReason. A key revocation
	// counts only in an index the backup key signs (D-108 M1), and it is never dropped again; BackupKeyID can never be revoked.
	RevokeKeys   []string
	RevokeReason string
	BackupKeyID  string
}

// keyIDRE is the form of a key id in a key revocation (internal/release Revocation.validate).
var keyIDRE = regexp.MustCompile(`^(?:[0-9A-F]{16}|[0-9a-f]{64})$`)

// maxSequenceJump is the largest step of an explicit -sequence.
const maxSequenceJump = 10

// checkChannelsStable refuses an index that announces, for a channel and version the previous index already announced, another
// manifest (hash or URL): a published release is immutable, a changed one needs a new version (and boxes that pulled the old one
// would otherwise hold a manifest the index no longer describes).
func checkChannelsStable(prev, cur *release.Index) error {
	for name, c := range cur.Channels {
		old, ok := prev.Channels[name]
		if ok && old.Latest == c.Latest && (old.ManifestSHA256 != c.ManifestSHA256 || old.Manifest != c.Manifest) {
			return fmt.Errorf("channel %s is still at %s but its manifest hash or URL changed: a published release is immutable, release a new version", name, c.Latest)
		}
	}
	return nil
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
	if err := addKeyRevocations(&x, p); err != nil {
		return nil, err
	}
	x.Sequence = p.Sequence
	if x.Sequence == 0 {
		x.Sequence = prevSeq + 1
	}
	if x.Sequence <= prevSeq {
		return nil, fmt.Errorf("sequence %d is not above the previous index's %d", x.Sequence, prevSeq)
	}
	if x.Sequence <= p.MinSequence {
		return nil, fmt.Errorf("sequence %d is not above %d, the floor (MIN_SEQUENCE) compiled into this release's vedette-host", x.Sequence, p.MinSequence)
	}
	// A box never accepts a lower sequence than it stored, so a typo that jumps ahead strands every box until the next signed index
	// is numbered above it: a bigger step than a few weeks of refreshes is refused.
	if x.Sequence > prevSeq+maxSequenceJump {
		return nil, fmt.Errorf("sequence %d is more than %d above the previous index's %d; a box could never accept a lower one again", x.Sequence, maxSequenceJump, prevSeq)
	}
	if p.ManifestVersion != "" {
		if err := refuseTestVersion(p.ManifestVersion); err != nil {
			return nil, err
		}
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
	if prev != nil {
		if err := checkChannelsStable(prev, &x); err != nil {
			return nil, err
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

// addKeyRevocations appends the key revocations of p to x (D-259): the rescue index revokes the leaked active key.
func addKeyRevocations(x *release.Index, p IndexParams) error {
	if len(p.RevokeKeys) == 0 {
		if p.RevokeReason != "" {
			return errors.New("a revocation reason without a key to revoke")
		}
		return nil
	}
	if p.RevokeReason == "" || len(p.RevokeReason) > 256 || strings.IndexFunc(p.RevokeReason, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("a key revocation needs a reason: one line of at most 256 bytes")
	}
	if p.BackupKeyID == "" {
		return errors.New("revoking a key needs the backup key id, which can never be revoked")
	}
	for _, id := range p.RevokeKeys {
		switch {
		case !keyIDRE.MatchString(id):
			return fmt.Errorf("%q is not a key id (minisign: 16 upper-case hex; cosign: 64 lower-case hex)", id)
		case id == p.BackupKeyID:
			return fmt.Errorf("%s is the backup key: no index can revoke it (D-108)", id)
		case x.KeyRevoked(id):
			return fmt.Errorf("key %s is already revoked", id)
		}
		x.Revoked = append(x.Revoked, release.Revocation{Kind: release.KindKey, ID: id, Reason: p.RevokeReason, Since: x.GeneratedAt, Action: "block_install"})
	}
	return nil
}
