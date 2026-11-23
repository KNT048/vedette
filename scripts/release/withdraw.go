package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/knt048/vedette/internal/release"
)

// Withdrawing a published release (update-manifest.md §8): an index that adds a revocation of kind "release" (one version) or
// "image_digest" (one image), numbered and signed like every index. A box that verifies it never installs the release or the image
// again (VerifyManifest refuses it, the host refuses to pull it), offers nothing that is withdrawn, and a box that runs it shows the
// reason (Settings -> Updates; on every page for block_install_and_warn). The rows carry into every later index (BuildIndex copies the
// previous index's list, and a box carries them itself, revoke.go in internal/release).
//
// The builder refuses what would leave boxes in an undefined state:
//   - a version or digest it cannot tie to a published release: each must be named by a signed release-manifest.json given as
//     evidence (-revoked-manifest), verified with the release keys, and when the release is a channel's latest, the very bytes the
//     published index announces;
//   - a row the index already has, the same row twice, and a withdrawal of the release this same index announces;
//   - a channel whose latest release is withdrawn without saying what the channel offers now: move it back to an earlier release of
//     the channel that is not withdrawn (-channel-manifest, its signed manifest), or keep it naming the withdrawn one
//     (-hold-channel: boxes on that channel are offered nothing until the next release);
//   - the action rollback_if_possible: boxes do not roll back by themselves yet, so it would promise what no box does.

// SignedRelease is a published release-manifest.json, verified with the release keys.
type SignedRelease struct {
	M      *release.Manifest
	Raw    []byte
	SHA256 string
}

// LoadSignedRelease reads path and path.minisig (the two files of a GitHub release: gh release download v<version> -p
// 'release-manifest.json*') and verifies them with trust. Revocations do not matter here (the manifest is evidence, not something to
// install), so it is verified against an index that revokes nothing.
func LoadSignedRelease(path string, trust release.Trust) (*SignedRelease, error) {
	raw, sig, err := readSigned(path)
	if err != nil {
		return nil, err
	}
	m, err := release.VerifyManifest(raw, sig, trust, &release.Index{})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sum := sha256.Sum256(raw)
	return &SignedRelease{M: m, Raw: raw, SHA256: hex.EncodeToString(sum[:])}, nil
}

// Withdrawal is what an index withdraws, and what the channels that offered it offer instead.
type Withdrawal struct {
	Releases []string // versions to revoke (kind release)
	Digests  []string // image digests to revoke (kind image_digest)
	Action   string   // block_install or block_install_and_warn (default)
	// Evidence are the signed manifests of the releases Releases and Digests name.
	Evidence []*SignedRelease
	// MoveTo are signed manifests of earlier releases: each channel whose latest is withdrawn moves back to the one of its channel.
	MoveTo []*SignedRelease
	// Hold are channels whose latest is withdrawn and that keep naming it.
	Hold []string
}

func (w Withdrawal) revokes() bool { return len(w.Releases) > 0 || len(w.Digests) > 0 }

func (w Withdrawal) empty() bool {
	return !w.revokes() && len(w.Evidence) == 0 && len(w.MoveTo) == 0 && len(w.Hold) == 0 && w.Action == ""
}

// defaultWithdrawAction tells the boxes that run the release on every page: a withdrawn release is one an administrator should
// replace.
const defaultWithdrawAction = "block_install_and_warn"

// withdrawn is what addWithdrawals made unavailable.
type withdrawn struct {
	releases, digests map[string]bool
}

func hasRevocation(x *release.Index, kind, id string) *release.Revocation {
	for i := range x.Revoked {
		if x.Revoked[i].Kind == kind && x.Revoked[i].ID == id {
			return &x.Revoked[i]
		}
	}
	return nil
}

// addWithdrawals appends the release and digest revocations of w to x, the index being built on a previous one (channels as they
// were published). announced is the version this index announces, and announcedRaw its manifest ("" and nil for none).
func addWithdrawals(x *release.Index, w Withdrawal, reason string, hasPrev bool, announced string, announcedRaw []byte) (withdrawn, error) {
	out := withdrawn{releases: map[string]bool{}, digests: map[string]bool{}}
	if w.empty() {
		return out, nil
	}
	if !w.revokes() {
		return out, errors.New("-revoked-manifest, -channel-manifest, -hold-channel and -revoke-action go with -revoke-release or -revoke-digest")
	}
	if !hasPrev {
		return out, errors.New("withdrawing a release needs -prev-index: the published index it carries on from")
	}
	if err := checkRevokeReason(reason); err != nil {
		return out, err
	}
	action := w.Action
	switch action {
	case "":
		action = defaultWithdrawAction
	case "block_install", "block_install_and_warn":
	case "rollback_if_possible":
		return out, errors.New("-revoke-action rollback_if_possible: boxes do not roll back by themselves yet, it would show like block_install_and_warn; use that")
	default:
		return out, fmt.Errorf("-revoke-action %q: block_install (the Updates page only) or block_install_and_warn (a banner on every page)", w.Action)
	}
	byVersion := map[string]*SignedRelease{}
	for _, ev := range w.Evidence {
		if byVersion[ev.M.Version] != nil {
			return out, fmt.Errorf("-revoked-manifest names release %s twice", ev.M.Version)
		}
		byVersion[ev.M.Version] = ev
		for name, c := range x.Channels {
			if c.Latest == ev.M.Version && c.ManifestSHA256 != ev.SHA256 {
				return out, fmt.Errorf("the manifest of %s given is not the one the published index announces for channel %s (sha256 %s): download it again from the release", ev.M.Version, name, c.ManifestSHA256)
			}
		}
	}
	var announcedImages []string
	if announcedRaw != nil {
		var m struct {
			Images []struct {
				Digest string `json:"digest"`
			} `json:"images"`
		}
		if err := json.Unmarshal(announcedRaw, &m); err == nil {
			for _, im := range m.Images {
				announcedImages = append(announcedImages, im.Digest)
			}
		}
	}
	add := func(kind, id string) {
		x.Revoked = append(x.Revoked, release.Revocation{Kind: kind, ID: id, Reason: reason, Since: x.GeneratedAt, Action: action})
	}
	for _, v := range w.Releases {
		switch {
		case out.releases[v]:
			return out, fmt.Errorf("release %s is named twice", v)
		case !validSemVer(v):
			return out, fmt.Errorf("release %q is not a SemVer version", v)
		case v == announced:
			return out, fmt.Errorf("release %s is the one this index announces: withdraw it in a later index, or do not announce it", v)
		case byVersion[v] == nil:
			return out, fmt.Errorf("unknown release %s: give its published, signed release-manifest.json with -revoked-manifest (gh release download v%s -p 'release-manifest.json*')", v, v)
		}
		if r := hasRevocation(x, release.KindRelease, v); r != nil {
			return out, fmt.Errorf("release %s is already revoked (since %s, %s)", v, r.Since.Format("2006-01-02"), r.Action)
		}
		out.releases[v] = true
		add(release.KindRelease, v)
	}
	for _, d := range w.Digests {
		switch {
		case out.digests[d]:
			return out, fmt.Errorf("image digest %s is named twice", d)
		case !serviceDigestRE.MatchString(d):
			return out, fmt.Errorf("%q is not an image digest (sha256: and 64 lower-case hex)", d)
		case slices.Contains(announcedImages, d):
			return out, fmt.Errorf("image digest %s is in the release this index announces", d)
		}
		if !slices.ContainsFunc(w.Evidence, func(ev *SignedRelease) bool {
			return slices.ContainsFunc(ev.M.Images, func(im release.Image) bool { return im.Digest == d })
		}) {
			return out, fmt.Errorf("unknown image digest %s: it is in none of the -revoked-manifest releases", d)
		}
		if r := hasRevocation(x, release.KindImageDigest, d); r != nil {
			return out, fmt.Errorf("image digest %s is already revoked (since %s, %s)", d, r.Since.Format("2006-01-02"), r.Action)
		}
		out.digests[d] = true
		add(release.KindImageDigest, d)
	}
	for _, ev := range w.Evidence {
		if !out.releases[ev.M.Version] && !slices.ContainsFunc(ev.M.Images, func(im release.Image) bool { return out.digests[im.Digest] }) {
			return out, fmt.Errorf("-revoked-manifest %s: neither that release nor any of its images is withdrawn by -revoke-release or -revoke-digest", ev.M.Version)
		}
	}
	return out, nil
}

// pointWithdrawnChannels decides each channel whose latest release this index withdraws (after a release this index announces has
// moved its channel on): back to an earlier release (w.MoveTo) or held (w.Hold); a channel hit with neither is refused, and so is
// either for a channel that is not hit.
func pointWithdrawnChannels(x *release.Index, w Withdrawal, wd withdrawn, rollout int) error {
	hit := func(c release.Channel) bool {
		return wd.releases[c.Latest] || slices.ContainsFunc(w.Evidence, func(ev *SignedRelease) bool {
			return ev.SHA256 == c.ManifestSHA256 && slices.ContainsFunc(ev.M.Images, func(im release.Image) bool { return wd.digests[im.Digest] })
		})
	}
	hold := map[string]bool{}
	for _, name := range w.Hold {
		if hold[name] {
			return fmt.Errorf("-hold-channel %s is given twice", name)
		}
		hold[name] = true
	}
	moveTo := map[string]*SignedRelease{}
	for _, ev := range w.MoveTo {
		if moveTo[ev.M.Channel] != nil {
			return fmt.Errorf("-channel-manifest gives two releases for channel %s", ev.M.Channel)
		}
		moveTo[ev.M.Channel] = ev
	}
	for _, name := range slices.Sorted(maps.Keys(hold)) {
		if _, ok := x.Channels[name]; !ok {
			return fmt.Errorf("-hold-channel %s: the index has no channel %s", name, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(moveTo)) {
		if _, ok := x.Channels[name]; !ok {
			return fmt.Errorf("-channel-manifest %s is a release of channel %s, which the index does not have", moveTo[name].M.Version, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(x.Channels)) {
		c := x.Channels[name]
		to := moveTo[name]
		if !hit(c) {
			if hold[name] || to != nil {
				return fmt.Errorf("channel %s offers %s, which this index does not withdraw: -hold-channel and -channel-manifest are only for a channel whose latest release is withdrawn", name, c.Latest)
			}
			continue
		}
		switch {
		case hold[name] && to != nil:
			return fmt.Errorf("channel %s: -hold-channel or -channel-manifest, not both", name)
		case hold[name]:
			continue
		case to == nil:
			return fmt.Errorf("this index withdraws %s, the latest release of channel %s: say what the channel offers now, -channel-manifest FILE "+
				"(the signed release-manifest.json of an earlier release of that channel, which boxes below it are then offered) or -hold-channel %s "+
				"(the channel keeps naming the withdrawn release, so its boxes are offered nothing until the next release)", c.Latest, name, name)
		}
		v := to.M.Version
		cmp, err := release.CompareVersions(v, c.Latest)
		if err != nil || cmp >= 0 {
			return fmt.Errorf("-channel-manifest %s is not below %s, the withdrawn latest of channel %s: a newer release is announced with -manifest", v, c.Latest, name)
		}
		if hasRevocation(x, release.KindRelease, v) != nil || slices.ContainsFunc(to.M.Images, func(im release.Image) bool { return hasRevocation(x, release.KindImageDigest, im.Digest) != nil }) {
			return fmt.Errorf("-channel-manifest %s is withdrawn too: move channel %s to a release no box refuses", v, name)
		}
		if rollout < 0 {
			rollout = 100
		}
		x.Channels[name] = release.Channel{Latest: v, Manifest: manifestURL(v), ManifestSHA256: to.SHA256, Rollout: &release.Rollout{Percent: rollout}}
	}
	return nil
}

// checkRevokeReason: the reason every revocation row carries, which boxes show as given.
func checkRevokeReason(reason string) error {
	if reason == "" || len(reason) > 256 || strings.IndexFunc(reason, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("a revocation needs a reason (-revoke-reason): one line of at most 256 bytes, which boxes show as given")
	}
	return nil
}

func validSemVer(v string) bool {
	_, err := release.CompareVersions(v, v)
	return err == nil
}

// checkChannelsMovedBack is VerifyDir's check of an index without a manifest: each channel is as published, or moved back to an
// earlier release because the new index withdraws the one it offered (the index's builder checked the signed manifests; here the
// rule is checked again on the signed index alone). It returns the channels moved and the revocations the new index adds.
func checkChannelsMovedBack(stored, idx *release.Index) (moved, added []string, err error) {
	added = addedWithdrawals(stored, idx)
	for _, name := range slices.Sorted(maps.Keys(idx.Channels)) {
		c := idx.Channels[name]
		old, ok := stored.Channels[name]
		if ok && old.Latest == c.Latest && old.Rollout != nil && c.Rollout != nil && *old.Rollout == *c.Rollout {
			continue
		}
		if !ok {
			return nil, nil, fmt.Errorf("channel %s is new, and no manifest is here to announce it", name)
		}
		down, cerr := release.CompareVersions(c.Latest, old.Latest)
		// The old latest is withdrawn: by version, or by an image digest this index adds (which image is whose, the builder checked).
		gone := hasRevocation(idx, release.KindRelease, old.Latest) != nil || slices.ContainsFunc(added, func(a string) bool { return strings.HasPrefix(a, release.KindImageDigest+" ") })
		switch {
		case cerr != nil || down >= 0 || !gone:
			return nil, nil, fmt.Errorf("channel %s differs from the published index, and no manifest is here to announce it", name)
		case hasRevocation(idx, release.KindRelease, c.Latest) != nil:
			return nil, nil, fmt.Errorf("channel %s moves back to %s, which the index withdraws too", name, c.Latest)
		case c.Manifest != manifestURL(c.Latest):
			return nil, nil, fmt.Errorf("channel %s moves back to %s with a manifest URL that is not that release's", name, c.Latest)
		}
		moved = append(moved, fmt.Sprintf("%s %s -> %s", name, old.Latest, c.Latest))
	}
	for name := range stored.Channels {
		if _, ok := idx.Channels[name]; !ok {
			return nil, nil, fmt.Errorf("channel %s is gone from the new index", name)
		}
	}
	return moved, added, nil
}

// addedWithdrawals lists the release and image-digest revocations idx has and stored lacks ("release 0.2.0").
func addedWithdrawals(stored, idx *release.Index) []string {
	var added []string
	for _, r := range idx.Revoked {
		if hasRevocation(stored, r.Kind, r.ID) == nil && (r.Kind == release.KindRelease || r.Kind == release.KindImageDigest) {
			added = append(added, r.Kind+" "+r.ID)
		}
	}
	return added
}
