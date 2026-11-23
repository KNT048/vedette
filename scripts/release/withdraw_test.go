//nolint:gosec // test code: every path is in a directory the test made
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/internal/release"
)

// withdrawRig is two published releases on stable, 0.1.0 then 0.2.0, and their signed manifests.
type withdrawRig struct {
	r              *rig
	pub1, pub2     string // the release directories; pub2 holds the index boxes have now
	rel1, rel2     *SignedRelease
	published      *release.Index // pub2's index as a box verified it
	publishedRaw   []byte
	publishedSig   []byte
	sensor2, core2 string // image digests of 0.2.0
}

func newWithdrawRig(t *testing.T) *withdrawRig {
	t.Helper()
	w := &withdrawRig{r: newRig(t)}
	var err error
	w.pub1, err = w.r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	w.pub2, err = w.r.build(buildOpts{version: "0.2.0", channel: "stable", cur: addOnlyTree, prevDir: w.pub1})
	must(t, err)
	w.rel1, err = LoadSignedRelease(filepath.Join(w.pub1, manifestFile), w.r.trust)
	must(t, err)
	w.rel2, err = LoadSignedRelease(filepath.Join(w.pub2, manifestFile), w.r.trust)
	must(t, err)
	w.publishedRaw, w.publishedSig = readSignedT(t, w.pub2, indexFile)
	w.published, err = release.VerifyIndex(w.publishedRaw, w.publishedSig, w.r.trust, nil)
	must(t, err)
	for _, im := range w.rel2.M.Images {
		switch im.Service {
		case "sensor":
			w.sensor2 = im.Digest
		case "core":
			w.core2 = im.Digest
		}
	}
	return w
}

// index builds an index without a manifest on top of the published one, signs it with the active key and returns its directory.
func (w *withdrawRig) index(t *testing.T, prev *release.Index, wd Withdrawal) (string, error) {
	t.Helper()
	reason := ""
	if wd.revokes() {
		reason = "0.2.0 deletes findings on upgrade"
	}
	files, err := BuildIndex(prev, IndexParams{Now: t1.Add(time.Hour), Rollout: -1, RevokeReason: reason, BackupKeyID: w.r.trust.Backup.KeyID(), Withdraw: wd})
	if err != nil {
		return "", err
	}
	dir := t.TempDir()
	for _, f := range files {
		must(t, os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o600))
	}
	_, err = SignRelease(context.Background(), testSigner{t, w.r.active}, dir, slotActive)
	must(t, err)
	return dir, nil
}

// boxSees is what a box that holds stored makes of the index of dir, with the verifier every box runs.
func (w *withdrawRig) boxSees(t *testing.T, dir string, stored *release.Index) *release.Index {
	t.Helper()
	raw, sig := readSignedT(t, dir, indexFile)
	idx, err := release.VerifyIndex(raw, sig, w.r.trust, stored)
	if err != nil {
		t.Fatalf("the box refuses the withdrawal index: %v", err)
	}
	return idx
}

func manifestVerdict(t *testing.T, w *withdrawRig, dir string, idx *release.Index) error {
	t.Helper()
	raw, sig := readSignedT(t, dir, manifestFile)
	_, err := release.VerifyManifest(raw, sig, w.r.trust, idx)
	return err
}

// The rehearsed withdrawal: 0.2.0 is revoked and stable moves back to 0.1.0. verify passes it, a box accepts the index, never
// installs 0.2.0 again, is offered 0.1.0 (the manifest hash the index names), and the revocation carries into the next indexes.
func TestWithdrawReleaseMovesTheChannelBack(t *testing.T) {
	w := newWithdrawRig(t)
	dir, err := w.index(t, w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{w.rel2}, MoveTo: []*SignedRelease{w.rel1}})
	must(t, err)
	s, err := VerifyDir(dir, w.pub2, w.r.trust)
	must(t, err)
	if !s.IndexOnly || s.Sequence != w.published.Sequence+1 || !slices.Equal(s.Withdrawn, []string{"release 0.2.0"}) || !slices.Equal(s.Moved, []string{"stable 0.2.0 -> 0.1.0"}) {
		t.Fatalf("%+v", s)
	}
	idx := w.boxSees(t, dir, w.published)
	if !errors.Is(manifestVerdict(t, w, w.pub2, idx), release.ErrReleaseRevoked) {
		t.Error("the box still accepts 0.2.0")
	}
	if err := manifestVerdict(t, w, w.pub1, idx); err != nil {
		t.Errorf("the box refuses 0.1.0, the release it is now offered: %v", err)
	}
	if err := release.CheckManifestSHA256(idx, "stable", w.rel1.Raw); err != nil || idx.Channels["stable"].Latest != "0.1.0" || idx.Channels["stable"].Manifest != manifestURL("0.1.0") {
		t.Errorf("stable: %+v %v", idx.Channels["stable"], err)
	}
	r := idx.Revoked[len(idx.Revoked)-1]
	if r.Kind != release.KindRelease || r.ID != "0.2.0" || r.Action != "block_install_and_warn" || r.Reason != "0.2.0 deletes findings on upgrade" {
		t.Errorf("%+v", r)
	}

	// The weekly refresh and the next release carry the row, and the channel moves on from 0.1.0.
	refresh, err := w.index(t, idx, Withdrawal{})
	must(t, err)
	if s, err := VerifyDir(refresh, dir, w.r.trust); err != nil || len(s.Withdrawn) != 0 || len(s.Moved) != 0 {
		t.Fatalf("refresh: %+v %v", s, err)
	}
	if ridx := w.boxSees(t, refresh, idx); hasRevocation(ridx, release.KindRelease, "0.2.0") == nil {
		t.Error("the refresh dropped the withdrawal")
	}
	next, err := w.r.build(buildOpts{version: "0.2.1", channel: "stable", cur: addOnlyTree, prevDir: dir})
	must(t, err)
	if _, err := VerifyDir(next, dir, w.r.trust); err != nil {
		t.Fatal(err)
	}
	if nidx := w.boxSees(t, next, idx); hasRevocation(nidx, release.KindRelease, "0.2.0") == nil || nidx.Channels["stable"].Latest != "0.2.1" {
		t.Errorf("%+v", nidx)
	}
}

// Holding the channel, and withdrawing one image: the channel keeps naming 0.2.0, which no box installs.
func TestWithdrawDigestHoldsTheChannel(t *testing.T) {
	w := newWithdrawRig(t)
	dir, err := w.index(t, w.published, Withdrawal{Digests: []string{w.sensor2}, Evidence: []*SignedRelease{w.rel2}, Hold: []string{"stable"}, Action: "block_install"})
	must(t, err)
	s, err := VerifyDir(dir, w.pub2, w.r.trust)
	must(t, err)
	if !slices.Equal(s.Withdrawn, []string{"image_digest " + w.sensor2}) || len(s.Moved) != 0 {
		t.Fatalf("%+v", s)
	}
	idx := w.boxSees(t, dir, w.published)
	if err := manifestVerdict(t, w, w.pub2, idx); !errors.Is(err, release.ErrReleaseRevoked) || idx.Channels["stable"].Latest != "0.2.0" {
		t.Errorf("0.2.0 with a withdrawn image: %v, stable %s", err, idx.Channels["stable"].Latest)
	}
	if err := manifestVerdict(t, w, w.pub1, idx); err != nil {
		t.Errorf("0.1.0 is not affected: %v", err)
	}
}

// A release that replaces the withdrawn one in the same index needs no channel decision: its channel moved on.
func TestWithdrawWithTheNextRelease(t *testing.T) {
	w := newWithdrawRig(t)
	dir, err := w.r.build(buildOpts{version: "0.2.1", channel: "stable", cur: addOnlyTree, prevDir: w.pub2,
		withdraw: Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{w.rel2}}})
	must(t, err)
	s, err := VerifyDir(dir, w.pub2, w.r.trust)
	must(t, err)
	if s.Version != "0.2.1" {
		t.Fatalf("%+v", s)
	}
	idx := w.boxSees(t, dir, w.published)
	if !errors.Is(manifestVerdict(t, w, w.pub2, idx), release.ErrReleaseRevoked) {
		t.Error("0.2.0 is not withdrawn")
	}
}

// When the active key is the problem the withdrawal rides in the rescue: the backup key signs an index that revokes the key and the
// release, and the boxes that trust the old keys accept it.
func TestWithdrawInARescue(t *testing.T) {
	w := newWithdrawRig(t)
	dir, err := w.r.build(buildOpts{version: "0.2.1", channel: "stable", cur: addOnlyTree, prevDir: w.pub2, rescue: true,
		revoke: []string{w.r.trust.Active.KeyID()}, withdraw: Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{w.rel2}}})
	must(t, err)
	s, err := VerifyDir(dir, w.pub2, w.r.trust)
	must(t, err)
	if !s.Rescue || !slices.Equal(s.Withdrawn, []string{"release 0.2.0"}) {
		t.Fatalf("%+v", s)
	}
	idx := w.boxSees(t, dir, w.published)
	if idx.KeyID != w.r.trust.Backup.KeyID() || hasRevocation(idx, release.KindRelease, "0.2.0") == nil {
		t.Fatalf("%+v", idx)
	}
}

func TestWithdrawRefusals(t *testing.T) {
	w := newWithdrawRig(t)
	// another build of 0.2.0: signed by the same key, but not the bytes the published index announces
	other, err := w.r.build(buildOpts{version: "0.2.0", channel: "stable", cur: addOnlyTree, prevDir: w.pub1})
	must(t, err)
	otherRel, err := LoadSignedRelease(filepath.Join(other, manifestFile), w.r.trust)
	must(t, err)
	done, err := w.index(t, w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{w.rel2}, Hold: []string{"stable"}})
	must(t, err)
	withdrawnIdx := w.boxSees(t, done, w.published)

	ev := []*SignedRelease{w.rel2}
	move := []*SignedRelease{w.rel1}
	cases := []struct {
		name string
		prev *release.Index
		w    Withdrawal
		want string
	}{
		{"unknown version", w.published, Withdrawal{Releases: []string{"0.1.9"}, Evidence: ev, Hold: []string{"stable"}}, "unknown release 0.1.9"},
		{"no evidence", w.published, Withdrawal{Releases: []string{"0.2.0"}, Hold: []string{"stable"}}, "unknown release 0.2.0"},
		{"evidence of another build", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{otherRel}, Hold: []string{"stable"}}, "not the one the published index announces"},
		{"evidence nothing uses", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: []*SignedRelease{w.rel2, w.rel1}, Hold: []string{"stable"}}, "-revoked-manifest 0.1.0: neither"},
		{"the same release twice", w.published, Withdrawal{Releases: []string{"0.2.0", "0.2.0"}, Evidence: ev, Hold: []string{"stable"}}, "named twice"},
		{"a duplicate row", withdrawnIdx, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}}, "already revoked"},
		{"a duplicate digest row", withdrawnIdx, Withdrawal{Digests: []string{w.sensor2}, Evidence: ev, Hold: []string{"stable"}}, ""},
		{"unknown digest", w.published, Withdrawal{Digests: []string{digestOf("nothing")}, Evidence: ev, Hold: []string{"stable"}}, "unknown image digest"},
		{"malformed digest", w.published, Withdrawal{Digests: []string{"sha256:ABC"}, Evidence: ev, Hold: []string{"stable"}}, "not an image digest"},
		{"the channel's only release without a decision", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev}, "say what the channel offers now"},
		{"a digest of the latest without a decision", w.published, Withdrawal{Digests: []string{w.core2}, Evidence: ev}, "say what the channel offers now"},
		{"hold and move", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}, MoveTo: move}, "not both"},
		{"hold a channel that is not hit", w.published, Withdrawal{Releases: []string{"0.1.0"}, Evidence: move, Hold: []string{"stable"}}, "does not withdraw"},
		{"hold a channel the index lacks", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable", "beta"}}, "no channel beta"},
		{"move to the withdrawn release", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, MoveTo: ev}, "is not below"},
		{"move to a release withdrawn too", w.published, Withdrawal{Releases: []string{"0.2.0", "0.1.0"}, Evidence: []*SignedRelease{w.rel2, w.rel1}, MoveTo: move}, "withdrawn too"},
		{"rollback_if_possible", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}, Action: "rollback_if_possible"}, "do not roll back by themselves"},
		{"an unknown action", w.published, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}, Action: "warn"}, "-revoke-action"},
		{"a channel decision without a withdrawal", w.published, Withdrawal{Hold: []string{"stable"}}, "go with -revoke-release"},
		{"no previous index", nil, Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}}, "needs -prev-index"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := w.index(t, c.prev, c.w)
			want := c.want
			if want == "" { // a digest of a withdrawn release is a row of its own: refused only when that row is there
				if err != nil {
					t.Fatalf("a digest of a withdrawn release: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
		})
	}
	// no reason, and the release this same index announces
	if _, err := BuildIndex(w.published, IndexParams{Now: t1.Add(time.Hour), Rollout: -1, Withdraw: Withdrawal{Releases: []string{"0.2.0"}, Evidence: ev, Hold: []string{"stable"}}}); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Errorf("no reason: %v", err)
	}
	if _, err := BuildIndex(w.published, IndexParams{Now: t1.Add(time.Hour), Rollout: -1, RevokeReason: "x", Channel: "stable", ManifestVersion: "0.3.0",
		ManifestRaw: []byte(`{"version":"0.3.0"}`), Withdraw: Withdrawal{Releases: []string{"0.3.0"}, Evidence: ev}}); err == nil || !strings.Contains(err.Error(), "the one this index announces") {
		t.Errorf("withdrawing the announced release: %v", err)
	}
}

// verify refuses an index without a manifest that moves a channel down without withdrawing what it offered.
func TestVerifyRefusesAChannelMovedDownWithoutAWithdrawal(t *testing.T) {
	w := newWithdrawRig(t)
	x := *w.published
	x.Sequence++
	x.Channels = map[string]release.Channel{"stable": {Latest: "0.1.0", Manifest: manifestURL("0.1.0"), ManifestSHA256: w.rel1.SHA256, Rollout: &release.Rollout{Percent: 100}}}
	raw, err := marshal(x)
	must(t, err)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, indexFile), raw, 0o600))
	_, err = SignRelease(context.Background(), testSigner{t, w.r.active}, dir, slotActive)
	must(t, err)
	if _, err := VerifyDir(dir, w.pub2, w.r.trust); err == nil || !strings.Contains(err.Error(), "differs from the published index") {
		t.Fatalf("%v", err)
	}
}

// Through the command line, as the runbook runs it: index with the downloaded manifests, sign, verify.
func TestWithdrawCommands(t *testing.T) {
	w := newWithdrawRig(t)
	keys := t.TempDir()
	writeKeys(t, w.r, keys)
	run1 := func(args ...string) (int, string) {
		var o, e bytes.Buffer
		c := run(args, nil, &o, &e)
		return c, o.String() + e.String()
	}
	out := t.TempDir()
	base := []string{"index", "-out", out, "-prev-index", w.pub2, "-keys-dir", keys, "-revoke-release", "0.2.0", "-revoked-manifest", filepath.Join(w.pub2, manifestFile)}
	if c, msg := run1(append(base, "-revoke-reason", "deletes findings")...); c == 0 || !strings.Contains(msg, "say what the channel offers now") {
		t.Errorf("no channel decision: %d %s", c, msg)
	}
	if _, err := os.Stat(filepath.Join(out, indexFile)); err == nil {
		t.Error("an index was written for a refused withdrawal")
	}
	if c, msg := run1(append(base, "-channel-manifest", filepath.Join(w.pub1, manifestFile))...); c == 0 || !strings.Contains(msg, "reason") {
		t.Errorf("no reason: %d %s", c, msg)
	}
	if c, msg := run1("index", "-out", t.TempDir(), "-keys-dir", keys, "-revoke-release", "0.2.0", "-revoked-manifest", filepath.Join(w.pub2, manifestFile)); c == 0 || !strings.Contains(msg, "-prev-index") {
		t.Errorf("no -prev-index: %d %s", c, msg)
	}
	if c, msg := run1(append(base, "-channel-manifest", filepath.Join(w.pub1, manifestFile), "-revoke-reason", "deletes findings")...); c != 0 {
		t.Fatalf("%d %s", c, msg)
	}
	_, err := SignRelease(context.Background(), testSigner{t, w.r.active}, out, slotActive)
	must(t, err)
	c, msg := run1("verify", "-dir", out, "-prev-index", w.pub2, "-keys-dir", keys)
	if c != 0 || !strings.Contains(msg, "WITHDRAWAL index") || !strings.Contains(msg, "revokes release 0.2.0") || !strings.Contains(msg, "channel stable 0.2.0 -> 0.1.0") {
		t.Errorf("verify: %d %s", c, msg)
	}
	raw, err := os.ReadFile(filepath.Join(out, indexFile))
	must(t, err)
	var x release.Index
	must(t, json.Unmarshal(raw, &x))
	if x.Channels["stable"].Latest != "0.1.0" {
		t.Errorf("%+v", x.Channels)
	}
}
