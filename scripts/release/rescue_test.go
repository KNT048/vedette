package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/release"
	"github.com/knt048/vedette/internal/release/releasetest"
)

// readSignedT reads a document and its .minisig from dir.
func readSignedT(t *testing.T, dir, name string) (raw, sig []byte) {
	t.Helper()
	raw, sig, err := readSigned(filepath.Join(dir, name))
	must(t, err)
	return raw, sig
}

// D-258, D-259: the active key leaked. The backup key signs a rescue index (revoking the leaked key) and the rescue manifest
// into the .minisig files a box downloads; installed boxes accept it with the box-side verifier, also after the leaked key fed
// them an index with a huge sequence; the leaked key's manifests are refused from then on; and a box running the rescued binary
// (new active key, old one retired) keeps the stored rescue index and takes the next ordinary release signed by the new key.
func TestRescueRoundTrip(t *testing.T) {
	r := newRig(t) // the keys the installed boxes embed; r.active is the key that leaks
	old := r.trust
	leaked := old.Active.KeyID()
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)

	// What an installed box holds: the published index, or worse an index the leaked key signed with a huge sequence.
	praw, psig := readSignedT(t, pub, indexFile)
	published, err := release.VerifyIndex(praw, psig, old, nil)
	must(t, err)
	var evil release.Index
	must(t, json.Unmarshal(praw, &evil))
	evil.Sequence = 1 << 40
	eraw, err := marshal(evil)
	must(t, err)
	attacked, err := release.VerifyIndex(eraw, r.active.SignComment(eraw, "t"), old, published)
	must(t, err)

	// The rescue, built against the published index and verified with the keys the boxes trust.
	resc, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, revoke: []string{leaked}, rescue: true})
	must(t, err)
	s, err := VerifyDir(resc, pub, old)
	must(t, err)
	if !s.Rescue || s.IndexKeyID != old.Backup.KeyID() || s.Version != "0.1.1" || len(s.Images) != 2 {
		t.Fatalf("%+v", s)
	}
	for _, n := range []string{"index.json.minisig", "release-manifest.json.minisig"} {
		if _, err := os.Stat(filepath.Join(resc, n)); err != nil {
			t.Errorf("the box downloads %s: %v", n, err)
		}
	}
	if _, err := os.Stat(filepath.Join(resc, manifestFile+".backup.minisig")); err == nil {
		t.Error("a rescue writes the box's .minisig, not a .backup.minisig")
	}

	iraw, isig := readSignedT(t, resc, indexFile)
	mraw, msig := readSignedT(t, resc, manifestFile)
	for name, stored := range map[string]*release.Index{"published": published, "attacked": attacked} {
		idx, err := release.VerifyIndex(iraw, isig, old, stored)
		if err != nil {
			t.Fatalf("%s box refuses the rescue index: %v", name, err)
		}
		m, err := release.VerifyManifest(mraw, msig, old, idx)
		if err != nil || m.KeyID != old.Backup.KeyID() {
			t.Fatalf("%s box refuses the rescue manifest: %v", name, err)
		}
		// the leaked key's manifest is refused from now on, even for the very same bytes
		if _, err := release.VerifyManifest(mraw, r.active.SignComment(mraw, "t"), old, idx); !errors.Is(err, release.ErrKeyRevoked) {
			t.Errorf("%s box: a manifest of the leaked key after the rescue: %v", name, err)
		}
		if _, err := release.VerifyIndex(eraw, r.active.SignComment(eraw, "t2"), old, idx); err == nil {
			t.Errorf("%s box: an index of the leaked key after the rescue passed", name)
		}
	}

	// The rescued binary: a new active key, the leaked one retired (D-130), the same backup and cosign keys.
	nw := &rig{t: t, active: releasetest.NewMinisign(t), backup: r.backup, cos: r.cos}
	nw.trust, err = release.NewTrust(nw.active.PubLine(), r.backup.PubLine(), r.cos.PubPEM(t))
	must(t, err)
	nw.trust.Retired = []release.MinisignKey{old.Active}
	// with the new keys the backup key has no business signing a manifest: the new active key is not revoked
	if _, err := VerifyDir(resc, "", nw.trust); err == nil || !strings.Contains(err.Error(), "rescue") {
		t.Errorf("a rescue verified with the new build's keys: %v", err)
	}
	idxOld, err := release.VerifyIndex(iraw, isig, old, attacked)
	must(t, err)
	stored, err := release.VerifyStoredIndex(iraw, isig, nw.trust, idxOld.Revoked)
	if err != nil {
		t.Fatalf("the rescued box re-verifies its stored rescue index: %v", err)
	}
	next, err := nw.build(buildOpts{version: "0.1.2", channel: "stable", cur: addOnlyTree, prevDir: resc})
	must(t, err)
	s, err = VerifyDir(next, resc, nw.trust)
	if err != nil || s.Rescue || s.IndexKeyID != nw.trust.Active.KeyID() {
		t.Fatalf("the next ordinary release: %+v %v", s, err)
	}
	nraw, nsig := readSignedT(t, next, indexFile)
	nidx, err := release.VerifyIndex(nraw, nsig, nw.trust, stored)
	if err != nil || !nidx.KeyRevoked(leaked) {
		t.Fatalf("the next index on the rescued box (the leaked key stays revoked): %v", err)
	}
	nmraw, nmsig := readSignedT(t, next, manifestFile)
	if _, err := release.VerifyManifest(nmraw, nmsig, nw.trust, nidx); err != nil {
		t.Fatal(err)
	}
}

// clearSigs removes every signature of dir.
func clearSigs(t *testing.T, dir string) {
	t.Helper()
	sigs, _ := filepath.Glob(filepath.Join(dir, "*.minisig"))
	for _, s := range sigs {
		must(t, os.Remove(s))
	}
}

// The backup key's manifest passes verify only as a rescue: index signed by the backup key and revoking the active key, once.
func TestVerifyRefusesABackupManifestOutsideARescue(t *testing.T) {
	r := newRig(t)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	// an ordinary release whose manifest the backup key signed
	mraw, _ := readSignedT(t, pub, manifestFile)
	must(t, os.WriteFile(filepath.Join(pub, manifestFile+".minisig"), r.backup.SignComment(mraw, "t"), 0o600))
	if _, err := VerifyDir(pub, "", r.trust); err == nil || !strings.Contains(err.Error(), "backup key") {
		t.Errorf("a backup-signed manifest beside an active-signed index: %v", err)
	}
	pub, err = r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	// a backup-signed index that revokes a key, but not the active one (here the cosign key): sign refuses, verify too
	cosignID := release.CosignKeyID(r.trust.Cosign[0])
	if _, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, rescue: true, revoke: []string{cosignID}}); err == nil || !strings.Contains(err.Error(), "must revoke the active key") {
		t.Errorf("SignRescue of an index that does not revoke the active key: %v", err)
	}
	other, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, revoke: []string{cosignID}})
	must(t, err)
	clearSigs(t, other)
	_, err = SignRelease(t.Context(), testSigner{t, r.backup}, other, slotRescue)
	must(t, err)
	if _, err := VerifyDir(other, pub, r.trust); err == nil || !strings.Contains(err.Error(), "revoke the active key") {
		t.Errorf("a rescue that does not revoke the active key: %v", err)
	}
	// one rescue per leaked key: on top of the rescue index, the backup key signs no second release
	resc, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, rescue: true, revoke: []string{r.trust.Active.KeyID()}})
	must(t, err)
	if _, err := r.build(buildOpts{version: "0.1.2", channel: "stable", cur: addOnlyTree, prevDir: resc, rescue: true}); err == nil || !strings.Contains(err.Error(), "already revokes") {
		t.Errorf("a second rescue for the same key: %v", err)
	}
	second, err := r.build(buildOpts{version: "0.1.2", channel: "stable", cur: addOnlyTree, prevDir: resc})
	must(t, err)
	clearSigs(t, second)
	_, err = SignRelease(t.Context(), testSigner{t, r.backup}, second, slotRescue)
	must(t, err)
	if _, err := VerifyDir(second, resc, r.trust); err == nil || !strings.Contains(err.Error(), "already revokes") {
		t.Errorf("verify of a second rescue for the same key: %v", err)
	}
}

func TestSignRescueRefusals(t *testing.T) {
	r := newRig(t)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	leaked := r.trust.Active.KeyID()
	prev, err := LoadPrevIndex(pub, r.trust)
	must(t, err)
	rev := IndexParams{Now: t1, Rollout: -1, RevokeKeys: []string{leaked}, RevokeReason: "leak", BackupKeyID: r.trust.Backup.KeyID()}
	// an index-only directory: a rescue must bring the new binary
	files, err := BuildIndex(prev, rev)
	must(t, err)
	ref := t.TempDir()
	must(t, os.WriteFile(filepath.Join(ref, indexFile), files[0].Data, 0o600))
	if _, err := SignRescue(t.Context(), testSigner{t, r.backup}, ref, pub, r.trust); err == nil || !strings.Contains(err.Error(), "release manifest") {
		t.Errorf("a rescue without a manifest: %v", err)
	}
	if _, err := SignRescue(t.Context(), testSigner{t, r.backup}, ref, "", r.trust); err == nil || !strings.Contains(err.Error(), "-prev-index") {
		t.Errorf("a rescue without the published index: %v", err)
	}
	// signed by the wrong key (the leaked one itself): verify sees no rescue, and the signatures are gone
	dir, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, revoke: []string{leaked}})
	must(t, err)
	clearSigs(t, dir)
	if _, err := SignRescue(t.Context(), testSigner{t, r.active}, dir, pub, r.trust); err == nil || !strings.Contains(err.Error(), "signatures were removed") {
		t.Errorf("a rescue signed by the active key: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.minisig")); len(left) != 0 {
		t.Errorf("a refused rescue left signatures: %v", left)
	}
	// a signature of another run in the directory: refused before signing, and nothing of this run is left
	mraw, _ := os.ReadFile(filepath.Join(dir, manifestFile))
	must(t, os.WriteFile(filepath.Join(dir, manifestFile+".minisig"), r.active.SignComment(mraw, "t"), 0o600))
	if _, err := SignRescue(t.Context(), testSigner{t, r.backup}, dir, pub, r.trust); err == nil || !strings.Contains(err.Error(), "already there") {
		t.Errorf("a rescue over another run's signature: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, indexFile+".minisig")); err == nil {
		t.Error("a refused rescue signed the index")
	}
	must(t, os.Remove(filepath.Join(dir, manifestFile+".minisig")))
	// the signer dies half way: no signature of the run is left
	f := &failingSigner{inner: testSigner{t, r.backup}, failOn: 2}
	if _, err := SignRescue(t.Context(), f, dir, pub, r.trust); err == nil {
		t.Error("a failing signer passed")
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.minisig")); len(left) != 0 {
		t.Errorf("a failed rescue left signatures: %v", left)
	}
	if _, err := SignRelease(t.Context(), testSigner{t, r.backup}, dir, "root"); err == nil {
		t.Error("an unknown slot was accepted")
	}
}

func TestBuildIndexKeyRevocations(t *testing.T) {
	man := []byte(`{"version":"1.0.0"}`)
	backup := "8DD38917AD864FAE"
	base := IndexParams{Now: t1, Rollout: -1, Channel: "stable", ManifestVersion: "1.0.0", ManifestRaw: man, BackupKeyID: backup}
	p := base
	p.RevokeKeys, p.RevokeReason = []string{"7B78764E550D48D0", strings.Repeat("ab", 32)}, "the active key leaked"
	files, err := BuildIndex(nil, p)
	must(t, err)
	var x release.Index
	must(t, json.Unmarshal(files[0].Data, &x))
	if len(x.Revoked) != 2 || x.Revoked[0].Kind != release.KindKey || x.Revoked[0].Action != "block_install" || !x.Revoked[0].Since.Equal(x.GeneratedAt) || x.Revoked[1].Reason != "the active key leaked" {
		t.Fatalf("%+v", x.Revoked)
	}
	// the next index carries them and refuses to revoke one again
	q := base
	q.ManifestVersion = ""
	q.RevokeKeys, q.RevokeReason = []string{"7B78764E550D48D0"}, "again"
	if _, err := BuildIndex(&x, q); err == nil || !strings.Contains(err.Error(), "already revoked") {
		t.Errorf("revoking a revoked key: %v", err)
	}
	for name, f := range map[string]func(*IndexParams){
		"bad id":             func(p *IndexParams) { p.RevokeKeys = []string{"7b78764e550d48d0"} },
		"the backup key":     func(p *IndexParams) { p.RevokeKeys = []string{backup} },
		"no reason":          func(p *IndexParams) { p.RevokeReason = "" },
		"two-line reason":    func(p *IndexParams) { p.RevokeReason = "a\nb" },
		"long reason":        func(p *IndexParams) { p.RevokeReason = strings.Repeat("x", 257) },
		"reason without key": func(p *IndexParams) { p.RevokeKeys = nil },
		"no backup id":       func(p *IndexParams) { p.BackupKeyID = "" },
	} {
		p := base
		p.RevokeKeys, p.RevokeReason = []string{"7B78764E550D48D0"}, "leak"
		f(&p)
		if _, err := BuildIndex(nil, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Through the command line: index -revoke-key needs a reason, and verify names a rescue.
func TestRescueCommands(t *testing.T) {
	r := newRig(t)
	keys := t.TempDir()
	writeKeys(t, r, keys)
	pub, err := r.build(buildOpts{version: "0.1.0", channel: "stable", cur: addOnlyTree})
	must(t, err)
	run1 := func(args ...string) (int, string) {
		var o, e bytes.Buffer
		c := run(args, nil, &o, &e)
		return c, o.String() + e.String()
	}
	if c, msg := run1("index", "-out", t.TempDir(), "-prev-index", pub, "-keys-dir", keys, "-revoke-key", r.trust.Active.KeyID()); c == 0 || !strings.Contains(msg, "reason") {
		t.Errorf("-revoke-key without a reason: %d %s", c, msg)
	}
	out := t.TempDir()
	if c, msg := run1("index", "-out", out, "-prev-index", pub, "-keys-dir", keys, "-revoke-key", r.trust.Active.KeyID(), "-revoke-reason", "leak"); c != 0 {
		t.Fatalf("%d %s", c, msg)
	}
	raw, _ := os.ReadFile(filepath.Join(out, indexFile))
	if !bytes.Contains(raw, []byte(`"id": "`+r.trust.Active.KeyID()+`"`)) {
		t.Errorf("the revocation is not in the index:\n%s", raw)
	}
	if c, msg := run1("sign", "-dir", out, "-key", "/nonexistent", "-minisign", "/bin/true", "-slot", "root"); c == 0 || !strings.Contains(msg, "rescue") {
		t.Errorf("an unknown slot: %d %s", c, msg)
	}
	for _, args := range [][]string{
		{"-slot", "rescue"},                     // a rescue needs the published index and the boxes' keys
		{"-slot", "rescue", "-prev-index", pub}, // ... both of them
		{"-slot", "active", "-keys-dir", keys},  // and only a rescue takes them
		{"-slot", "backup", "-prev-index", pub},
	} {
		if c, msg := run1(append([]string{"sign", "-dir", out, "-key", "/nonexistent", "-minisign", "/bin/true"}, args...)...); c == 0 || !strings.Contains(msg, "-prev-index and -keys-dir") {
			t.Errorf("sign %v: %d %s", args, c, msg)
		}
	}
	if c, msg := run1("index", "-out", t.TempDir(), "-keys-dir", keys, "-manifest", filepath.Join(pub, manifestFile), "-revoke-key", r.trust.Active.KeyID(), "-revoke-reason", "leak"); c == 0 || !strings.Contains(msg, "-prev-index") {
		t.Errorf("-revoke-key without -prev-index: %d %s", c, msg)
	}
	resc, err := r.build(buildOpts{version: "0.1.1", channel: "stable", cur: addOnlyTree, prevDir: pub, revoke: []string{r.trust.Active.KeyID()}, rescue: true})
	must(t, err)
	if c, msg := run1("verify", "-dir", resc, "-prev-index", pub, "-keys-dir", keys); c != 0 || !strings.Contains(msg, "RESCUE") {
		t.Errorf("verify of a rescue: %d %s", c, msg)
	}
}
