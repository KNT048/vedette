package release

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"log/slog"
	"math"
	"testing"
)

func (e *env) withRevocations(seq uint64, revs ...m) m {
	x := e.indexMap(seq)
	r := []any{}
	for _, v := range revs {
		r = append(r, v)
	}
	x["revoked"] = r
	return x
}

func (e *env) tryIndex(s *msigner, x m, stored *Index) (*Index, error) {
	raw, sig := e.signedIndex(s, x)
	return VerifyIndex(raw, sig, e.trust, stored)
}

// Rule 1 and 3 (revoke.go): only the backup key revokes keys; the revocation outlives later indexes.
func TestBackupKeyRevokesActiveKey(t *testing.T) {
	e := newEnv(t)
	activeID := e.trust.Active.KeyID()
	stored := e.verifiedIndex(e.active, e.indexMap(1))
	rev, err := e.tryIndex(e.backup, e.withRevocations(2, revocation(KindKey, activeID)), stored)
	if err != nil || !rev.KeyRevoked(activeID) {
		t.Fatal(err)
	}
	// afterwards the active key signs nothing: not an index, not a manifest
	if _, err := e.tryIndex(e.active, e.indexMap(3), rev); !errors.Is(err, ErrKeyRevoked) || !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked key signed an index: %v", err)
	}
	mraw := js(t, e.manifestMap())
	if _, err := VerifyManifest(mraw, e.active.sign(mraw), e.trust, rev); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("revoked key signed a manifest: %v", err)
	}
	if _, err := VerifyManifest(mraw, e.backup.sign(mraw), e.trust, rev); err != nil {
		t.Errorf("backup-signed manifest after revoking active: %v", err)
	}
	// sticky: later backup-signed indexes that forget the revocation keep it
	next, err := e.tryIndex(e.backup, e.indexMap(4), rev)
	if err != nil || !next.KeyRevoked(activeID) {
		t.Fatalf("key revocation dropped: %v", err)
	}
	if _, err := e.tryIndex(e.active, e.indexMap(5), next); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("active key is back after a later index: %v", err)
	}
	// the backup key can revoke the cosign key; images then stop verifying
	cosID := CosignKeyID(e.cosign.pub())
	crev, err := e.tryIndex(e.backup, e.withRevocations(2, revocation(KindKey, cosID)), stored)
	if err != nil {
		t.Fatal(err)
	}
	post := e.verifiedManifest(e.manifestMap(), crev)
	if err := VerifyImage(post, "core", digestCore, e.trust); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("revoked cosign key verified an image: %v", err)
	}
	pre := e.verifiedManifest(e.manifestMap(), stored)
	if err := VerifyImage(pre, "core", digestCore, e.trust); err != nil {
		t.Fatal(err)
	}
}

// M1: key revocations in an index signed by the active key are dropped (and logged), whether or not
// this binary embeds the key; the index itself is accepted.
func TestActiveKeyKeyRevocationsAreDropped(t *testing.T) {
	e := newEnv(t)
	var buf bytes.Buffer
	old := logger
	logger = slog.New(slog.NewTextHandler(&buf, nil))
	t.Cleanup(func() { logger = old })

	stored := e.verifiedIndex(e.active, e.indexMap(1))
	for name, id := range map[string]string{
		"backup key": e.trust.Backup.KeyID(), "itself": e.trust.Active.KeyID(),
		"cosign key": CosignKeyID(e.cosign.pub()), "unknown key": "0123456789ABCDEF",
	} {
		buf.Reset()
		x, err := e.tryIndex(e.active, e.withRevocations(2, revocation(KindKey, id), revocation(KindRelease, "1.3.2")), stored)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if x.KeyRevoked(id) {
			t.Errorf("%s: key revocation from the active key was kept", name)
		}
		if x.revoked(KindRelease, "1.3.2") == nil {
			t.Errorf("%s: the release revocation next to it was lost", name)
		}
		if !bytes.Contains(buf.Bytes(), []byte("dropped key revocations")) {
			t.Errorf("%s: no log line: %q", name, buf.String())
		}
	}
}

// A leaked active key pre-revokes the keys of the next binary; once that binary is installed the
// stored index must not block them, and the backup key must not be dead on arrival.
func TestActiveKeyCannotPreRevokeNextBinaryKeys(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.active, e.indexMap(1))
	nextActive, nextBackup := newMsigner(t), newMsigner(t)
	attacked, err := e.tryIndex(e.active, e.withRevocations(2, revocation(KindKey, nextActive.key().KeyID()), revocation(KindKey, nextBackup.key().KeyID())), stored)
	if err != nil {
		t.Fatal(err)
	}
	trust2 := Trust{Active: nextActive.key(), Backup: e.backup.key(), Cosign: []*ecdsa.PublicKey{e.cosign.pub()}}
	raw, sig := e.signedIndex(nextActive, e.indexMap(3))
	if _, err := VerifyIndex(raw, sig, trust2, attacked); err != nil {
		t.Errorf("the next binary's active key was pre-revoked: %v", err)
	}
	trust3 := Trust{Active: nextActive.key(), Backup: nextBackup.key(), Cosign: []*ecdsa.PublicKey{e.cosign.pub()}}
	raw, sig = e.signedIndex(nextBackup, e.indexMap(3))
	if _, err := VerifyIndex(raw, sig, trust3, attacked); err != nil {
		t.Errorf("the next binary's backup key was pre-revoked: %v", err)
	}
}

// Rule 2: nobody revokes the backup key through an index, and a stored revocation of the binary's
// current backup key (from an older binary, or a hand-edited store) is ignored.
func TestBackupKeyIsNeverRevoked(t *testing.T) {
	e := newEnv(t)
	backupID := e.trust.Backup.KeyID()
	if _, err := e.tryIndex(e.backup, e.withRevocations(2, revocation(KindKey, backupID)), nil); !errors.Is(err, ErrKeyNotAuthorised) {
		t.Errorf("backup key revoked by its own index: %v", err)
	}
	stored := e.verifiedIndex(e.active, e.indexMap(1))
	stored.Revoked = append(stored.Revoked, revocation2(KindKey, backupID))
	next, err := e.tryIndex(e.backup, e.indexMap(2), stored)
	if err != nil {
		t.Fatalf("a stored revocation of the backup key blocked the backup key: %v", err)
	}
	if next.KeyRevoked(backupID) {
		t.Error("the stored revocation of the backup key was carried forward")
	}
	if _, err := e.tryIndex(e.active, e.indexMap(3), next); err != nil {
		t.Error(err)
	}
	// and a manifest signed by the backup key passes an index that still lists it
	mraw := js(t, e.manifestMap())
	if _, err := VerifyManifest(mraw, e.backup.sign(mraw), e.trust, stored); err != nil {
		t.Errorf("manifest signed by the backup key refused: %v", err)
	}
}

func revocation2(kind, id string) Revocation {
	return Revocation{Kind: kind, ID: id, Reason: "test", Since: t0, Action: "block_install"}
}

// H1: a revoked digest or release stays revoked in every later index unless the backup key says
// otherwise. The attack: the leaked active key publishes a newer index without the revocation, then a
// manifest that reuses the revoked digest under a new version, whose old cosign signature still verifies.
func TestActiveKeyCannotResurrectRevokedDigest(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.backup, e.withRevocations(5, revocation(KindImageDigest, digestCore)))
	idx, err := e.tryIndex(e.active, e.indexMap(6), stored)
	if err != nil {
		t.Fatal(err)
	}
	if idx.revoked(KindImageDigest, digestCore) == nil {
		t.Fatal("the digest revocation was dropped by an index signed by the active key")
	}
	mx := e.manifestMap()
	mx["version"] = "9.9.9"
	mx["min_upgrade_from"] = ""
	mx["images"] = []any{e.image("core", "9.9.9", digestCore)}
	mraw := js(t, mx)
	if _, err := VerifyManifest(mraw, e.active.sign(mraw), e.trust, idx); !errors.Is(err, ErrReleaseRevoked) {
		t.Errorf("a revoked digest was accepted again as release 9.9.9: %v", err)
	}
}

// H1, forced-rollback variant: the host's rollback consults the stored index for the previous version
// (previous_revoked). Dropping the revocation of a vulnerable release would let the leaked active key
// push boxes back to it.
func TestActiveKeyCannotUnrevokeReleaseForRollback(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.active, e.withRevocations(5, revocation(KindRelease, "1.3.2")))
	next, err := e.tryIndex(e.active, e.indexMap(6), stored)
	if err != nil {
		t.Fatal(err)
	}
	if next.revoked(KindRelease, "1.3.2") == nil {
		t.Fatal("release 1.3.2 is no longer revoked after an index signed by the active key")
	}
	// ...through any number of later indexes
	for seq := uint64(7); seq < 10; seq++ {
		if next, err = e.tryIndex(e.active, e.indexMap(seq), next); err != nil || next.revoked(KindRelease, "1.3.2") == nil {
			t.Fatalf("seq %d: %v", seq, err)
		}
	}
}

// H1: the backup key may remove a release or digest revocation (its own list is authoritative), and
// the carried list may be longer than the 256 entries one index may hold, up to a cap.
func TestBackupKeyMayRemoveRevocationsAndCarriedListGrows(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.active, e.withRevocations(1, revocation(KindRelease, "1.3.2"), revocation(KindImageDigest, digestSensor)))
	cleared, err := e.tryIndex(e.backup, e.indexMap(2), stored)
	if err != nil || len(cleared.Revoked) != 0 {
		t.Fatalf("backup index did not clear the revocations: %+v %v", cleared, err)
	}
	// the active key adds 256 new digests per index; they pile up past 256
	cur := stored
	for i := 0; i < 3; i++ {
		revs := []m{}
		for j := 0; j < 200; j++ {
			revs = append(revs, revocation(KindImageDigest, "sha256:"+hexN(i*200+j)))
		}
		if cur, err = e.tryIndex(e.active, e.withRevocations(uint64(2+i), revs...), cur); err != nil {
			t.Fatal(err)
		}
	}
	if len(cur.Revoked) <= 256 || cur.revoked(KindRelease, "1.3.2") == nil {
		t.Fatalf("carried list has %d entries", len(cur.Revoked))
	}
	// bounded: a leaked active key cannot grow it forever; a backup-signed index resets it
	var capErr error
	for i := 3; i < 40 && capErr == nil; i++ {
		revs := []m{}
		for j := 0; j < 200; j++ {
			revs = append(revs, revocation(KindImageDigest, "sha256:"+hexN(i*200+j)))
		}
		var next *Index
		if next, capErr = e.tryIndex(e.active, e.withRevocations(uint64(2+i), revs...), cur); capErr == nil {
			cur = next
		}
	}
	if !errors.Is(capErr, ErrMalformed) {
		t.Fatalf("the carried list never hit its cap: %v", capErr)
	}
	if _, err := e.tryIndex(e.backup, e.indexMap(100), cur); err != nil {
		t.Errorf("backup-signed index cannot reset the carried list: %v", err)
	}
}

func hexN(n int) string {
	const digits = "0123456789abcdef"
	b := bytes.Repeat([]byte{'0'}, 64)
	for i := 63; n > 0; i-- {
		b[i] = digits[n%16]
		n /= 16
	}
	return string(b)
}

// D-104 (2): the sequence never goes back; equal is allowed only for the same bytes (M2).
func TestIndexSequence(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.active, e.indexMap(10))
	for seq, want := range map[uint64]error{9: ErrSequenceRegress, 1: ErrSequenceRegress, 10: nil, 11: nil, 1 << 62: nil} {
		raw, sig := e.signedIndex(e.active, e.indexMap(seq))
		if _, err := VerifyIndex(raw, sig, e.trust, stored); (want == nil && err != nil) || (want != nil && !errors.Is(err, want)) {
			t.Errorf("seq %d: %v, want %v", seq, err, want)
		}
	}
	// the regress check does not depend on which trusted key signed
	if _, err := e.tryIndex(e.backup, e.indexMap(3), stored); !errors.Is(err, ErrSequenceRegress) {
		t.Error(err)
	}
}

// M2: a same-sequence replay of different content is refused; the identical bytes are accepted again,
// whoever signs them.
func TestSameSequenceNeedsSameBytes(t *testing.T) {
	e := newEnv(t)
	x := e.indexMap(10)
	raw, sig := e.signedIndex(e.active, x)
	stored, err := VerifyIndex(raw, sig, e.trust, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyIndex(raw, sig, e.trust, stored); err != nil {
		t.Errorf("the same index again: %v", err)
	}
	if _, err := VerifyIndex(raw, e.backup.sign(raw), e.trust, stored); err != nil {
		t.Errorf("the same bytes signed by the backup key: %v", err)
	}
	y := e.indexMap(10)
	y["channels"].(m)["stable"].(m)["rollout"] = m{"percent": 1} // same sequence, different content
	if _, err := e.tryIndex(e.active, y, stored); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("same-sequence replay with other content: %v", err)
	}
	if _, err := e.tryIndex(e.backup, y, stored); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("same-sequence replay signed by the backup key: %v", err)
	}
	// a stored index with no recorded hash (not produced by VerifyIndex) never matches
	if _, err := VerifyIndex(raw, sig, e.trust, &Index{Sequence: 10, KeyID: stored.KeyID}); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("stored index without a hash: %v", err)
	}
}

// M2 / D-108 residual risk: the leaked active key sets sequence to MaxUint64. A backup-signed index that
// revokes the signer of the stored index may go back in sequence; the revocation is sticky, so it
// works once per leaked key.
func TestBackupRecoversFromSequenceFreeze(t *testing.T) {
	e := newEnv(t)
	stored := e.verifiedIndex(e.active, e.indexMap(10))
	frozen, err := e.tryIndex(e.active, e.indexMap(math.MaxUint64), stored)
	if err != nil {
		t.Fatal(err)
	}
	activeRev := e.withRevocations(11, revocation(KindKey, e.trust.Active.KeyID()))
	// without revoking the signer of the stored index the backup key gets no exception
	if _, err := e.tryIndex(e.backup, e.indexMap(11), frozen); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("backup index that does not revoke the signer: %v", err)
	}
	// the active key cannot use the exception: its key revocations are dropped
	if _, err := e.tryIndex(e.active, activeRev, frozen); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("active-signed recovery: %v", err)
	}
	rec, err := e.tryIndex(e.backup, activeRev, frozen)
	if err != nil {
		t.Fatalf("the backup key cannot recover from a sequence frozen by the leaked active key: %v", err)
	}
	if rec.Sequence != 11 || !rec.KeyRevoked(e.trust.Active.KeyID()) {
		t.Fatalf("%+v", rec)
	}
	// from here the sequence rules apply again; the exception does not repeat (the signer of stored is
	// now the backup key)
	if _, err := e.tryIndex(e.backup, e.withRevocations(5, revocation(KindKey, e.trust.Active.KeyID())), rec); !errors.Is(err, ErrSequenceRegress) {
		t.Errorf("second recovery: %v", err)
	}
	if _, err := e.tryIndex(e.backup, e.indexMap(12), rec); err != nil {
		t.Error(err)
	}
}
