package release

import (
	"errors"
	"testing"
)

// A retired key only re-verifies the index the box stored; it never accepts a new index or manifest.
func TestRetiredKeyReverifiesTheStoredIndexOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	old := e.active
	x := e.indexMap(7)
	x["revoked"] = []any{revocation(KindRelease, "1.3.2")}
	raw, sig := e.signedIndex(old, x)
	first, err := VerifyIndex(raw, sig, e.trust, nil)
	if err != nil {
		t.Fatal(err)
	}

	next := newMsigner(t)
	tr := e.trust
	tr.Active, tr.Retired = next.key(), []MinisignKey{old.key()}

	if _, err := VerifyIndex(raw, sig, tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a new index signed by a retired key: %v", err)
	}
	stored, err := VerifyStoredIndex(raw, sig, tr, first.Revoked)
	if err != nil {
		t.Fatalf("the stored index no longer loads: %v", err)
	}
	if stored.Sequence != 7 || stored.KeyID != old.key().KeyID() || stored.RawSHA256 != first.RawSHA256 || !stored.revokedAny(KindRelease, "1.3.2") {
		t.Fatalf("%+v", stored)
	}
	// The floor holds, the revocation holds.
	if _, err := VerifyIndex(e.indexRaw(next, 6), e.sigOf(next, 6), tr, stored); !errors.Is(err, ErrSequenceRegress) {
		t.Fatalf("replay under a rotated key: %v", err)
	}
	r8, s8 := e.signedIndex(next, e.indexMap(8))
	n, err := VerifyIndex(r8, s8, tr, stored)
	if err != nil || !n.revokedAny(KindRelease, "1.3.2") {
		t.Fatalf("%v %+v", err, n)
	}
	// A manifest signed by the retired key is not accepted.
	mraw := js(t, e.manifestMap())
	if _, err := VerifyManifest(mraw, old.sign(mraw), tr, n); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a manifest signed by a retired key: %v", err)
	}
	// A key that is neither current nor retired still loads nothing.
	if _, err := VerifyStoredIndex(raw, newMsigner(t).sign(raw), tr, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("%v", err)
	}
}

func (x *Index) revokedAny(kind, id string) bool { return x.revoked(kind, id) != nil }

func (e *env) indexRaw(s *msigner, seq uint64) []byte {
	r, _ := e.signedIndex(s, e.indexMap(seq))
	return r
}
func (e *env) sigOf(s *msigner, seq uint64) []byte {
	_, g := e.signedIndex(s, e.indexMap(seq))
	return g
}

// The build's minimum sequence is the floor when nothing is stored, and no more than that.
func TestMinSequenceIsTheFloorOnlyWhenNothingIsStored(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	tr := e.trust
	tr.MinSequence = 10
	r9, s9 := e.signedIndex(e.active, e.indexMap(9))
	if _, err := VerifyIndex(r9, s9, tr, nil); !errors.Is(err, ErrSequenceRegress) {
		t.Fatalf("below the floor: %v", err)
	}
	r10, s10 := e.signedIndex(e.active, e.indexMap(10))
	idx, err := VerifyIndex(r10, s10, tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// With an index stored, its sequence is the floor, whatever the build says.
	tr.MinSequence = 500
	r11, s11 := e.signedIndex(e.active, e.indexMap(11))
	if _, err := VerifyIndex(r11, s11, tr, idx); err != nil {
		t.Fatalf("%v", err)
	}
}

func TestMinSequenceTextFromTheLinker(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]uint64{"0": 0, "17": 17, "18446744073709551615": 18446744073709551615} {
		if got, err := parseMinSequence(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "1.5", "0x10", "abc", " 1", "18446744073709551616"} {
		if _, err := parseMinSequence(in); err == nil {
			t.Errorf("%q was accepted", in)
		}
	}
}
