package exposure

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/egressip"
	"github.com/knt048/vedette/core/store"
)

// The proof that the box's own IP rests on, for the executors' own-IP fences (the scan worker, the host's ZAP fence): the latest
// sighting of the address as the box's egress. An address the box no longer goes out through keeps it for ValidDays, and the
// executors accept a job on it instead of needing a sighting right before they scan.

// twoLines makes the box go out through a and b alternately, as behind a router that balances two Internet lines: a is seen (and
// committed), then b is seen for the first time, then a again, then b. It returns when a was last seen; b is the current egress.
func (e *env) twoLines(a, b string) (aLast time.Time) {
	e.t.Helper()
	e.committedIP(a)
	e.advance(time.Hour)
	e.fullAs(b) // b's first sighting
	e.advance(time.Hour)
	e.fullAs(a)
	aLast = e.clock.Now()
	e.advance(time.Hour)
	e.fullAs(b) // the box goes out through b now
	return aLast
}

// Two lines in use at the same time (a's latest sighting is after b, the current egress, was first seen): a keeps its proof, the
// latest sighting, for its 90 days.
func TestOwnIPProofIsTheLatestSightingWhileTheBoxUsesAnotherLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	seen := e.twoLines(ipA, ipB)
	e.advance(3 * 24 * time.Hour)
	at, ok, err := e.svc.OwnIPProof(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA))
	if err != nil || !ok || !at.Equal(seen) {
		t.Fatalf("proof %v %v %v, want the sighting at %v", at, ok, err, seen)
	}
	if ok, err := e.svc.ScannableIP(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); err != nil || !ok {
		t.Fatalf("ScannableIP %v %v", ok, err)
	}
	if p := e.node(e.detectedID(ipA)).Proof; p.Replaced != nil {
		t.Fatalf("an address of a line still in use is shown replaced: %+v", p.Replaced)
	}
	e.advance(ValidDays * 24 * time.Hour) // past its days: no proof, no yes
	if at, ok, err := e.svc.OwnIPProof(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); err != nil || ok || !at.IsZero() {
		t.Fatalf("an expired proof: %v %v %v", at, ok, err)
	}
}

// A dynamic address the provider took back: a was last seen before b, the box's current egress, was first seen, so the lines never
// overlapped and a may belong to someone else now. The gate keeps it inside its 90 days as before, but no proof is sent: the
// executors scan it only if they see the box go out through it themselves. Its page says it was replaced, by what and when.
func TestOwnIPProofOfAReplacedAddressIsNone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.committedIP(ipA)
	e.advance(24 * time.Hour)
	e.fullAs(ipB) // the provider gave the box b; a is not seen again
	bFirst := e.clock.Now()
	e.advance(time.Hour)
	at, ok, err := e.svc.OwnIPProof(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA))
	if err != nil || !ok || !at.IsZero() {
		t.Fatalf("proof %v %v %v of a replaced address, want none (the gate still says yes)", at, ok, err)
	}
	r := e.node(e.detectedID(ipA)).Proof.Replaced
	if r == nil || r.By != ipB || r.At != store.FormatTS(bFirst) {
		t.Fatalf("replaced %+v, want by %s at %v", r, ipB, bFirst)
	}
	if p := e.node(e.detectedID(ipB)).Proof; p.Replaced != nil {
		t.Fatalf("the current egress shown replaced: %+v", p.Replaced)
	}
	// a is seen again later (the provider gave it back, or the second line came up): it is not replaced any more, and keeps its proof
	// after the box goes back to b
	e.advance(time.Hour)
	e.fullAs(ipA)
	aAgain := e.clock.Now()
	e.advance(time.Hour)
	e.fullAs(ipB)
	if at, ok, err := e.svc.OwnIPProof(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); err != nil || !ok || !at.Equal(aAgain) {
		t.Fatalf("proof %v %v %v after a was seen again, want %v", at, ok, err, aAgain)
	}
	if p := e.node(e.detectedID(ipA)).Proof; p.Replaced != nil {
		t.Fatalf("seen again, still shown replaced: %+v", p.Replaced)
	}
}

// When the box's records cannot say which address it goes out through (no sighting of any of its addresses holds), no proof is sent.
func TestOwnIPProofNeedsTheCurrentEgress(t *testing.T) {
	t.Parallel()
	if _, _, ok := (egressNow{}).proofOf(Target{Kind: KindIP, Method: methodBoxEgress, Value: ipA, VerifiedAt: time.Now()}, time.Now()); ok {
		t.Fatal("a proof with no current egress known")
	}
}

// A typed IP is proved by its own token file or reverse DNS name, never by a sighting: OwnIPProof gives no time for it, so an
// executor's own-IP fence never takes it as the box's own on that proof.
func TestOwnIPProofIsNeverTheProofOfATypedIP(t *testing.T) {
	t.Parallel()
	w, v := typedWithFence(t)
	w.files.serve(ipC, "http", v.Token)
	w.verify(v.ID)
	if _, err := w.commit(v.ID); err != nil {
		t.Fatal(err)
	}
	at, ok, err := w.svc.OwnIPProof(w.ctx(), "admin@acme.example", netip.MustParseAddr(ipC))
	if err != nil || !ok || !at.IsZero() {
		t.Fatalf("typed IP proof %v %v %v", at, ok, err)
	}
}

// The scan of the box's own IP tells the web step what its ownership rests on (ScanTarget.ProvenAt), so the host's ZAP fence can
// take the page on the proof while the box goes out through another line.
func TestTheWebStepOfAProvenIPCarriesItsProof(t *testing.T) {
	t.Parallel()
	e := stepsEnv(t)
	seen := e.twoLines(ipA, ipB)
	e.advance(ScanEvery)
	e.svc.SetRunner(&fakeRunner{content: gbOpen()})
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", e.detectedID(ipA)); err != nil {
		t.Fatal(err)
	}
	web, _ := e.svc.cfg.Web.(*fakeWeb)
	if len(web.targets) == 0 || !web.targets[0].ProvenAt.Equal(seen) {
		t.Fatalf("web step targets %+v, want proven at %v", web.targets, seen)
	}
}

// The executors' own-IP fences take a proof under egressip's rule: its window is this package's ValidDays, and its slack for a clock
// that was ahead is clockSlack, so core and the executors never disagree on whether a proof holds.
func TestOwnProofWindowIsValidDays(t *testing.T) {
	t.Parallel()
	if egressip.ProofValid != ValidDays*24*time.Hour || egressip.ProofSlack != clockSlack {
		t.Fatalf("egressip %v/%v, exposure %d days/%v", egressip.ProofValid, egressip.ProofSlack, ValidDays, clockSlack)
	}
}

// A sighting stored while the box's clock was ahead (a wrong real-time clock that NTP corrected) does not say when the box last went
// out through the address. The gate keeps such an IP scannable (provedAt clamps the time to now), but the executors get no proof
// from it: a proof dated "now" would let them skip their own sighting for an address the box may not have seen for months. Without
// a proof they ask for a sighting of their own, as before.
func TestOwnIPProofOfASightingDatedInTheFutureIsNone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.committedIP(ipA)
	e.advance(-30 * 24 * time.Hour) // NTP set the clock back: the stored sighting lies 30 days ahead
	e.fullAs(ipB)                   // the box goes out through another address now, so nothing renews ipA
	at, ok, err := e.svc.OwnIPProof(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA))
	if err != nil || !ok {
		t.Fatalf("gate %v %v: the address stays scannable", ok, err)
	}
	if !at.IsZero() {
		t.Fatalf("proof %v from a sighting dated in the future, want none (the executors' own sighting decides)", at)
	}
}
