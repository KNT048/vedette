package feeds

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// chunkEnv serves n addresses as the ET Open list (the only feed on) and returns the env, the origin and a
// function that makes the list the given text.
func chunkEnv(t *testing.T, text string) (*env, *origin) {
	t.Helper()
	e, o := pullEnv(t)
	e.only("et-open")
	o.body("/et.txt", `"e1"`, text)
	e.mirror("et-open", o.url("/et.txt"))
	return e, o
}

func listings(t *testing.T, e *env) int { return rowsOf(t, e.db, "feeds_ioc_source") }

func TestIOCChunksDropVanishedRowsOnlyAfterTheLastChunk(t *testing.T) {
	t.Parallel()
	n := 2*iocChunkRows + 500
	e, o := chunkEnv(t, testIPs(n+300))
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	if got := listings(t, e); got != n+300 {
		t.Fatalf("first pull stored %d", got)
	}
	f1 := e.feed("et-open")
	// the new list loses the last 300 and gains 100 new addresses (a different first octet)
	var more string
	for i := range 100 {
		more += fmt.Sprintf("60.0.%d.7\n", i)
	}
	o.body("/et.txt", `"e2"`, testIPs(n)+more)
	e.setNow(e.clock().Add(7 * time.Hour))
	var seen []int
	e.svc.afterChunk = func(chunk int) {
		if chunk < 2 { // before the final transaction: nothing is gone yet, the new rows are arriving
			seen = append(seen, listings(t, e))
		}
	}
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	e.svc.afterChunk = nil
	for _, got := range seen {
		if got < n+300 {
			t.Errorf("a reader saw %d listings during the pull, fewer than the %d before it", got, n+300)
		}
	}
	if len(seen) != 2 {
		t.Errorf("hook ran %d times before chunk 2", len(seen))
	}
	if got := listings(t, e); got != n+100 {
		t.Errorf("after the pull: %d listings, want %d", got, n+100)
	}
	f2 := e.feed("et-open")
	if *f2.Records != n+100 || *f1.Records != n+300 {
		t.Errorf("records %d then %d", *f1.Records, *f2.Records)
	}
	ev := e.pub.named(EventIOCUpdated)
	if last := ev[len(ev)-1]; last != (IOCUpdatedEvent{FeedID: "et-open", Added: 100, Removed: 300}) {
		t.Errorf("counts: %+v", last)
	}
}

func TestIOCSecondIdenticalPullChangesNothing(t *testing.T) {
	t.Parallel()
	e, _ := chunkEnv(t, testIPs(iocChunkRows+10))
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	e.setNow(e.clock().Add(7 * time.Hour))
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	if got := listings(t, e); got != iocChunkRows+10 {
		t.Errorf("%d listings", got)
	}
	ev := e.pub.named(EventIOCUpdated)
	if len(ev) != 1 {
		t.Errorf("an unchanged list published %v", ev)
	}
}

func TestIOCFeedSwitchedOffBetweenChunksStopsThePull(t *testing.T) {
	t.Parallel()
	e, _ := chunkEnv(t, testIPs(3*iocChunkRows))
	e.svc.afterChunk = func(chunk int) {
		if chunk == 0 {
			if c, b := e.put("et-open", `{"enabled":false}`); c != 200 {
				t.Error(c, b)
			}
		}
	}
	_, _ = e.fetch("et-open")
	if got := listings(t, e); got != iocChunkRows {
		t.Errorf("%d listings, want only the first chunk's %d: a later chunk wrote after the feed was switched off", got, iocChunkRows)
	}
	if st := e.feed("et-open").Status; st != "never" {
		t.Errorf("a pull that was stopped recorded an outcome: %s", st)
	}
}

func TestIOCCancelledPullLeavesExtraRowsNeverFewerAndTheNextConverges(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	src, err := NewStore(db).source(t.Context(), "et-open")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(ctx context.Context, at time.Time, recs []iocInput, hook func(int)) (int, int, error) {
		a, r, _, err := applyIOCs(ctx, db, at, src, recs, hook, func(*sql.Tx, int, int) error { return nil })
		return a, r, err
	}
	rows := func(from, n int) []iocInput {
		var out []iocInput
		for _, l := range strings.Fields(testIPs(from + n))[from:] {
			out = append(out, iocInput{Kind: "ip", Value: l})
		}
		return out
	}
	old := rows(0, 3*iocChunkRows)
	if _, _, err := apply(t.Context(), epoch0, old, nil); err != nil {
		t.Fatal(err)
	}
	// the new list is entirely different; the pull is cancelled after its first chunk
	fresh := rows(10*iocChunkRows, 3*iocChunkRows)
	ctx, cancel := context.WithCancel(t.Context())
	_, _, err = apply(ctx, epoch0.Add(time.Hour), fresh, func(int) { cancel() })
	if err == nil {
		t.Fatal("a cancelled pull reported success")
	}
	if got := listed(t, db, "et-open"); got != 3*iocChunkRows+iocChunkRows {
		t.Errorf("after the cut-off pull: %d listings, want the old %d plus one chunk", got, 3*iocChunkRows)
	}
	added, removed, err := apply(t.Context(), epoch0.Add(2*time.Hour), fresh, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := listed(t, db, "et-open"); got != len(fresh) || removed != len(old) || added != 2*iocChunkRows {
		t.Errorf("next pull: %d listings, +%d -%d", got, added, removed)
	}
}

// The deterministic form of the regression: when a chunk has committed, another write gets the connection now.
func TestIOCWriteGetsInBetweenChunks(t *testing.T) {
	t.Parallel()
	e, _ := chunkEnv(t, testIPs(2*iocChunkRows+1))
	ran := false
	e.svc.afterChunk = func(chunk int) {
		if chunk != 0 {
			return
		}
		ran = true
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if err := e.db.Write(ctx, func(*sql.Tx) error { return nil }); err != nil {
			t.Errorf("a write between chunks: %v", err)
		}
	}
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	if !ran {
		t.Error("the hook never ran")
	}
}

// A clock set back (NTP) leaves the earlier pull's rows stamped in the future; a listing that vanished is still removed.
func TestIOCVanishedListingsGoEvenWhenTheClockWentBack(t *testing.T) {
	t.Parallel()
	e, o := chunkEnv(t, testIPs(50))
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	o.body("/et.txt", `"e2"`, testIPs(20))
	e.setNow(e.clock().Add(-2 * time.Hour))
	if c, b := e.fetch("et-open"); c != 200 {
		t.Fatal(c, b)
	}
	if got := listings(t, e); got != 20 {
		t.Errorf("%d listings after a smaller list on a clock set back, want 20", got)
	}
	ev := e.pub.named(EventIOCUpdated)
	if last := ev[len(ev)-1]; last != (IOCUpdatedEvent{FeedID: "et-open", Removed: 30}) {
		t.Errorf("counts: %+v", last)
	}
}

// The same instant twice (a frozen clock): the second pull must still tell old rows from new ones.
func TestIOCVanishedListingsGoOnAFrozenClock(t *testing.T) {
	t.Parallel()
	_, db := newStore(t)
	src, err := NewStore(db).source(t.Context(), "et-open")
	if err != nil {
		t.Fatal(err)
	}
	ips := func(n int) []iocInput {
		var out []iocInput
		for _, l := range strings.Fields(testIPs(n)) {
			out = append(out, iocInput{Kind: "ip", Value: l})
		}
		return out
	}
	ok := func(*sql.Tx, int, int) error { return nil }
	if _, _, _, err := applyIOCs(t.Context(), db, epoch0, src, ips(30), nil, ok); err != nil {
		t.Fatal(err)
	}
	_, removed, _, err := applyIOCs(t.Context(), db, epoch0, src, ips(10), nil, ok)
	if err != nil || removed != 20 || listed(t, db, "et-open") != 10 {
		t.Errorf("removed %d, listed %d, err %v", removed, listed(t, db, "et-open"), err)
	}
}
