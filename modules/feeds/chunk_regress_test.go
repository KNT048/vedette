package feeds

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testIPs lists n distinct public-looking addresses, one per line.
func testIPs(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%d.%d.%d.7\n", 30+i>>16, (i>>8)&255, i&255)
	}
	return b.String()
}

// A long indicator list must not hold the single writer connection for the whole apply: another write that
// arrives during the pull gets it between chunks. The real list is 186k domains (~15 s on the e2e box, ~70 us a
// row). The bound is relative (the longest wait must be under a third of the pull) because an absolute one
// is not stable: under -race a 2000-row chunk takes seconds. 12k rows are 6 chunks, so the wait is about a
// sixth of the pull; in one transaction it was the whole pull (measured with 40k rows: 2.3 s of 2.5 s).
func TestIOCPullDoesNotHoldTheWriterForTheWholeList(t *testing.T) {
	t.Parallel()
	const rows = 12_000
	e, o := pullEnv(t)
	e.only("et-open")
	o.body("/et.txt", `"e1"`, testIPs(rows))
	e.mirror("et-open", o.url("/et.txt"))

	done := make(chan int, 1)
	began := time.Now()
	go func() { c, _ := e.fetch("et-open"); done <- c }()
	var worst time.Duration
	probes := 0
	for finished := false; !finished; {
		select {
		case c := <-done:
			if c != 200 {
				t.Fatalf("fetch: %d", c)
			}
			finished = true
		case <-time.After(5 * time.Millisecond):
			start := time.Now()
			if err := e.db.Write(t.Context(), func(*sql.Tx) error { return nil }); err != nil {
				t.Fatal(err)
			}
			worst = max(worst, time.Since(start))
			probes++
		}
	}
	total := time.Since(began)
	t.Logf("pull %v, %d probes, longest wait for the writer: %v", total, probes, worst)
	if worst > total/3 {
		t.Errorf("another write waited %v of a %v pull: the list was applied in one long transaction", worst, total)
	}
	if n := rowsOf(t, e.db, "feeds_ioc_source"); n != rows {
		t.Errorf("listings: %d", n)
	}
}
