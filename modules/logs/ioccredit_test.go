package logs

import (
	"database/sql"
	"strings"
	"testing"
	"time"
)

// A list whose terms ask for credit with a time (Spamhaus DROP) is stored on the hit by its plain name, and credited with the time of
// its feed's last fetch only where the hit is shown: the incident text when it is announced, and every read (digest, Bad connections,
// one hit). So a device that reaches a listed network every day is one feed on its 7-day row, credited with the newest fetch, not one
// entry per fetch time.
func TestIOCCreditIsShownNotStored(t *testing.T) {
	t.Parallel()
	e, src, ff, p := iocEnv(t)
	const dest = "80.0.2.77"
	ff.listed["ip:"+dest] = Listing{Feeds: []string{"Spamhaus DROP"}, Confidence: 0.9}
	ff.credits = map[string]string{"Spamhaus DROP": "Spamhaus DROP (list fetched 2026-11-09 07:00 UTC)"}
	e.feedAll(src, []string{traffic(lanDevice, dest)})
	if len(p.bad) != 1 || !strings.Contains(p.bad[0].What, "is listed by Spamhaus DROP (list fetched 2026-11-09 07:00 UTC)") {
		t.Fatalf("incident text: %+v", p.bad)
	}
	var stored string
	if err := e.vol.Reader().QueryRowContext(t.Context(), `SELECT feeds FROM logs_ioc_hits WHERE dest = ?`, dest).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != `["Spamhaus DROP"]` {
		t.Fatalf("stored feeds %s, want the plain name", stored)
	}
	// the same pair a day before, stored with the plain name too; the list was fetched again since
	if err := e.vol.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO logs_ioc_hits (id, ts, src_ip, dest, dest_kind, seen_via, feeds, confidence, source_id, blocked, listed_as)
VALUES ('ih-older', ?, ?, ?, 'ip', 'syslog:FW-HQ', '["Spamhaus DROP"]', 0.9, ?, 0, '')`, t0.Add(-24*time.Hour).Format("2006-01-02T15:04:05.000Z"), lanDevice, dest, src.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ff.mu.Lock()
	ff.credits = map[string]string{"Spamhaus DROP": "Spamhaus DROP (list fetched 2026-11-10 07:00 UTC)"}
	ff.mu.Unlock()
	want := "Spamhaus DROP (list fetched 2026-11-10 07:00 UTC)"
	pairs, err := e.svc.IocPairs(t.Context(), IocPairQuery{Window: "7d"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs.Items) != 1 || strings.Join(pairs.Items[0].Feeds, "|") != want || pairs.Items[0].Hits != 2 {
		t.Errorf("bad connections: %+v", pairs.Items)
	}
	d, err := e.svc.Digest(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.BadConnections) == 0 {
		t.Error("digest: no bad connection")
	}
	for _, b := range d.BadConnections {
		if strings.Join(b.Feeds, "|") != want {
			t.Errorf("digest: %+v", b)
		}
	}
	h, found, err := e.svc.IocHit(t.Context(), "ih-older")
	if err != nil || !found || strings.Join(h.Feeds, "|") != want {
		t.Errorf("one hit: %+v %v %v", h, found, err)
	}
	// a feed name with no credit (every other list), and the feeds module off: the plain name
	ff.mu.Lock()
	ff.credits = nil
	ff.mu.Unlock()
	if h, _, _ = e.svc.IocHit(t.Context(), "ih-older"); strings.Join(h.Feeds, "|") != "Spamhaus DROP" {
		t.Errorf("without a credit: %v", h.Feeds)
	}
}
