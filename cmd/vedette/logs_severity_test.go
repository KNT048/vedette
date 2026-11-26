package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/logs"
)

// seedListings stores indicators the way a pull of the built-in lists does: every listing with the default confidence 0.5 (the lists
// carry none per line), all indicator feeds switched on. Each value is listed by the given feed ids.
func seedListings(ctx context.Context, t *testing.T, s *stack, kind string, listed map[string][]string) {
	t.Helper()
	stamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE feeds_source SET enabled = 1 WHERE kind = 'ioc'`); err != nil {
			return err
		}
		for value, lists := range listed {
			id := "ioc-" + strings.NewReplacer(".", "-").Replace(value)
			if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc (id, type, value, first_seen, last_seen) VALUES (?1, ?2, ?3, ?4, ?4)`, id, kind, value, stamp); err != nil {
				return err
			}
			for _, src := range lists {
				if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_ioc_source (ioc_id, source_id, last_seen, confidence) VALUES (?, ?, ?, 0.5)`, id, src, stamp); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The severity of a bad-address incident over the five built-in indicator lists, through the real feeds store and the logs adapter.
// The counts are the listings of a real box (abuse.ch Feodo Tracker 5, ET Open 568, hagezi TIF 164,565, IPsum 17,554, Tor exit list
// 1,257), each as if a device had reached one listed by its feed alone, and the four real hits of that box (three Tor exits, one
// listed by IPsum and the Tor exit list). Before, a hit was high only from confidence 0.7 and every listing was 0.5, so every one was
// medium and none was sent by the default alert triggers (bad_address from high); now a hit is high by default, critical on the
// command-and-control list, and medium for a name only hagezi TIF lists (a pooled domain list with known false positives) and for a
// Tor exit relay that nothing but aggregated blocklists lists.
func TestBadAddressSeverityOverTheBuiltinLists(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	ctx := t.Context()
	s.setModule("feeds", true)
	rows := []struct {
		name, kind, value string
		lists             []string
		n                 int
		sev               string
	}{
		{"Feodo Tracker", "ip", "80.0.0.1", []string{"abusech-feodo"}, 5, "critical"},
		{"ET Open", "ip", "80.0.0.2", []string{"et-open"}, 568, "high"},
		{"hagezi TIF", "domain", "tif-listed.net", []string{"hagezi-tif"}, 164_565, "medium"},
		{"IPsum", "ip", "80.0.0.3", []string{"ipsum"}, 17_554, "high"},
		{"Tor exit list", "ip", "80.0.0.4", []string{"tor-exit"}, 1_257, "medium"},
		{"real hit: Tor exit", "ip", "80.0.0.5", []string{"tor-exit"}, 3, "medium"},
		{"real hit: IPsum + Tor exit", "ip", "80.0.0.6", []string{"ipsum", "tor-exit"}, 1, "medium"},
	}
	for _, r := range rows {
		seedListings(ctx, t, s, r.kind, map[string][]string{r.value: r.lists})
	}
	f := logsFeeds{s.d}
	stored, oldHigh := 0.5, 0.7 // the rule before: high only when the highest stored confidence reached 0.7
	before, after := map[string]int{}, map[string]int{}
	var table strings.Builder
	for _, r := range rows {
		l, ok, err := f.Lookup(ctx, r.kind, r.value)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", r.name, ok, err)
		}
		old := "medium"
		if stored >= oldHigh {
			old = "high"
		}
		before[old] += r.n
		after[l.Severity()] += r.n
		fmt.Fprintf(&table, "%-28s %8d  %s -> %s (confidence %.0f%%)\n", r.name, r.n, old, l.Severity(), l.Confidence*100)
		if l.Severity() != r.sev {
			t.Errorf("%s: %s (confidence %v, c2 %v), want %s", r.name, l.Severity(), l.Confidence, l.C2, r.sev)
		}
	}
	t.Logf("\n%sbefore %v\nafter  %v", table.String(), before, after)
	if before["medium"] != 183_953 || len(before) != 1 {
		t.Errorf("before: %v", before)
	}
	if after["critical"] != 5 || after["high"] != 18_122 || after["medium"] != 165_826 {
		t.Errorf("after: %v", after)
	}
}

// Through the real logs -> notify path with the default alert triggers: a device that reaches an address ET Open lists (stored at the
// default 0.5) opens a high incident that is sent; one that reaches a Feodo Tracker server opens a critical one, sent; one that reaches
// a Tor exit relay opens a medium incident that is recorded and held by the trigger (bad_address sends from high). The text says the
// real confidence.
func TestWiringBadAddressIncidentIsSentByTheDefaultTriggers(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	s.telegramOn()
	ctx := t.Context()
	s.setModule("feeds", true)
	s.setModule("logs", true)
	seedListings(ctx, t, s, "ip", map[string][]string{"80.0.0.2": {"et-open"}, "80.0.0.1": {"abusech-feodo"}, "80.0.0.4": {"tor-exit"}})
	lsvc := logsService(*s.d)
	src, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.254", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := func(local, dst string) logs.Line {
		return logs.Line{SourceID: src.ID, At: time.Now().UTC(), Text: `date=2026-11-26 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=` + local + ` dstip=` + dst + ` dstport=443 action="accept"`}
	}
	notices := len(s.queuedNotices())
	if _, err := lsvc.Ingest(ctx, []logs.Line{line("10.0.10.21", "80.0.0.2"), line("10.0.10.22", "80.0.0.1"), line("10.0.10.23", "80.0.0.4")}); err != nil {
		t.Fatal(err)
	}
	for dest, want := range map[string]struct{ sev, unsent, conf string }{
		"80.0.0.2": {"high", "queued", "Confidence 85%"},
		"80.0.0.1": {"critical", "queued", "Confidence 95%"},
		"80.0.0.4": {"medium", "trigger_off", "Confidence 20%"},
	} {
		var sev, unsent, what string
		if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT severity, ifnull(unsent, ''), what FROM notify_incident WHERE kind = 'bad_address' AND title LIKE ?`, "%"+dest+"%").Scan(&sev, &unsent, &what); err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
		if sev != want.sev || unsent != want.unsent || !strings.Contains(what, want.conf) {
			t.Errorf("%s: severity %s unsent %q what %q, want %s %q %s", dest, sev, unsent, what, want.sev, want.unsent, want.conf)
		}
	}
	if n := len(s.queuedNotices()) - notices; n != 2 {
		t.Errorf("%d notices queued, want the high and the critical one", n)
	}
}

// Spamhaus DROP lists networks, not addresses. Through the real logs -> notify path with the default alert triggers: a device that reaches
// an address inside a listed network opens a high incident (0.9) that is sent, and the incident and the stored hit credit Spamhaus DROP
// with the time the box fetched the list; an address just outside the network is no hit at all.
func TestWiringSpamhausDROPNetworkHitIsHighAndCredited(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.enableNotify()
	s.telegramOn()
	ctx := t.Context()
	s.setModule("feeds", true)
	s.setModule("logs", true)
	seedListings(ctx, t, s, "ip", map[string][]string{"80.0.2.0/24": {"spamhaus-drop"}})
	var fetched string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT last_seen FROM feeds_ioc_source WHERE source_id = 'spamhaus-drop'`).Scan(&fetched); err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse("2006-01-02T15:04:05.000Z", fetched)
	if err != nil {
		t.Fatal(err)
	}
	credit := "Spamhaus DROP (list fetched " + at.Format("2006-01-02 15:04") + " UTC)"
	lsvc := logsService(*s.d)
	src, err := lsvc.AddSource(ctx, "admin@acme.example", logs.Input{Kind: "fortigate", Name: "FW-HQ", SenderIP: "10.0.10.254", Proto: "udp", Port: 514})
	if err != nil {
		t.Fatal(err)
	}
	line := func(local, dst string) logs.Line {
		return logs.Line{SourceID: src.ID, At: time.Now().UTC(), Text: `date=2026-11-26 time=10:20:00 devname="FW-HQ" logid="0000000013" type="traffic" subtype="forward" srcip=` + local + ` dstip=` + dst + ` dstport=443 action="accept"`}
	}
	notices := len(s.queuedNotices())
	if _, err := lsvc.Ingest(ctx, []logs.Line{line("10.0.10.21", "80.0.2.77"), line("10.0.10.22", "80.0.3.1")}); err != nil {
		t.Fatal(err)
	}
	var sev, unsent, what string
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT severity, ifnull(unsent, ''), what FROM notify_incident WHERE kind = 'bad_address' AND title LIKE '%80.0.2.77%'`).Scan(&sev, &unsent, &what); err != nil {
		t.Fatal(err)
	}
	if sev != "high" || unsent != "queued" || !strings.Contains(what, "Confidence 90%") || !strings.Contains(what, credit) {
		t.Errorf("incident: severity %s unsent %q what %q, want high, queued, 90%%, %q", sev, unsent, what, credit)
	}
	var n int
	if err := s.d.DB.Reader().QueryRowContext(ctx, `SELECT count(*) FROM notify_incident WHERE kind = 'bad_address' AND title LIKE '%80.0.3.1%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("an address outside the listed network: %d incidents, %v", n, err)
	}
	hits, err := lsvc.IocHits(ctx, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Dest != "80.0.2.77" || len(hits[0].Feeds) != 1 || hits[0].Feeds[0] != credit {
		t.Errorf("hits: %+v", hits)
	}
	if k := len(s.queuedNotices()) - notices; k != 1 {
		t.Errorf("%d notices queued, want the high one", k)
	}
}
