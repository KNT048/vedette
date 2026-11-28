package notify_test

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// Home shows the box's first look: the summary while it waits for the rest of its load, then when and where it was delivered, and the
// list of every finding its load named. A later "N more" summary of the same load keeps the first one as the headline.
func TestHomeFirstRunSummaryFollowsTheMessage(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	week := func() time.Time { return e.clock.Now().Add(-7 * 24 * time.Hour) }
	if f, err := e.svc.FirstRunSummary(e.ctx(), week()); err != nil || f != nil {
		t.Fatalf("before any load: %+v, %v; want none", f, err)
	}
	made := e.clock.Now()
	dir.at("f-1", 2, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-2", 2, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-1", "f-2"))

	f, err := e.svc.FirstRunSummary(e.ctx(), week())
	if err != nil || f == nil {
		t.Fatalf("waiting summary: %+v, %v", f, err)
	}
	if f.State != notify.SummaryWaiting || f.Quiet || !f.DueAt.Equal(made.Add(2*time.Minute)) || f.Load != "install" ||
		f.Title != "Patch first: 2 urgent findings on 2 devices" || f.Link != "/findings?tab=device&status=exploited" || f.Later != 0 {
		t.Fatalf("waiting summary = %+v", f)
	}
	first := f.ID

	e.clock.Add(3 * time.Minute)
	e.flush()
	f, err = e.svc.FirstRunSummary(e.ctx(), week())
	if err != nil || f == nil {
		t.Fatalf("sent summary: %+v, %v", f, err)
	}
	if f.State != notify.SummarySent || !f.SentAt.Equal(made.Add(3*time.Minute)) || len(f.Channels) != 1 || f.Channels[0] != channel.Telegram || f.NotSent != nil {
		t.Fatalf("sent summary = %+v", f)
	}

	e.clock.Add(time.Hour)
	dir.at("f-3", 2, finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-3"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	f, err = e.svc.FirstRunSummary(e.ctx(), week())
	if err != nil || f == nil {
		t.Fatalf("after a later summary: %+v, %v", f, err)
	}
	if f.ID != first || f.Title != "Patch first: 2 urgent findings on 2 devices" || f.State != notify.SummarySent || f.Later != 1 ||
		f.LaterTitle != "1 more urgent finding on 1 device to patch first" || f.Link != "/findings?tab=device&status=exploited" {
		t.Fatalf("after a later summary = %+v", f)
	}

	e.clock.Add(8 * 24 * time.Hour)
	if f, err := e.svc.FirstRunSummary(e.ctx(), week()); err != nil || f != nil {
		t.Fatalf("eight days on: %+v, %v; want none", f, err)
	}
}

// A box with no alert channel still made its summary: Home shows it with why it was not sent, said of the summary.
func TestHomeFirstRunSummaryWithoutAChannelSaysWhy(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	dir.at("f-1", 2, finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical))
	ev := firstRun(e, "f-1")
	ev.Key = "catalogue-20261109"
	if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFirstRun, ev)); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(3 * time.Minute)
	e.flush()
	f, err := e.svc.FirstRunSummary(e.ctx(), e.clock.Now().Add(-7*24*time.Hour))
	if err != nil || f == nil {
		t.Fatalf("summary: %+v, %v", f, err)
	}
	if f.State != notify.SummaryNotSent || f.NotSent == nil || f.NotSent.Reason != notify.UnsentNoChannel ||
		f.NotSent.Text != "Not sent: no alert channel was set up when it was made." || f.Load != "catalogue" ||
		f.Title != "Patch first: 1 urgent finding on 1 device" || f.Link != "/findings?tab=device&status=exploited" || !f.SentAt.IsZero() {
		t.Fatalf("summary = %+v (not sent: %+v)", f, f.NotSent)
	}
}

// Home is read by every role, the alert history by administrators only: a summary every channel failed to deliver says which channel
// failed, never the provider's or the network's error text (it can name the mail server or the webhook host; History has it).
func TestHomeFirstRunSummaryFailedKeepsTheErrorInHistory(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	e.net.failTelegram(http.StatusBadRequest)
	dir.at("f-1", 2, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	pub(notify.EventFirstRun, firstRun(e, "f-1"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	f, err := e.svc.FirstRunSummary(e.ctx(), e.clock.Now().Add(-7*24*time.Hour))
	if err != nil || f == nil {
		t.Fatalf("summary: %+v, %v", f, err)
	}
	if f.State != notify.SummaryNotSent || f.NotSent == nil || f.NotSent.Reason != notify.UnsentFailed || f.NotSent.Channel != channel.Telegram ||
		f.NotSent.Text != "Not delivered. Telegram failed to deliver it." {
		t.Fatalf("summary = %+v (not sent: %+v)", f, f.NotSent)
	}
}

// A box with no alert channel keeps each pass of its first look as its own summary (nothing waits in the queue to join). Home's headline
// is the whole first look: every finding of every pass, once (also the ones a pass counted without listing them), on how many devices;
// there is no "Since then" for passes seconds apart.
func TestHomeFirstLookWithoutAChannelCountsEveryPass(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	pub := func(ev any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFirstRun, ev)); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-1", 2, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-2", 2, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	dir.at("f-3", 2, finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical))
	dir.at("f-4", 2, finding("OpenSSH", "CVE-2026-20001", "web-01", notify.High))
	big := firstRun(e, "f-1") // a pass that counts more findings than it lists
	big.Findings, big.Devices = 3, 2
	pub(big)
	first, err := e.svc.FirstRunSummary(e.ctx(), e.clock.Now().Add(-time.Hour))
	if err != nil || first == nil {
		t.Fatalf("first pass: %+v, %v", first, err)
	}
	e.clock.Add(20 * time.Second)
	pub(firstRun(e, "f-2"))
	e.clock.Add(20 * time.Second)
	pub(firstRun(e, "f-3", "f-4"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	if n := e.count(`SELECT count(*) FROM notify_notice WHERE event = 'first_run'`); n != 3 {
		t.Fatalf("summaries kept = %d, want one per pass (3)", n)
	}
	f, err := e.svc.FirstRunSummary(e.ctx(), e.clock.Now().Add(-7*24*time.Hour))
	if err != nil || f == nil {
		t.Fatalf("summary: %+v, %v", f, err)
	}
	if f.ID != first.ID || f.Title != "Patch first: 6 urgent findings on 3 devices" || f.Later != 0 || f.LaterTitle != "" ||
		f.State != notify.SummaryNotSent || f.NotSent == nil || f.NotSent.Reason != notify.UnsentNoChannel ||
		f.Link != "/findings?tab=device&status=exploited" {
		t.Fatalf("summary = %+v (not sent: %+v)", f, f.NotSent)
	}
}

// A pass that lands while the first summary is being sent (claimed by a delivery run, not delivered yet) says "N more": the customer is
// getting the first one. On Home it joins the first look; "Since then" counts only summaries made after one was delivered.
func TestHomeFirstLookPassWhileTheFirstSummaryIsBeingSent(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	dir.at("f-1", 2, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-2", 2, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	dir.at("f-3", 2, finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-1"))
	e.clock.Add(3 * time.Minute)
	e.write(func(tx *sql.Tx) error { // a delivery run claimed it and has not sent it yet
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_pending SET state = 'claimed', claimed_at = ?`, store.FormatTS(e.clock.Now()))
		return err
	})
	e.clock.Add(20 * time.Second)
	pub(notify.EventFirstRun, firstRun(e, "f-2"))
	var title string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT title FROM notify_notice WHERE event = 'first_run' ORDER BY id DESC LIMIT 1`).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title != "1 more urgent finding on 1 device to patch first" {
		t.Fatalf("the pass made while the first summary was being sent = %q, want the \"N more\" words", title)
	}
	e.write(func(tx *sql.Tx) error { // the run sends it
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_pending SET state = 'pending', claimed_at = NULL WHERE state = 'claimed'`)
		return err
	})
	e.flush()
	e.clock.Add(3 * time.Minute)
	e.flush()
	got := summaries(e)
	if len(got) != 2 || got[0].Title != "Patch first: 1 urgent finding on 1 device" || got[1].Title != "1 more urgent finding on 1 device to patch first" ||
		!strings.HasPrefix(got[1].What, "Since the previous summary, Vedette rated 1 more finding on 1 device") {
		t.Fatalf("messages = %+v", got)
	}
	week := e.clock.Now().Add(-7 * 24 * time.Hour)
	f, err := e.svc.FirstRunSummary(e.ctx(), week)
	if err != nil || f == nil {
		t.Fatalf("summary: %+v, %v", f, err)
	}
	if f.Title != "Patch first: 2 urgent findings on 2 devices" || f.State != notify.SummarySent || f.Later != 0 || f.LaterTitle != "" {
		t.Fatalf("summary = %+v", f)
	}

	e.clock.Add(time.Hour)
	pub(notify.EventFirstRun, firstRun(e, "f-3"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	f, err = e.svc.FirstRunSummary(e.ctx(), week)
	if err != nil || f == nil {
		t.Fatalf("after a later summary: %+v, %v", f, err)
	}
	if f.Title != "Patch first: 2 urgent findings on 2 devices" || f.Later != 1 || f.LaterTitle != "1 more urgent finding on 1 device to patch first" {
		t.Fatalf("after a later summary = %+v", f)
	}
}

// countedFindings is a finding directory that counts its lookups.
type countedFindings struct {
	*liveFindings
	mu sync.Mutex
	n  int
}

func (c *countedFindings) Finding(ctx context.Context, id string) (notify.FindingInfo, bool, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.liveFindings.Finding(ctx, id)
}

func (c *countedFindings) lookups() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// Home and the menu badge read the overview every minute for a week after a first load. The headline of a first look told in several
// summaries reads each of its findings through the finding directory (milliseconds each, up to firstLookLookups); a read that finds the
// same first look counts it again from memory, not from the directory.
func TestHomeFirstLookIsCountedOncePerPass(t *testing.T) {
	dir := &countedFindings{liveFindings: &liveFindings{}}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	pub := func(ev any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFirstRun, ev)); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-1", 2, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-2", 2, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	dir.at("f-3", 2, finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical))
	pub(firstRun(e, "f-1"))
	e.clock.Add(20 * time.Second)
	pub(firstRun(e, "f-2"))
	week := e.clock.Now().Add(-7 * 24 * time.Hour)
	read := func() string {
		t.Helper()
		f, err := e.svc.FirstRunSummary(e.ctx(), week)
		if err != nil || f == nil {
			t.Fatalf("summary: %+v, %v", f, err)
		}
		return f.Title
	}
	if got := read(); got != "Patch first: 2 urgent findings on 2 devices" {
		t.Fatalf("title = %q", got)
	}
	before := dir.lookups()
	for range 3 {
		if got := read(); got != "Patch first: 2 urgent findings on 2 devices" {
			t.Fatalf("title read again = %q", got)
		}
	}
	if n := dir.lookups() - before; n != 0 {
		t.Fatalf("reading the same first look again made %d finding lookups, want 0", n)
	}
	e.clock.Add(20 * time.Second) // a new pass changes the first look: it is counted again
	pub(firstRun(e, "f-3"))
	if got := read(); got != "Patch first: 3 urgent findings on 3 devices" {
		t.Fatalf("title after a new pass = %q", got)
	}
}
