package notify_test

import (
	"net/http"
	"testing"
	"time"

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
	dir.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-2", 4, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-1", "f-2"))

	f, err := e.svc.FirstRunSummary(e.ctx(), week())
	if err != nil || f == nil {
		t.Fatalf("waiting summary: %+v, %v", f, err)
	}
	if f.State != notify.SummaryWaiting || f.Quiet || !f.DueAt.Equal(made.Add(2*time.Minute)) || f.Load != "install" ||
		f.Title != "Patch first: 2 urgent findings on 2 devices" || f.Link != "/findings?tab=device&status=public_exploit,critical_edge" || f.Later != 0 {
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
		f.LaterTitle != "1 more urgent finding on 1 device to patch first" || f.Link != "/findings?tab=device&status=exploited,public_exploit,critical_edge" {
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
	dir.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
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
