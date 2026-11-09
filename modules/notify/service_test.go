package notify_test

import (
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

func apiCode(err error) (int, string) {
	if e, ok := apierr.As(err); ok {
		return e.Status, e.Code
	}
	return 0, ""
}

func wantCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	if s, c := apiCode(err); s != status || c != code {
		t.Fatalf("error = %v (%d %s), want %d %s", err, s, c, status, code)
	}
}

func (e *env) rules(q notify.Quiet, g notify.Grouping) {
	e.t.Helper()
	if _, err := e.svc.SaveRules(e.ctx(), "admin@acme.example", notify.Rules{Quiet: q, Grouping: g}); err != nil {
		e.t.Fatal(err)
	}
}

// plain turns the rules into "send at once, no quiet hours".
func (e *env) plain() {
	e.rules(notify.Quiet{From: "22:00", To: "06:30", AllowCritical: true}, notify.Grouping{Enabled: false, WindowMin: 60})
}

func TestMigrationsUsePrefix(t *testing.T) {
	storetest.AssertMigrationsUsePrefix(t, "notify", notify.Migrations, "notify_", storetest.Migration{Module: "core", FS: core.Migrations})
}

func TestContract_INV1_SecretsOnlyAsLast4(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Medium)
	v, err := e.svc.Channels(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), tgSecret) {
		t.Fatalf("the channel list holds the secret: %s", raw)
	}
	tg := v.Channels[0]
	if tg.SecretLast4 == nil || *tg.SecretLast4 != tgToken[len(tgToken)-4:] || len(v.Channels) != 6 {
		t.Fatalf("telegram = %+v, %d channels", tg, len(v.Channels))
	}
	if got := e.count(`SELECT COUNT(*) FROM core_audit WHERE detail LIKE '%' || ? || '%' OR target LIKE '%' || ? || '%'`, tgSecret, tgSecret); got != 0 {
		t.Fatalf("the audit log holds the secret (%d rows)", got)
	}
	// An empty secret keeps the saved one: the test message is sent with the old token.
	e.save(channel.Telegram, notify.ChannelInput{Enabled: true, Fields: map[string]string{"chat_id": "@vedette_alerts"}, MinSeverity: notify.High})
	res, err := e.svc.TestChannel(e.ctx(), "admin@acme.example", channel.Telegram)
	if err != nil || !res.OK {
		t.Fatalf("test = %+v, %v", res, err)
	}
	calls := e.net.to("api.telegram.org")
	if len(calls) != 1 || !strings.Contains(calls[0].Path, tgToken) {
		t.Fatalf("calls = %+v", calls)
	}
	if strings.Contains(res.Detail, tgSecret) {
		t.Fatalf("test result shows the token: %s", res.Detail)
	}
}

func TestContract_INV2_NoUnmatchedCVE(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	for _, devs := range [][]string{nil, {"  "}, {""}} {
		if err := e.svc.Publish(e.ctx(), e.vulnNotice("n-"+strings.Join(devs, "x")+"u", "QNAP", "CVE-2026-1", notify.Critical, devs...)); err != nil {
			t.Fatal(err)
		}
	}
	e.flush()
	if e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 || e.count(`SELECT COUNT(*) FROM notify_send`) != 0 || e.count(`SELECT COUNT(*) FROM notify_notice`) != 0 {
		t.Fatalf("an unmatched notice left a trace: %d calls", e.net.total())
	}
	h, err := e.svc.History(e.ctx())
	if err != nil || h.Suppressed.Count != 3 || h.Suppressed.Days != 7 || len(h.Items) != 0 {
		t.Fatalf("history = %+v, %v", h, err)
	}
	// A matched one is sent.
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("n-ok", "QNAP", "CVE-2026-2", notify.Critical, "NAS-01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 1 {
		t.Fatalf("matched notice not sent: %d", e.net.total())
	}
}

func TestContract_INV3_GroupsSameProductInsideWindow(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{From: "22:00", To: "06:30", AllowCritical: true}, notify.Grouping{Enabled: true, WindowMin: 15})
	t0 := e.clock.Now()
	for i, id := range []string{"a", "b", "c"} {
		n := e.vulnNotice(id, "QNAP Photo Station", "CVE-2026-"+id, notify.High, "NAS-01")
		n.At = t0.Add(time.Duration(i*5) * time.Minute)
		if err := e.svc.Publish(e.ctx(), n); err != nil {
			t.Fatal(err)
		}
	}
	other := e.vulnNotice("z", "WordPress", "CVE-2026-9", notify.High, "WEB01")
	if err := e.svc.Publish(e.ctx(), other); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if e.net.total() != 0 {
		t.Fatalf("sent before the window ended: %d", e.net.total())
	}
	e.clock.Add(15 * time.Minute)
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want one grouped message and one for the other product", len(calls))
	}
	var grouped int
	for _, c := range calls {
		if strings.Contains(c.Body, "3 vulnerabilities") {
			grouped++
		}
	}
	if grouped != 1 {
		t.Fatalf("grouped messages = %d: %+v", grouped, calls)
	}
	// The finding page lists the one message for each of the three findings.
	for _, f := range []string{"f-a", "f-b", "f-c"} {
		l, err := e.svc.FindingNotices(e.ctx(), f)
		if err != nil || len(l) != 1 {
			t.Fatalf("notices of %s = %+v, %v", f, l, err)
		}
	}
}

func TestContract_INV3_CriticalIsNeverHeldByGrouping(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{From: "22:00", To: "06:30", AllowCritical: true}, notify.Grouping{Enabled: true, WindowMin: 240})
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("c", "Fortinet FortiOS", "CVE-2026-5", notify.Critical, "FW-01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 1 {
		t.Fatalf("a critical notice waited for the grouping window")
	}
}

func TestContract_INV4_MinSeverityPerChannel(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.High)
	e.slack(notify.Low)
	e.plain()
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("m", "WordPress", "CVE-2026-3", notify.Medium, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 0 || len(e.net.to("hooks.slack.com")) != 1 {
		t.Fatalf("telegram %d, slack %d", len(e.net.to("api.telegram.org")), len(e.net.to("hooks.slack.com")))
	}
	// Raising the minimum after queueing drops what is still waiting for that channel.
	e.rules(notify.Quiet{From: "22:00", To: "06:30", AllowCritical: true}, notify.Grouping{Enabled: true, WindowMin: 60})
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("m2", "WordPress", "CVE-2026-4", notify.Medium, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.slack(notify.High)
	e.clock.Add(time.Hour)
	e.flush()
	if len(e.net.to("hooks.slack.com")) != 1 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("slack %d, pending %d", len(e.net.to("hooks.slack.com")), e.count(`SELECT COUNT(*) FROM notify_pending`))
	}
}

func TestContract_INV5_QuietHoursHoldThenReleaseGrouped(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: true}, notify.Grouping{Enabled: false, WindowMin: 60})
	e.clock.Add(13 * time.Hour) // 23:00
	for _, n := range []notify.Notice{
		e.vulnNotice("h1", "QNAP", "CVE-2026-11", notify.High, "NAS-01"),
		e.vulnNotice("h2", "QNAP", "CVE-2026-12", notify.Medium, "NAS-01"),
		e.vulnNotice("k1", "Fortinet", "CVE-2026-13", notify.Critical, "FW-01"),
	} {
		if err := e.svc.Publish(e.ctx(), n); err != nil {
			t.Fatal(err)
		}
	}
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 1 || !strings.Contains(calls[0].Body, "CVE-2026-13") {
		t.Fatalf("during quiet hours only the critical notice goes: %+v", calls)
	}
	e.clock.Add(7 * time.Hour) // 06:00, still quiet
	e.flush()
	if len(e.net.to("api.telegram.org")) != 1 {
		t.Fatalf("released before the end of quiet hours")
	}
	e.clock.Add(31 * time.Minute) // 06:31
	e.flush()
	calls = e.net.to("api.telegram.org")
	if len(calls) != 2 || !strings.Contains(calls[1].Body, "2 vulnerabilities") {
		t.Fatalf("after quiet hours the held notices go as one message: %+v", calls)
	}
	e.flush()
	if len(e.net.to("api.telegram.org")) != 2 {
		t.Fatalf("sent twice")
	}
}

func TestContract_INV5_QuietHoursCriticalWaitsWhenNotAllowed(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "22:00", To: "06:30", AllowCritical: false}, notify.Grouping{Enabled: false, WindowMin: 60})
	e.clock.Add(13 * time.Hour)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("k", "Fortinet", "CVE-2026-13", notify.Critical, "FW-01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if e.net.total() != 0 {
		t.Fatalf("critical went during quiet hours although allow_critical is off")
	}
}

func TestContract_INV6_EveryAttemptHasRecord(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.slack(notify.Low)
	e.plain()
	e.net.failTelegram(500)
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("r", "WordPress", "CVE-2026-20", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.flush()
	h, err := e.svc.History(e.ctx())
	if err != nil || len(h.Items) != 2 {
		t.Fatalf("history = %+v, %v", h, err)
	}
	var okN, failN int
	for _, it := range h.Items {
		if it.OK {
			okN++
		} else if it.Error != "" && it.Kind == "vuln" && it.Link == "/findings/f-r" {
			failN++
		}
	}
	if okN != 1 || failN != 1 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("ok %d, failed %d: %+v", okN, failN, h.Items)
	}
	if e.seen.count("notify.message.failed") != 1 || e.seen.count("notify.message.sent") != 1 {
		t.Fatalf("events: sent %d, failed %d", e.seen.count("notify.message.sent"), e.seen.count("notify.message.failed"))
	}
}

func TestContract_INV6_NeverSentTwice(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("d", "WordPress", "CVE-2026-21", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	// The same notice published again (an event delivered twice) is not queued twice.
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("d", "WordPress", "CVE-2026-21", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() { _ = e.svc.Flush(e.ctx()) })
	}
	wg.Wait()
	if n := len(e.net.to("api.telegram.org")); n != 1 || e.count(`SELECT COUNT(*) FROM notify_send`) != 1 {
		t.Fatalf("sent %d times, %d records", n, e.count(`SELECT COUNT(*) FROM notify_send`))
	}
}

func TestContract_INV6_InterruptedSendIsRecordedNotRepeated(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	if err := e.svc.Publish(e.ctx(), e.vulnNotice("s", "WordPress", "CVE-2026-22", notify.High, "WEB01")); err != nil {
		t.Fatal(err)
	}
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_pending SET state = 'claimed', claimed_at = ?`, store.FormatTS(e.clock.Now().Add(-time.Hour)))
		return err
	})
	e.flush()
	h, err := e.svc.History(e.ctx())
	if err != nil || len(h.Items) != 1 || h.Items[0].OK || h.Items[0].Error == "" || e.net.total() != 0 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("history = %+v, %v, %d calls", h, err, e.net.total())
	}
}
