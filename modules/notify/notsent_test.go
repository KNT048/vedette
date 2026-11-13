package notify_test

import (
	"database/sql"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// open opens a trap incident of the given severity and returns its id.
func (e *env) open(target string, sev notify.Severity) string {
	e.t.Helper()
	id, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "192.168.10.107", Target: target, Title: "192.168.10.107 touched the " + target + " trap",
		Severity: sev, Link: "/honeypot/hits/h-" + target})
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

// notSent is the reason the list gives for one incident (nil: a channel has it).
func (e *env) notSent(id string) *notify.NotSent {
	e.t.Helper()
	list, err := e.svc.Incidents(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, i := range list {
		if i.ID == id {
			d, err := e.svc.IncidentDetail(e.ctx(), id)
			if err != nil {
				e.t.Fatal(err)
			}
			if (d.Incident.NotSent == nil) != (i.NotSent == nil) || (i.NotSent != nil && *d.Incident.NotSent != *i.NotSent) {
				e.t.Fatalf("list and detail disagree: %+v, %+v", i.NotSent, d.Incident.NotSent)
			}
			return i.NotSent
		}
	}
	e.t.Fatalf("incident %s not listed", id)
	return nil
}

func wantReason(t *testing.T, got *notify.NotSent, why notify.NotSentReason, text string) {
	t.Helper()
	if got == nil || got.Reason != why || !strings.Contains(got.Text, text) {
		t.Fatalf("not sent = %+v, want %s with %q", got, why, text)
	}
}

func TestContract_INV24_NotSentSaysWhyFromTheDecision(t *testing.T) {
	e := newEnv(t)
	e.plain()
	wantReason(t, e.notSent(e.open("a", notify.Critical)), notify.UnsentNoChannel, "no alert channel was set up")

	e.telegram(notify.High)
	e.slack(notify.Critical)
	low := e.open("b", notify.Medium)
	// the decision is kept: lowering the minimum afterwards does not change why that incident was not sent
	e.telegram(notify.Low)
	wantReason(t, e.notSent(low), notify.UnsentBelowMin, "this incident is medium, and your channels only send high and above")

	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, MinSeverity: notify.Low})
	e.save(channel.Slack, notify.ChannelInput{Enabled: false, Fields: map[string]string{"label": "#it-alerts"}, MinSeverity: notify.Low})
	wantReason(t, e.notSent(e.open("c", notify.High)), notify.UnsentChannelsOff, "turned off")

	e.telegram(notify.Low)
	sent := e.open("d", notify.High)
	wantReason(t, e.notSent(sent), notify.UnsentQueued, "within a minute")
	e.flush()
	if ns := e.notSent(sent); ns != nil {
		t.Fatalf("a delivered incident has no reason: %+v", ns)
	}

	e.net.failTelegram(http.StatusBadRequest)
	// a Resend of the delivered message that fails does not undo the delivery: the customer got the alert
	h, err := e.svc.History(e.ctx())
	if err != nil || len(h.Items) == 0 {
		t.Fatalf("history: %+v, %v", h.Items, err)
	}
	if _, err := e.svc.Resend(e.ctx(), "it@acme.example", h.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if ns := e.notSent(sent); ns != nil || e.count(`SELECT COUNT(*) FROM notify_send WHERE ref_id = ? AND ok = 0`, sent) != 1 {
		t.Fatalf("delivered, then a failed resend: %+v", ns)
	}
	failed := e.open("e", notify.High)
	e.flush()
	if ns := e.notSent(failed); ns == nil || ns.Reason != notify.UnsentFailed || ns.Channel != channel.Telegram || !strings.HasPrefix(ns.Text, "Not delivered. Telegram failed to deliver it.") {
		t.Fatalf("failed send: %+v", ns)
	}
}

func TestContract_INV24_QuietHoursSayUntilWhenAndThenSend(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{Enabled: true, From: "22:00", To: "07:00"}, notify.Grouping{Enabled: false, WindowMin: 60})
	e.clock.Add(13 * time.Hour) // 23:00
	id := e.open("a", notify.High)
	e.flush()
	ns := e.notSent(id)
	wantReason(t, ns, notify.UnsentQuietHours, "Held for quiet hours until 07:00")
	if ns.Until != "2026-11-10T07:00:00.000Z" {
		t.Fatalf("until = %q", ns.Until)
	}
	// the channel it waited for is turned off before the end: the held message is dropped, and the incident says so
	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, MinSeverity: notify.Low})
	e.clock.Add(8 * time.Hour)
	e.flush()
	wantReason(t, e.notSent(id), notify.UnsentChannelOff, "was turned off before it went out")
}

func TestNotSentOfAnIncidentOpenedBeforeTheReasonWasKept(t *testing.T) {
	e := newEnv(t)
	e.plain()
	id := e.open("a", notify.Medium)
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_incident SET unsent = NULL`)
		return err
	})
	wantReason(t, e.notSent(id), notify.UnsentNoChannel, "no alert channel")
	e.telegram(notify.High)
	wantReason(t, e.notSent(id), notify.UnsentBelowMin, "only send high and above")
	e.telegram(notify.Low) // today's channels would take it: Vedette does not invent a reason
	wantReason(t, e.notSent(id), notify.UnsentUnknown, "before this version")
}

func TestContract_INV25_BulkAcknowledgeAndResolve(t *testing.T) {
	e := newEnv(t)
	e.plain()
	a, b, c := e.open("a", notify.High), e.open("b", notify.High), e.open("c", notify.High)
	if _, err := e.svc.HandleIncident(e.ctx(), "it@acme.example", c, notify.StatusResolved, "done by hand"); err != nil {
		t.Fatal(err)
	}
	audits := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status'`)

	_, err := e.svc.HandleIncidents(e.ctx(), "it@acme.example", []string{a, "in-gone"}, notify.StatusResolved, "")
	wantCode(t, err, http.StatusNotFound, "not_found")
	if e.count(`SELECT COUNT(*) FROM notify_incident WHERE status = 'resolved'`) != 1 {
		t.Fatal("an unknown id must change nothing")
	}
	_, err = e.svc.HandleIncidents(e.ctx(), "it@acme.example", []string{a}, notify.StatusNew, "")
	wantCode(t, err, http.StatusBadRequest, "bad_status")
	_, err = e.svc.HandleIncidents(e.ctx(), "it@acme.example", nil, notify.StatusResolved, "")
	wantCode(t, err, http.StatusBadRequest, "invalid")

	r, err := e.svc.HandleIncidents(e.ctx(), "it@acme.example", []string{a, a, b}, notify.StatusAcknowledged, " checking ")
	if err != nil || r != (notify.BulkResult{Updated: 2}) {
		t.Fatalf("acknowledge: %+v, %v", r, err)
	}
	r, err = e.svc.HandleIncidents(e.ctx(), "op@acme.example", []string{a, b, c}, notify.StatusAcknowledged, "")
	if err != nil || r != (notify.BulkResult{AlreadyAcknowledged: 2, AlreadyResolved: 1}) {
		t.Fatalf("acknowledge again: %+v, %v", r, err)
	}
	r, err = e.svc.HandleIncidents(e.ctx(), "op@acme.example", []string{b}, notify.StatusResolved, "")
	if err != nil || r != (notify.BulkResult{Updated: 1}) {
		t.Fatalf("resolve without a note: %+v, %v", r, err)
	}
	if d, _ := e.svc.IncidentDetail(e.ctx(), b); d.Incident.Note == nil || *d.Incident.Note != "checking" {
		t.Fatalf("no note given keeps the acknowledge note: %+v", d.Incident.Note)
	}
	r, err = e.svc.HandleIncidents(e.ctx(), "op@acme.example", []string{a, b, c}, notify.StatusResolved, "false alarm")
	if err != nil || r != (notify.BulkResult{Updated: 1, AlreadyResolved: 2}) {
		t.Fatalf("resolve: %+v, %v", r, err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_audit WHERE action = 'notify.incident_status'`) - audits; n != 4 {
		t.Fatalf("one audit row per changed incident: %d", n)
	}
	d, err := e.svc.IncidentDetail(e.ctx(), c)
	if err != nil || d.Incident.Note == nil || *d.Incident.Note != "done by hand" || *d.Incident.HandledBy != "it@acme.example" {
		t.Fatalf("a resolved incident keeps its note and who: %+v, %v", d.Incident, err)
	}
	d, _ = e.svc.IncidentDetail(e.ctx(), a)
	if d.Incident.Status != notify.StatusResolved || *d.Incident.Note != "false alarm" || *d.Incident.HandledBy != "op@acme.example" {
		t.Fatalf("resolved by the bulk change: %+v", d.Incident)
	}
}

// An earlier "Delayed (rate limited)" row does not hide what happened after it: the last attempt of the channel counts (Opus r1 MED-1).
func TestNotSentAfterARateLimitIsTheLastOutcome(t *testing.T) {
	var mu sync.Mutex
	answer := 429
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.ReadAll(r.Body)
		body := `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`
		if answer == 400 {
			body = `{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}`
		}
		return &http.Response{StatusCode: answer, Header: http.Header{}, Request: r, Body: io.NopCloser(strings.NewReader(body))}, nil
	}))
	set := func(code int) { mu.Lock(); answer = code; mu.Unlock() }
	e.telegram(notify.Low)
	e.plain()
	failed := e.open("a", notify.High)
	e.flush()
	wantReason(t, e.notSent(failed), notify.UnsentQueued, "within a minute") // waits in the queue for the provider: not a failure yet
	set(400)
	e.clock.Add(time.Minute)
	e.flush()
	if ns := e.notSent(failed); ns == nil || ns.Reason != notify.UnsentFailed || ns.Channel != channel.Telegram {
		t.Fatalf("delayed then failed: %+v", ns)
	}

	set(429)
	dropped := e.open("b", notify.High)
	e.flush()
	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, MinSeverity: notify.Low})
	e.clock.Add(time.Minute)
	e.flush()
	ns := e.notSent(dropped)
	wantReason(t, ns, notify.UnsentChannelOff, "was turned off before it went out")
	if ns.Channel != channel.Telegram {
		t.Fatalf("the channel to fix: %+v", ns)
	}

	e.telegram(notify.Low)
	gone := e.open("c", notify.High)
	e.flush() // rate limited again: waits in the queue
	if err := e.svc.DeleteChannel(e.ctx(), "admin@acme.example", channel.Telegram); err != nil {
		t.Fatal(err)
	}
	wantReason(t, e.notSent(gone), notify.UnsentChannelGone, "was removed before it went out")
}
