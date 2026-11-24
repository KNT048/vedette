package honeypot_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/honeypot"
)

// alerter is a TestAlerter that records what it was asked to send and answers with fixed results.
type alerter struct {
	mu   sync.Mutex
	got  []honeypot.HitEventData
	res  []honeypot.TestAlertResult
	fail bool
}

func (a *alerter) TestAlert(_ context.Context, h honeypot.HitEventData) ([]honeypot.TestAlertResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, h)
	if a.fail {
		return nil, errors.New("channels unreadable")
	}
	return a.res, nil
}

// Test trap proves the whole path to an alert: the test hit hands the alerter the hit a real one would publish (the trap, the service,
// the box as source), the answer and the hit's events say what each channel did, and the hit stays a test: counted nowhere, published
// nowhere.
func TestTestTrapSendsATestAlertAndStaysATest(t *testing.T) {
	t.Parallel()
	a := &alerter{res: []honeypot.TestAlertResult{
		{Channel: "email", Name: "Email", OK: true, Detail: "Email sent to it@example.com."},
		{Channel: "telegram", Name: "Telegram", Detail: "The bot token was refused."},
	}}
	e := newEnv(t, func(e *env) { e.cfg.TestAlert = a })
	e.setup()
	h, err := e.svc.TestHit(e.ctx(), "op", honeypot.SSH)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.got) != 1 || a.got[0].ID != h.ID || a.got[0].Service != "ssh" || a.got[0].Decoy != "FILESRV-OLD" || a.got[0].SrcIP != "192.168.10.2" || a.got[0].Port != 22 {
		t.Fatalf("alerter got %+v", a.got)
	}
	if h.TestAlert == nil || len(h.TestAlert.Channels) != 2 || !h.TestAlert.Channels[0].OK || h.TestAlert.Channels[1].OK {
		t.Fatalf("answer %+v", h.TestAlert)
	}
	d, err := e.svc.HitDetail(e.ctx(), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, ev := range d.Events {
		lines = append(lines, ev.Text)
	}
	all := strings.Join(lines, "\n")
	if !strings.Contains(all, "Test alert sent by Email. Email sent to it@example.com.") || !strings.Contains(all, "Test alert not delivered by Telegram: The bot token was refused.") {
		t.Fatalf("events:\n%s", all)
	}
	if len(e.pub.all()) != 0 {
		t.Fatal("a test hit was announced")
	}
	if o, _ := e.svc.Overview(e.ctx()); o.Summary.Today != 0 || o.Summary.Week != 0 {
		t.Fatalf("a test hit was counted: %+v", o.Summary)
	}
	// a hit read later carries no test alert field: it is the answer of the test only
	if l, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{}); len(l) != 1 || l[0].TestAlert != nil {
		t.Fatalf("listed %+v", l)
	}
}

// With no channel on, the test says so (a real touch would only show in Vedette); a failure to read the channels is said too, and the
// test hit is still recorded.
func TestTestTrapSaysWhenNoAlertWouldArrive(t *testing.T) {
	t.Parallel()
	a := &alerter{}
	e := newEnv(t, func(e *env) { e.cfg.TestAlert = a })
	e.setup()
	h, err := e.svc.TestHit(e.ctx(), "op", honeypot.SSH)
	if err != nil || h.TestAlert == nil || len(h.TestAlert.Channels) != 0 {
		t.Fatalf("%+v %v", h.TestAlert, err)
	}
	d, _ := e.svc.HitDetail(e.ctx(), h.ID)
	if last := d.Events[len(d.Events)-1].Text; !strings.HasPrefix(last, "No alert channel is on") {
		t.Fatalf("last event %q", last)
	}
	a.fail = true
	h, err = e.svc.TestScan(e.ctx(), "op")
	if err == nil {
		t.Fatal("a scan test needs two Trap IPs")
	}
	e.addTrapIP("NAS-OLD", "192.168.10.241", honeypot.NAS, honeypot.HTTP)
	if h, err = e.svc.TestScan(e.ctx(), "op"); err != nil || h.TestAlert == nil {
		t.Fatalf("%+v %v", h, err)
	}
	d, _ = e.svc.HitDetail(e.ctx(), h.ID)
	if last := d.Events[len(d.Events)-1].Text; !strings.HasPrefix(last, "The test alert could not be sent") {
		t.Fatalf("last event %q", last)
	}
}
