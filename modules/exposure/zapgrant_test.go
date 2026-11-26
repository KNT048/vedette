package exposure

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// INV-24a, the host's own witness of a person's press: a person's Scan now (or Run once now) of the box's own IP asks the host for
// its grant of the disruptive rules, and the active pass hands it to the host with each page; a scan the box runs by itself never
// asks. When the host runs a page without the disruptive rules (no grant that holds, or its own read of the gateway), the page counts
// as a page without them and the run says why.

// grantWeb is an activeWeb that is also the host's zap.authorize, and whose host may refuse the disruptive rules (refused: the
// sentence the adapter makes of the host's code).
type grantWeb struct {
	*activeWeb
	mu      sync.Mutex
	asked   []string // user@ip of each grant asked for
	refused string
}

func (g *grantWeb) GrantDisruptive(_ context.Context, user string, ip netip.Addr) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, user+"@"+ip.String())
	return "grant-" + user, nil
}

func (g *grantWeb) Active(ctx context.Context, st ScanTarget, p WebPage) (WebScan, error) {
	res, err := g.activeWeb.Active(ctx, st, p)
	if st.Mode.Disruptive && g.refused != "" {
		res.DisruptiveRefused = g.refused
	}
	return res, err
}

func (g *grantWeb) grantsAsked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.asked...)
}

func (e *env) wireGrant(active func(string) []byte) *grantWeb {
	g := &grantWeb{activeWeb: e.wireActive(active)}
	e.svc.cfg.Web = g
	e.svc.cfg.Gateway = &fakeGateway{g: GatewayDevice{IP: netip.MustParseAddr("192.0.2.1")}}
	return g
}

// A person's press of Scan now asks the host for the grant once, for that person and the target's IP; every page of the active pass
// carries it. A scheduled scan and a scan whose terms leave out the disruptive checks ask for none.
func TestZapActive_APersonsPressAsksTheHostForItsGrant(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireGrant(emptyReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if got := w.grantsAsked(); len(got) != 1 || got[0] != "admin@acme.example@"+ipA {
		t.Fatalf("grants asked at the press: %q", got)
	}
	if len(w.calls) != 3 {
		t.Fatalf("%d active pages", len(w.calls))
	}
	for _, c := range w.calls {
		if !c.Mode.Disruptive || c.Grant != "grant-admin@acme.example" {
			t.Fatalf("a page of the person's pass: disruptive %v, grant %q", c.Mode.Disruptive, c.Grant)
		}
	}
	w.calls = nil
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), SystemUser, id); err != nil {
		t.Fatal(err)
	}
	if got := w.grantsAsked(); len(got) != 1 {
		t.Fatalf("a scheduled scan asked the host for a grant: %q", got)
	}
	e.acceptTerms(id, false)
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if got := w.grantsAsked(); len(got) != 1 {
		t.Fatalf("a scan without the disruptive checks asked the host for a grant: %q", got)
	}
	for _, c := range w.calls {
		if c.Mode.Disruptive || c.Grant != "" {
			t.Fatalf("a page without the disruptive checks: disruptive %v, grant %q", c.Mode.Disruptive, c.Grant)
		}
	}
}

// Run once now is a person's press too: it asks for the grant with the person who pressed it.
func TestZapActive_RunOnceNowAsksTheHostForItsGrant(t *testing.T) {
	t.Parallel()
	e, sch := scheduleEnv(t)
	w := e.wireGrant(emptyReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	runID, err := sch.RunNow(e.ctx(), ScheduleKey(id), "admin@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	e.waitScan(runID)
	if got := w.grantsAsked(); len(got) != 1 || got[0] != "admin@acme.example@"+ipA {
		t.Fatalf("grants asked at Run once now: %q", got)
	}
	if len(w.calls) == 0 || w.calls[0].Grant != "grant-admin@acme.example" {
		t.Fatalf("the pages of Run once now: %+v", w.calls)
	}
}

// The host ran the pages without the disruptive rules: they count as pages of a pass without them (an issue a disruptive rule found
// earlier stays open), the active step says so with the host's reason, and so does the scan's line.
func TestZapActive_AHostRefusalRunsThePageWithoutTheDisruptiveRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	w := e.wireGrant(persistentXSSReport)
	id := e.committedIP(ipA).ID
	e.acceptTerms(id, true)
	open := func(plugin string) int {
		return e.count(`SELECT count(*) FROM exp_issue WHERE engine = 'zap' AND key LIKE '` + plugin + `@%' AND state = 'open'`)
	}
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if open("40014") != 3 {
		t.Fatalf("after the disruptive pass: %d open 40014", open("40014"))
	}
	const why = "the box's host helper read the box's default gateway in 100.64.0.0/10 (carrier-grade NAT)."
	w.refused, w.active = why, emptyReport
	e.advance(ScanEvery)
	s, err := e.svc.Scan(e.ctx(), "admin@acme.example", id)
	if err != nil {
		t.Fatal(err)
	}
	if open("40014") != 3 {
		t.Fatalf("a pass the host ran without the disruptive rules closed %d issues of a disruptive rule", 3-open("40014"))
	}
	if open("40012") != 0 {
		t.Fatalf("the rules it did run did not close %d issues", open("40012"))
	}
	if !lineWith(notChecked(s), "ran without its disruptive rules") || !lineWith(notChecked(s), why) {
		t.Fatalf("not checked: %q", notChecked(s))
	}
	st, note := e.runStep(stepNameZAPAct)
	if !strings.Contains(note, "ZAP attacked 3 of 3 pages without the disruptive rules") || !strings.Contains(note, why) {
		t.Fatalf("the active step: %s %q", st.Status, note)
	}
}
