package ops

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server/servertest"
)

// The host's own checks before the disruptive rules of zap.active: a grant the host minted when a person pressed Scan now (for that
// person, that address, one active pass, within its lifetime), and the box's default gateway read by the host itself (not
// 100.64.0.0/10, and readable). A refusal runs the page without the disruptive rules and says why in the result.
//
// The commands go through the host's socket as core sends them (JSON args, the actor header), and the args and results are written
// in their wire form, so these tests read the same on a host that does not know the grant.

// The default routes the tests give the host (/proc/net/route, the gateway in the kernel's byte order).
const (
	routeHeader  = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	routeLAN     = routeHeader + "eth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" // 192.168.10.1
	routeCGNAT   = routeHeader + "eth0\t00000000\t01004064\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" // 100.64.0.1
	routeNoDflt  = routeHeader + "eth0\t000AA8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
	zapPerson    = "exposure:admin@example.com"
	zapOther     = "exposure:operator@example.com"
	zapOtherIP   = "1.1.1.1"
	zapRuleDoS   = 30001 // Buffer Overflow: a disruptive rule
	zapRuleNoDoS = 40012 // Cross Site Scripting (Reflected): runs on every page
)

type zapAuthz struct {
	*zapWorld
	h   *servertest.Harness
	clk *servertest.Clock
}

// newZapAuthz is a host whose /proc/net/route is route ("" = none) with every command behind its socket.
func newZapAuthz(t *testing.T, route string) *zapAuthz {
	t.Helper()
	clk := servertest.NewClock(time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC))
	w := newZapWorld(t, Deps{Now: clk.Now})
	w.report = cleanZapReport()
	if route != "" {
		put(t, filepath.Dir(w.state), "proc/net/route", route)
	}
	return &zapAuthz{zapWorld: w, h: servertest.Start(t, w.o.Commands()), clk: clk}
}

func zapReqID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// call sends one command and follows its run to its end.
func (a *zapAuthz) call(cmd string, args any, actor string) (api.Run, error) {
	a.t.Helper()
	run, err := a.h.Client.Run(a.t.Context(), cmd, args, zapReqID(a.t), actor)
	for err == nil && !run.Status.Terminal() {
		select {
		case <-a.t.Context().Done():
			return run, a.t.Context().Err()
		case <-time.After(2 * time.Millisecond):
		}
		run, err = a.h.Client.GetRun(a.t.Context(), run.RunID)
	}
	return run, err
}

// grant asks the host for a person's grant of the disruptive rules on ip, as core does when a person presses Scan now.
func (a *zapAuthz) grant(ip, actor string) (string, error) {
	a.t.Helper()
	run, err := a.call("zap.authorize", map[string]any{"ip": ip}, actor)
	if err != nil {
		return "", err
	}
	if run.Status != api.StatusSucceeded {
		return "", fmt.Errorf("%s: %+v", run.Status, run.Error)
	}
	var r struct {
		Grant     string `json:"grant"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(run.Result, &r); err != nil || len(r.Grant) != 32 || r.ExpiresAt == "" {
		return "", fmt.Errorf("result %s: %w", run.Result, err)
	}
	return r.Grant, nil
}

// mustGrant is grant for a case whose point is a later refusal: a host that cannot mint one still gets the run, without a grant.
func (a *zapAuthz) mustGrant(ip string) string {
	a.t.Helper()
	g, err := a.grant(ip, zapPerson)
	if err != nil {
		a.t.Errorf("a person's grant for %s: %v", ip, err)
	}
	return g
}

// active runs zap.active with the disruptive rules asked for on the box's own IP, and returns why the host refused them ("" when it
// ran them) and whether the plan it wrote has them.
func (a *zapAuthz) active(grant, actor string) (string, bool) {
	a.t.Helper()
	args := map[string]any{"url": "https://" + zapTestIP + ":8443/", "host": zapTestIP, "ip": zapTestIP, "port": 8443, "kind": "ip", "disruptive": true}
	if grant != "" {
		args["grant"] = grant
	}
	run, err := a.call("zap.active", args, actor)
	if err != nil || run.Status != api.StatusSucceeded {
		a.t.Fatalf("zap.active: %+v %v", run, err)
	}
	var r struct {
		Refused string `json:"disruptive_refused"`
	}
	if err := json.Unmarshal(run.Result, &r); err != nil {
		a.t.Fatal(err)
	}
	a.mu.Lock()
	plan := a.plan
	a.mu.Unlock()
	rules := planRules(a.t, plan)
	if _, ok := rules[zapRuleNoDoS]; !ok {
		a.t.Fatalf("the active scan proper did not run: %s", plan)
	}
	_, rough := rules[zapRuleDoS]
	if rough != (r.Refused == "") {
		a.t.Fatalf("the plan has the disruptive rules %v, the result says refused %q", rough, r.Refused)
	}
	if rough != strings.Contains(plan, "postForm: true") {
		a.t.Fatalf("forms are posted only with the disruptive rules: %s", plan)
	}
	return r.Refused, rough
}

// The disruptive rules need a grant the host minted for a person's press: without one, or with one the host never minted (it
// restarted since, or core made one up), the page runs without them and the result says why. With the grant they run.
func TestZapActive_DisruptiveNeedsAPersonsGrant(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	if why, rough := a.active("", zapPerson); rough || why != "zap_grant_missing" {
		t.Fatalf("no grant: the host ran the disruptive rules %v (refused %q), on core's word alone", rough, why)
	}
	if why, rough := a.active("0123456789abcdef0123456789abcdef", zapPerson); rough || why != "zap_grant_unknown" {
		t.Fatalf("a grant the host never minted: the host ran the disruptive rules %v (refused %q)", rough, why)
	}
	g := a.mustGrant(zapTestIP)
	if why, rough := a.active(g, zapPerson); !rough || why != "" {
		t.Fatalf("a person's grant: disruptive rules %v, refused %q", rough, why)
	}
}

// The host reads the box's default gateway itself right before the run: behind carrier-grade NAT (100.64.0.0/10) the address is the
// provider's, shared with its other customers, and a gateway the host cannot read is treated the same (fail closed).
func TestZapActive_TheHostChecksTheGatewayItself(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, route, want string }{
		{"carrier-grade NAT", routeCGNAT, "zap_gateway_shared"},
		{"no route file", "", "zap_gateway_unreadable"},
		{"no default route", routeNoDflt, "zap_gateway_unreadable"},
	} {
		a := newZapAuthz(t, tc.route)
		g := a.mustGrant(zapTestIP)
		if why, rough := a.active(g, zapPerson); rough || why != tc.want {
			t.Errorf("%s: the host ran the disruptive rules %v (refused %q, want %s)", tc.name, rough, why, tc.want)
		}
		// The refusal did not spend the grant: the gateway back on the LAN, the same press runs them.
		put(t, filepath.Dir(a.state), "proc/net/route", routeLAN)
		if why, rough := a.active(g, zapPerson); !rough || why != "" {
			t.Errorf("%s, then the LAN gateway: disruptive rules %v, refused %q", tc.name, rough, why)
		}
	}
}

// A grant is one person's press for one address and one active pass: it expires, it is spent after the pass (its window or its pages),
// and it is refused for another address or for a run of another actor. A scheduled scan (actor system) gets none.
func TestZapActive_AGrantIsForOnePressOneAddressOnePass(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	// Expired: the active pass came too long after the press.
	g := a.mustGrant(zapTestIP)
	a.clk.Advance(6*time.Hour + time.Second)
	if why, rough := a.active(g, zapPerson); rough || why != "zap_grant_expired" {
		t.Errorf("an expired grant: disruptive rules %v, refused %q", rough, why)
	}
	// Replayed: one active pass has at most four pages.
	g = a.mustGrant(zapTestIP)
	for i := range 4 {
		if why, rough := a.active(g, zapPerson); !rough || why != "" {
			t.Errorf("page %d of the pass: disruptive rules %v, refused %q", i+1, rough, why)
		}
	}
	if why, rough := a.active(g, zapPerson); rough || why != "zap_grant_spent" {
		t.Errorf("a fifth page on one grant: disruptive rules %v, refused %q", rough, why)
	}
	// Replayed: a later scan reuses the grant of an earlier pass.
	g = a.mustGrant(zapTestIP)
	if why, rough := a.active(g, zapPerson); !rough || why != "" {
		t.Errorf("the pass: disruptive rules %v, refused %q", rough, why)
	}
	a.clk.Advance(91 * time.Minute)
	if why, rough := a.active(g, zapPerson); rough || why != "zap_grant_spent" {
		t.Errorf("a grant used again after its pass: disruptive rules %v, refused %q", rough, why)
	}
	// Another address, another person.
	if why, rough := a.active(a.mustGrant(zapOtherIP), zapPerson); rough || why != "zap_grant_mismatch" {
		t.Errorf("a grant for another address: disruptive rules %v, refused %q", rough, why)
	}
	if why, rough := a.active(a.mustGrant(zapTestIP), zapOther); rough || why != "zap_grant_mismatch" {
		t.Errorf("a grant used by a run of another actor: disruptive rules %v, refused %q", rough, why)
	}
	// Only a person's press mints one.
	for _, actor := range []string{"exposure:system", "exposure:SYSTEM", "system", "exposure", "core"} {
		_, err := a.grant(zapTestIP, actor)
		if err == nil || !strings.Contains(err.Error(), "zap_grant_not_person") {
			t.Errorf("a grant for actor %q: %v", actor, err)
		}
	}
	for _, ip := range []string{"10.0.0.1", "100.64.0.9", "203.0.113.5", "not an ip"} {
		if _, err := a.grant(ip, zapPerson); err == nil || !strings.Contains(err.Error(), "invalid_args") {
			t.Errorf("a grant for %q: %v", ip, err)
		}
	}
}

// A grant whose pass is over gives up its place at once, and a host that holds as many grants as it keeps drops the oldest press
// instead of refusing the newest one: a person who presses Scan now again always gets the disruptive rules for that press. A spent
// grant is still refused as spent, and the dropped one as one the host no longer holds.
func TestZapAuthorize_ASpentGrantFreesItsPlaceAndAFullHostDropsTheOldest(t *testing.T) {
	t.Parallel()
	a := newZapAuthz(t, routeLAN)
	spent := a.mustGrant(zapTestIP)
	for range 4 {
		if why, rough := a.active(spent, zapPerson); !rough || why != "" {
			t.Fatalf("a page of the pass: disruptive rules %v, refused %q", rough, why)
		}
	}
	held := make([]string, 0, 32)
	for i := range 32 {
		a.clk.Advance(time.Second)
		g, err := a.grant(zapTestIP, zapPerson)
		if err != nil {
			t.Fatalf("press %d after a spent grant: %v", i+1, err)
		}
		held = append(held, g)
	}
	if why, rough := a.active(spent, zapPerson); rough || why != "zap_grant_spent" {
		t.Errorf("the spent grant: disruptive rules %v, refused %q", rough, why)
	}
	a.clk.Advance(time.Second)
	newest, err := a.grant(zapTestIP, zapPerson)
	if err != nil {
		t.Fatalf("a press while the host holds as many grants as it keeps: %v", err)
	}
	if why, rough := a.active(held[0], zapPerson); rough || why != "zap_grant_unknown" {
		t.Errorf("the oldest press, dropped for the newest: disruptive rules %v, refused %q", rough, why)
	}
	for _, g := range []string{newest, held[1], held[31]} {
		if why, rough := a.active(g, zapPerson); !rough || why != "" {
			t.Errorf("a press the host still holds: disruptive rules %v, refused %q", rough, why)
		}
	}
}
