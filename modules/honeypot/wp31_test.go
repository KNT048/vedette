package honeypot_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/honeypot"
)

// WP-31 L13 (D-189): variation selectors are invisible text an attacker chooses; clean drops them like the other invisible characters.
func TestHostileTextLosesVariationSelectors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	hidden := "\ufe00\ufe0f\U000e0100\U000e01ef\u034f\u3164\u180b" // variation selectors, then other default-ignorable characters
	e.appendLog(ln{LogType: 4002, Src: "192.168.10.157", SrcPort: 1, DstPort: 22, At: t0, Data: map[string]any{"USERNAME": "ro" + hidden + "ot", "REMOTEVERSION": "SSH" + hidden + "-2.0"}}.json())
	e.poll()
	hits, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits %d, %v", len(hits), err)
	}
	h := hits[0]
	for _, field := range []string{h.Excerpt, h.Label} {
		for _, r := range field {
			if observe.Ignorable(r) {
				t.Fatalf("invisible character U+%04X survived in %q", r, field)
			}
		}
	}
	if !strings.Contains(h.Excerpt, "root") {
		t.Fatalf("the visible text was lost: %q", h.Excerpt)
	}
}

// WP-31 L14 (D-189, INV-10): a viewer sees the bait password masked, an operator and an administrator in full.
func TestTokenPasswordIsMaskedForAViewer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	tk, err := e.svc.AddToken(e.ctx(), "admin@acme.example", honeypot.TokenInput{Type: honeypot.TokenCredential, Name: "svc-old", PlantAt: "Password manager"})
	if err != nil || tk.Password == nil {
		t.Fatalf("token %+v, %v", tk, err)
	}
	full := *tk.Password
	h := honeypot.NewHoneypotHandlers(e.svc)
	read := func(role routes.Role) string {
		res, err := h.HoneypotGetHoneypotTokens(server.WithPrincipal(e.ctx(), server.Principal{ID: "u", Email: "u@acme.example", Role: role}))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(res)
		var out struct{ Items []struct{ Password *string } }
		if err := json.Unmarshal(raw, &out); err != nil || len(out.Items) != 1 || out.Items[0].Password == nil {
			t.Fatalf("%s: %s, %v", role, raw, err)
		}
		return *out.Items[0].Password
	}
	if got := read(routes.Viewer); got == full || strings.Contains(got, full[:len(full)-4]) || !strings.HasSuffix(got, full[len(full)-4:]) {
		t.Fatalf("viewer saw %q of %q", got, full)
	}
	for _, r := range []routes.Role{routes.Operator, routes.Admin} {
		if got := read(r); got != full {
			t.Fatalf("%s saw %q, want the full password", r, got)
		}
	}
	if _, err := h.HoneypotGetHoneypotTokens(e.ctx()); err == nil {
		t.Fatal("no principal must not read tokens")
	}
	if got := honeypot.MaskTokens([]honeypot.Token{{Password: new("short")}})[0].Password; strings.Contains(*got, "hort") {
		t.Fatalf("a short password shows its tail: %q", *got)
	}
}

// WP-31 L11 (D-189, SYS-5): EnsureOff keeps failing until the host has confirmed, then it is done; on a module that is on it does nothing.
func TestEnsureOffConvergesOnlyWhenTheHostConfirms(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.host.running || len(e.host.ips) == 0 {
		t.Fatal("setup: the traps are not up")
	}
	if err := e.svc.EnsureOff(ctx); err != nil || !e.host.running {
		t.Fatalf("EnsureOff on a module that is on must do nothing: %v running=%v", err, e.host.running)
	}
	e.gate.turnOff()
	e.host.mu.Lock()
	e.host.failStop, e.host.failRm = errors.New("host busy"), errors.New("host busy")
	e.host.mu.Unlock()
	if err := e.svc.EnsureOff(ctx); err == nil {
		t.Fatal("a failed teardown reported success")
	}
	e.host.mu.Lock()
	still := e.host.running || len(e.host.ips) > 0
	e.host.failStop, e.host.failRm = nil, nil
	e.host.mu.Unlock()
	if !still {
		t.Fatal("fake host torn down despite the failures")
	}
	if got := e.svc.DecoyIPs(ctx); len(got) == 0 {
		t.Fatal("the module forgot the addresses the host still holds")
	}
	if err := e.svc.EnsureOff(ctx); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	defer e.host.mu.Unlock()
	if e.host.running || len(e.host.ips) != 0 {
		t.Fatalf("after the retry: running=%v ips=%v", e.host.running, e.host.ips)
	}
}

// A restart with the module off: a fresh service (nothing in memory) tears down what the database says the host holds.
func TestEnsureOffAfterARestartRemovesWhatTheLastRunLeft(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.gate.turnOff()
	again, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.EnsureOff(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	defer e.host.mu.Unlock()
	if e.host.running || len(e.host.ips) != 0 {
		t.Fatalf("running=%v ips=%v", e.host.running, e.host.ips)
	}
}

// H1: a host that is unreachable during the switch-off is not a host with nothing on it: the teardown fails (the guard
// retries) while the record says the host holds addresses, and succeeds once the host answers and has been cleaned.
func TestEnsureOffFailsWhileAnUnavailableHostMayStillHoldTraps(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx := e.ctx()
	if err := e.svc.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	e.gate.turnOff()
	e.host.mu.Lock()
	e.host.status.Available = false
	e.host.failRm = errors.New("vedette-host is not answering") // unreachable: nothing can be removed either
	e.host.mu.Unlock()
	if err := e.svc.EnsureOff(ctx); err == nil {
		t.Fatal("an unavailable host that still holds applied addresses was reported as torn down")
	}
	e.host.mu.Lock()
	e.host.status.Available = true
	e.host.failRm = nil
	e.host.mu.Unlock()
	if err := e.svc.EnsureOff(ctx); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	defer e.host.mu.Unlock()
	if e.host.running || len(e.host.ips) != 0 {
		t.Fatalf("running=%v ips=%v", e.host.running, e.host.ips)
	}
}

// With nothing recorded and nothing running, an unavailable host is simply not an appliance: done.
func TestEnsureOffOnAHostThatIsNotAnApplianceIsDone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.host.mu.Lock()
	e.host.status.Available = false
	e.host.mu.Unlock()
	e.gate.turnOff()
	if err := e.svc.EnsureOff(e.ctx()); err != nil {
		t.Fatal(err)
	}
}

// M1: an Apply that gets the lock after the module was switched off must not bring the traps back.
func TestApplyDoesNothingWhileTheModuleIsOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.gate.turnOff()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got := e.host.log(); len(got) != 0 {
		t.Fatalf("Apply on a module that is off called the host: %v", got)
	}
}

// M1: an address the host accepted while core was stopping (the context was cancelled) is still on record, so the teardown can remove it.
func TestApplyRecordsAnAddressTheHostTookWhileTheContextWasCancelled(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	ctx, cancel := context.WithCancel(e.ctx())
	e.host.mu.Lock()
	e.host.onAdd = cancel
	e.host.mu.Unlock()
	_ = e.svc.Apply(ctx)
	e.host.mu.Lock()
	held := len(e.host.ips)
	e.host.mu.Unlock()
	if held == 0 {
		t.Fatal("setup: the host took nothing")
	}
	if got := e.svc.DecoyIPs(e.ctx()); len(got) != held {
		t.Fatalf("the host holds %d addresses, the record has %v", held, got)
	}
	e.gate.turnOff()
	if err := e.svc.EnsureOff(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.host.mu.Lock()
	defer e.host.mu.Unlock()
	if len(e.host.ips) != 0 {
		t.Fatalf("the teardown left %v", e.host.ips)
	}
}

// H2: only a refusal of the host drops an address from the record and shows a conflict; an unknown outcome (the answer was
// lost, the host was busy) keeps it on record, shows no conflict, stops this Apply from asking for more, and the teardown
// removes what the host did take (SYS-5).
func TestApplyTreatsOnlyARefusalAsARefusal(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	sec := addr("192.168.10.240")
	e.host.mu.Lock()
	e.host.failAdd = map[netip.Addr]error{sec: errors.New("the host's answer was lost, outcome unknown")}
	e.host.addTook = true
	e.host.mu.Unlock()
	if err := e.svc.Apply(e.ctx()); err == nil || errors.Is(err, honeypot.ErrRefused) {
		t.Fatalf("an unknown outcome: %v", err)
	}
	if got := e.svc.DecoyIPs(e.ctx()); len(got) != 1 || got[0] != sec {
		t.Fatalf("the address the host may hold is not on record: %v", got)
	}
	for _, tr := range overviewTraps(t, e) {
		if tr.State == "conflict" {
			t.Fatalf("an unknown outcome shows %s as a conflict", tr.Service)
		}
	}
	if ok, _ := e.svc.HostStatus(); ok {
		t.Fatal("a trap listens on an address nobody confirmed")
	}
	e.gate.turnOff()
	if err := e.svc.EnsureOff(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.host.ipCount() != 0 {
		t.Fatalf("the teardown left %d addresses on the host", e.host.ipCount())
	}

	// A refusal is a refusal: dropped from the record, shown as a conflict.
	e2 := newEnv(t)
	e2.setup()
	e2.host.mu.Lock()
	e2.host.failAdd = map[netip.Addr]error{sec: fmt.Errorf("another device answers (ip_in_use): %w", honeypot.ErrRefused)}
	e2.host.mu.Unlock()
	_ = e2.svc.Apply(e2.ctx())
	if got := e2.svc.DecoyIPs(e2.ctx()); len(got) != 0 {
		t.Fatalf("a refused address is on record: %v", got)
	}
	conflicts := 0
	for _, tr := range overviewTraps(t, e2) {
		if tr.State == "conflict" {
			conflicts++
		}
	}
	if conflicts == 0 {
		t.Fatal("a refused address shows no conflict")
	}

	// #475: a refusal for the host's own failure (its decoy build failed) is dropped from the record too, but it is no
	// clash: the traps are "failed" (the secondary IP is not up), even with a decoy placed and the container running.
	e3 := newEnv(t)
	e3.setup()
	e3.addTrapIP("LNX-OLD", "192.168.10.241", honeypot.Linux, honeypot.HTTP)
	e3.host.mu.Lock()
	e3.host.failAdd = map[netip.Addr]error{sec: fmt.Errorf("the host could not do it (decoy_failed): %w %w", honeypot.ErrRefused, honeypot.ErrHostFailed)}
	e3.host.mu.Unlock()
	_ = e3.svc.Apply(e3.ctx())
	if got := e3.svc.DecoyIPs(e3.ctx()); len(got) != 1 || got[0] != addr("192.168.10.241") {
		t.Fatalf("on record: %v", got)
	}
	if !e3.host.isRunning() || e3.svc.TrapConflicts()[sec] == "" {
		t.Fatalf("running=%v conflicts=%v", e3.host.isRunning(), e3.svc.TrapConflicts())
	}
	for _, tr := range overviewTraps(t, e3) {
		mine := tr.Service == honeypot.SSH || tr.Service == honeypot.SMB // the services only the refused Trap IP has
		if mine != (tr.State == honeypot.StateFailed) {                  // no clash, but not listening either: the box says it could not set the address up
			t.Fatalf("a Trap IP the host could not set up shows %s as %s", tr.Service, tr.State)
		}
	}
	if d := e3.trapIP(e3.main); d.State != honeypot.StateFailed {
		t.Fatalf("the Trap IP the host could not set up: %+v", d)
	}
}

// M1: after an unknown outcome the Apply asks the host for no further address.
func TestApplyStopsAskingAfterAnUnknownOutcome(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.addTrapIP("LNX-OLD", "192.168.10.241", honeypot.Linux, honeypot.SSH)
	busy := errors.New("the host is busy")
	e.host.mu.Lock()
	e.host.failAdd = map[netip.Addr]error{addr("192.168.10.240"): busy, addr("192.168.10.241"): busy}
	e.host.mu.Unlock()
	_ = e.svc.Apply(e.ctx())
	adds := 0
	for _, c := range e.host.log() {
		if strings.HasPrefix(c, "add ") {
			adds++
		}
	}
	if adds != 1 {
		t.Fatalf("%d adds asked after an unknown outcome: %v", adds, e.host.log())
	}
}

// M2: a host that answers but cannot run the container (its unit is missing) still has its decoy addresses removed when
// the module is switched off; done only when they are all gone.
func TestEnsureOffRemovesAddressesWhenTheContainerIsNotAvailable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.gate.turnOff()
	e.host.mu.Lock()
	e.host.status = honeypot.HostStatus{Available: false, Reason: "the honeypot container is not installed on this box"}
	e.host.mu.Unlock()
	if err := e.svc.EnsureOff(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.host.ipCount() != 0 {
		t.Fatalf("decoy addresses left on the host: %d", e.host.ipCount())
	}
}

func overviewTraps(t *testing.T, e *env) []honeypot.Trap {
	t.Helper()
	o, err := e.svc.Overview(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	return o.Traps
}
