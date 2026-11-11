package honeypot_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/routes"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/modules/honeypot"
)

// WP-31 L13 (D-189): variation selectors are invisible text an attacker chooses; clean drops them like the other invisible characters.
func TestHostileTextLosesVariationSelectors(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	hidden := "︀️\U000e0100\U000e01ef"
	e.appendLog(ln{LogType: 4002, Src: "192.168.10.157", SrcPort: 1, DstPort: 22, At: t0, Data: map[string]any{"USERNAME": "ro" + hidden + "ot", "REMOTEVERSION": "SSH" + hidden + "-2.0"}}.json())
	e.poll()
	hits, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil || len(hits) != 1 {
		t.Fatalf("hits %d, %v", len(hits), err)
	}
	h := hits[0]
	for _, field := range []string{h.Excerpt, h.Label} {
		for _, r := range field {
			if r >= 0xfe00 && r <= 0xfe0f || r >= 0xe0100 && r <= 0xe01ef {
				t.Fatalf("variation selector U+%04X survived in %q", r, field)
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
