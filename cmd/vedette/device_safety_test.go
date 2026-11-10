package main

import (
	"context"
	"database/sql"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/response"
)

// Review of slice 13b-6 in the real wiring: the credential key cannot be made outside core/conn, a stop pressed during the check before stops
// the write, an undo survives a rotated token, and an outcome that is not known has a way out.

// cred.Key is `struct{}`. A composite literal struct{}{} has an unnamed type with the same underlying type, so it is assignable
// to cred.Key in any package (Go spec, Assignability). cmd/vedette here, and modules/core, which holds the *conn.Service, can call
// OpenCredential (the decrypted token, password or SSH key) and WriteAccess (the writer's dialer) without importing core/conn/write or
// anything internal: the FORBID-1 import walk and INV-23 ("only core/conn decrypts") do not hold. Reflection is used so this file keeps
// compiling once Key gets an unexported field (then struct{}{} is no longer assignable and the test passes).
func TestWiringCredKeyCannotBeMadeOutsideCoreConn(t *testing.T) {
	t.Parallel()
	svc := reflect.TypeFor[*conn.Service]()
	m, ok := svc.MethodByName("OpenCredential")
	if !ok {
		t.Fatal("OpenCredential is gone: this test would pass vacuously")
	}
	keyT := m.Type.In(2) // receiver, ctx, key, connection
	if reflect.TypeFor[struct{}]().AssignableTo(keyT) {
		t.Logf("struct{}{} is assignable to %s", keyT)
	}
	s := newStack(t)
	f := conntest.NewHTTPS(t, nil)
	c := s.connCreate(conn.Input{Name: "Office firewall", Kind: "http", Target: f.URL, AuthType: "token", Secret: secrets.NewValue("tok-0123456789-abcdef"),
		Allow: []string{f.URL + "/api/"}, Enabled: true})
	// Every key a package outside core/conn can make through reflection: the zero value, new(K), reflect.Zero, a struct{}{} when that
	// is assignable. Each must be refused at runtime: no secret, no dialer, no lock.
	keys := map[string]reflect.Value{
		"zero value":   reflect.New(keyT).Elem(),
		"reflect.Zero": reflect.Zero(keyT),
		"new(K) deref": reflect.New(keyT).Elem(),
	}
	if reflect.TypeFor[struct{}]().AssignableTo(keyT) {
		keys["struct{}{}"] = reflect.ValueOf(struct{}{})
	}
	for name, k := range keys {
		sv := reflect.ValueOf(s.d.Conn)
		out := sv.MethodByName("OpenCredential").Call([]reflect.Value{reflect.ValueOf(context.Background()), k, reflect.ValueOf(c)})
		v, _ := out[0].Interface().(secrets.Value)
		if v.Reveal() != "" || out[1].IsNil() {
			t.Errorf("%s: OpenCredential gave a credential (%v) or no error", name, out[1])
		}
		acc := sv.MethodByName("WriteAccess").Call([]reflect.Value{k})[0].Interface().(conn.WriteAccess)
		if acc.Dialer != nil {
			t.Errorf("%s: WriteAccess handed out the writer's dialer", name)
		}
		lk := sv.MethodByName("LockConn").Call([]reflect.Value{reflect.ValueOf(context.Background()), k, reflect.ValueOf(c.ID)})
		if lk[1].Bool() {
			t.Errorf("%s: LockConn gave the connection's turn", name)
		}
	}
}

// the emergency stop "stops what the execution switch does not ... every item still to run", and a person presses it because
// something is going wrong. The claim reads the switch once; then the check before runs (an SSH session: up to 60 s), and the write
// goes out after it without reading the switch again. A stop pressed while the check before is running does not stop the change.
func TestDeviceEmergencyStopDuringTheCheckBeforeStopsTheWrite(t *testing.T) {
	t.Parallel()
	const port = "Gi1/0/12"
	e := newDevEnv(t)
	var shut atomic.Bool
	f := conntest.NewSSH(t, conntest.SSHOpts{Respond: func(line string) string {
		switch line {
		case "show interfaces " + port + " switchport":
			return "Name: " + port + "\nAdministrative Mode: static access\nSwitchport: Enabled"
		case "show interfaces " + port:
			return port + " is up, line protocol is up"
		case "shutdown":
			shut.Store(true)
		}
		return ""
	}})
	c := e.connect(sshInput(f, "Core switch"))
	e.bind("cisco_port_shut", c.ID)
	e.turnOn()
	e.rule("honeypot", []response.RuleAction{{ActionID: "cisco_port_shut", Params: map[string]string{"interface": "{{trigger.switch_port}}"}, TTLMin: ttl(30)}})
	e.fire(e.trap("h1", "192.168.10.157", port))
	e.exec.after = map[string]func(){"precheck": func() {
		_, err := e.svc.EmergencyStop(e.ctx(), devAdmin) // committed before the write is sent
		e.must(err)
	}}
	got := e.approve()
	if shut.Load() || got.Items[0].Status == response.ItemExecuted {
		t.Fatalf("the emergency stop committed before the write went out, and the port was shut anyway (item %s: %s); lines %v",
			got.Items[0].Status, deref(got.Items[0].Result), f.Lines())
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// the fingerprint of a connection changes with any security field (secret, pin, allow-list, a tool switched on or off).
// The undo gate and the writer both compare it, so after a routine password/token rotation, or a certificate renewal (clear_pin and a
// new Test), the undo of every change still in force is refused forever: the sweep tries every 30 s and never sends it, and the
// connection cannot be deleted (409 in_use, "Roll it back in Response, or wait until it expires", neither of which can happen). A
// temporary block becomes permanent. The target, the kind and the id are unchanged, so the stored rollback is still addressed to the
// right device, and removing a change is the safe direction (D-88 (4)).
func TestDeviceUndoSurvivesACredentialRotation(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	f := conntest.NewHTTPS(t, bans())
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	if got := e.approve(); got.Items[0].Status != response.ItemExecuted {
		t.Fatalf("item %+v", got.Items[0])
	}
	e.editSecret(c, conn.ToolInput{Name: "send_request", Enabled: true}) // the firewall's API token is rotated
	base := len(f.Requests())
	e.clock.Advance(61 * time.Minute)
	for range 3 {
		e.must(e.svc.Sweep(e.ctx()))
	}
	undone := false
	for _, r := range f.Requests()[base:] {
		undone = undone || r.Path == "/api/v2/monitor/user/banned/clear_users"
	}
	if !undone {
		it := e.only().Items[0]
		derr := e.s.d.DB.Write(e.ctx(), func(tx *sql.Tx) error { return e.s.d.Conn.Delete(e.ctx(), tx, "admin@acme.example", c.ID) })
		code := ""
		if ae, ok := apierr.As(derr); ok {
			code = ae.Code
		}
		t.Fatalf("after a token rotation the 60-minute ban is never undone: item %s %q; delete the connection -> %s", it.Status, deref(it.Result), code)
	}
}

// an outcome of "state unknown" (an HTTP 5xx, a time-out after sending, a line refused after an earlier one was accepted)
// counts as in force for ever: nothing ever clears state_unknown (only a late result of the same run, which cannot come after a restart),
// a failed item cannot be rolled back (not_executed), it has no undo time, and the connection can never be deleted (409 in_use). There
// is no way for a person who checked the device to say so.
func TestDeviceStateUnknownHasAWayOut(t *testing.T) {
	t.Parallel()
	e := newDevEnv(t)
	// The device answers the run with 502 (a proxy in front of it timed out): state unknown, in force.
	var cleared atomic.Bool
	f := conntest.NewHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/add_users"):
			w.WriteHeader(http.StatusBadGateway)
		case strings.HasSuffix(r.URL.Path, "/clear_users"):
			cleared.Store(true)
		case strings.HasSuffix(r.URL.Path, "/select") && cleared.Load():
			_, _ = io.WriteString(w, `{"results":[]}`)
		}
		// otherwise an empty answer: the read-back cannot tell
	}))
	c := e.connect(httpsInput(f, "Office firewall"))
	e.bind("fgt_ban_ip", c.ID)
	e.turnOn()
	e.rule("ioc_connection", banRule())
	e.fire(e.ioc())
	got := e.approve()
	if !strings.Contains(deref(got.Items[0].Result), "State unknown") {
		t.Fatalf("item %+v", got.Items[0])
	}
	_, rerr := e.svc.Rollback(e.ctx(), devOper, got.ID)
	e.clock.Advance(90 * 24 * time.Hour)
	for range 2 {
		e.must(e.svc.Sweep(e.ctx()))
	}
	derr := e.s.d.DB.Write(e.ctx(), func(tx *sql.Tx) error { return e.s.d.Conn.Delete(e.ctx(), tx, "admin@acme.example", c.ID) })
	if rerr != nil || derr != nil {
		rc, dc := "", ""
		if ae, ok := apierr.As(rerr); ok {
			rc = ae.Code
		}
		if ae, ok := apierr.As(derr); ok {
			dc = ae.Code
		}
		t.Fatalf("90 days after a state-unknown outcome: rollback -> %s, delete the connection -> %s; nothing can ever clear it", rc, dc)
	}
	if rerr == nil && !strings.Contains(deref(e.only().Items[0].Result), "Undone") {
		t.Fatalf("the undo of an unknown item: %+v", e.only().Items[0])
	}
}
