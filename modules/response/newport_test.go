package response_test

import (
	"context"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/response"
)

// D-384: exposure.port.opened (published by cmd/vedette from exposure's diff) is an event of the new_port trigger. Its fields came
// from a scan, so each is checked at the edge; one port of one target on one scan day is one event, however often that day is scanned.
func TestNewPortEvent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	pub := func(ev response.PortOpenedEvent) {
		t.Helper()
		e.must(e.bus.Publish(context.Background(), events.Event{Name: response.EventPortOpened, Data: ev}))
	}
	ok := response.PortOpenedEvent{TargetID: "xt-abc", Date: "2026-11-12", IP: "203.0.113.10", Port: 8080, Service: "http-alt‮"}
	pub(ok)
	pub(ok) // a second scan on the same day: one event
	next := ok
	next.Date = "2026-11-13" // closed and open again on a later day: a new event
	pub(next)
	for name, bad := range map[string]func(*response.PortOpenedEvent){
		"private address":    func(p *response.PortOpenedEvent) { p.IP = "192.168.1.10" },
		"CGNAT address":      func(p *response.PortOpenedEvent) { p.IP = "100.100.1.2" },
		"6to4 address":       func(p *response.PortOpenedEvent) { p.IP = "2002:c000:204::1" },
		"address with zone":  func(p *response.PortOpenedEvent) { p.IP = "fe80::1%eth0" },
		"shell in address":   func(p *response.PortOpenedEvent) { p.IP = "203.0.113.10; reboot" },
		"loopback":           func(p *response.PortOpenedEvent) { p.IP = "127.0.0.1" },
		"port 0":             func(p *response.PortOpenedEvent) { p.Port = 0 },
		"port 65536":         func(p *response.PortOpenedEvent) { p.Port = 65536 },
		"no target":          func(p *response.PortOpenedEvent) { p.TargetID = "" },
		"colon in target":    func(p *response.PortOpenedEvent) { p.TargetID = "xt:1" },
		"newline in target":  func(p *response.PortOpenedEvent) { p.TargetID = "xt\n1" },
		"not a day":          func(p *response.PortOpenedEvent) { p.Date = "2026-13-01" },
		"day with more text": func(p *response.PortOpenedEvent) { p.Date = "2026-11-14T00:00:00Z" },
	} {
		ev := ok
		ev.Date = "2026-11-14"
		bad(&ev)
		pub(ev)
		if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE trigger = 'new_port'`); n != 2 {
			t.Fatalf("%s: %d events stored, want 2", name, n)
		}
	}
	if n := e.count(`SELECT COUNT(*) FROM resp_events WHERE id = 'port:xt-abc:2026-11-12:203.0.113.10:8080' AND summary = 'New open port 8080 on public IP 203.0.113.10 (http-alt)'
		AND fields LIKE '%"ip":"203.0.113.10"%' AND fields LIKE '%"port":"8080"%' AND fields LIKE '%"service":"http-alt"%' AND fields LIKE '%"device":""%'`); n != 1 {
		t.Fatal("the fields of a new port were not kept (or the bidi character of the banner was)")
	}
	// The rule of template tpl-newport-msg runs on both; the second day's message is the same text while the first still waits, so it
	// is folded into it (the engine's usual dedupe).
	e.rule("New public port", "new_port", []response.RuleAction{{ActionID: "msg_send", Params: map[string]string{"text": "New open port {{trigger.port}} on public IP {{trigger.ip}}, service {{trigger.service}}"}}}, nil)
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	if acts := e.actions(); sum.Matched != 2 || sum.Requests != 1 || sum.Deduped != 1 || len(acts) != 1 || acts[0].Items[0].Change.CLI != "notify New open port 8080 on public IP 203.0.113.10, service http-alt" {
		t.Fatalf("summary %+v, requests %+v", sum, acts)
	}
}

// Review of D-384: the address of a new port is the customer's own or whatever their name points at, so a pre-approved rule never
// blocks it by itself; a pre-approved action on another address still runs.
func TestNewPortPreApprovalNeverActsOnTheAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.Subscribe(e.bus)
	e.rule("Block it", "new_port", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.ip}}"}, TTLMin: intp(60)}},
		func(in *response.RuleInput) { in.PreApproved = true })
	e.rule("Block another", "new_port", []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "198.51.100.9"}, TTLMin: intp(60)}},
		func(in *response.RuleInput) { in.PreApproved = true })
	e.must(e.bus.Publish(context.Background(), events.Event{Name: response.EventPortOpened,
		Data: response.PortOpenedEvent{TargetID: "xt-abc", Date: "2026-11-12", IP: "203.0.113.10", Port: 8080, Service: "http-alt"}}))
	_, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	status := map[string]string{}
	for _, a := range e.actions() {
		status[a.Items[0].Title] = string(a.Status)
	}
	var mine, other string
	for title, st := range status {
		switch {
		case strings.Contains(title, "203.0.113.10"):
			mine = st
		case strings.Contains(title, "198.51.100.9"):
			other = st
		}
	}
	if mine != "pending" || other == "pending" || other == "" {
		t.Fatalf("pre-approval: %v (want the block of the port's address pending a person, the other one run)", status)
	}
}
