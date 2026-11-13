package response_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/response"
)

// D-509 (W1-16, S-RESP-3): Respond on an incident offers only what can really happen to its source, and asking for it makes a pending
// request (approval, expiry, undo, log) that changes nothing by itself.

type fakeIncidents struct {
	m map[string]response.IncidentInfo
}

func (f *fakeIncidents) Incident(_ context.Context, id string) (response.IncidentInfo, bool, error) {
	i, ok := f.m[id]
	return i, ok, nil
}

func incidentEnv(t *testing.T) *env {
	t.Helper()
	inc := &fakeIncidents{m: map[string]response.IncidentInfo{
		"in-lan":    {ID: "in-lan", Kind: "trap", Title: "192.168.18.145 touched the SSH trap", Action: "Take the machine off the network.", SourceIP: "192.168.18.145", AssetID: "a-pc"},
		"in-public": {ID: "in-public", Kind: "trap", Title: "203.0.113.9 touched the SSH trap", Action: "Block it.", SourceIP: "203.0.113.9"},
		"in-log":    {ID: "in-log", Kind: "log_anomaly", Title: "WEB01 logged far more failed sign-ins than usual"},
		"in-gw":     {ID: "in-gw", Kind: "trap", Title: "10.0.0.1 touched the SSH trap", SourceIP: "10.0.0.1"},
	}}
	e := newEnv(t, func(c *response.Config) { c.Incidents = inc })
	e.dir.devices["a-pc"] = response.DeviceInfo{ID: "a-pc", Name: "PC-HR-01", IP: "192.168.18.145", Kind: "workstation"}
	return e
}

func (e *env) panel(id string) response.IncidentPanel {
	e.t.Helper()
	p, err := e.svc.IncidentPanel(e.ctx(), id)
	e.must(err)
	return p
}

func option(p response.IncidentPanel, id string) *response.IncidentOption {
	for i := range p.Options {
		if p.Options[i].ActionID == id {
			return &p.Options[i]
		}
	}
	return nil
}

// A LAN source with no firewall or switch: no option at all (the block list never holds a LAN address, D-469), and asking for the
// block list anyway is refused and logged.
func TestD509_LANSourceWithoutAConnectionOffersNothing(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	p := e.panel("in-lan")
	if p.Source == nil || p.Source.IP != "192.168.18.145" || p.Source.Scope != "lan" || p.Source.Device == nil || *p.Source.Device != "PC-HR-01" {
		t.Fatalf("source: %+v", p.Source)
	}
	if len(p.Options) != 0 || p.Incident.Action != "Take the machine off the network." {
		t.Fatalf("panel: %+v", p)
	}
	_, err := e.svc.RequestFromIncident(e.ctx(), oper, "in-lan", "blocklist_add")
	wantCode(t, err, http.StatusForbidden, "tool_not_allowed")
	if len(e.actions()) != 0 || !e.logHas("refused", "not offered for this incident") {
		t.Fatal("a refused ask made a request or was not logged")
	}
}

// A LAN source and a firewall block action: one click asks for approval; the request waits, runs nothing, says who asked, is undone
// after 24 hours, and a second ask is a duplicate.
func TestD509_LANSourceWithAFirewallMakesAPendingRequest(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	e.firewall("fgt_addrgrp_add")
	e.turnOn()
	o := option(e.panel("in-lan"), "fgt_addrgrp_add")
	if o == nil || !o.Ready || o.Why != nil || o.Connection == nil || *o.Connection != "Office firewall" || !strings.Contains(o.Title, "192.168.18.145") || o.TTLMin != 1440 {
		t.Fatalf("option: %+v", o)
	}
	a, err := e.svc.RequestFromIncident(e.ctx(), oper, "in-lan", "fgt_addrgrp_add")
	e.must(err)
	e.svc.WaitSendsForTest()
	if a.Source != "person" || a.Status != response.StatusPending || a.ProposalID != "incident:in-lan" || a.AssetName != "PC-HR-01" || len(a.Items) != 1 || a.Items[0].TTLMin == nil || *a.Items[0].TTLMin != 1440 || a.PreApproved {
		t.Fatalf("request: %+v", a)
	}
	if len(e.exec.steps) != 0 {
		t.Fatalf("asking sent %d steps to a device", len(e.exec.steps))
	}
	if e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = 'request' AND actor = ?`, "it@acme.example (app)") != 1 {
		t.Fatal("the request line does not name the person who asked")
	}
	if o := option(e.panel("in-lan"), "fgt_addrgrp_add"); o == nil || o.Ready || !o.Requested {
		t.Fatalf("after asking: %+v", o)
	}
	_, err = e.svc.RequestFromIncident(e.ctx(), oper, "in-lan", "fgt_addrgrp_add")
	wantCode(t, err, http.StatusConflict, "already_requested")
	// The approval is a separate, explicit step (D-41): only then does the firewall get the change.
	got, err := e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	if got.Items[0].Status != response.ItemExecuted || len(e.exec.steps) == 0 {
		t.Fatalf("after approval: %+v, %d steps", got.Items[0], len(e.exec.steps))
	}
}

// A device action while execution is off: shown with the reason, refused when asked.
func TestD509_DeviceActionNeedsExecution(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	e.firewall("fgt_addrgrp_add")
	if o := option(e.panel("in-lan"), "fgt_addrgrp_add"); o == nil || o.Ready || o.Why == nil || !strings.Contains(*o.Why, "Execution is off") {
		t.Fatalf("option: %+v", o)
	}
	_, err := e.svc.RequestFromIncident(e.ctx(), oper, "in-lan", "fgt_addrgrp_add")
	wantCode(t, err, http.StatusConflict, "execution_off")
	if len(e.actions()) != 0 {
		t.Fatal("a request was made while execution is off")
	}
}

// A public source: the block list is offered (a box action, so execution off does not stop it) and goes through approval.
func TestD509_PublicSourceGoesToTheBlockListAfterApproval(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	p := e.panel("in-public")
	o := option(p, "blocklist_add")
	if p.Source == nil || p.Source.Scope != "public" || o == nil || !o.Ready || o.Device || o.Title != "Add 203.0.113.9 to the block list" {
		t.Fatalf("panel: %+v, option %+v", p.Source, o)
	}
	a, err := e.svc.RequestFromIncident(e.ctx(), oper, "in-public", "blocklist_add")
	e.must(err)
	e.svc.WaitSendsForTest()
	bl, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	if a.Status != response.StatusPending || len(bl.Entries) != 0 {
		t.Fatalf("before approval: %s, %d entries", a.Status, len(bl.Entries))
	}
	_, err = e.svc.Approve(e.ctx(), oper, a.ID, nil, "")
	e.must(err)
	bl, err = e.svc.Blocklist(e.ctx())
	e.must(err)
	if len(bl.Entries) != 1 || bl.Entries[0].Value != "203.0.113.9" || bl.Entries[0].Source != "Asked from an incident" {
		t.Fatalf("entries: %+v", bl.Entries)
	}
}

// The never-touch list still holds: a source on it is refused when asked, and the option says why.
func TestD509_NeverTouchStillApplies(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	e.firewall("fgt_addrgrp_add")
	e.turnOn()
	_, err := e.svc.SetAllowlist(e.ctx(), admin, []response.AllowEntry{{Value: "10.0.0.1", Label: "Core switch"}})
	e.must(err)
	if o := option(e.panel("in-gw"), "fgt_addrgrp_add"); o == nil || o.Ready || o.Why == nil || !strings.Contains(*o.Why, "never-touch") {
		t.Fatalf("option: %+v", o)
	}
	_, err = e.svc.RequestFromIncident(e.ctx(), oper, "in-gw", "fgt_addrgrp_add")
	wantCode(t, err, http.StatusConflict, "never_touch")
}

// An incident with no source (another kind) offers nothing and refuses; an unknown one is 404.
func TestD509_NoSourceAndUnknownIncident(t *testing.T) {
	t.Parallel()
	e := incidentEnv(t)
	e.firewall("fgt_addrgrp_add")
	e.turnOn()
	if p := e.panel("in-log"); p.Source != nil || len(p.Options) != 0 {
		t.Fatalf("panel: %+v", p)
	}
	_, err := e.svc.RequestFromIncident(e.ctx(), oper, "in-log", "fgt_addrgrp_add")
	wantCode(t, err, http.StatusConflict, "no_source")
	_, err = e.svc.IncidentPanel(e.ctx(), "in-nope")
	wantCode(t, err, http.StatusNotFound, "not_found")
	_, err = e.svc.RequestFromIncident(e.ctx(), oper, "../x", "fgt_addrgrp_add")
	wantCode(t, err, http.StatusNotFound, "not_found")
}
