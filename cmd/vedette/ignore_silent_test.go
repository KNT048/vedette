package main

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/response"
)

// countingPlanner is a response planner that counts the findings it is asked to plan for and plans none.
type countingPlanner struct {
	mu    sync.Mutex
	asked []string
}

func (p *countingPlanner) Available(context.Context) bool { return true }
func (p *countingPlanner) Plan(_ context.Context, a response.PlanAsk) (response.PlanDraft, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, a.Target.FindingID)
	return response.PlanDraft{}, errors.New("no plan in this test")
}
func (p *countingPlanner) Proposed(context.Context, response.PlanTarget, []response.SentProposal) {}

func (p *countingPlanner) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.asked)
}

// An ignored device is silent: while it is ignored, its CVE joining an exploited list and an intrusion alert naming it change none of
// its findings' layers, send no alert, fire no response rule and cost no planner call; the readers of one finding (notify, response, the
// assistant, MCP) do not find it and the lists leave it out. Stop ignoring brings its findings back into every list and rates them
// again at once: the rises that happened meanwhile are told then (one alert and one response event each), and the planner is asked.
func TestWiringAnIgnoredDeviceIsSilentUntilItIsWatchedAgain(t *testing.T) {
	t.Parallel()
	s := responseOn(t)
	s.setModule("logs", true)
	s.setModule("ids", true)
	s.telegramOn()
	ctx := t.Context()
	s.exec(`UPDATE notify_box SET first_run_at = ?`, store.FormatTS(time.Now().AddDate(0, 0, -3))) // past the box's first run: a rise is an alert
	seedUrgencyCatalogue(t, s)
	id := s.addFortiGate() // 192.168.30.1, FortiOS 7.2.5: 50001 critical on an edge device, 50002 public exploit, 50003 update
	fid := map[string]string{}
	fs, err := s.d.Findings.Findings(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		fid[f.CVE] = f.ID
	}
	if len(fid) != 3 {
		t.Fatalf("the device's findings: %v", fid)
	}
	critical := responseCritical{fnd: s.d.Findings, inv: findingsInventory{s.d.Inventory}}
	if targets, err := critical.list(ctx); err != nil || len(targets) != 1 || targets[0].FindingID != fid["CVE-2026-50001"] {
		t.Fatalf("before ignoring, the plan targets = %+v, %v (want the critical edge finding)", targets, err)
	}
	cfg, err := responseConfig(s.d)
	if err != nil {
		t.Fatal(err)
	}
	planner := &countingPlanner{}
	cfg.Planner, cfg.Critical = planner, critical.list
	plans, err := response.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plans.Close)

	if c, b := s.do("POST", "/inventory/devices/"+id+"/ignore", "operator", `{"ignored":true}`); c != 200 {
		t.Fatalf("ignore: %d %v", c, b)
	}
	notices, events := len(s.queuedNotices()), s.count(`SELECT count(*) FROM resp_events WHERE asset_id = ?`, id)
	layers := layersOf(t, s, id)

	// while ignored: its CVE joins CISA KEV this week, and an intrusion alert names another of its CVEs aimed at it
	s.kevAdded("CVE-2026-50003", "Fortinet", "FortiOS", time.Now())
	now := store.FormatTS(time.Now().UTC().Add(-time.Minute))
	s.exec(`INSERT INTO ids_alert (id, source, signature, priority, src_ip, dst_ip, dst_asset_id, first_ts, last_ts, count, dedupe_key)
		VALUES ('al-1', 'suricata', 'ET EXPLOIT FortiOS', 1, '203.0.113.9', '192.168.30.1', ?1, ?2, ?2, 1, ?3)`, id, now, strings.Repeat("a", 64))
	s.exec(`INSERT INTO ids_alert_cve (alert_id, cve) VALUES ('al-1', 'CVE-2026-50002')`)
	started := time.Now().UTC()
	for _, j := range []int{0, 2} { // the reconcile pass (it rates at its end) and the hourly urgency pass
		if err := findingsJobs(*s.d)[j].Run(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.d.Findings.RateUrgency(ctx, ""); err != nil { // what an intrusion alert runs
		t.Fatal(err)
	}
	if got := layersOf(t, s, id); !maps.Equal(got, layers) {
		t.Fatalf("an ignored device's layers changed: %v, were %v", got, layers)
	}
	s.exec(`INSERT INTO core_job_run (id, module, job, started_at, finished_at, status) VALUES ('jr-urgency-1', 'findings', ?, ?, ?, 'ok')`,
		findings.UrgencyJob, store.FormatTS(started), store.FormatTS(time.Now().UTC().Add(time.Millisecond)))
	if n, err := urgencyMismatches(ctx, s.d.DB.Reader()); err != nil || n != 0 {
		t.Fatalf("the selfcheck counts %d mismatches (%v): an ignored device's kept layers are not a stale pass", n, err)
	}
	if n := len(s.queuedNotices()); n != notices {
		t.Fatalf("an ignored device queued %d notices", n-notices)
	}
	if n := s.count(`SELECT count(*) FROM resp_events WHERE asset_id = ?`, id); n != events {
		t.Fatalf("an ignored device fired %d response events", n-events)
	}
	if n, err := plans.PlanOpen(ctx); err != nil || n != 0 || len(planner.calls()) != 0 {
		t.Fatalf("the plan job for an ignored device: saved %d, %v, planner asked for %v", n, err, planner.calls())
	}
	// the readers of one finding do not find it; the lists leave the device out
	for cve, f := range fid {
		if _, ok, err := (notifyFindings{s.d}).Finding(ctx, f); err != nil || ok {
			t.Errorf("notify found %s of an ignored device: %v %v", cve, ok, err)
		}
		if _, ok, err := (responseDirectory{inv: s.d.Inventory, fnd: s.d.Findings}).Finding(ctx, f); err != nil || ok {
			t.Errorf("response found %s of an ignored device: %v %v", cve, ok, err)
		}
		if _, ok, err := (aiAsk{findings: s.d.Findings, cases: caseSource{findings: s.d.Findings}, inv: s.d.Inventory}).Finding(ctx, f); err != nil || ok {
			t.Errorf("the assistant found %s of an ignored device: %v %v", cve, ok, err)
		}
		if _, ok, err := (mcpSource{reg: s.d.Reg, cases: caseSource{findings: s.d.Findings}}).Finding(ctx, f); err != nil || ok {
			t.Errorf("MCP get_finding found %s of an ignored device: %v %v", cve, ok, err)
		}
	}
	visible := func() int {
		t.Helper()
		vs, err := s.d.Findings.Views(ctx, findings.ViewFilter{AssetID: id})
		if err != nil {
			t.Fatal(err)
		}
		ms, err := (mcpSource{reg: s.d.Reg, cases: caseSource{findings: s.d.Findings}}).Findings(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != len(vs) {
			t.Fatalf("MCP list_findings has %d findings, the views %d", len(ms), len(vs))
		}
		return len(vs)
	}
	if n := visible(); n != 0 {
		t.Fatalf("%d findings of an ignored device are listed", n)
	}
	if targets, err := critical.list(ctx); err != nil || len(targets) != 0 {
		t.Fatalf("the plan targets of an ignored device = %+v, %v", targets, err)
	}

	// Stop ignoring: the findings come back, rated again at once, and what rose meanwhile is told now
	if c, b := s.do("POST", "/inventory/devices/"+id+"/ignore", "operator", `{"ignored":false}`); c != 200 {
		t.Fatalf("stop ignoring: %d %v", c, b)
	}
	if n := visible(); n != 3 {
		t.Fatalf("after stop ignoring %d findings are listed, want 3", n)
	}
	got := layersOf(t, s, id)
	if got["CVE-2026-50002"] != findings.UrgencyUnderAttack || got["CVE-2026-50003"] != findings.UrgencyExploited {
		t.Fatalf("after stop ignoring the layers are %v: the device was not rated again", got)
	}
	for cve, layer := range map[string]string{"CVE-2026-50002": "1", "CVE-2026-50003": "2"} {
		n := 0
		for _, x := range s.queuedNotices() {
			if strings.HasPrefix(x.ID, "nt-"+fid[cve]+"-urgency_changed-"+layer) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: %d alerts of its rise after stop ignoring, want 1", cve, n)
		}
		if n := s.count(`SELECT count(*) FROM resp_events WHERE finding_id = ? AND trigger = 'finding'`, fid[cve]); n != 1 {
			t.Errorf("%s: %d response events of its rise after stop ignoring, want 1", cve, n)
		}
	}
	if _, ok, err := (notifyFindings{s.d}).Finding(ctx, fid["CVE-2026-50003"]); err != nil || !ok {
		t.Fatalf("notify does not find the finding of a watched device: %v %v", ok, err)
	}
	if _, err := plans.PlanOpen(ctx); err != nil || len(planner.calls()) == 0 {
		t.Fatalf("the plan job after stop ignoring: %v, planner asked for %v", err, planner.calls())
	}
}
