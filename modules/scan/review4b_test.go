package scan

import (
	"testing"
	"time"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/pack"
)

// backlogOf queues the two events the review's examples need and lets them settle, so one pass rescans them in one run.
func backlogOf(t *testing.T, r *runEnv, cves ...string) {
	t.Helper()
	for _, c := range cves {
		if err := r.svc.OnNewKEV(r.ctx(), kev(c)); err != nil {
			t.Fatal(err)
		}
	}
	r.advance(2 * time.Minute)
}

func eventResults(r *runEnv) map[string]EventView {
	got := map[string]EventView{}
	for _, e := range r.events() {
		got[e.CVE] = e
	}
	return got
}

// #189 review L1: in a run that holds several CVEs, an event is matched only by a match on its own CVE's finding, not
// by a template path it shares with another CVE (a finding id belongs to one CVE).
func TestReview4b_L1_AnEventMatchesOnlyOnItsOwnFinding(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	ix, err := pack.Parse([]byte(`{"version": "2026.11.1", "sha256": "5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592", "templates": [
{"id": "tpl-a", "cve": "CVE-2024-3400", "path": "http/shared/one-check.yaml", "sha256": "c4ca4238a0b923820dcc509a6f75849bc4ca4238a0b923820dcc509a6f75849b", "tags": ["kev"], "sets": ["kev"], "request": "GET / HTTP/1.1"},
{"id": "tpl-b", "cve": "CVE-2023-46805", "path": "http/shared/one-check.yaml", "sha256": "c4ca4238a0b923820dcc509a6f75849bc4ca4238a0b923820dcc509a6f75849b", "tags": ["kev"], "sets": ["kev"], "request": "GET / HTTP/1.1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.svc.cfg
	cfg.Pack = ix
	if r.svc, err = NewService(cfg); err != nil {
		t.Fatal(err)
	}
	r.findings.mu.Lock()
	r.findings.list = append(r.findings.list, FindingRef{ID: "f-4", AssetID: "a-srv", CVE: "CVE-2023-46805", Status: "suspected"})
	r.findings.mu.Unlock()
	r.eng.reply = func(j nucleiargv.Job) (Output, error) { // WEB01 matches its CVE-2024-3400 check; SRV-AD matches nothing
		if j.Targets[0].Host == "192.168.10.12" {
			return Output{JSONL: []byte(`{"template-id":"tpl-a","host":"` + j.Targets[0].Input() + `","matcher-status":true}` + "\n")}, nil
		}
		return Output{}, nil
	}
	backlogOf(t, r, "CVE-2024-3400", "CVE-2023-46805")
	r.tick()
	r.tick()
	got := eventResults(r)
	if got["CVE-2024-3400"].Result != "matched" || got["CVE-2023-46805"].Result != "clear" {
		t.Fatalf("CVE-2024-3400 %s, CVE-2023-46805 %s: a match on another CVE's finding closed the event as matched",
			got["CVE-2024-3400"].Result, got["CVE-2023-46805"].Result)
	}
}
