package scan

import (
	"database/sql"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

func (f *runEngine) blockRuns() chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.blocked, f.block = true, make(chan struct{})
	return f.block
}

// INV-1 (D-126): what the list says about each device, from the inventory's VulnScanPolicy with explicit=true plus
// scan's own rules; external targets are listed but not scanned yet.
func TestContract_INV1_TargetsInScope(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.cfgExternal(ExternalTarget{ID: "xt-1", Value: "acme.example", IP: "198.51.100.7", Verified: true},
		ExternalTarget{ID: "xt-2", Value: "203.0.113.10", IP: "203.0.113.10", Verified: true, Expired: true},
		ExternalTarget{ID: "xt-3", Value: "new.example", IP: "—"})
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{Exclusions: []string{"192.168.10.10"}}); err != nil {
		t.Fatal(err)
	}
	ts, err := r.svc.Targets(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"a-nas02": "", "a-web01": "", "a-srv": "excluded", "a-unk": "unapproved", "a-box": "box", "a-never": "regular_scan_never", "a-far": "out_of_scope",
		"ext:xt-1": "not_supported", "ext:xt-2": "expired", "ext:xt-3": "unverified",
	}
	for _, v := range ts {
		got := ""
		if v.Reason != nil {
			got = *v.Reason
		}
		if w, ok := want[v.ID]; !ok || got != w || v.Selectable != (w == "") {
			t.Errorf("%s: reason %q selectable %v, want %q", v.ID, got, v.Selectable, w)
		}
		delete(want, v.ID)
	}
	if len(want) != 0 {
		t.Errorf("missing: %v", want)
	}
	byID := func(id string) TargetView {
		return ts[slices.IndexFunc(ts, func(v TargetView) bool { return v.ID == id })]
	}
	if !byID("a-nas02").PickOnly || byID("a-web01").PickOnly || byID("a-srv").PickOnly {
		t.Errorf("pick_only: only the fragile NAS needs a pick here (D-126 (2))")
	}
	if !byID("a-nas02").Fragile || !byID("a-unk").Fragile || byID("a-web01").Fragile || byID("a-web01").Findings != 2 || byID("a-nas02").Findings != 1 {
		t.Errorf("fragile/findings: %+v %+v %+v", byID("a-nas02"), byID("a-unk"), byID("a-web01"))
	}
	for _, d := range sampleDevices() { // whether a device can be picked is asked as for a pick
		if !slices.Contains(r.inv.calls, policyCall{d.ID, true}) {
			t.Fatalf("no explicit policy call for %s", d.ID)
		}
	}
	// a target that cannot be picked is refused by the API with its reason, and nothing starts
	for id, msg := range map[string]string{
		"a-unk":    "has not been approved in the inventory",
		"a-box":    "is the Vedette box itself, which is never scanned",
		"a-never":  "is set to never be scanned in the inventory; change that setting first",
		"ext:xt-1": "is an external target, and this version does not scan external targets yet",
	} {
		_, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01", id})
		wantAPI(t, err, 400, "out_of_scope")
		if !strings.Contains(err.Error(), msg+", so it cannot be scanned.") {
			t.Errorf("%s: %v", id, err)
		}
	}
	if len(r.eng.sent()) != 0 || r.count(`SELECT count(*) FROM scan_run`) != 0 {
		t.Fatal("a refused start sent or wrote something")
	}
}

// INV-1, D-126 (2): a picked fragile device runs at a quarter of the rate, and the pick is passed to the policy as
// explicit; a device that stopped being allowed after the start is skipped before its job leaves core.
func TestContract_INV1_PolicyD126AndCheckedRightBeforeTheJob(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{Rate: ptr(8)}); err != nil {
		t.Fatal(err)
	}
	// While the first device is scanned, the second is excluded and the third loses its approval.
	r.eng.onRun = func(j nucleiargv.Job) {
		if j.Targets[0].Host == "192.168.10.21" {
			if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{Exclusions: []string{"192.168.10.12"}}); err != nil {
				t.Error(err)
			}
			r.inv.edit("a-srv", func(d *Device) { d.Approved = false })
		}
	}
	v := r.start("a-nas02", "a-web01", "a-srv")
	r.wait()
	jobs := r.eng.sent()
	if len(jobs) != 1 || jobs[0].Rate != 2 || jobs[0].MaxHostErrors != 3 {
		t.Fatalf("jobs: %+v", jobs) // 8 / 4 = 2 for the fragile NAS; only it was sent
	}
	got := r.run(v.ID)
	if row := rowOf(got, "a-web01", "skipped"); row == nil || row.Note != "On the exclusion list; not scanned." {
		t.Fatalf("a-web01: %+v", got.Results)
	}
	if row := rowOf(got, "a-srv", "skipped"); row == nil || row.Note != "Not approved in the inventory any more; not scanned." {
		t.Fatalf("a-srv: %+v", got.Results)
	}
	// the policy for an automatic run (explicit=false) refuses the fragile device with its note
	why, _, err := r.svc.consent(r.ctx(), Settings{}, sampleDevices()[0], false)
	if err != nil || why != "fragile_passive_only" || skipNote[why] != "Fragile device: scanned only when you pick it in Scan now." {
		t.Fatalf("automatic: %q %v", why, err)
	}
}

// INV-2: nothing without the commitment or without a ready scanner; nothing is written either.
func TestContract_INV2_CommitmentAndScanner(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.inv.set(Scope{Networks: []string{"192.168.10.0/24"}})
	_, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"})
	wantAPI(t, err, 400, "commitment_required")
	r.inv.set(confirmedScope())
	r.eng.setDown(errNoHeartbeat)
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"})
	wantAPI(t, err, 503, "scanner_unavailable")
	r.eng.setDown(nil)
	r.svc.cfg.Pack = nil // no template pack: the scanner cannot be used either
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-web01"})
	wantAPI(t, err, 503, "scanner_unavailable")
	if len(r.eng.sent()) != 0 || r.count(`SELECT count(*) FROM scan_run`) != 0 || len(r.audits()) != 0 {
		t.Fatal("a refused start sent or wrote something")
	}
}

// INV-3: one run at a time, 1..200 known targets.
func TestContract_INV3_OneRunAndLimits(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	_, err := r.svc.StartRun(r.ctx(), "it@acme.example", nil)
	wantAPI(t, err, 400, "no_targets")
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", slices.Repeat([]string{"a-web01"}, 201))
	wantAPI(t, err, 400, "too_many")
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", []string{"192.168.99.1"})
	wantAPI(t, err, 400, "unknown_target")
	if !strings.HasSuffix(err.Error(), `There is no target "192.168.99.1" in the scan list.`) {
		t.Fatal(err)
	}
	started := r.eng.blockRuns()
	v := r.start("a-web01", "a-web01") // a repeated id counts once
	<-started
	if v.Total != 1 || v.Status != "running" || v.Done != 0 || v.Current == nil || v.Current.Label != "WEB01" {
		t.Fatalf("POST-1: %+v", v)
	}
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-nas02"})
	wantAPI(t, err, 409, "already_running")
	// the database refuses a second live run whatever the code does
	err = r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_run (id, trigger, started_at, started_by, status, picked, target_ids, total)
VALUES ('run-x', 'manual', '2026-11-10T10:00:00.000Z', 'x', 'running', '[]', '["a"]', 1)`)
		return err
	})
	if err == nil {
		t.Fatal("a second live run was stored")
	}
	if _, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	r.wait()
}

// INV-4: only templates of the pack for the device's own CVEs; the argv the worker will build is valid; a device
// with nothing to check gets no job at all.
func TestContract_INV4_OnlyPackTemplatesForTheDevicesCVEs(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	v := r.start("a-web01", "a-srv")
	r.wait()
	jobs := r.eng.sent()
	if len(jobs) != 1 || !slices.Equal(jobs[0].Templates, []string{"http/cves/2024/CVE-2024-3400.yaml"}) {
		t.Fatalf("jobs: %+v", jobs)
	}
	if !slices.Equal(jobs[0].Targets, []nucleiargv.Target{{Host: "192.168.10.12", Port: 443, Scheme: "https"}}) {
		t.Fatalf("targets: %+v", jobs[0].Targets)
	}
	args, err := nucleiargv.Build(jobs[0])
	if err != nil || nucleiargv.Validate(args) != nil {
		t.Fatalf("argv: %v", err)
	}
	got := r.run(v.ID)
	if row := rowOf(got, "a-web01", "no_template"); row == nil || row.Note != "CVE-2021-44228: no safe scan template yet, still suspected by version." || *row.FindingID != "f-3" {
		t.Fatalf("no_template: %+v", got.Results)
	}
	if row := rowOf(got, "a-srv", "not_applicable"); row == nil || row.Note != "No scan template applies to the software on this device." {
		t.Fatalf("not_applicable: %+v", got.Results)
	}
}

// INV-6, PRE-2, POST-2: Stop now ends the run within 5 seconds; the device being scanned has its requests logged as
// stopped and no result; the devices after it are not touched.
func TestContract_INV6_StopNow(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	started := r.eng.blockRuns()
	v := r.start("a-web01", "a-nas02")
	<-started
	t0 := time.Now()
	s, err := r.svc.StopRun(r.ctx(), "it@acme.example", v.ID)
	if err != nil || (s.Status != "stopping" && s.Status != "stopped") {
		t.Fatalf("%+v %v", s, err)
	}
	r.wait()
	if d := time.Since(t0); d > 5*time.Second {
		t.Fatalf("stopped after %s", d)
	}
	got := r.run(v.ID)
	if got.Status != "stopped" || *got.StopReason != "You pressed Stop now." || got.EndedAt == nil || got.Current != nil || got.Done != 0 {
		t.Fatalf("run: %+v", got)
	}
	if row := rowOf(got, "a-web01", "skipped"); row == nil || !strings.HasPrefix(row.Note, "Stopped while this device was being scanned") {
		t.Fatalf("a-web01: %+v", got.Results)
	}
	if row := rowOf(got, "a-nas02", "skipped"); row == nil || row.Note != "Not scanned because the scan was stopped. This device was not touched." {
		t.Fatalf("a-nas02: %+v", got.Results)
	}
	if len(r.eng.sent()) != 1 || r.count(`SELECT count(*) FROM scan_probe WHERE result = 'stopped'`) != 1 || r.count(`SELECT count(*) FROM scan_probe WHERE result IS NULL`) != 0 {
		t.Fatal("probe log or jobs after Stop now")
	}
	if len(r.findings.confirms) != 0 {
		t.Fatal("a stopped device changed findings")
	}
	_, err = r.svc.StopRun(r.ctx(), "it@acme.example", v.ID)
	wantAPI(t, err, 409, "not_running")
	_, err = r.svc.StopRun(r.ctx(), "it@acme.example", "run-nope")
	wantAPI(t, err, 404, "not_found")
	if !slices.ContainsFunc(r.audits(), func(a auditRow) bool {
		return a.Action == "scan.stop" && a.Target == v.ID && a.User == "it@acme.example"
	}) {
		t.Fatal("Stop now not audited")
	}
}

// INV-6: a device that answers nothing ends the run (auto_stopped) when stop_on_unresponsive is on, and it is not
// pushed further: nuclei got -mhe with unresponsive_after; off, the run goes on.
func TestContract_INV6_AutoStopOnUnresponsive(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(j nucleiargv.Job) (Output, error) {
		if j.Targets[0].Host == "192.168.10.12" {
			return dead(j)
		}
		return lines("CVE-2022-27593")(j)
	}
	v := r.start("a-web01", "a-nas02")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || *got.StopReason != "WEB01 (192.168.10.12) did not respond after 3 attempts in a row. Vedette stopped so the device is not hung." {
		t.Fatalf("run: %+v", got)
	}
	if rowOf(got, "a-web01", "no_response") == nil || rowOf(got, "a-nas02", "skipped") == nil || len(r.eng.sent()) != 1 || r.eng.sent()[0].MaxHostErrors != 3 {
		t.Fatalf("rows: %+v", got.Results)
	}
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{StopOnUnresponsive: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	v = r.start("a-web01", "a-nas02")
	r.wait()
	got = r.run(v.ID)
	if got.Status != "done" || got.Done != 2 || rowOf(got, "a-web01", "no_response").Note != "The device did not respond within the timeout; skipped." || rowOf(got, "a-nas02", "matched") == nil {
		t.Fatalf("go on: %+v", got)
	}
}

// INV-7: the probe rows exist before the job leaves core, and get their results after; the log lists them and the
// CSV keeps a spreadsheet from reading a name as a formula.
func TestContract_INV7_ProbeLogWrittenFirst(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.inv.edit("a-nas02", func(d *Device) { d.Label = "=HYPERLINK(\"http://x\")" })
	var before int
	r.eng.onRun = func(nucleiargv.Job) {
		before = r.count(`SELECT count(*) FROM scan_probe WHERE result IS NULL AND ip = '192.168.10.21' AND template = 'http/cves/2022/CVE-2022-27593.yaml' AND request = 'GET /photo/p/api/video.php HTTP/1.1'`)
	}
	r.start("a-nas02")
	r.wait()
	if before != 1 {
		t.Fatalf("probe rows before the job: %d", before)
	}
	ps, err := r.svc.Probes(r.ctx())
	if err != nil || len(ps) != 1 || ps[0].Result != "matched" || ps[0].RunID == nil {
		t.Fatalf("%+v %v", ps, err)
	}
	rd, err := r.svc.ProbesCSV(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(rd)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if lines[0] != "time,target,name,template,request,result" || len(lines) != 2 || !strings.Contains(lines[1], `"'=HYPERLINK(""http://x"")"`) {
		t.Fatalf("csv: %q", b)
	}
}

// INV-8, S-SCAN-3: a match confirms the finding with evidence and a way to check it yourself; no match records a
// clear rescan; the rows carry the finding.
func TestContract_INV8_ResultsBecomeFindings(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	v := r.start("a-nas02", "a-web01")
	r.wait()
	got := r.run(v.ID)
	m := rowOf(got, "a-nas02", "matched")
	if m == nil || *m.FindingID != "f-1" || *m.Template != "http/cves/2022/CVE-2022-27593.yaml" || m.Note != "CVE-2022-27593: the scan template matches, the flaw is still there." || got.Matched != 1 {
		t.Fatalf("matched: %+v", got)
	}
	if n := rowOf(got, "a-web01", "not_matched"); n == nil || n.Note != "CVE-2024-3400: no match reported by the scan template." {
		t.Fatalf("not_matched: %+v", got.Results)
	}
	if !slices.Equal(r.findings.confirms, []string{"a-nas02|CVE-2022-27593"}) { // a no-match never reaches findings (D-133 (5))
		t.Fatalf("findings: %v", r.findings.confirms)
	}
	ev := r.findings.confirmed[0]
	if ev.Template != "http/cves/2022/CVE-2022-27593.yaml" || ev.Request != "GET /photo/p/api/video.php HTTP/1.1\nHost: x" || ev.Response != "HTTP/1.1 200 OK\n\nphoto station" ||
		!strings.Contains(ev.Summary, "To check it yourself, run: nuclei -t http/cves/2022/CVE-2022-27593.yaml -u http://192.168.10.21:5000") || ev.CheckedAt.IsZero() {
		t.Fatalf("evidence: %+v", ev)
	}
	if got.Status != "done" || got.Done != 2 || got.EndedAt == nil {
		t.Fatalf("POST-1/done: %+v", got)
	}
}

// INV-10: output the parser cannot trust is thrown away whole: nothing is confirmed, the rows say so.
func TestContract_INV10_UntrustedOutputFailsClosed(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(nucleiargv.Job) (Output, error) {
		return Output{JSONL: []byte(`{"template-id":"CVE-2022-27593","host":"http://192.168.10.99:80","matcher-status":true}`)}, nil // a host the job did not name
	}
	v := r.start("a-nas02")
	r.wait()
	got := r.run(v.ID)
	if row := rowOf(got, "a-nas02", "no_response"); row == nil || row.Note != noteEngine || len(r.findings.confirms) != 0 {
		t.Fatalf("%+v %v", got.Results, r.findings.confirms)
	}
	r.eng.reply = func(nucleiargv.Job) (Output, error) { return Output{Truncated: true}, nil }
	v = r.start("a-nas02")
	r.wait()
	if rowOf(r.run(v.ID), "a-nas02", "no_response") == nil || len(r.findings.confirms) != 0 {
		t.Fatal("truncated output was used")
	}
}

// PRE-1, POST-1: the person who started is the audit trail's, with the picked ids (the consent of D-126 (2)).
func TestContract_PRE1_StartAudited(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	v := r.start("a-nas02")
	r.wait()
	a := r.audits()
	if len(a) != 2 || a[0].Action != "scan.start" || a[0].User != "it@acme.example" || a[0].Target != v.ID || !strings.HasPrefix(a[0].Detail, "1 targets, 1 picked by hand, sha256 ") ||
		a[1].Action != "scan.pick" || a[1].Target != "a-nas02" || a[1].Detail != "run "+v.ID {
		t.Fatalf("%+v", a)
	}
	runs, err := r.svc.Runs(r.ctx())
	if err != nil || len(runs) != 1 || runs[0].ID != v.ID || runs[0].StartedBy != "it@acme.example" || runs[0].Trigger != "manual" {
		t.Fatalf("%+v %v", runs, err)
	}
}

// A run that was live when Vedette stopped is closed as stopped, with its open probe rows, before the next start.
func TestRun_OrphanFromARestartIsClosed(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_run (id, trigger, started_at, started_by, status, picked, target_ids, total)
VALUES ('run-old', 'manual', '2026-11-10T09:00:00.000Z', 'x', 'running', '[]', '["a-web01"]', 1)`); err != nil {
			return err
		}
		_, err := tx.ExecContext(r.ctx(), `INSERT INTO scan_probe (id, ts, run_id, ip, label, template, request) VALUES ('pr-1', '2026-11-10T09:00:00.000Z', 'run-old', '192.168.10.12', 'WEB01', 't.yaml', 'GET / HTTP/1.1')`)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	r.start("a-web01")
	r.wait()
	old := r.run("run-old")
	if old.Status != "stopped" || *old.StopReason != "Vedette restarted during this scan, so it was stopped." || r.count(`SELECT count(*) FROM scan_probe WHERE id = 'pr-1' AND result = 'stopped'`) != 1 {
		t.Fatalf("%+v", old)
	}
}

// Roles and shapes of the run endpoints, through the real pipeline (ogen checks every body against the contract).
func TestHandlers_RunEndpoints(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	h := r.http()
	if code, _ := h.call("POST", "/scans/runs", "viewer", `{"targets":["a-nas02"]}`); code != 403 {
		t.Fatalf("viewer POST: %d", code)
	}
	code, b := h.call("POST", "/scans/runs", "operator", `{"targets":["a-nas02"]}`)
	if code != 201 || b["status"] != "running" || b["trigger"] != "manual" {
		t.Fatalf("POST: %d %v", code, b)
	}
	r.wait()
	for _, p := range []string{"/scans/runs", "/scans/targets", "/scans/probes"} {
		if code, b := h.call("GET", p, "viewer", ""); code != 200 || b["items"] == nil {
			t.Fatalf("GET %s: %d %v", p, code, b)
		}
	}
	if _, b := h.call("GET", "/scans/probes", "viewer", ""); b["retention_days"] != 90.0 {
		t.Fatalf("retention: %v", b)
	}
	id := b["id"].(string)
	if code, b := h.call("POST", "/scans/runs/"+id+"/stop", "operator", ""); code != 409 {
		t.Fatalf("stop an ended run: %d %v", code, b)
	}
	if code, b := h.call("POST", "/scans/runs", "operator", `{"targets":["nope"]}`); code != 400 {
		t.Fatalf("unknown: %d %v", code, b)
	}
	r.eng.setDown(errNoHeartbeat)
	if code, b := h.call("POST", "/scans/runs", "operator", `{"targets":["a-nas02"]}`); code != 503 {
		t.Fatalf("scanner down: %d %v", code, b)
	} else if c, _ := errOf(b); c != "scanner_unavailable" {
		t.Fatalf("code %s", c)
	}
}

// L7, S-SCAN-3: the "check it yourself" line names the job's own target that matched, never a field of the output.
func TestContract_INV8_RecheckLineIsTheJobsTarget(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(j nucleiargv.Job) (Output, error) { // the NAS answers on its second target, ssh port 22
		return Output{JSONL: []byte(`{"template-id":"CVE-2022-27593","host":"` + j.Targets[1].Input() + `","matcher-status":true,"curl-command":"curl http://attacker.example"}` + "\n")}, nil
	}
	r.start("a-nas02")
	r.wait()
	if len(r.findings.confirmed) != 1 {
		t.Fatalf("confirmed: %v", r.findings.confirms)
	}
	if s := r.findings.confirmed[0].Summary; !strings.HasSuffix(s, "-u 192.168.10.21:22") || strings.Contains(s, "attacker") {
		t.Fatalf("summary: %q", s)
	}
}
