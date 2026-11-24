package scan

import (
	"strings"
	"testing"
	"time"
)

// INV-17: the target list counts, per device, what a vulnerability check can do with the same rule the run plans with: the suspected
// findings (distinct CVEs), how many of them have a safe template, and how many confirmed ones have one to run again.
func TestTargets_CountWhatACheckCanCheck(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.findings.list = append(r.findings.list,
		FindingRef{ID: "f-4", AssetID: "a-web01", CVE: "CVE-2024-3400", Status: "suspected"},       // the same CVE twice: counted once
		FindingRef{ID: "f-5", AssetID: "a-web01", CVE: "CVE-2023-46805", Status: "false_positive"}, // closed by a person: never checked
	)
	ts, err := r.svc.Targets(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][3]int{}
	for _, x := range ts {
		got[x.ID] = [3]int{x.Suspected, x.Checkable, x.Again}
	}
	want := map[string][3]int{
		"a-web01": {2, 1, 0}, // CVE-2024-3400 has a template, CVE-2021-44228 has none
		"a-nas02": {0, 0, 1}, // a confirmed CVE with a template: checked again
		"a-srv":   {0, 0, 0},
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: suspected, checkable, again = %v, want %v", id, got[id], w)
		}
	}
}

// INV-17: Scan now checks only the picked devices that have something to check; a pick with nothing to check starts no run and says why.
func TestStartRun_OnlyDevicesWithSomethingToCheck(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	_, err := r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-srv"})
	wantAPI(t, err, 400, "nothing_to_check")
	if !strings.Contains(err.Error(), "SRV-AD") {
		t.Errorf("the refusal does not name the device: %v", err)
	}
	if n := r.count(`SELECT count(*) FROM core_run`); n != 0 {
		t.Fatalf("%d runs started with nothing to check", n)
	}
	v := r.start("a-srv", "a-web01", "a-nas02")
	r.wait()
	if v.Total != 2 {
		t.Fatalf("total %d, want 2 (WEB01 and NAS-PHOTOS; SRV-AD has nothing to check)", v.Total)
	}
	got := r.run(v.ID)
	for _, row := range got.Results {
		if row.TargetID == "a-srv" {
			t.Fatalf("SRV-AD was in the run: %+v", row)
		}
	}
}

// INV-17: the schedule checks only the devices that need no pick and have something to check; with none, it starts nothing and says why.
func TestScheduled_OnlyDevicesWithSomethingToCheck(t *testing.T) {
	t.Parallel()
	r, sched := schedEnv(t)
	save(t, r, sched)
	r.setNow(r.clock.Now().Add(13*time.Hour + 30*time.Second)) // 23:00:30
	tick(t, r, sched, r.clock.Now())
	runs, _ := r.svc.Runs(r.ctx())
	if len(runs) != 1 || runs[0].Total != 1 {
		t.Fatalf("runs: %+v (want one run of WEB01 alone: SRV-AD has nothing to check)", runs)
	}
	r.findings.mu.Lock()
	r.findings.list = nil
	r.findings.mu.Unlock()
	tick(t, r, sched, r.clock.Now().Add(24*time.Hour))
	if n := r.scheduled(); n != 1 {
		t.Fatalf("%d scheduled runs, want still 1: nothing to check", n)
	}
	if why := skipReason(t, r, sched); !strings.Contains(why, "Nothing to check") {
		t.Errorf("skip reason %q", why)
	}
}
