package scan

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/core/run"
)

// A check is a core_run: one step per device, the rows as items (the finding of a row follows it), a Scan now's identification
// as items of its own, and the rules of the runs tables hold afterwards.
func TestRun_IsACoreRunWithStepsAndItems(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	v := r.start("a-nas02", "a-web01")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "done" || got.Total != 2 || got.Done != 2 {
		t.Fatalf("run: %+v", got)
	}
	if r.count(`SELECT count(*) FROM core_run WHERE id = '`+v.ID+`' AND module = 'scan' AND kind = 'vuln_check' AND lane = 'nuclei' AND trigger = 'manual'
AND requested_by = 'it@acme.example' AND status = 'done' AND total = 2 AND done = 2`) != 1 {
		t.Fatal("the run is not a core_run of the vulnerability checks")
	}
	if r.count(`SELECT count(*) FROM core_run_step WHERE run_id = '`+v.ID+`' AND status = 'done' AND done = 1 AND total = 1`) != 2 {
		t.Fatal("each device is not a done step")
	}
	row := rowOf(got, "a-nas02", "")
	if row == nil || row.IP != "192.168.10.21" || row.Label != "NAS-PHOTOS" || row.FindingID == nil || *row.FindingID != "f-1" || row.Template == nil {
		t.Fatalf("a row read back from its items: %+v", row)
	}
	if r.count(`SELECT count(*) FROM core_run_item WHERE run_id = '`+v.ID+`' AND subject_kind = 'device' AND subject_id = 'a-web01'`) != 2 ||
		r.count(`SELECT count(*) FROM core_run_item WHERE run_id = '`+v.ID+`' AND subject_kind = 'finding' AND subject_id = 'f-1'`) != 1 ||
		r.count(`SELECT count(*) FROM core_run_item WHERE run_id = '`+v.ID+`' AND subject_kind = 'identification'`) != 2 {
		t.Fatal("the items of the run are not what its rows were")
	}
	if len(got.Identification) != 2 || got.Identification[0].TargetID != "a-nas02" || got.Identification[0].IP != "192.168.10.21" {
		t.Fatalf("identification: %+v", got.Identification)
	}
	for _, inv := range run.Invariants {
		if n := r.count(inv.Query); n != 0 {
			t.Errorf("%s: %d rows break %q", inv.Name, n, inv.Rule)
		}
	}
}

// A queued check a restart left has lost the picks it was started with: it ends failed with a sentence, never runs on guesses.
func TestRun_AQueuedCheckAfterARestartDoesNotRun(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if err := r.db.Write(r.ctx(), func(tx *sql.Tx) error {
		return seedRun(r.ctx(), tx, "run-queued", "queued", "2026-11-10T09:00:00.000Z", "a-web01")
	}); err != nil {
		t.Fatal(err)
	}
	r.runs.Kick()
	r.wait()
	got := r.run("run-queued")
	if got.Status != "stopped" || got.StopReason == nil || *got.StopReason != noteLost || len(r.eng.sent()) != 0 {
		t.Fatalf("%+v, %d jobs", got, len(r.eng.sent()))
	}
}

func TestItemLabelRoundTrips(t *testing.T) {
	t.Parallel()
	for _, c := range [][2]string{{"NAS-PHOTOS", "192.168.10.21"}, {"printer (2nd floor)", "192.0.2.7"}, {"—", "—"}, {"a b (c) d", "10.0.0.1"}} {
		if n, ip := splitLabel(itemLabel(c[0], c[1])); n != c[0] || ip != c[1] {
			t.Errorf("%q %q came back as %q %q", c[0], c[1], n, ip)
		}
	}
	long := make([]rune, 400)
	for i := range long {
		long[i] = 'x'
	}
	if l := itemLabel(string(long), "192.0.2.7"); len([]rune(l)) > itemLabelMax {
		t.Errorf("a label of %d characters", len([]rune(l)))
	} else if _, ip := splitLabel(l); ip != "192.0.2.7" {
		t.Errorf("the address of a clipped label: %q", ip)
	}
}
