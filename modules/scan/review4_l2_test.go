package scan

import "testing"

// L2: one bad event does not stop the queue: it is logged and the next event is handled.
func TestReview4_L2_OneBadEventDoesNotStopTheQueue(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{AutoRescan: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	r.exec(`INSERT INTO scan_event (id, ts, cve, product, run_id) VALUES ('e-bad', '2026-11-10T08:00:00.000Z', 'CVE-2020-0001', 'x', 'run-gone')`)
	r.exec(`INSERT INTO scan_event (id, ts, cve, product) VALUES ('e-ok', '2026-11-10T09:00:00.000Z', 'CVE-2020-0002', 'x')`)
	err := r.svc.RunRescans(r.ctx())
	if r.count(`SELECT count(*) FROM scan_event WHERE id = 'e-ok' AND result = 'skipped_off'`) != 1 {
		t.Fatalf("the event after a bad one was not handled (job error: %v)", err)
	}
}
