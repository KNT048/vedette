package sensorlink_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
)

const progressPath = "/sensor/v1/jobs/" + jobID + "/progress"

// #830: the active role reports the progress of a running job; the body is checked like any other and reaches the Backend.
func TestProgressReachesTheBackend(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	var got []sensorlink.JobProgress
	r.be.progress = func(_ context.Context, id string, p *sensorlink.JobProgress) error {
		if id != jobID {
			t.Errorf("id = %s", id)
		}
		got = append(got, *p)
		return nil
	}
	act := r.goodActive(t)
	for _, b := range []string{
		`{"phase":"ports","percent":12.5,"done":0,"total":0,"remaining_s":90}`,
		`{"phase":"vulns","percent":-1,"done":3,"total":32,"remaining_s":0}`,
		`{"phase":"discovery","percent":0}`, // fields left out are zero
	} {
		if res := mustCall(t, act, r.url(), "POST", progressPath, []byte(b), nil); res.status != 204 {
			t.Fatalf("%s: %d %s", b, res.status, res.body)
		}
	}
	want := []sensorlink.JobProgress{{Phase: "ports", Percent: 12.5, RemainingS: 90}, {Phase: "vulns", Percent: -1, Done: 3, Total: 32}, {Phase: "discovery"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
	// the passive role has no such route
	if res := mustCall(t, r.good(t), r.url(), "POST", progressPath, []byte(`{"phase":"ports","percent":1}`), nil); res.status != 403 {
		t.Fatalf("passive: %d", res.status)
	}
}

func TestProgressOfAJobThatIsNotRunningIsUnknown(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	r.be.running = func(string) bool { return false }
	if res := mustCall(t, r.goodActive(t), r.url(), "POST", progressPath, []byte(`{"phase":"ports","percent":1}`), nil); res.status != 404 || errCode(t, res) != "unknown_job" {
		t.Fatalf("%d %s", res.status, res.body)
	}
	if res := mustCall(t, r.goodActive(t), r.url(), "POST", "/sensor/v1/jobs/NOTANID/progress", []byte(`{"phase":"ports","percent":1}`), nil); res.status != 400 {
		t.Fatalf("bad id: %d %s", res.status, res.body)
	}
	if slices.Contains(r.be.Calls(), "progress") {
		t.Fatal("the Backend saw a report it should not have")
	}
}

// A core whose Backend does not take progress answers 404 unknown_job; the worker ignores it (no protocol bump, #830).
func TestProgressWithoutAReceiverIsUnknown(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{noProgress: true})
	if res := mustCall(t, r.goodActive(t), r.url(), "POST", progressPath, []byte(`{"phase":"ports","percent":1}`), nil); res.status != 404 || errCode(t, res) != "unknown_job" {
		t.Fatalf("%d %s", res.status, res.body)
	}
}

func TestProgressBodiesOutOfShapeAre400Or413(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	act := r.goodActive(t)
	for _, b := range []string{
		`{"phase":"exploit","percent":1}`,
		`{"phase":"ports","percent":101}`,
		`{"phase":"ports","percent":-0.5}`,
		`{"phase":"ports","percent":1,"done":5,"total":4}`,
		`{"phase":"ports","percent":1,"done":-1,"total":4}`,
		`{"phase":"ports","percent":1,"total":1048577}`,
		`{"phase":"ports","percent":1,"remaining_s":86401}`,
		`{"phase":"ports","percent":1,"remaining_s":-1}`,
		`{"phase":"ports","percent":1,"extra":1}`,
		`{"phase":"ports","phase":"vulns"}`,
		`{"phase":"ports","percent":"1"}`,
	} {
		if res := mustCall(t, act, r.url(), "POST", progressPath, []byte(b), nil); res.status != 400 {
			t.Errorf("%s: %d, want 400", b, res.status)
		}
	}
	big := []byte(`{"phase":"ports","percent":1` + strings.Repeat(" ", sensorlink.MaxProgressBody) + `}`)
	if res := mustCall(t, act, r.url(), "POST", progressPath, big, nil); res.status != 413 {
		t.Errorf("over the cap: %d, want 413", res.status)
	}
	if slices.Contains(r.be.Calls(), "progress") {
		t.Fatal("the Backend saw a refused body")
	}
}
