package scan

import (
	"slices"
	"strconv"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
)

// INV-6 mid-run (D-165): with -ms a device that answered some templates and then died leaves lines that look like answers,
// so core learns it from the host errors the worker counted in nuclei's error log. The helpers say what the fake worker
// reports. A device that never answered prints only error lines and is the older rule (TestContract_INV6_AutoStopOnUnresponsive).

// timedOut reports a count of timeouts for the given targets of the job (all of them when only is empty); a count at the
// job's max host errors is "unreachable", below it is not.
func timedOut(count int, only ...int) func(j nucleiargv.Job) []nucleiout.HostError {
	return func(j nucleiargv.Job) []nucleiout.HostError {
		var he []nucleiout.HostError
		for i, t := range j.Targets {
			if len(only) > 0 && !slices.Contains(only, i) {
				continue
			}
			he = append(he, nucleiout.HostError{Target: t.Host + ":" + strconv.Itoa(t.Port), Errors: count, Unreachable: count >= j.MaxHostErrors})
		}
		return he
	}
}

// silent is a device that printed no line and the host errors the worker saw.
func silent(he func(nucleiargv.Job) []nucleiout.HostError) func(j nucleiargv.Job) (Output, error) {
	return func(j nucleiargv.Job) (Output, error) { return Output{HostErrors: he(j)}, nil }
}

// The run ends as auto_stopped with the stop reason although nuclei printed nothing, and the next device is not scanned.
func TestContract_INV6_SilentDeadDeviceAutoStops(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(j nucleiargv.Job) (Output, error) {
		if j.Targets[0].Host == "192.168.10.12" {
			return silent(timedOut(j.MaxHostErrors))(j)
		}
		return lines("CVE-2022-27593")(j)
	}
	v := r.start("a-web01", "a-nas02")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || got.StopReason == nil || *got.StopReason != "WEB01 (192.168.10.12) stopped responding after 3 failed requests. Vedette stopped so the device is not hung." {
		t.Fatalf("run: %+v", got)
	}
	if rowOf(got, "a-web01", "no_response") == nil || rowOf(got, "a-nas02", "skipped") == nil || len(r.eng.sent()) != 1 {
		t.Fatalf("rows: %+v", got.Results)
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'no_response'`); n == 0 {
		t.Fatal("the probe rows of the silent device did not close as no_response")
	}
	if len(r.findings.confirms) != 0 {
		t.Fatalf("an unreachable device touched findings: %v", r.findings.confirms)
	}

	// Off: the device is still no_response, and the run goes on to the next one.
	if _, err := r.svc.SaveConfig(r.ctx(), "admin@acme.example", Patch{StopOnUnresponsive: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	v = r.start("a-web01", "a-nas02")
	r.wait()
	got = r.run(v.ID)
	if got.Status != "done" || got.Done != 2 || rowOf(got, "a-web01", "no_response") == nil || rowOf(got, "a-nas02", "matched") == nil {
		t.Fatalf("go on: %+v", got)
	}
}

// What is not "stopped answering": too few timeouts, a target of the device that did answer, or a line that is an answer.
func TestContract_INV6_NotEveryTimeoutIsADeadDevice(t *testing.T) {
	t.Parallel()
	for name, he := range map[string]func(nucleiargv.Job) []nucleiout.HostError{
		"two timeouts, below the limit of three": timedOut(2),
		"one error, nothing else":                timedOut(1),
		"no host errors at all":                  func(nucleiargv.Job) []nucleiout.HostError { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := newRunEnv(t)
			r.eng.reply = silent(he)
			v := r.start("a-web01", "a-nas02")
			r.wait()
			got := r.run(v.ID)
			if got.Status != "done" || got.Done != 2 || rowOf(got, "a-web01", "no_response") != nil || rowOf(got, "a-nas02", "no_response") != nil || len(r.eng.sent()) != 2 {
				t.Fatalf("%s: %+v", name, got)
			}
		})
	}
	t.Run("one of the device's targets answered", func(t *testing.T) {
		t.Parallel()
		r := newRunEnv(t)
		r.eng.reply = func(j nucleiargv.Job) (Output, error) {
			if len(j.Targets) < 2 {
				t.Errorf("the test needs a device with two targets: %+v", j.Targets)
			}
			return silent(timedOut(j.MaxHostErrors, 0))(j) // the first target timed out, the others did not
		}
		v := r.start("a-nas02")
		r.wait()
		got := r.run(v.ID)
		if got.Status != "done" || rowOf(got, "a-nas02", "no_response") != nil {
			t.Fatalf("a device with a target that answered stopped the run: %+v", got)
		}
	})
}

// answeredThenDied is a device that answered with a line per template (not matched, no error, plus a match for the ids in
// hit) and was then given up on: the worker reports every target unreachable.
func answeredThenDied(hit ...string) func(j nucleiargv.Job) (Output, error) {
	return func(j nucleiargv.Job) (Output, error) {
		out, err := lines(hit...)(j)
		out.HostErrors = timedOut(j.MaxHostErrors)(j)
		return out, err
	}
}

// H1 (review 1): a device that answered some templates (not-matched lines, no error) and then died is no_response and ends
// the run, whatever it answered before.
func TestContract_INV6_AnsweredThenDiedAutoStops(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(j nucleiargv.Job) (Output, error) {
		if j.Targets[0].Host == "192.168.10.12" {
			return answeredThenDied()(j)
		}
		return lines("CVE-2022-27593")(j)
	}
	v := r.start("a-web01", "a-nas02")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || got.StopReason == nil || *got.StopReason != "WEB01 (192.168.10.12) stopped responding after 3 failed requests. Vedette stopped so the device is not hung." {
		t.Fatalf("run: %+v", got)
	}
	if rowOf(got, "a-web01", "no_response") == nil || rowOf(got, "a-web01", "not_matched") != nil || rowOf(got, "a-nas02", "skipped") == nil || len(r.eng.sent()) != 1 {
		t.Fatalf("rows: %+v", got.Results)
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'no_response'`); n == 0 {
		t.Fatal("the probe rows did not close as no_response")
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'not_matched'`); n != 0 {
		t.Fatalf("a lost device has %d probe rows as not_matched", n)
	}
}

// A match the device gave before it died is not lost: the finding is confirmed and the row and the probe say matched; the
// rest of the device is no_response and the run still stops.
func TestContract_INV6_MatchBeforeDeathIsKept(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = answeredThenDied("CVE-2022-27593")
	v := r.start("a-nas02", "a-web01")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || got.StopReason == nil {
		t.Fatalf("run: %+v", got)
	}
	if rowOf(got, "a-nas02", "matched") == nil || rowOf(got, "a-nas02", "no_response") == nil || rowOf(got, "a-web01", "skipped") == nil {
		t.Fatalf("rows: %+v", got.Results)
	}
	if !slices.Equal(r.findings.confirms, []string{"a-nas02|CVE-2022-27593"}) {
		t.Fatalf("the match was lost: %v", r.findings.confirms)
	}
	if n := r.count(`SELECT count(*) FROM scan_probe WHERE result = 'matched'`); n != 1 {
		t.Fatalf("probe rows as matched: %d", n)
	}
	if got.Matched != 1 {
		t.Fatalf("matched count: %d", got.Matched)
	}
}
