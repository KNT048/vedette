package main

import (
	"fmt"
	"testing"

	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// How many errors in a row a template run of exposure lets nuclei meet on a port before it gives the port up (-mhe), over the fakes of
// exposuretemplates_test.go and the committed pack. No process runs and no packet leaves.

// nucleiOnOnePort plays nuclei 3.11.1's host-error rule (pkg/protocols/common/hosterrorscache) over the templates of a run, in order:
// the count is per host:port, a timeout adds one, an answer resets it, and once it reaches -mhe every later template prints the
// "skipped as unresponsive" line instead of running. noAnswer says which positions time out; each timeout also writes the error-log
// line the worker counts (nucleiout.ParseHostErrors), so the run carries the host errors a real worker would report.
func nucleiOnOnePort(r sensoractive.NucleiRequest, noAnswer func(i int) bool) nucleiout.Outcome {
	t := r.Targets[0]
	addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	var o nucleiout.Outcome
	var elog []byte
	inARow := 0
	for i, id := range r.Templates {
		switch {
		case inARow >= r.MaxHostErrors:
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: addr, Error: nucleiout.UnresponsiveError})
		case noAnswer(i):
			inARow++
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: addr, Error: "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"})
			elog = fmt.Appendf(elog, `{"template":%q,"input":%q,"address":%q,"error":"i/o timeout","kind":"network-temporary-error"}`+"\n", id, t.Input(), addr)
		default:
			inARow = 0
			o.Results = append(o.Results, nucleiout.Result{Template: id, Target: addr})
		}
	}
	o.HostErrors = nucleiout.ParseHostErrors(elog, []string{addr}, r.MaxHostErrors)
	return o
}

// A port that is slow but alive (an HTTPS admin page of a firewall under load) misses a whole wave of the templates in flight now
// and then and answers the rest: a deep run keeps checking it, so only the templates that really got no answer are errors, and
// exposure does not read the port as one that stopped answering. The gentle speed allows two of its smaller waves. On the old
// -mhe 3 nuclei dropped the port at the third timeout and most templates of every run came back as errors.
func TestExposureTemplatesSlowPortKeepsItsTemplates(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		gentle   bool
		mhe      int
		noAnswer func(i int) bool
	}{
		{"deep", false, 20, func(i int) bool { return i%20 >= 3 && i%20 < 13 }}, // a wave of 10 (-c 10) misses at once
		{"deep, gentle", true, 4, func(i int) bool { return i%10 >= 3 && i%10 < 6 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := &templatesFake{gateOK: true}
			f.answer = func(r sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiOnOnePort(r, c.noAnswer) }
			a := f.scanner()
			a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
			st := fullTarget(true)
			st.Mode, st.Gentle = modeAllGroups, c.gentle
			got, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf()})
			if err != nil {
				t.Fatal(err)
			}
			if len(f.reqs) == 0 {
				t.Fatal("no nuclei job")
			}
			want := map[string]string{}
			for _, r := range f.reqs {
				if r.MaxHostErrors != c.mhe {
					t.Fatalf("-mhe %d, want %d", r.MaxHostErrors, c.mhe)
				}
				for i, id := range r.Templates {
					want[id] = map[bool]string{false: exposure.OutcomeNoMatch, true: exposure.OutcomeError}[c.noAnswer(i)]
				}
			}
			bad := 0
			for _, res := range got.Results {
				if res.Outcome != want[res.Template] {
					bad++
				}
			}
			if bad > 0 || len(got.Results) != len(want) {
				t.Fatalf("%d of %d templates have another outcome than their answer (%d results)", bad, len(want), len(got.Results))
			}
		})
	}
}

// The KEV check on the own IP runs one template at a time (-c 1): three timeouts in a row are already half a minute or more of
// silence, so it keeps -mhe 3.
func TestExposureTemplatesOwnIPKeepsThreeHostErrors(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, answer: func(r sensoractive.NucleiRequest) nucleiout.Outcome {
		return nucleiOnOnePort(r, func(int) bool { return false })
	}}
	if _, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{User: "u-admin"}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379", "CVE-2019-19781")}); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 || f.reqs[0].MaxHostErrors != 3 {
		t.Fatalf("requests %+v", f.reqs)
	}
}

// A port that stops answering mid-run is still told apart: every template after it went quiet is an error (nuclei gave it up, or each
// one timed out), so exposure's "results incomplete, the port may have stopped answering" line keeps its meaning.
func TestExposureTemplatesDeadPortStillReadsUnanswered(t *testing.T) {
	t.Parallel()
	for _, gentle := range []bool{false, true} {
		f := &templatesFake{gateOK: true}
		dead := func(i int) bool { return i >= 5 }
		f.answer = func(r sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiOnOnePort(r, dead) }
		a := f.scanner()
		a.mode = (&modes{list: []exposure.ScanMode{modeAllGroups}}).now
		st := fullTarget(true)
		st.Mode, st.Gentle = modeAllGroups, gentle
		got, err := a.ScanTemplates(t.Context(), st, ownPublicIP, []exposure.TemplateJob{fullJobOf()})
		if err != nil {
			t.Fatal(err)
		}
		pos := map[string]int{}
		for _, r := range f.reqs {
			for i, id := range r.Templates {
				pos[id] = i
			}
		}
		errs := 0
		for _, res := range got.Results {
			if dead(pos[res.Template]) != (res.Outcome == exposure.OutcomeError) {
				t.Fatalf("gentle %t: %s at position %d is %s", gentle, res.Template, pos[res.Template], res.Outcome)
			}
			if res.Outcome == exposure.OutcomeError {
				errs++
			}
		}
		if len(got.Results) < 20 || 2*errs < len(got.Results) {
			t.Fatalf("gentle %t: %d errors of %d results", gentle, errs, len(got.Results))
		}
	}
}
