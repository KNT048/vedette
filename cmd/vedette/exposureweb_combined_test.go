package main

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureWebScan.Combined over a fake host: one zap.active with passive for both scans of a page, both reports read back, and an
// older host that refuses the field is said as exposure.ErrNoCombined (nothing started).

const (
	webPassiveRID = "11111111111111111111111111111111"
	webActiveRID  = "22222222222222222222222222222222"
)

func combinedHost(t *testing.T, res api.ZapActiveResult) *fakeZapHost {
	t.Helper()
	r := zapRun(t, api.StatusSucceeded, "", nil)
	r.Command = api.CmdZapActive
	r.Result, _ = json.Marshal(res)
	return &fakeZapHost{run: r, reports: map[string][]byte{webPassiveRID: []byte(`{"passive":1}`), webActiveRID: []byte(`{"active":1}`)}}
}

func TestExposureWeb_CombinedIsOneRunWithBothReports(t *testing.T) {
	t.Parallel()
	h := combinedHost(t, api.ZapActiveResult{ReportID: webActiveRID, PassiveReportID: webPassiveRID, Rules: []int{40012, 40019}, SkippedRules: []int{40021}})
	w := exposureWebScan{host: h}
	tg := webIPTarget
	tg.Mode = modeAllGroups
	passive, active, activeErr, err := w.Combined(t.Context(), tg, webIPPage)
	if err != nil || activeErr != nil {
		t.Fatal(err, activeErr)
	}
	if string(passive.Report) != `{"passive":1}` || string(active.Report) != `{"active":1}` || !slices.Equal(active.Rules, []string{"40012", "40019"}) ||
		!slices.Equal(active.SkippedRules, []string{"40021"}) {
		t.Fatalf("passive %q, active %+v", passive.Report, active)
	}
	if len(h.active) != 1 || !h.active[0].Passive {
		t.Fatalf("one zap.active with passive: %+v", h.active)
	}
	// Active never sends passive: an older host takes it as before
	h2 := combinedHost(t, api.ZapActiveResult{ReportID: webActiveRID})
	if _, err := (exposureWebScan{host: h2}).Active(t.Context(), tg, webIPPage); err != nil || h2.active[0].Passive {
		t.Fatalf("Active sent %+v (%v)", h2.active, err)
	}
}

// The active part ended without its report: the passive report stands and the active outcome says why.
func TestExposureWeb_CombinedKeepsThePassiveReport(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]error{api.CodeZapTimedOut: exposure.ErrActiveTimedOut, api.CodeZapFailed: nil} {
		h := combinedHost(t, api.ZapActiveResult{PassiveReportID: webPassiveRID, ActiveFailed: code, CutShort: true, Rules: []int{40012}})
		passive, _, activeErr, err := (exposureWebScan{host: h}).Combined(t.Context(), webIPTarget, webIPPage)
		if err != nil || string(passive.Report) != `{"passive":1}` || activeErr == nil || (want != nil && !errors.Is(activeErr, want)) {
			t.Fatalf("%s: passive %q, activeErr %v, err %v", code, passive.Report, activeErr, err)
		}
	}
	// no passive report at all: the run's own error
	h := combinedHost(t, api.ZapActiveResult{ReportID: webActiveRID})
	if _, _, _, err := (exposureWebScan{host: h}).Combined(t.Context(), webIPTarget, webIPPage); err == nil {
		t.Fatal("a run without its passive report was taken")
	}
}

// A host older than passive refuses the args (unknown field) or the command: nothing started, ErrNoCombined, no stop sent.
func TestExposureWeb_CombinedOnAnOlderHost(t *testing.T) {
	t.Parallel()
	for _, code := range []string{api.CodeInvalidArgs, api.CodeUnknownCommand} {
		h := &fakeZapHost{err: &hostclient.Error{Status: 400, Code: code}}
		_, _, _, err := (exposureWebScan{host: h}).Combined(t.Context(), webIPTarget, webIPPage)
		if !errors.Is(err, exposure.ErrNoCombined) || len(h.stops) != 0 {
			t.Fatalf("%s: %v, stops %v", code, err, h.stops)
		}
	}
}
