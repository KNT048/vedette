package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// exposureWebScan over a fake host: what goes to zap.baseline, and how each way a run ends reaches exposure.

type fakeZapHost struct {
	run      api.Run
	err      error
	report   []byte
	got      api.ZapBaselineArgs
	actor    string
	reportID string
	active   []api.ZapActiveArgs // the zap.active calls
	block    bool                // zap.active waits until its context ends
	stops    []string            // the request ids zap.stop named
	reqs     []string            // the request ids of the zap.active calls
}

func (f *fakeZapHost) ZapActive(ctx context.Context, args api.ZapActiveArgs, req, actor string) (api.Run, error) {
	f.active, f.actor, f.reqs = append(f.active, args), actor, append(f.reqs, req)
	if f.block {
		<-ctx.Done()
		return api.Run{}, ctx.Err()
	}
	return f.run, f.err
}

func (f *fakeZapHost) ZapStop(ctx context.Context, args api.ZapStopArgs, _, _ string) (api.Run, error) {
	if ctx.Err() != nil {
		return api.Run{}, ctx.Err() // a stop sent on the scan's own ended context would never reach the host
	}
	f.stops = append(f.stops, args.RequestID)
	return api.Run{Status: api.StatusSucceeded}, nil
}

func (f *fakeZapHost) ZapBaseline(_ context.Context, args api.ZapBaselineArgs, _, actor string) (api.Run, error) {
	f.got, f.actor = args, actor
	return f.run, f.err
}

func (f *fakeZapHost) DownloadZapReport(_ context.Context, id string) (io.ReadCloser, int64, error) {
	f.reportID = id
	return io.NopCloser(bytes.NewReader(f.report)), int64(len(f.report)), nil
}

func zapRun(t *testing.T, status api.Status, code string, res *api.ZapBaselineResult) api.Run {
	t.Helper()
	r := api.Run{RunID: "rn_0123456789abcdef", Command: api.CmdZapBaseline, Status: status}
	if code != "" {
		r.Error = &api.RunError{Code: code, Message: "host text"}
	}
	if res != nil {
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		r.Result = b
	}
	return r
}

var (
	webIPTarget  = exposure.ScanTarget{ID: "t1", Kind: exposure.KindIP, Value: "93.184.216.34", User: "us_admin"}
	webIPPage    = exposure.WebPage{URL: "https://93.184.216.34:8443/", Host: "93.184.216.34", IP: netip.MustParseAddr("93.184.216.34"), Port: 8443}
	webDomTarget = exposure.ScanTarget{ID: "t2", Kind: exposure.KindDomain, Value: "example.com", User: "us_admin"}
	webDomPage   = exposure.WebPage{URL: "https://www.example.com/", Host: "www.example.com", IP: netip.MustParseAddr("93.184.216.34"), Port: 443}
)

func TestExposureWeb_AReportComesBack(t *testing.T) {
	t.Parallel()
	const rid = "0123456789abcdef0123456789abcdef"
	for _, code := range []int{0, 1, 2} {
		h := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid, Size: 11, ExitCode: code}), report: []byte(`{"site":[]}`)}
		w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
		got, err := w.Baseline(t.Context(), webDomTarget, webDomPage)
		if err != nil || string(got.Report) != `{"site":[]}` || h.reportID != rid {
			t.Fatalf("exit %d: %q %v (report %s)", code, got.Report, err, h.reportID)
		}
		want := api.ZapBaselineArgs{URL: webDomPage.URL, Host: "www.example.com", IP: "93.184.216.34", Port: 443, Kind: api.ZapKindDomain, Domain: "example.com", TXTToken: "0123456789abcdef"}
		if h.got != want || h.actor != "exposure:us_admin" {
			t.Fatalf("args %+v actor %q", h.got, h.actor)
		}
	}
	// review r1 M of #941: a child covered only by its parent (git.example.com by example.com) has its pages checked against
	// the parent's record: the host is asked for the parent's domain and token, and the page's name stays the child's
	child := exposure.ScanTarget{ID: "t3", Kind: exposure.KindDomain, Value: "git.example.com", User: "us_admin", Proof: &exposure.ProofOwner{Domain: "example.com", Token: "fedcba9876543210"}}
	childPage := exposure.WebPage{URL: "https://git.example.com/", Host: "git.example.com", IP: netip.MustParseAddr("93.184.216.34"), Port: 443}
	hc := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid}), report: []byte(`{}`)}
	if _, err := (exposureWebScan{host: hc, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}).Baseline(t.Context(), child, childPage); err != nil {
		t.Fatal(err)
	}
	if hc.got.Domain != "example.com" || hc.got.TXTToken != "fedcba9876543210" || hc.got.Host != "git.example.com" {
		t.Fatalf("covered child: %+v", hc.got)
	}
	// A target proved by its own record on the apex: the host gets the target itself and proof_at
	own := child
	own.Proof = &exposure.ProofOwner{Domain: "git.example.com", Token: "0123456789abcdef", ProofAt: "example.com"}
	ho := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid}), report: []byte(`{}`)}
	if _, err := (exposureWebScan{host: ho}).Baseline(t.Context(), own, childPage); err != nil {
		t.Fatal(err)
	}
	if ho.got.Domain != "git.example.com" || ho.got.ProofAt != "example.com" || ho.got.TXTToken != "0123456789abcdef" {
		t.Fatalf("own record on the apex: %+v", ho.got)
	}
	// A name proved by the token of another target on the name above both: the host gets that target's domain and token, the shared
	// name as proof_at, and the page's own name; a refusal names the donor, not the scanned name
	sib := exposure.ScanTarget{ID: "t4", Kind: exposure.KindDomain, Value: "example.com", User: "us_admin", Proof: &exposure.ProofOwner{Domain: "git.example.com", Token: "0123456789abcdef", ProofAt: "example.com"}}
	hs := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid}), report: []byte(`{}`)}
	if _, err := (exposureWebScan{host: hs}).Baseline(t.Context(), sib, exposure.WebPage{URL: "https://example.com/", Host: "example.com", IP: netip.MustParseAddr("93.184.216.34"), Port: 443}); err != nil {
		t.Fatal(err)
	}
	if hs.got.Domain != "git.example.com" || hs.got.ProofAt != "example.com" || hs.got.Host != "example.com" || hs.got.TXTToken != "0123456789abcdef" {
		t.Fatalf("a name proved by another target's token: %+v", hs.got)
	}
	if why := webReason(api.CodeTargetNotOwned, sib, childPage); !strings.Contains(why, "example.com no longer has the vedette-verify TXT record of git.example.com") {
		t.Fatalf("refusal text: %q", why)
	}
	h := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid}), report: []byte(`{}`)}
	if _, err := (exposureWebScan{host: h}).Baseline(t.Context(), webIPTarget, webIPPage); err != nil {
		t.Fatal(err)
	}
	if h.got.Kind != api.ZapKindIP || h.got.Domain != "" || h.got.TXTToken != "" || h.got.Host != "93.184.216.34" {
		t.Fatalf("an IP page sent %+v", h.got)
	}
}

func TestExposureWeb_TheReportReadIsBounded(t *testing.T) {
	t.Parallel()
	h := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: "0123456789abcdef0123456789abcdef"}), report: make([]byte, exposure.MaxWebReport+100)}
	got, err := (exposureWebScan{host: h}).Baseline(t.Context(), webIPTarget, webIPPage)
	if err != nil || len(got.Report) != exposure.MaxWebReport+1 {
		t.Fatalf("%d bytes, %v", len(got.Report), err)
	}
	if _, perr := exposure.ParseZAPReport(got.Report, webIPPage.URL); !errors.Is(perr, exposure.ErrBadReport) {
		t.Fatalf("a report over the limit reads as %v", perr)
	}
}

func TestExposureWeb_HowARunThatDidNotScanReachesThePage(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		target exposure.ScanTarget
		page   exposure.WebPage
		run    api.Run
		err    error
		want   string // the Unavailable reason; "" for a plain error
	}{
		"image missing":     {webIPTarget, webIPPage, zapRun(t, api.StatusRefused, api.CodeZapPulling, nil), nil, webPulling},
		"pull failed":       {webIPTarget, webIPPage, zapRun(t, api.StatusRefused, api.CodeZapPullFailed, nil), nil, webPullFailed},
		"busy":              {webIPTarget, webIPPage, zapRun(t, api.StatusRefused, api.CodeBusy, nil), nil, webBusy},
		"cleaning up":       {webIPTarget, webIPPage, zapRun(t, api.StatusRefused, api.CodeZapCleaningUp, nil), nil, webCleaningUp},
		"IP not the box's":  {webIPTarget, webIPPage, zapRun(t, api.StatusRefused, api.CodeTargetNotOwned, nil), nil, "this box no longer reaches the Internet through 93.184.216.34, so its pages were not scanned."},
		"TXT gone":          {webDomTarget, webDomPage, zapRun(t, api.StatusRefused, api.CodeTargetNotOwned, nil), nil, "example.com no longer has its vedette-verify TXT record, so its pages were not scanned."},
		"not checked":       {webIPTarget, webIPPage, zapRun(t, api.StatusFailed, api.CodeOwnershipUnchecked, nil), nil, webUnchecked},
		"no fence":          {webIPTarget, webIPPage, zapRun(t, api.StatusFailed, api.CodeZapFenceFailed, nil), nil, webFence},
		"old host":          {webIPTarget, webIPPage, api.Run{}, &hostclient.Error{Status: 404, Code: api.CodeUnknownCommand}, webOldHost},
		"exit 3":            {webIPTarget, webIPPage, zapRun(t, api.StatusFailed, api.CodeZapFailed, nil), nil, ""},
		"host's time limit": {webIPTarget, webIPPage, zapRun(t, api.StatusFailed, api.CodeZapTimedOut, nil), nil, ""},
		"too large":         {webIPTarget, webIPPage, zapRun(t, api.StatusFailed, api.CodeZapReportTooLarge, nil), nil, ""},
		"host gone":         {webIPTarget, webIPPage, api.Run{}, errors.New("dial unix: no such file"), ""},
	} {
		h := &fakeZapHost{run: tc.run, err: tc.err}
		w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
		_, err := w.Baseline(t.Context(), tc.target, tc.page)
		var un *exposure.Unavailable
		switch {
		case err == nil:
			t.Errorf("%s: no error", name)
		case tc.want == "" && errors.As(err, &un):
			t.Errorf("%s: Unavailable %q, want a failure of this page", name, un.Reason)
		case tc.want != "" && (!errors.As(err, &un) || un.Reason != tc.want):
			t.Errorf("%s: %v, want Unavailable %q", name, err, tc.want)
		}
		if h.reportID != "" {
			t.Errorf("%s: a report was read", name)
		}
	}
}

func TestExposureWeb_NoHostIsSaidSo(t *testing.T) {
	t.Parallel()
	_, err := exposureWebScan{}.Baseline(t.Context(), webIPTarget, webIPPage)
	var un *exposure.Unavailable
	if !errors.As(err, &un) || !strings.Contains(un.Reason, "appliance install") {
		t.Fatalf("%v", err)
	}
	// What exposureService wires on an install without a socket.
	if w := exposureWebFor(deps{}); w.host != nil {
		t.Fatal("a host client without a socket")
	}
}

// INV-24 (LEGAL §3) on this side: RecordWebProbe has written the page's row to the scan module's probe log when it returns, so a ZAP
// run exposure starts after it (modules/exposure TestWebPassive… checks that order with its fake log) is always on record first.
func TestExposureWeb_APageIsInTheProbeLogBeforeTheRun(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	var log exposure.WebProbeLog = exposureProbeLog{d: *s.d}
	const rid = "0123456789abcdef0123456789abcdef"
	h := &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: rid}), report: []byte(`{}`)}
	var seen []string
	host := zapHostFunc{fakeZapHost: h, before: func() {
		rows, err := scanService(*s.d).Probes(t.Context())
		if err != nil {
			t.Error(err)
		}
		for _, r := range rows {
			seen = append(seen, r.Label+" "+r.Template+" "+r.Request)
		}
	}}
	if err := log.RecordWebProbe(t.Context(), exposure.WebProbe{ID: "pb_web1", IP: "93.184.216.34", Port: 8443, URL: webIPPage.URL, Tool: "ZAP baseline passive"}); err != nil {
		t.Fatal(err)
	}
	if _, err := (exposureWebScan{host: host}).Baseline(t.Context(), webIPTarget, webIPPage); err != nil {
		t.Fatal(err)
	}
	want := "93.184.216.34:8443 exposure: ZAP baseline passive planned: passive web scan of https://93.184.216.34:8443/, ZAP pinned to 93.184.216.34:8443 (no other address, no DNS)"
	if len(seen) != 1 || seen[0] != want {
		t.Fatalf("the probe log when zap.baseline was asked: %q", seen)
	}
}

// zapHostFunc runs before ahead of each zap.baseline call of the fake host.
type zapHostFunc struct {
	*fakeZapHost
	before func()
}

func (z zapHostFunc) ZapBaseline(ctx context.Context, args api.ZapBaselineArgs, id, actor string) (api.Run, error) {
	z.before()
	return z.fakeZapHost.ZapBaseline(ctx, args, id, actor)
}

// Review 2 N2: a page whose name now points elsewhere is a skip of that page alone, with a sentence that does not blame the TXT record.
func TestExposureWeb_AMovedNameSkipsThatPageOnly(t *testing.T) {
	t.Parallel()
	h := &fakeZapHost{run: zapRun(t, api.StatusRefused, api.CodeZapNameMoved, nil)}
	w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
	_, err := w.Baseline(t.Context(), webDomTarget, webDomPage)
	var skip *exposure.PageSkipped
	var un *exposure.Unavailable
	if !errors.As(err, &skip) || errors.As(err, &un) || !strings.HasPrefix(skip.Reason, "www.example.com now points at other addresses than 93.184.216.34") || strings.Contains(skip.Reason, "TXT") {
		t.Fatalf("%v", err)
	}
}

// A scan container older than this version refuses the proof-name shape of a job as invalid: the customer reads that the box needs an
// update, not that DNS did not answer.
func TestDomainErr_AnOlderScanContainerSaysUpdateTheBox(t *testing.T) {
	t.Parallel()
	d := &exposure.DomainScope{Domain: "git.example.com", Name: "example.com", Token: "0123456789abcdef", ProofAt: "example.com"}
	u, ok := domainErr(&sensoractive.DomainRefusedError{Reason: domainfence.InvalidJob}, d, "93.184.216.34")
	if !ok || !strings.Contains(u.Reason, "Update the box") {
		t.Fatalf("%+v %v", u, ok)
	}
}

// zap.active gets the page's args and the disruptive rules only for the box's own IP; a domain's page (a CDN or hosting address) never
// carries them, whatever the step's mode. ZAP's cut-short flag comes back to exposure.
func TestExposureWeb_ActiveSendsTheDisruptiveRulesOnlyForTheBoxsOwnIP(t *testing.T) {
	t.Parallel()
	const rid = "0123456789abcdef0123456789abcdef"
	ok := func() *fakeZapHost {
		r := zapRun(t, api.StatusSucceeded, "", nil)
		r.Command = api.CmdZapActive
		r.Result, _ = json.Marshal(api.ZapActiveResult{ReportID: rid, Size: 11, CutShort: true})
		return &fakeZapHost{run: r, report: []byte(`{"site":[]}`)}
	}
	deep := exposure.ScanMode{Full: true, Disruptive: true}
	ipT, domT := webIPTarget, webDomTarget
	ipT.Mode, domT.Mode = deep, deep
	h := ok()
	w := exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
	got, err := w.Active(t.Context(), ipT, webIPPage)
	if err != nil || !got.CutShort || h.reportID != rid {
		t.Fatalf("%+v %v", got, err)
	}
	if len(h.active) != 1 || !h.active[0].Disruptive || h.active[0].URL != webIPPage.URL || h.active[0].Kind != api.ZapKindIP {
		t.Fatalf("own IP: %+v", h.active)
	}
	ipT.Mode.Disruptive = false
	if _, err := w.Active(t.Context(), ipT, webIPPage); err != nil || h.active[1].Disruptive {
		t.Fatalf("own IP without the disruptive checks: %+v %v", h.active, err)
	}
	h2 := ok()
	w.host = h2
	if _, err := w.Active(t.Context(), domT, webDomPage); err != nil || len(h2.active) != 1 || h2.active[0].Disruptive || h2.active[0].Kind != api.ZapKindDomain {
		t.Fatalf("a domain's page: %+v %v", h2.active, err)
	}
}

// A scan stopped while ZAP runs stops ZAP on the host: exposure's context ends, the adapter sends zap.stop (on a context of its own,
// since the scan's has ended) naming the request of its own zap.active, before it returns.
func TestExposureWeb_AStoppedScanStopsZAPOnTheHost(t *testing.T) {
	t.Parallel()
	h := &fakeZapHost{block: true}
	w := exposureWebScan{host: h}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := w.Active(ctx, webIPTarget, webIPPage)
		done <- err
	}()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || len(h.stops) != 1 || len(h.reqs) != 1 || h.stops[0] != h.reqs[0] || h.stops[0] == "" {
		t.Fatalf("%v, stops %q of runs %q", err, h.stops, h.reqs)
	}
}
