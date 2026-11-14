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

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
)

// exposureWebScan over a fake host (D-521): what goes to zap.baseline, and how each way a run ends reaches exposure.

type fakeZapHost struct {
	run      api.Run
	err      error
	report   []byte
	got      api.ZapBaselineArgs
	actor    string
	reportID string
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
