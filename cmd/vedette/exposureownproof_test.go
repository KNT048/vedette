package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	sensoractive "github.com/knt048/vedette/modules/sensor-active"
)

// The box's own public IP stays the box's for 90 days from its latest sighting as the box's egress, also while the box goes out
// through another line. Each adapter hands the sighting exposure's gate rests on to its executor, whose own-IP fence takes the
// address on it: the worker's nuclei job, and the host's ZAP run.

var testProven = time.Date(2026, 10, 27, 3, 53, 0, 0, time.UTC)

func TestExposureTemplates_TheRunCarriesTheGatesProof(t *testing.T) {
	t.Parallel()
	f := &templatesFake{gateOK: true, provenAt: testProven, answer: func(sensoractive.NucleiRequest) nucleiout.Outcome { return nucleiout.Outcome{} }}
	if _, err := f.scanner().ScanTemplates(t.Context(), exposure.ScanTarget{User: "u-admin"}, ownPublicIP, []exposure.TemplateJob{ownJob("CVE-2018-13379")}); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 1 || !f.reqs[0].ProvenAt.Equal(testProven) {
		t.Fatalf("requests %+v", f.reqs)
	}
}

// The page of the box's own IP goes to the host with the sighting (proven_at, RFC 3339); a domain page and a typed IP never carry one.
// A host older than the field refuses it as invalid_args, which the page reads as "update the box".
func TestExposureWeb_TheBoxsOwnIPGoesWithItsProof(t *testing.T) {
	t.Parallel()
	ok := func() *fakeZapHost {
		return &fakeZapHost{run: zapRun(t, api.StatusSucceeded, "", &api.ZapBaselineResult{ReportID: strings.Repeat("ab", 16), Size: 2}), report: []byte(`{}`)}
	}
	h := ok()
	w := exposureWebScan{host: h}
	own := webIPTarget
	own.ProvenAt = testProven
	if _, err := w.Baseline(t.Context(), own, webIPPage); err != nil {
		t.Fatal(err)
	}
	if h.got.ProvenAt != "2026-10-27T03:53:00Z" || h.got.Kind != api.ZapKindIP {
		t.Fatalf("args %+v", h.got)
	}
	h = ok() // the proof is about the target's own address: a page on another address never carries it
	w = exposureWebScan{host: h}
	other := webIPPage
	other.IP = netip.MustParseAddr("93.184.216.35")
	if _, err := w.Baseline(t.Context(), own, other); err != nil || h.got.ProvenAt != "" {
		t.Fatalf("a page on another address: args %+v, %v", h.got, err)
	}
	h = ok()
	w = exposureWebScan{host: h}
	if _, err := w.Baseline(t.Context(), webIPTarget, webIPPage); err != nil || h.got.ProvenAt != "" {
		t.Fatalf("no proof: args %+v, %v", h.got, err)
	}
	h = ok()
	w = exposureWebScan{host: h, token: func(context.Context, string) (string, error) { return "0123456789abcdef", nil }}
	dom := webDomTarget
	dom.ProvenAt = testProven
	if _, err := w.Baseline(t.Context(), dom, webDomPage); err != nil || h.got.ProvenAt != "" {
		t.Fatalf("a domain page: args %+v, %v", h.got, err)
	}
	old := &fakeZapHost{err: &hostclient.Error{Code: api.CodeInvalidArgs}}
	_, err := exposureWebScan{host: old}.Baseline(t.Context(), own, webIPPage)
	var un *exposure.Unavailable
	if !errors.As(err, &un) || un.Reason != webOldHost {
		t.Fatalf("an older host: %v", err)
	}
}
