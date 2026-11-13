package findings

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// D-484 (customer walk 1, W1-3): "I have this" on Home means "alert me about this product": a version-less product of
// the answered key matches the answered entry and newer ones, never the product's whole history.
func TestHaveScope_VersionlessAnsweredProductMatchesFromTheAnsweredEntryOn(t *testing.T) {
	t.Parallel()
	day := func(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d }
	vulns := []Vuln{
		{CVE: "CVE-2009-0556", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2022-03-03")},
		{CVE: "CVE-2026-21509", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-11-01")},
		{CVE: "CVE-2026-30000", Vendor: "QNAP", Product: "Photo Station", DateAdded: day("2026-11-12")},
		{CVE: "CVE-2026-30001", Vendor: "QNAP", Product: "Photo Station"}, // no date: kept
	}
	since := map[string]time.Time{"qnap|photo station": day("2026-11-01")}
	cves := func(ms []Match) []string {
		var out []string
		for _, m := range ms {
			out = append(out, m.CVE)
		}
		return out
	}
	got := haveScope(nas(""), vulns, MatchAsset(nas(""), vulns, nil, t0), since)
	if want := "[CVE-2026-21509 CVE-2026-30000 CVE-2026-30001]"; fmt.Sprint(cves(got.New)) != want {
		t.Fatalf("version-less: %v, want %v", cves(got.New), want)
	}
	// An existing finding out of scope is no longer produced (the service then notes no_longer_matches, never closes it).
	got = haveScope(nas(""), vulns, MatchAsset(nas(""), vulns, map[string]bool{"CVE-2009-0556": true}, t0), since)
	if len(got.Existing) != 0 {
		t.Fatalf("existing out of scope kept: %v", cves(got.Existing))
	}
	// With a version the version decides, not the answer on Home.
	if got := haveScope(nas("6.1"), vulns, MatchAsset(nas("6.1"), vulns, nil, t0), since); len(got.New) != 4 {
		t.Fatalf("with a version: %v", cves(got.New))
	}
}

// W1-12: one action and one note for many findings; each gets its own history, audit row and event; all or nothing.
func TestSetStatusMany_OneRowEachAllOrNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, Vuln{CVE: "CVE-2024-0001", Vendor: "QNAP", Product: "Photo Station"})
	res, err := e.svc.OnMatchChanged(t.Context(), "a-1")
	if err != nil || len(res.Created) != 2 {
		t.Fatalf("seed: %+v %v", res, err)
	}
	e.pub.take()
	before := e.count(`SELECT count(*) FROM core_audit`)
	for _, c := range []struct {
		name   string
		ids    []string
		action Action
		note   string
		want   error
	}{
		{"unknown id", []string{res.Created[0], "f-nope"}, ActionFalsePositive, "lab", ErrNotFound},
		{"note required", res.Created, ActionFalsePositive, "", ErrNoteRequired},
		{"reopen", res.Created, ActionReopen, "", ErrBadAction},
		{"none", nil, ActionPatched, "", ErrTooMany},
		{"too many", make([]string, MaxBulk+1), ActionPatched, "", ErrTooMany},
	} {
		if c.name == "too many" {
			for i := range c.ids {
				c.ids[i] = fmt.Sprintf("f-%d", i)
			}
		}
		if _, err := e.svc.SetStatusMany(t.Context(), c.ids, c.action, c.note, "it@acme.example"); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if e.count(`SELECT count(*) FROM core_audit`) != before || e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'suspected'`) != 2 || len(e.pub.take()) != 0 {
		t.Fatal("a refused bulk change wrote something")
	}
	n, err := e.svc.SetStatusMany(t.Context(), append(res.Created, res.Created[0]), ActionFalsePositive, "iPhone on guest Wi-Fi", "it@acme.example")
	if err != nil || n != 2 {
		t.Fatalf("bulk = %d %v", n, err)
	}
	if e.count(`SELECT count(*) FROM fnd_finding WHERE status = 'false_positive' AND resolution_note = 'iPhone on guest Wi-Fi'`) != 2 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.status'`) != 2 || len(e.pub.take()) != 2 {
		t.Fatal("each finding needs its own status, audit row and event")
	}
}

// W1-2, W1-32: a device with no hostname and no IP is named, never shown by its internal id, even in old evidence.
func TestRow_DeviceWithoutIPIsNamedNotByItsID(t *testing.T) {
	t.Parallel()
	r := Record{ID: "f-1", AssetID: "a-vft3", CVE: "CVE-2023-36845", Finding: Finding{Evidence: &Evidence{Summary: "a-vft3 runs Juniper Junos 15.1R7.9."}}}
	row := newRow(r, &AssetView{ID: "a-vft3", Name: "a-vft3", IP: NoIP, Kind: "switch", Display: "Juniper Junos"}, nil)
	if row.Asset.Name != "Juniper Junos" || row.Evidence.Summary != "Juniper Junos runs Juniper Junos 15.1R7.9." || row.Asset.HasIP() {
		t.Fatalf("asset = %+v, evidence = %q", row.Asset, row.Evidence.Summary)
	}
	row = newRow(r, &AssetView{ID: "a-vft3", Name: "Juniper Networks EX4200-48T", IP: NoIP, Kind: "switch"}, nil)
	if row.Asset.Name != "Juniper Networks EX4200-48T" || row.Evidence.Summary != "Juniper Networks EX4200-48T runs Juniper Junos 15.1R7.9." {
		t.Fatalf("asset = %+v, evidence = %q", row.Asset, row.Evidence.Summary)
	}
}
