package findings

import (
	"bytes"
	"database/sql"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// walk3VMware is the Windows device of customer walk 3 (W3-7): VMware Tools 13.0.10 as the agent maps it (pkgmap
// "vmware tools" → VMware|Tools).
func walk3VMware() Asset {
	return Asset{ID: "a-win", Name: "win11", OS: "Microsoft Windows 11 Pro", Software: []Software{
		{ID: "s-tools", Display: "VMware Tools", Vendor: "VMware", Product: "Tools", Version: "13.0.10", KevKeys: []string{"vmware|tools"}},
	}}
}

var walk3Multi = []string{"CVE-2020-3950", "CVE-2020-4006", "CVE-2022-22960"} // CISA "VMware | Multiple Products"

// openProductFindings gives the device the old open findings of cves the way the matcher made them before D-500: suspected,
// basis product, high.
func openProductFindings(t *testing.T, e *env, a Asset, vulns []Vuln, cves []string) {
	t.Helper()
	guess := make([]Vuln, 0, len(cves))
	for _, v := range vulns {
		if slices.Contains(cves, v.CVE) {
			v.Affected = []Affected{{CPE: "cpe:2.3:a:" + strings.ToLower(v.Vendor) + ":*:*:*:*:*:*:*:*:*"}} // may be anything: product
			guess = append(guess, v)
		}
	}
	if res, err := e.svc.UpsertFromMatch(t.Context(), a, guess); err != nil || len(res.Created) != len(cves) {
		t.Fatalf("setup: %+v %v", res, err)
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET severity = 'high' WHERE asset_id = ?`, a.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// W3-7, D-505, D-506: VMware Tools 13.0.10 gets nothing from the three "VMware Multiple Products" entries, whose real NVD
// lists name Fusion, Horizon Client, Remote Console, Identity Manager, Workspace ONE Access, Cloud Foundation… but not
// Tools. The entries are years old in KEV, so NVD's list is settled (D-506): the old open product findings the retired
// vendor-wide rule made close by themselves at the first reconcile pass. A "Multiple Products" entry added 100 days ago
// keeps D-505 (open, medium, the note); a version finding and one a person reopened are never closed.
func TestGolden_VMwareToolsMultipleProducts(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	dev := walk3VMware()
	if r := MatchAsset(dev, vulns, nil, t0); len(r.New) != 0 || len(r.NeedVersion)+len(r.Unlisted)+len(r.Retired) != 0 {
		t.Fatalf("VMware Tools 13.0.10: %+v", r)
	}
	// Three more entries with the real NVD list of CVE-2020-3950 (ids made up): one CISA added 100 days ago, one whose
	// finding is basis version, one a person closed and reopened.
	const recent, version, reopened = "CVE-2026-0001", "CVE-2021-0002", "CVE-2021-0003"
	idx := slices.IndexFunc(vulns, func(v Vuln) bool { return v.CVE == walk3Multi[0] })
	for _, x := range []struct {
		cve   string
		added time.Time
	}{{recent, t0.Add(-100 * 24 * time.Hour)}, {version, vulns[idx].DateAdded}, {reopened, vulns[idx].DateAdded}} {
		v := vulns[idx]
		v.CVE, v.DateAdded = x.cve, x.added
		vulns = append(vulns, v)
	}
	all := append(slices.Clone(walk3Multi), recent, version, reopened)
	have := map[string]bool{}
	for _, c := range all {
		have[c] = true
	}
	r := MatchAsset(dev, vulns, have, t0)
	var unlisted, retired []string
	for _, m := range r.Unlisted {
		unlisted = append(unlisted, m.CVE)
	}
	for _, m := range r.Retired {
		retired = append(retired, m.CVE)
	}
	slices.Sort(unlisted)
	if slices.Sort(retired); len(unlisted) != len(all) || !slices.Equal(retired, []string{"CVE-2020-3950", "CVE-2020-4006", version, reopened, "CVE-2022-22960"}) ||
		len(r.Existing)+len(r.NotAffected) != 0 {
		t.Fatalf("unlisted %v, retired %v, kept %+v, proved %+v", unlisted, retired, r.Existing, r.NotAffected)
	}

	e := newEnv(t)
	e.inv.match = map[string]Asset{dev.ID: dev}
	e.inv.assets = map[string]AssetView{dev.ID: {ID: dev.ID, Hostname: ptr("byn"), IP: "192.168.18.50", Kind: "computer", Display: "VMware Tools"}}
	e.feeds.vulns = vulns
	openProductFindings(t, e, dev, vulns, all)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET basis = 'version', confidence = 0.7 WHERE cve = ?`, version)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, reopened)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []Action{ActionNotRelevant, ActionReopen} {
		if _, err := e.svc.SetStatus(t.Context(), f.ID, a, "checked by hand", "kien@example.test"); err != nil {
			t.Fatal(err)
		}
	}
	// The N100 already said "no longer matches" in the generic words (no NVD data at the time) and closed nothing.
	var noNVD []Vuln
	for _, v := range vulns {
		if slices.Contains(all, v.CVE) {
			v.Affected = nil
		}
		noNVD = append(noNVD, v)
	}
	if res, err := e.svc.UpsertFromMatch(t.Context(), dev, noNVD); err != nil || len(res.Created)+res.Retired != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	e.pub.take()

	// The module starts: the reconcile pass closes the three, says so in the log, and a second pass changes nothing.
	var logged bytes.Buffer
	svc, err := NewService(ServiceConfig{DB: e.db, Audit: audit.New(func() time.Time { return *e.clock }), Publisher: e.pub, Inventory: e.inv, Feeds: e.feeds,
		Log: slog.New(slog.NewTextHandler(&logged, nil)), Clock: func() time.Time { return *e.clock }})
	if err != nil {
		t.Fatal(err)
	}
	for pass, want := range []int{3, 0} {
		res, err := svc.Reconcile(t.Context())
		if err != nil || res.Retired != want || res.Closed != 0 || res.Created != 0 {
			t.Fatalf("pass %d: %+v %v", pass, res, err)
		}
	}
	if l := logged.String(); !strings.Contains(l, "findings: closed (D-506)") || !strings.Contains(l, "count=3") ||
		strings.Count(l, "findings: reconcile pass done") != 2 || !strings.Contains(l, "closed_multiple_products=3") {
		t.Errorf("log:\n%s", logged.String())
	}
	const want = "Closed by Vedette: CISA lists CVE-2020-3950 for several VMware products; NVD names fusion, horizon client, remote console, not VMware Tools (settled: CISA added it over a year ago). Vedette reopens it if NVD later names VMware Tools."
	for _, c := range all {
		f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, c)
		if err != nil {
			t.Fatal(err)
		}
		last := f.History[len(f.History)-1]
		switch c {
		case recent, version, reopened:
			if f.Status != StatusSuspected || last.Action != "no_longer_matches" || !strings.Contains(last.Note, "not VMware Tools; check the vendor advisory") {
				t.Errorf("%s: %+v, last history %+v", c, f.Finding, last)
			}
		default:
			if f.Status != StatusNotRelevant || f.ResolvedBy != SystemUser || f.ResolutionReason != ReasonNotAffectedVersion || f.Severity != SeverityMedium ||
				last.Action != string(StatusNotRelevant) || last.User != SystemUser || last.Note != f.ResolutionNote || !strings.HasPrefix(last.Note, "Closed by Vedette: CISA lists "+c) {
				t.Errorf("%s: %+v, last history %+v", c, f.Finding, last)
			}
			if c == "CVE-2020-3950" && last.Note != want {
				t.Errorf("note %q, want %q", last.Note, want)
			}
		}
	}
	if got := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.auto_resolved' AND detail LIKE '%D-506%'`); got != 3 {
		t.Errorf("auto_resolved audit rows %d, want 3", got)
	}
	ev := e.pub.take()
	if len(ev) != 3 {
		t.Fatalf("events %+v", ev)
	}
	for _, x := range ev {
		if p, ok := x.Payload.(StatusChangedEvent); !ok || p.From != StatusSuspected || p.To != StatusNotRelevant || p.Reason != ReasonNotAffectedVersion {
			t.Errorf("event %+v", x)
		}
	}

	// NVD later names VMware Tools for CVE-2020-3950 with 13.0.10 inside: the finding reopens by itself.
	vulns[idx].Affected = append(vulns[idx].Affected, Affected{CPE: "cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "13.0.0", EndExcl: "13.0.11"}})
	if res, err := svc.Reconcile(t.Context()); err != nil || res.Retired != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if f, err := loadByPair(t.Context(), e.db.Reader(), dev.ID, "CVE-2020-3950"); err != nil || f.Status != StatusSuspected || f.Basis != BasisVersion ||
		f.History[len(f.History)-1].Action != "matches_again" {
		t.Errorf("after NVD names Tools: %+v %v", f, err)
	}
}

// D-506: only when NVD names none of the device's software of the vendor. A device that also has Fusion, which NVD names
// for CVE-2020-3950 and whose version is outside its range, keeps the D-505 behaviour: Tools is unlisted, nothing retires.
func TestMultipleProducts_RetiresOnlyWhenNoSoftwareIsNamed(t *testing.T) {
	t.Parallel()
	dev := walk3VMware()
	dev.Software = append(dev.Software, Software{ID: "s-fusion", Display: "VMware Fusion", Vendor: "VMware", Product: "Fusion", Version: "12.0.0", KevKeys: []string{"vmware|fusion"}})
	multi := Vuln{CVE: "CVE-2020-3950", Vendor: "VMware", Product: "Multiple Products", DateAdded: t0.AddDate(-5, 0, 0), Affected: []Affected{
		{CPE: "cpe:2.3:a:vmware:fusion:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.0.0", EndExcl: "11.5.2"}}}}
	r := MatchAsset(dev, []Vuln{multi}, map[string]bool{multi.CVE: true}, t0)
	if len(r.Unlisted) != 1 || len(r.Retired)+len(r.NotAffected)+len(r.Existing) != 0 {
		t.Fatalf("%+v", r)
	}
	multi.DateAdded = time.Time{} // a date Vedette could not read is never settled
	if r := MatchAsset(walk3VMware(), []Vuln{multi}, map[string]bool{multi.CVE: true}, t0); len(r.Unlisted) != 1 || len(r.Retired) != 0 {
		t.Fatalf("no date: %+v", r)
	}
}

// D-505, review L4 of #671: a "Multiple Products" entry with an NVD entry Vedette cannot tie to a product (vendor or
// product ANY, or not a CPE) may be about the software: a product finding (medium), never a proof, never "unlisted".
func TestMultipleProducts_UnreadableEntryIsNoProof(t *testing.T) {
	t.Parallel()
	tools := Vuln{CVE: "CVE-2023-20867", Vendor: "VMware", Product: "Tools", Affected: []Affected{{CPE: "cpe:2.3:a:vmware:tools:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "10.3.0", EndExcl: "12.2.5"}}}}
	for _, odd := range []string{"cpe:2.3:a:vmware:*:*:*:*:*:*:*:*:*", "not a cpe"} {
		multi := Vuln{CVE: "CVE-2020-3950", Vendor: "VMware", Product: "Multiple Products", Affected: []Affected{
			{CPE: "cpe:2.3:a:vmware:fusion:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "11.0.0", EndExcl: "11.5.2"}}, {CPE: odd}}}
		r := MatchAsset(walk3VMware(), []Vuln{tools, multi}, map[string]bool{multi.CVE: true}, t0)
		if len(r.NotAffected)+len(r.Unlisted) != 0 || len(r.Existing) != 1 || r.Existing[0].Basis != BasisProduct || r.Existing[0].Severity != SeverityMedium {
			t.Errorf("%q: %+v", odd, r)
		}
	}
}

// W3-8: the box (Ubuntu 26.04, software from the host's dpkg, D-470) is judged by its OS like an agent host: CVE-2021-3493
// lists only Ubuntu releases before 20.10, so it gives no finding and the old product finding closes. Without an OS (the
// cause on the N100) the same kernel stays a product finding.
func TestGolden_BoxOSRulesOutOverlayFS(t *testing.T) {
	t.Parallel()
	vulns := goldenVulns(t)
	const cve = "CVE-2021-3493"
	box := Asset{ID: "a-box", Name: "boxkien", OS: "Ubuntu 26.04", Software: []Software{agentPkg("Linux", "Kernel", "7.0.0")}}
	r := MatchAsset(box, vulns, map[string]bool{cve: true}, t0)
	if slices.ContainsFunc(append(r.New, r.Existing...), func(m Match) bool { return m.CVE == cve }) {
		t.Fatalf("%s on Ubuntu 26.04: %+v", cve, r)
	}
	if !slices.ContainsFunc(r.NotAffected, func(m Match) bool { return m.CVE == cve && strings.Contains(m.Evidence.Summary, "(Ubuntu 26.04)") }) {
		t.Fatalf("%s not proved: %+v", cve, r.NotAffected)
	}
	box.OS = ""
	if r := MatchAsset(box, vulns, nil, t0); !slices.ContainsFunc(r.New, func(m Match) bool { return m.CVE == cve && m.Basis == BasisProduct }) {
		t.Fatalf("without an OS: %+v", r.New)
	}
}
