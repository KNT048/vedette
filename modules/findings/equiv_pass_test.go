package findings

import (
	"database/sql"
	"reflect"
	"slices"
	"testing"
	"time"
)

// equivPassVulns is equivVulns with a few entries CISA added in the last days (they are news, the rest backlog), so a pass writes both
// parts of every device.
func equivPassVulns(t *testing.T, assets []Asset) []Vuln {
	t.Helper()
	vulns := equivVulns(t, assets)
	for i := range vulns {
		if vulns[i].Vendor != "" && i%7 == 0 {
			vulns[i].DateAdded = t0.Add(-48 * time.Hour)
		}
	}
	return vulns
}

// passRows is what a match pass leaves in the database: every finding (all its columns but the random id), its events, and every
// question (all columns but the id), in a stable order.
type passRows struct {
	Findings  []map[string]any `json:"findings"`
	Events    []map[string]any `json:"events"`
	Questions []map[string]any `json:"questions"`
}

func (e *env) passRows() passRows {
	e.t.Helper()
	read := func(q string) []map[string]any {
		rows, err := e.db.Reader().QueryContext(e.t.Context(), q)
		if err != nil {
			e.t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		cols, err := rows.Columns()
		if err != nil {
			e.t.Fatal(err)
		}
		var out []map[string]any
		for rows.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			m := map[string]any{}
			for i, c := range cols {
				if vals[i].Valid {
					m[c] = vals[i].String
				} else {
					m[c] = nil
				}
			}
			out = append(out, m)
		}
		if err := rows.Err(); err != nil {
			e.t.Fatal(err)
		}
		return out
	}
	const findingCols = `asset_id, cve, software_id, detected, basis, verified, range_origin, matched_version, fix_kind, fix_version, fix_ref,
		fix_key, evidence, state, resolution, via, resolved_by, resolved_at, note, accepted_until, from_version, to_version, urgency, urgency_at,
		first_seen, last_seen, updated_at`
	return passRows{
		Findings: read(`SELECT ` + findingCols + ` FROM fnd_finding ORDER BY asset_id, cve, ifnull(software_id, '')`),
		Events: read(`SELECT f.asset_id, f.cve, f.software_id, e.ts, e.actor, e.kind, e.detail FROM fnd_finding_event e JOIN fnd_finding f ON f.id = e.finding_id
			ORDER BY f.asset_id, f.cve, ifnull(f.software_id, ''), e.id`),
		Questions: read(`SELECT asset_id, software_id, cve, kind, detail, cves, asked_at, answer, answered_by, answered_at FROM fnd_question
			ORDER BY asset_id, ifnull(software_id, ''), ifnull(cve, ''), kind`),
	}
}

// The hourly match pass writes exactly what it wrote before it was made faster: every finding row (detection, fix, state, resolution,
// urgency, dates), every event and every question of every device of the equivalence fixture, over four passes: the first (backlog and
// news written apart), one after the devices and the catalogue changed (a version moved, a line removed, a line added, an entry gone, a
// range changed, an entry added), one with nothing changed an hour later, one a day later (last_seen moves once a day), and one with a
// version moved back (findings open again).
func TestMatchPass_SameRowsOnTheFixture(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	assets := equivAssets(t)
	e.inv.match = map[string]Asset{}
	for _, a := range assets {
		e.inv.match[a.ID] = a
	}
	e.feeds.vulns = equivPassVulns(t, assets)
	svc := e.reconciler(e.pub, e.inv)
	pass := func() passRows {
		t.Helper()
		if _, err := svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		return e.passRows()
	}
	var got []passRows
	got = append(got, pass())

	e.advance(time.Hour)
	e.inv.mu.Lock()
	moved := e.inv.match["eq-fortigate"]
	moved.Software = slices.Clone(moved.Software)
	moved.Software[0].Version, moved.Software[0].CPE = "7.4.8", "cpe:2.3:o:fortinet:fortios:7.4.8:*:*:*:*:*:*:*"
	e.inv.match["eq-fortigate"] = moved
	ub := e.inv.match["eq-ubuntu"]
	ub.Software = slices.Delete(slices.Clone(ub.Software), 1, 2) // openssl removed
	e.inv.match["eq-ubuntu"] = ub
	ssh := e.inv.match["eq-ssh"]
	ssh.Software = append(slices.Clone(ssh.Software), Software{ID: "s-photo", Display: "Photo Station", Vendor: "QNAP", Product: "Photo Station", Version: "6.0.0",
		Source: "agent", KevKeys: []string{"qnap|photo station"}})
	e.inv.match["eq-ssh"] = ssh
	e.inv.mu.Unlock()
	vulns := slices.Clone(e.feeds.vulns)
	gone := slices.IndexFunc(vulns, func(v Vuln) bool { return v.Vendor == "Apple" })
	vulns = slices.Delete(vulns, gone, gone+1)
	for i := range vulns {
		if vulns[i].Vendor == "Microsoft" && len(vulns[i].Affected) > 0 {
			vulns[i].Affected = slices.Clone(vulns[i].Affected)
			vulns[i].Affected[0].Range = VersionRange{EndExcl: "99"}
			break
		}
	}
	vulns = append(vulns, Vuln{CVE: "CVE-2026-9990001", Vendor: "QNAP", Product: "Photo Station", DateAdded: t0, NVDAnswered: true, Origin: RangeNVD,
		Affected: []Affected{{CPE: qnapCPE, Range: VersionRange{EndExcl: "6.1.2"}}}})
	e.feeds.vulns = vulns
	got = append(got, pass())

	e.advance(time.Hour)
	got = append(got, pass())
	e.advance(25 * time.Hour)
	got = append(got, pass())
	e.advance(time.Hour) // the firewall back on its older version: its findings open again
	e.inv.mu.Lock()
	e.inv.match["eq-fortigate"] = with(fortigate(), "eq-fortigate")
	e.inv.mu.Unlock()
	got = append(got, pass())

	if len(got[0].Findings) == 0 || len(got[0].Questions) == 0 {
		t.Fatalf("the fixture made %d findings and %d questions: it no longer reaches the pass", len(got[0].Findings), len(got[0].Questions))
	}
	equivGolden(t, "equiv-matchpass", got)
}

// MatchAsset answers exactly what it answered before it was made faster, every field of its result, on every device of the equivalence
// fixture, for a device with no finding yet and for one with a finding of every CVE (proofs, unlisted and retired entries then show),
// with the device's whole list as its Windows list (as the pass reads it) and without.
func TestMatchAsset_SameResultsOnTheFixture(t *testing.T) {
	t.Parallel()
	assets := equivAssets(t)
	set := newMatchSet(equivPassVulns(t, assets))
	type answers struct {
		Device                 string
		Fresh, HasAll, OwnList MatchResult
	}
	var got []answers
	for _, a := range assets {
		dev := set.forDevice(a)
		all := cveSet(dev)
		own := MatchAsset(a, dev[:len(dev)/2], all, t0) // its Windows list is the part it is given
		a.winList = dev
		got = append(got, answers{Device: a.ID, Fresh: MatchAsset(a, dev, nil, t0), HasAll: MatchAsset(a, dev, all, t0), OwnList: own})
	}
	equivGolden(t, "equiv-matchasset", got)
}

// The match pass assembles each write's match from the readings of the device's whole list (devMatch): the match of a part, for any
// findings the device has, is exactly MatchAsset of that part with the whole list as the device's Windows list, on every device of the
// fixture, for the parts the pass writes (backlog and news) and for an arbitrary part with a duplicate entry.
func TestDevMatch_PartIsMatchAssetOfThePart(t *testing.T) {
	t.Parallel()
	assets := equivAssets(t)
	set := newMatchSet(equivPassVulns(t, assets))
	for _, a := range assets {
		dev := set.forDevice(a)
		a.winList = dev
		var back, news, odd []int
		for i, v := range dev {
			if v.DateAdded.Equal(t0.Add(-48 * time.Hour)) {
				news = append(news, i)
			} else {
				back = append(back, i)
			}
			if i%3 == 0 {
				odd = append(odd, i)
			}
		}
		if len(odd) > 1 {
			odd = append(odd, odd[0]) // a CVE twice: the first is read
		}
		dm := newDevMatch(a, dev, t0)
		for _, have := range []map[string]bool{nil, cveSet(dev)} {
			for _, part := range [][]int{back, news, odd} {
				want := MatchAsset(a, pick(dev, part), have, t0)
				if got := dm.result(part, have); !reflect.DeepEqual(got, want) {
					t.Fatalf("%s: the part's match from the whole list's readings differs from MatchAsset of the part", a.ID)
				}
			}
			if got, want := dm.result(nil, have), MatchAsset(a, dev, have, t0); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: the whole match read twice differs", a.ID)
			}
		}
	}
}
