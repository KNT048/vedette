package findings

import (
	"database/sql"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

// A synthetic product the catalogue does not know: Quillfeather Mail 115.9.0. One CVE's NVD range decides the line affected (fixed in
// 115.12.0); the others name the product with no version, so they stay undecided.
const (
	cveAnchor    = "CVE-2026-993001" // decided by NVD's range: the open finding
	cveCovered   = "CVE-2026-993002" // undecided, on no exploited list
	cveKEV       = "CVE-2026-993003" // undecided, on an exploited list
	cveSignalled = "CVE-2026-993004" // undecided, on no list, but an exploitation signal keeps it
	cveLaterFix  = "CVE-2026-993005" // undecided: the record's rows list 115.10.0 up to 115.20.0, which 115.9.0 is outside of
	// undecided: its record is tagged unsupported when assigned, and its row (the ESR edition before 116.0) covers 115.9.0 unless the
	// edition says otherwise, which the box does not know
	cveUnsupported = "CVE-2026-993006"
	// undecided the same way, tagged unsupported, but its row ends before 115.0: it covers older lines, not this one
	cveUnsupportedOlder = "CVE-2026-993007"
)

func quillAt(id, version string) Software {
	return Software{ID: id, Display: "Quillfeather Mail", Vendor: "Quillfeather", Product: "Mail", Version: version, Source: "agent"}
}

// coveredWorld is one or more workstations running Quillfeather Mail 115.9.0, matched against cves (from cveAnchor and the undecided
// ones above), with a checker whose research answers nothing.
func coveredWorld(t *testing.T, devices []string, cves ...string) (*env, *fakeChecker) {
	t.Helper()
	e := newEnv(t)
	e.inv.assets, e.inv.match = map[string]AssetView{}, map[string]Asset{}
	for _, d := range devices {
		e.inv.assets[d] = AssetView{ID: d, Hostname: ptr(d), IP: "192.0.2.10", Kind: "workstation", Approved: true}
		e.inv.match[d] = Asset{ID: d, Name: d, OS: "Microsoft Windows 11 Pro", Software: []Software{quillAt("s-"+d, "115.9.0")}}
	}
	cpe := "cpe:2.3:a:quillfeather:mail:*:*:*:*:*:*:*:*"
	none := "cpe:2.3:a:quillfeather:mail:-:*:*:*:*:*:*:*"
	e.feeds.vulns, e.feeds.unlisted, e.feeds.kept, e.feeds.unsupported = nil, map[string]bool{}, map[string]bool{}, map[string]bool{}
	fc := &fakeChecker{budget: ReadBudget{Auto: true}, pages: map[string][]FetchedPage{}, records: map[string]CVERecordText{}}
	for _, c := range cves {
		v := Vuln{CVE: c, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: none}}}
		switch c {
		case cveAnchor:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{EndExcl: "115.12.0"}}}
		case cveLaterFix:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "115.10.0", EndExcl: "115.20.0"}, AffectedOnly: true}}
		case cveSignalled:
			e.feeds.kept[c] = true
		case cveUnsupported:
			v.Affected = []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:esr:*:*:*", Range: VersionRange{EndExcl: "116.0"}}}
			e.feeds.unsupported[c] = true
		case cveUnsupportedOlder:
			v.Affected = []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:esr:*:*:*", Range: VersionRange{StartIncl: "114.0", EndExcl: "114.9"}},
				{CPE: none}}
			e.feeds.unsupported[c] = true
		}
		if c != cveKEV {
			e.feeds.unlisted[c] = true
		}
		e.feeds.vulns = append(e.feeds.vulns, v)
		fc.records[c] = CVERecordText{Description: "A flaw in Quillfeather Mail.", Rows: []RecordRow{{Vendor: "quillfeather", Product: "mail", Text: "quillfeather mail [nvd]"}}}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.svc.SetChecker(fc)
	return e, fc
}

func findingID(t *testing.T, e *env, device, cve string) string {
	t.Helper()
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, device, cve).Scan(&id); err != nil {
		t.Fatalf("the finding of %s on %s: %v", cve, device, err)
	}
	return id
}

func possibleRows(t *testing.T, e *env) (map[string]PossibleRowJS, PossibleCounts) {
	t.Helper()
	l, err := e.svc.Possible(t.Context(), PossibleFilter{}, Page{Limit: PageMax})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]PossibleRowJS{}
	for _, r := range l.Items {
		out[r.Device.ID+"|"+r.CVE] = r
	}
	return out, l.Counts
}

// A line that already needs an update for a CVE Vedette decided from data: its other undecided CVEs on no exploited list cannot change
// what the customer must do, so they are grouped under that update (deferred), counted apart, and stay undecided. An exploited CVE, by
// a list or by a signal, is never deferred.
func TestDeferred_AnUpdateTheLineNeedsCoversItsOtherUndecidedCVEs(t *testing.T) {
	t.Parallel()
	e, _ := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered, cveKEV, cveSignalled)
	anchor := findingID(t, e, "pc-01", cveAnchor)
	rows, counts := possibleRows(t, e)
	got := rows["pc-01|"+cveCovered]
	if got.Deferred == nil || got.Deferred.Anchor != anchor || got.Deferred.AnchorKind != AnchorFinding || got.Deferred.AnchorCVE != cveAnchor || got.Deferred.Kind != FixUpdate ||
		got.Deferred.Version == nil || *got.Deferred.Version != "115.12.0" || got.Deferred.Raised {
		t.Fatalf("the covered CVE: deferred %+v, want under %s's update to 115.12.0", got.Deferred, anchor)
	}
	if got.State != PossibleOpen || got.Cause == nil || *got.Cause == "" {
		t.Errorf("a deferred row stays undecided with its cause: state %s, cause %v", got.State, got.Cause)
	}
	for _, c := range []string{cveKEV, cveSignalled} {
		if r, ok := rows["pc-01|"+c]; !ok || r.Deferred != nil {
			t.Errorf("%s is exploited: listed %v, deferred %+v, want listed and researched as before", c, ok, r.Deferred)
		}
	}
	if counts.Deferred != 1 || counts.Possible != 2 {
		t.Errorf("counts %+v: want 1 deferred apart from 2 possible", counts)
	}
	sum := 0
	for _, n := range counts.Causes {
		sum += n
	}
	if sum != counts.Possible {
		t.Errorf("causes count %d rows, want the %d possible ones only", sum, counts.Possible)
	}
	// the match passes again: nothing decides the deferred CVE, closes it or proves it not affected
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveCovered + `'`); n != 0 {
		t.Errorf("%d findings of the deferred CVE, want none", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_question WHERE cve = '` + cveCovered + `' AND answer IS NULL`); n != 1 {
		t.Errorf("%d open questions about the deferred CVE, want it still asked", n)
	}
	if rows, _ := possibleRows(t, e); rows["pc-01|"+cveCovered].Deferred == nil {
		t.Error("the row is not deferred after a second pass")
	}
}

// Only an open finding decided by data or a person is an anchor: one the AI's reading opened, one opened through the product the AI
// chose for the line, an accepted one or a handled one is not, and the line's other CVEs are researched as before.
func TestDeferred_OnlyAnOpenFindingDecidedByDataOrAPersonIsAnAnchor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		change   func(t *testing.T, e *env, id string)
		deferred bool
	}{
		{"nvd range", func(*testing.T, *env, string) {}, true},
		{"a person confirmed the AI's proposal", func(t *testing.T, e *env, id string) { setOrigin(t, e, id, RangeAIConfirmed) }, true},
		{"a person said affected", func(t *testing.T, e *env, id string) { setOrigin(t, e, id, RangePerson) }, true},
		{"the AI's reading", func(t *testing.T, e *env, id string) { setOrigin(t, e, id, RangeAIRead) }, false},
		{"the product the AI chose", func(t *testing.T, e *env, id string) {
			execSQL(t, e, `UPDATE fnd_finding SET evidence = json_set(ifnull(evidence, '{}'), '$.identity', json('{"method":"ai"}')) WHERE id = ?`, id)
		}, false},
		{"accepted", func(t *testing.T, e *env, id string) {
			if _, _, err := e.svc.Handle(t.Context(), []string{id}, ResolutionAccepted, "The vendor fix waits for the next window.", dayOf(t0).AddDate(0, 1, 0), "ana@example.com"); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"patched", func(t *testing.T, e *env, id string) {
			if _, _, err := e.svc.HandleConfirmed(t.Context(), []string{id}, ResolutionPatched, "", time.Time{}, "ana@example.com"); err != nil {
				t.Fatal(err)
			}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, _ := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered)
			tc.change(t, e, findingID(t, e, "pc-01", cveAnchor))
			rows, counts := possibleRows(t, e)
			if got := rows["pc-01|"+cveCovered].Deferred != nil; got != tc.deferred {
				t.Errorf("deferred %v, want %v (counts %+v)", got, tc.deferred, counts)
			}
		})
	}
}

func setOrigin(t *testing.T, e *env, id, origin string) {
	t.Helper()
	execSQL(t, e, `UPDATE fnd_finding SET range_origin = ? WHERE id = ?`, origin, id)
}

func execSQL(t *testing.T, e *env, query string, args ...any) {
	t.Helper()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), query, args...); return err }); err != nil {
		t.Fatal(err)
	}
}

// The anchor's fix does not always clear the line's other CVEs: one whose rows list releases from 115.10.0 to before 115.20.0 is
// still there on 115.12.0. The group's target is then the lowest release the data names that is outside every such range (computed,
// never read by the AI), and says it was raised.
func TestDeferred_ALaterFixTheDataStatesRaisesTheTarget(t *testing.T) {
	t.Parallel()
	e, _ := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered, cveLaterFix)
	rows, counts := possibleRows(t, e)
	for _, c := range []string{cveCovered, cveLaterFix} {
		d := rows["pc-01|"+c].Deferred
		if d == nil || d.Version == nil || *d.Version != "115.20.0" || !d.Raised {
			t.Errorf("%s: deferred %+v, want the target raised to 115.20.0", c, d)
		}
	}
	if counts.Deferred != 2 {
		t.Errorf("counts %+v: want 2 deferred", counts)
	}
}

// The research worker leaves a release line only when every device's row of it is deferred: on one device the line already needs an
// update; on the other the same line has no anchor (its finding is accepted), so the line is researched for it. Exploited CVEs are
// researched as always.
func TestResearchWorker_SkipsALineOnlyWhenEveryDeviceRowIsDeferred(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered, cveKEV, cveSignalled)
		stop := startWorker(t, e)
		synctest.Wait()
		stop()
		got := researchedCVEs(fc)
		slices.Sort(got)
		if want := []string{cveKEV, cveSignalled}; !slices.Equal(got, want) {
			t.Fatalf("researched %v, want %v (the covered CVE left)", got, want)
		}
		if run := checkRun(t, e); run.LinesTotal != 2 {
			t.Errorf("lines total %d, want the 2 lines the AI may research", run.LinesTotal)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		e, fc := coveredWorld(t, []string{"pc-01", "pc-02"}, cveAnchor, cveCovered)
		if _, _, err := e.svc.Handle(t.Context(), []string{findingID(t, e, "pc-02", cveAnchor)}, ResolutionAccepted, "The vendor fix waits for the next window.", dayOf(t0).AddDate(0, 1, 0), "ana@example.com"); err != nil {
			t.Fatal(err)
		}
		stop := startWorker(t, e)
		synctest.Wait()
		stop()
		if got := researchedCVEs(fc); !slices.Equal(got, []string{cveCovered}) {
			t.Fatalf("researched %v, want the line researched once for the device without an anchor", got)
		}
	})
}

// A person's "Research deeper" runs on a deferred row: grouping saves the automatic research, never a person's request.
func TestDeferred_ResearchDeeperStillRuns(t *testing.T) {
	t.Parallel()
	e, fc := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered)
	rows, _ := possibleRows(t, e)
	r := rows["pc-01|"+cveCovered]
	if r.Deferred == nil {
		t.Fatal("the row is not deferred")
	}
	u, err := e.svc.deeperUnit(t.Context(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.check.run = &CheckRun{Running: true}
	e.svc.runPossibleCheck(t.Context(), []checkUnit{*u}, "ana@example.com")
	if got := researchedCVEs(fc); !slices.Equal(got, []string{cveCovered}) || !fc.research[0].Deeper {
		t.Errorf("researched %v, want the deferred line researched deeper", got)
	}
}

// When the anchor closes, the rows are ordinary undecided rows again and the worker researches them by itself: after a person's
// "patched" at once, and after the version moved past the fix with the next match.
func TestDeferred_ResearchResumesWhenTheAnchorCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e, fc := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered)
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait()
		if got := researchedCVEs(fc); len(got) != 0 {
			t.Fatalf("researched %v while the line needs its update", got)
		}
		if _, _, err := e.svc.HandleConfirmed(t.Context(), []string{findingID(t, e, "pc-01", cveAnchor)}, ResolutionPatched, "", time.Time{}, "ana@example.com"); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if got := researchedCVEs(fc); !slices.Equal(got, []string{cveCovered}) {
			t.Fatalf("researched %v after the anchor was handled, want the covered CVE at once", got)
		}
		if rows, counts := possibleRows(t, e); rows["pc-01|"+cveCovered].Deferred != nil || counts.Deferred != 0 {
			t.Errorf("still deferred after the anchor closed: %+v", counts)
		}
	})
	synctest.Test(t, func(t *testing.T) {
		e, fc := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered)
		stop := startWorker(t, e)
		defer stop()
		synctest.Wait()
		e.inv.match["pc-01"] = Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{quillAt("s-pc-01", "115.12.0")}}
		if _, err := e.svc.OnMatchChanged(t.Context(), "pc-01"); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveAnchor + `' AND state = 'open'`); n != 0 {
			t.Fatalf("the anchor is still open after the update")
		}
		if got := researchedCVEs(fc); !slices.Equal(got, []string{cveCovered}) {
			t.Fatalf("researched %v after the update, want the covered CVE", got)
		}
	})
}

// A release line the CVE record states unsupported by its vendor is an anchor too, with no finding: the record of one of the line's
// undecided CVEs is tagged unsupported when assigned, and its row covers the installed release (it might be the edition the row
// names). The action for the line is then "move to a supported release": the line's other undecided CVEs on no exploited list are
// grouped under that statement; the tagged CVE itself stays an ordinary row (it is the reason; an edition only the device or a person
// states decides it), an exploited CVE is researched, and nothing is closed. A tagged record whose rows cover other lines only is no anchor for this one.
func TestDeferred_ALineTheRecordStatesUnsupportedIsAnAnchor(t *testing.T) {
	t.Parallel()
	e, fc := coveredWorld(t, []string{"pc-01"}, cveUnsupported, cveCovered, cveKEV)
	if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 0 {
		t.Fatalf("%d findings, want none: every CVE of the line is undecided", n)
	}
	rows, counts := possibleRows(t, e)
	tagged := rows["pc-01|"+cveUnsupported]
	got := rows["pc-01|"+cveCovered].Deferred
	if got == nil || got.AnchorKind != AnchorUnsupported || got.Anchor != tagged.ID || got.AnchorCVE != cveUnsupported ||
		got.Kind != FixFeatureUpdate || got.Version != nil || got.FixKey != nil {
		t.Fatalf("the covered CVE: deferred %+v, want under the record's statement that the line is unsupported", got)
	}
	if tagged.Deferred != nil || rows["pc-01|"+cveKEV].Deferred != nil {
		t.Errorf("the tagged CVE (%+v) and the exploited one (%+v) are not deferred", tagged.Deferred, rows["pc-01|"+cveKEV].Deferred)
	}
	if counts.Deferred != 1 || counts.Possible != 2 {
		t.Errorf("counts %+v: want 1 deferred, 2 possible", counts)
	}
	runCheck(t, e)
	if got := researchedCVEs(fc); slices.Contains(got, cveCovered) || !slices.Contains(got, cveKEV) {
		t.Errorf("researched %v, want the exploited CVE, not the covered one", got)
	}

	other, _ := coveredWorld(t, []string{"pc-01"}, cveUnsupportedOlder, cveCovered)
	if rows, _ := possibleRows(t, other); rows["pc-01|"+cveCovered].Deferred != nil {
		t.Errorf("a record tagged unsupported for older lines only defers %+v", rows["pc-01|"+cveCovered].Deferred)
	}
}
