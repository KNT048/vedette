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
	// undecided: the record's rows list 115.10.0 up to and including 115.15.0, past the anchor's fix
	cveThroughTarget = "CVE-2026-993008"
	// undecided: the record's rows list 115.10.0 and every later release
	cveNoEnd = "CVE-2026-993009"
	// undecided: the record lists the one release 115.14.0 of the line, above the anchor's fix
	cveListedAbove = "CVE-2026-993010"
	// undecided: NVD's row names the product with no version bound, every version (the matcher does not decide on it alone)
	cveEveryVersion = "CVE-2026-993011"
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
	e.feeds.vulns, e.feeds.unlisted, e.feeds.signalled, e.feeds.unsupported = nil, map[string]bool{}, map[string]bool{}, map[string]bool{}
	fc := &fakeChecker{budget: ReadBudget{Auto: true}, pages: map[string][]FetchedPage{}, records: map[string]CVERecordText{}}
	for _, c := range cves {
		v := Vuln{CVE: c, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: none}}}
		switch c {
		case cveAnchor:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{EndExcl: "115.12.0"}}}
		case cveLaterFix:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "115.10.0", EndExcl: "115.20.0"}, AffectedOnly: true}}
		case cveSignalled:
			e.feeds.signalled[c] = true
		case cveUnsupported:
			v.Affected = []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:esr:*:*:*", Range: VersionRange{EndExcl: "116.0"}}}
			e.feeds.unsupported[c] = true
		case cveThroughTarget:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "115.10.0", EndIncl: "115.15.0"}, AffectedOnly: true}}
		case cveNoEnd:
			v.Affected = []Affected{{CPE: cpe, Range: VersionRange{StartIncl: "115.10.0"}, AffectedOnly: true}}
		case cveEveryVersion:
			v.Affected = []Affected{{CPE: cpe}}
		case cveListedAbove:
			v.Affected = []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:115.14.0:*:*:*:*:*:*:*"}}
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

// anchorID is the id of the open finding of cveAnchor on device.
func anchorID(t *testing.T, e *env, device string) string {
	t.Helper()
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = ? AND cve = ?`, device, cveAnchor).Scan(&id); err != nil {
		t.Fatalf("the finding of %s on %s: %v", cveAnchor, device, err)
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
	anchor := anchorID(t, e, "pc-01")
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
			tc.change(t, e, anchorID(t, e, "pc-01"))
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
		if _, _, err := e.svc.Handle(t.Context(), []string{anchorID(t, e, "pc-02")}, ResolutionAccepted, "The vendor fix waits for the next window.", dayOf(t0).AddDate(0, 1, 0), "ana@example.com"); err != nil {
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
		if _, _, err := e.svc.HandleConfirmed(t.Context(), []string{anchorID(t, e, "pc-01")}, ResolutionPatched, "", time.Time{}, "ana@example.com"); err != nil {
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

// A release line the CVE record states unsupported by its vendor anchors the line only when the box matches the record's statement to
// the installed product, edition and line strictly. A tagged record whose row names an edition the box does not know (it might be
// another edition's statement), or whose rows cover other lines only, anchors nothing: the line's CVEs are researched as before.
func TestDeferred_ARecordTaggedUnsupportedAnchorsOnlyALineItMatchesStrictly(t *testing.T) {
	t.Parallel()
	for _, tagged := range []string{cveUnsupported, cveUnsupportedOlder} {
		e, fc := coveredWorld(t, []string{"pc-01"}, tagged, cveCovered)
		if n := e.count(`SELECT count(*) FROM fnd_finding`); n != 0 {
			t.Fatalf("%s: %d findings, want none: every CVE of the line is undecided", tagged, n)
		}
		rows, counts := possibleRows(t, e)
		if d := rows["pc-01|"+cveCovered].Deferred; d != nil || counts.Deferred != 0 {
			t.Errorf("%s: the covered CVE is deferred under %+v, want no anchor", tagged, d)
		}
		runCheck(t, e)
		if got := researchedCVEs(fc); !slices.Contains(got, cveCovered) {
			t.Errorf("%s: researched %v, want the covered CVE researched", tagged, got)
		}
	}
	// what covers strictly: a row of the product with no edition pinned whose range holds the installed release; not a row of an
	// edition the box does not know, and not an exact release of a product whose release lines the catalogue does not name
	sw := quillAt("s-pc-01", "115.9.0")
	a := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{sw}}
	for _, tc := range []struct {
		name string
		row  Affected
		want bool
	}{
		{"the product's range holds the release", Affected{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "115.0", EndExcl: "116.0"}}, true},
		{"an edition the box does not know", Affected{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:esr:*:*:*", Range: VersionRange{EndExcl: "116.0"}}, false},
		{"an exact release, the line unknown", Affected{CPE: "cpe:2.3:a:quillfeather:mail:115.2.0:*:*:*:*:*:*:*"}, false},
		{"no version", Affected{CPE: "cpe:2.3:a:quillfeather:mail:-:*:*:*:*:*:*:*"}, false},
	} {
		v := Vuln{CVE: cveUnsupported, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{tc.row}}
		if got := lineCovered(a, sw, v); got != tc.want {
			t.Errorf("%s: covered %v, want %v", tc.name, got, tc.want)
		}
	}
	// a line the record reaches only through the product the AI chose for it: the AI never states a line unsupported
	chosen := Software{ID: "s-pc-01", Display: "QF Mailer", Vendor: "QF Labs", Product: "Mailer", Version: "115.9.0", Source: "agent",
		AIProduct: &AIProduct{Vendor: "quillfeather", Product: "mail"}}
	byAI := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{chosen}}
	v := Vuln{CVE: cveUnsupported, NVDAnswered: true, Origin: RangeNVD, Affected: []Affected{{CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:*:*:*:*",
		Range: VersionRange{StartIncl: "115.0", EndExcl: "116.0"}}}}
	if lineCovered(byAI, chosen, v) {
		t.Error("a row reached only through the AI's choice of product covers the line, want it not to")
	}
}

// The group never says an update covers a CVE it does not: a CVE whose stated range on the line still holds the target (an inclusive
// end at or past it, a range with no end, every version, an exact release of the line at or above it) is not deferred; it stays an ordinary
// undecided row and is researched. A CVE with no stated range for the line is still grouped.
func TestDeferred_ACVETheTargetDoesNotLeaveIsNotGrouped(t *testing.T) {
	t.Parallel()
	e, fc := coveredWorld(t, []string{"pc-01"}, cveAnchor, cveCovered, cveThroughTarget, cveNoEnd, cveListedAbove, cveEveryVersion)
	rows, counts := possibleRows(t, e)
	if d := rows["pc-01|"+cveCovered].Deferred; d == nil || d.Version == nil || *d.Version != "115.12.0" || d.Raised {
		t.Fatalf("the CVE with no stated range: deferred %+v, want under the update to 115.12.0", d)
	}
	for _, c := range []string{cveThroughTarget, cveNoEnd, cveListedAbove, cveEveryVersion} {
		r, ok := rows["pc-01|"+c]
		if !ok || r.Deferred != nil {
			t.Errorf("%s: listed %v, deferred %+v, want an ordinary undecided row", c, ok, r.Deferred)
		}
	}
	if counts.Deferred != 1 || counts.Possible != 4 {
		t.Errorf("counts %+v: want 1 deferred, 4 possible", counts)
	}
	runCheck(t, e)
	got := researchedCVEs(fc)
	slices.Sort(got)
	if want := []string{cveThroughTarget, cveNoEnd, cveListedAbove, cveEveryVersion}; !slices.Equal(got, want) {
		t.Errorf("researched %v, want %v", got, want)
	}
}
