package findings

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// anonFixture is testdata/anon-findings-before.json: the findings of an anonymised test network in the older model (one row per
// device and CVE, with a status) and the software lines they name.
type anonFixture struct {
	Findings []struct {
		AssetID          string  `json:"asset_id"`
		CVE              string  `json:"cve"`
		SoftwareID       *string `json:"software_id"`
		Status           string  `json:"status"`
		Basis            string  `json:"basis"`
		ResolutionReason *string `json:"resolution_reason"`
		ProvedVersion    *string `json:"proved_version"`
		FirstSeen        string  `json:"first_seen"`
		ResolvedAt       *string `json:"resolved_at"`
	} `json:"findings"`
	Software []struct {
		ID, AssetID, Vendor, Product, Source string
		Version                              *string `json:"version"`
	} `json:"software"`
}

// The count test of the model on the export of a test network: findings rows per (device, CVE) in the older model (the export as it
// is) and after its findings go through Transition into fnd_finding. The older model holds one row per (device, CVE), whatever the
// software line, and a row for every pair it matched by product name only and closed as checked; the new one holds a row per
// (device, CVE, software line) that was affected at some time, and every row passes the data invariants (selfcheck).
func TestFixture_RowsPerDeviceCVEAndLine(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/anon-findings-before.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx anonFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{} // software id → source
	for _, s := range fx.Software {
		lines[s.ID] = s.Source
	}
	type stats struct{ rows, pairs, maxPerPair, nameOnly int }
	count := func(keys []string) (pairs, max int) {
		per := map[string]int{}
		for _, k := range keys {
			per[k]++
		}
		for _, n := range per {
			if n > max {
				max = n
			}
		}
		return len(per), max
	}
	var before stats
	var pairsBefore []string
	for _, x := range fx.Findings {
		pairsBefore = append(pairsBefore, x.AssetID+"|"+x.CVE)
		if x.Basis == string(BasisProduct) {
			before.nameOnly++
		}
	}
	before.rows = len(fx.Findings)
	before.pairs, before.maxPerPair = count(pairsBefore)

	e := newEnv(t)
	ts := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		for i, x := range fx.Findings {
			if x.Basis == string(BasisProduct) {
				continue // matched by the product name only: never affected with version evidence, so no row (a question when one is needed)
			}
			f := Finding{ID: fmt.Sprintf("f-%04d", i), AssetID: x.AssetID, CVE: x.CVE}
			d := Detection{Basis: DetectBannerVersion, Verified: VerifiedNo, Urgency: 2}
			if x.SoftwareID != nil {
				if src, ok := lines[*x.SoftwareID]; ok { // a line the inventory has; else the network OS a device states, which has none
					f.SoftwareID, d.SoftwareID = *x.SoftwareID, *x.SoftwareID
					if src == "agent" || src == SourceSNMP {
						d.Basis = DetectDeviceVersion
					}
				}
			}
			if x.Status == string(StatusConfirmed) && x.Basis == string(BasisVersion) {
				d.Basis, d.Verified = DetectDeviceVersion, VerifiedDevice
			}
			at := ts(x.FirstSeen)
			g, _, err := apply(t.Context(), tx, f, true, Trigger{Kind: TrDetected, At: at, Detection: d})
			if err != nil {
				return err
			}
			if x.Basis == string(BasisPerson) {
				if g, _, err = apply(t.Context(), tx, g, false, Trigger{Kind: TrVerify, At: at, Actor: "person@example.com", Note: "confirmed on the device"}); err != nil {
					return err
				}
			}
			if x.ResolvedAt == nil || x.Status == string(StatusConfirmed) {
				continue
			}
			via := ViaDataCorrected // no longer detected while nothing on the device changed
			if p := x.ProvedVersion; p != nil && strings.ContainsAny(*p, "-_") {
				via = ViaDistroFixed // the distribution's package release the device has is a fixed one
			}
			if _, _, err := apply(t.Context(), tx, g, false, Trigger{Kind: TrGone, At: ts(*x.ResolvedAt), Via: via}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fs, err := e.svc.Findings(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	var pairsAfter, linesAfter []string
	byState := map[string]int{}
	for _, f := range fs {
		pairsAfter = append(pairsAfter, f.AssetID+"|"+f.CVE)
		linesAfter = append(linesAfter, f.AssetID+"|"+f.CVE+"|"+f.SoftwareID)
		k := string(f.State)
		if f.State == StateHandled {
			k += " " + string(f.Resolution) + " via " + string(f.Via)
		}
		byState[k]++
	}
	pairs, maxPair := count(pairsAfter)
	_, maxLine := count(linesAfter)
	t.Logf("before: %d rows, %d (device, CVE) pairs, at most %d row per pair, %d rows matched by the product name only", before.rows, before.pairs, before.maxPerPair, before.nameOnly)
	t.Logf("after:  %d rows, %d (device, CVE) pairs, at most %d rows per pair, at most %d per (device, CVE, line); %v", len(fs), pairs, maxPair, maxLine, byState)
	if before.rows != 278 || before.pairs != 278 || before.maxPerPair != 1 || before.nameOnly != 254 {
		t.Fatalf("the export changed: %+v", before)
	}
	if len(fs) != before.rows-before.nameOnly || maxLine != 1 {
		t.Fatalf("after: %d rows, at most %d per line", len(fs), maxLine)
	}
	for _, inv := range invariants {
		var n int
		if err := e.db.Reader().QueryRowContext(t.Context(), inv.Query).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d rows break it (%v)", inv.Name, n, err)
		}
	}
}
