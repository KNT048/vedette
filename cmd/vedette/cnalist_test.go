package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/inventory"
)

// A record's "unaffected" for the versions it does not list closes a CVE only when the vendor's own CNA wrote it, end to end on the
// binary's wiring. The CNA "qwz" of "Quasar Widgets Corp" is the vendor of "Quasar Widgets" only by the CVE Program's CNA list: until
// the list arrives its record decides nothing for a version it does not list (a question). The list's pull announces the change and
// wakes findings' match pass, which then decides the version not affected. A researcher CNA, and a CNA whose scope takes other CNAs'
// reports even under the vendor's own organization name, never close anything, list or not.
func TestCNAList_ArrivingLaterDecidesOnlyTheVendorsOwnRecord(t *testing.T) {
	t.Parallel()
	var woke []string
	s := newStackWith(t, func(d *deps) { d.Wake = func(module, job string) { woke = append(woke, module+"/"+job) } })
	ctx := t.Context()
	list := []map[string]any{
		{"shortName": "qwz", "organizationName": "Quasar Widgets Corp", "scope": "Quasar Widgets products only.", "CNA": map[string]any{"type": []string{"Vendor"}}},
		{"shortName": "labx", "organizationName": "Labx Security Research", "scope": "Vulnerabilities discovered by Labx.", "CNA": map[string]any{"type": []string{"Researcher"}}},
		{"shortName": "orbitcna", "organizationName": "Orbit Gadgets Inc.", "scope": "Orbit products, and vulnerabilities discovered by Orbit that are not in another CNA's scope.",
			"CNA": map[string]any{"type": []string{"Vendor", "Researcher"}}},
	}
	body, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)

	entry := func(vendor, product string) string {
		return `{"vendor":"` + vendor + `","product":"` + product + `","defaultStatus":"unaffected","versions":[{"version":"5.0.0","lessThan":"5.0.3","status":"affected","versionType":"semver"}]}`
	}
	cases := []struct{ cve, assigner, vendor, product, want string }{ // want: the device's answer once the list is read
		{"CVE-2026-70301", "qwz", "Quasar Widgets", "Beacon", "none"},
		{"CVE-2026-70302", "labx", "Quasar Widgets", "Lantern", "question"},
		{"CVE-2026-70303", "orbitcna", "Orbit Gadgets", "Relay", "question"},
	}
	devices := map[string]string{}
	err = s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		for _, c := range cases {
			raw := []byte(`{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"` + c.cve + `","state":"PUBLISHED","assignerShortName":"` +
				c.assigner + `"},"containers":{"cna":{"affected":[` + entry(c.vendor, c.product) + `]}}}`)
			rec, err := feeds.ParseCVERecord(raw, c.cve)
			if err != nil {
				return err
			}
			if err := seedNVD(ctx, tx, c.cve, time.Now().AddDate(0, -1, 0), 7.5); err != nil {
				return err
			}
			if err := storeRecordRanges(ctx, tx, c.cve, rec.Assigner, rec.Ranges); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		r, err := s.d.Inventory.AddDevice(ctx, "it@acme.example", inventory.AddInput{Vendor: c.vendor, Product: c.product, Version: "4.2.0", Name: c.product,
			IP: "192.0.2." + string(rune('1'+i))})
		if err != nil {
			t.Fatal(err)
		}
		devices[c.cve] = r.ID
	}
	answers := func() map[string]string {
		t.Helper()
		if _, err := s.d.Findings.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, c := range cases {
			got := "none"
			switch {
			case slices.Contains(openFindings(t, s, devices[c.cve]), c.cve):
				got = "open"
			case s.count(`SELECT count(*) FROM fnd_question WHERE asset_id = ? AND cve = ? AND answer IS NULL`, devices[c.cve], c.cve) > 0:
				got = "question"
			}
			out[c.cve] = got
		}
		return out
	}
	for cve, got := range answers() {
		if got != "question" {
			t.Errorf("before the CNA list: %s %s, want question (no record's unlisted versions are decided)", cve, got)
		}
	}

	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.d.DB.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE feeds_source SET url = ?, enabled = 1, rev = rev + 1 WHERE id = 'cve-cna-list'`, srv.URL+"/CNAsList.json")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	woke = nil
	if err := fs.Fetch(ctx, "cve-cna-list"); err != nil {
		t.Fatal(err)
	}
	if s.count(`SELECT count(*) FROM feeds_cna`) != 3 {
		t.Fatalf("CNAs stored: %d", s.count(`SELECT count(*) FROM feeds_cna`))
	}
	if !slices.Contains(woke, "findings/reconcile") {
		t.Fatalf("the CNA list's arrival woke %v, want findings' match pass", woke)
	}
	for _, c := range cases {
		if got := answers()[c.cve]; got != c.want {
			t.Errorf("with the CNA list: %s (%s, %s) %s, want %s", c.cve, c.assigner, c.vendor, got, c.want)
		}
	}
}
