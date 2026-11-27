package inventory

import (
	"database/sql"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// A program that reports its version with a token beside the release (a word before it, a tag's "v", its build in parentheses) is
// stored at the release it states, so every reader compares that release; the source's own text stays in the reading's item. Its
// train is the release's. A version with no such token, or one whose rest is not a release, is stored as given.
func TestReportedVersion_StoredAsTheReleaseItStates(t *testing.T) {
	t.Parallel()
	b := newBoxStart(t)
	svc := b.start(false)
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.30")}
	sightedBy(t.Context(), t, svc, hint, observe.Osquery)
	items := []observe.Software{
		{Display: "Orbit Viewer", Vendor: "Example Labs", Product: "Orbit Viewer", Version: "4.2.9 (31207)", Confidence: 0.9},
		{Display: "Quill Desk", Vendor: "Example Labs", Product: "Quill Desk", Version: "qd 5.4.2", Confidence: 0.9},
		{Display: "Lumen Agent v2.3.1", Vendor: "Example Labs", Product: "Lumen Agent v2.3.1", Version: "v2.3.1", Confidence: 0.9},
		{Display: "Ember Notes", Vendor: "Example Labs", Product: "Ember Notes", Version: "beta 2.0.1", Confidence: 0.9},
		{Display: "Node.js", Vendor: "Node.js", Product: "Node.js", Version: "v20.11.1", Confidence: 0.9},
	}
	if err := svc.ReplaceSoftware(t.Context(), hint, observe.Osquery, nil, items); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Orbit Viewer":       "4.2.9|4.2.9 (31207)|",
		"Quill Desk":         "5.4.2|qd 5.4.2|",
		"Lumen Agent v2.3.1": "2.3.1|v2.3.1|",
		"Ember Notes":        "beta 2.0.1|beta 2.0.1|", // a word that qualifies the number is kept: nothing is guessed
		"Node.js":            "20.11.1|v20.11.1|20",    // the train of the release
	}
	check := func(when string) {
		t.Helper()
		rows, err := b.db.Reader().QueryContext(t.Context(), `SELECT s.display, ifnull(s.version, ''), ifnull(r.item_version, ''), s.line
			FROM inv_software s JOIN inv_software_reading r ON r.software_id = s.id`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		got := map[string]string{}
		for rows.Next() {
			var display, version, item, line string
			if err := rows.Scan(&display, &version, &item, &line); err != nil {
				t.Fatal(err)
			}
			got[display] = version + "|" + item + "|" + line
		}
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s: %s stored %q, want %q (version|the source's text|train)", when, k, got[k], w)
			}
		}
	}
	check("read")

	// A line an earlier build stored with the source's text is read again at the next start of this build (the catalogue pass).
	if err := b.db.Write(t.Context(), func(tx *sql.Tx) error {
		for _, q := range []string{
			`UPDATE inv_software_reading SET version = item_version`,
			`UPDATE inv_software SET version = (SELECT r.version FROM inv_software_reading r WHERE r.software_id = inv_software.id)`,
			`UPDATE inv_software SET line = '' WHERE product_key = 'node.js|node.js'`,
			`UPDATE inv_catalogue_pass SET revision = 'older-catalogue'`,
		} {
			if _, err := tx.ExecContext(t.Context(), q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n := b.count(`SELECT count(*) FROM inv_software WHERE version = '4.2.9 (31207)'`); n != 1 {
		t.Fatalf("the earlier build's line is not set up: %d", n)
	}
	b.start(false)
	check("after the catalogue pass")
	b.checks()
}
