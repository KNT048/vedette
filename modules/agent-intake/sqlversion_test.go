package agentintake_test

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// D-606 on the wire, N100's DESKTOP-55UKKFV: one programs snapshot with SQL Server 2022's own Uninstall entry (no DisplayVersion),
// its 13 components at 16.0.1000.6 and other programs. Before, the inventory got "Microsoft SQL Server 2022 (64-bit)" with no version
// and findings asked a person for it. Now the release's row has a version: the components' build from an agent without the setup
// value, and the instance's PatchLevel (a cumulative update's build) from the programs query of D-606, which the next snapshot brings.
func TestContract_D606_SQLServerVersionFromTheMachine(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("pc", 7)
	key := w.enroll(secret, "DESKTOP-55UKKFV", peerA)
	prog := func(name, version string) map[string]string {
		return map[string]string{"name": name, "version": version, "publisher": "Microsoft Corporation", "install_date": "20261012", "sql_setup": ""}
	}
	const rtm = "16.0.1000.6"
	list := []map[string]string{
		prog("7-Zip 24.08 (x64)", "24.08"),
		prog("Microsoft SQL Server 2022 (64-bit)", ""),
		prog("Browser for SQL Server 2022", rtm),
		prog("Microsoft SQL Server 2022 RsFx Driver", rtm),
		prog("Microsoft VSS Writer for SQL Server 2022", rtm),
		prog("SQL Server 2022 Batch Parser", rtm),
		prog("SQL Server 2022 Common Files", rtm),
		prog("SQL Server 2022 Connection Info", rtm),
		prog("SQL Server 2022 DMF", rtm),
		prog("SQL Server 2022 Database Engine Services", rtm),
		prog("SQL Server 2022 Database Engine Shared", rtm),
		prog("SQL Server 2022 SQL Diagnostics", rtm),
		prog("SQL Server 2022 Shared Management Objects", rtm),
		prog("SQL Server 2022 Shared Management Objects Extensions", rtm),
		prog("SQL Server 2022 XEvent", rtm),
		prog("SQL Server Management Studio 21", "21.6.17"),
	}
	type sqlRow struct {
		display, version string
		confidence       float64
	}
	// agent is the device's software rows the agent reported, read through inventory's own reads (INV-2: no SQL on inv_* outside
	// inventory): the device detail for display, version and confidence, MatchInput for the KEV keys of each row.
	type agentRow struct {
		sqlRow
		keys []string
	}
	agent := func() []agentRow {
		t.Helper()
		d, ok := w.device(peerA)
		if !ok {
			t.Fatal("no device")
		}
		det, err := w.inv.Detail(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		in, _, err := w.inv.MatchInput(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		keys := map[string][]string{}
		for _, s := range in.Software {
			keys[s.ID] = s.KevKeys
		}
		var out []agentRow
		for _, s := range det.Asset.Software {
			if s.Source != "agent" {
				continue
			}
			r := agentRow{sqlRow: sqlRow{display: s.Display, confidence: s.Confidence}, keys: keys[s.ID]}
			if s.Version != nil {
				r.version = *s.Version
			}
			out = append(out, r)
		}
		return out
	}
	rows := func() []sqlRow { // the rows keyed to SQL Server
		t.Helper()
		var out []sqlRow
		for _, r := range agent() {
			if slices.Contains(r.keys, "microsoft|sql server") {
				out = append(out, r.sqlRow)
			}
		}
		slices.SortFunc(out, func(a, b sqlRow) int { return strings.Compare(a.display, b.display) })
		return out
	}
	without := func(bad func(agentRow) bool) int {
		t.Helper()
		n := 0
		for _, r := range agent() {
			if bad(r) {
				n++
			}
		}
		return n
	}

	// an agent whose config predates D-606: the components give the build (the RsFx Driver stated the same one)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", list...)))
	if got := rows(); len(got) != 1 || got[0].version != rtm {
		t.Fatalf("components: %+v", got)
	}
	if n := without(func(r agentRow) bool { return r.version == "" }); n != 0 {
		t.Fatalf("%d agent rows without a version", n)
	}

	// the programs query of D-606, after a cumulative update: the setup value comes first in the same snapshot
	setup := map[string]string{"name": "", "version": "16.0.4135.4", "publisher": "", "install_date": "",
		"sql_setup": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Setup`}
	w.clock.Advance(6 * time.Minute) // past the source's list window
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", append([]map[string]string{setup}, list...)...)))
	if got := rows(); len(got) != 1 || got[0] != (sqlRow{"Microsoft SQL Server 2022 (64-bit)", "16.0.4135.4", 0.95}) {
		t.Fatalf("setup registry: %+v", got)
	}
	if n := without(func(r agentRow) bool {
		return strings.HasPrefix(r.display, "HKEY") || strings.HasPrefix(r.version, "HKEY") || r.display == ""
	}); n != 0 {
		t.Fatalf("the setup value became %d software rows", n)
	}
	if n := len(agent()); n != len(list) {
		t.Fatalf("%d agent rows for %d programs", n, len(list))
	}
}
