package agentintake_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// On the wire, a test box's DESKTOP-55UKKFV: one programs snapshot with SQL Server 2022's own Uninstall entry (no DisplayVersion),
// its 13 components at 16.0.1000.6 and other programs. Before, the inventory got "Microsoft SQL Server 2022 (64-bit)" with no version
// and findings asked a person for it. Now the release's row has a version: the components' build from an agent without the setup
// value, and the instance's PatchLevel (a cumulative update's build) from the setup-registry programs query, which the next snapshot brings.
func TestContract_SQLServerVersionFromTheMachine(t *testing.T) {
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
	type sqlRow struct{ display, version string }
	// read through inventory's own API, never its tables (inventory FORBID-4)
	agentRows := func() []inventory.MatchSoftware {
		t.Helper()
		d, ok := w.device(peerA)
		if !ok {
			t.Fatal("no device")
		}
		in, _, err := w.inv.MatchInput(t.Context(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		var out []inventory.MatchSoftware
		for _, s := range in.Software {
			if s.Source == "agent" {
				out = append(out, s)
			}
		}
		return out
	}
	rows := func() []sqlRow {
		t.Helper()
		var out []sqlRow
		for _, s := range agentRows() {
			if slices.Contains(s.KevKeys, "microsoft|sql server") {
				out = append(out, sqlRow{s.Display, s.Version})
			}
		}
		return out
	}
	count := func(keep func(inventory.MatchSoftware) bool) int {
		t.Helper()
		n := 0
		for _, s := range agentRows() {
			if keep(s) {
				n++
			}
		}
		return n
	}

	// an agent whose config predates the setup-registry query: the components give the build (the RsFx Driver stated the same one)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", list...)))
	if got := rows(); len(got) != 1 || got[0].version != rtm {
		t.Fatalf("components: %+v", got)
	}
	if n := count(func(s inventory.MatchSoftware) bool { return s.Version == "" }); n != 0 {
		t.Fatalf("%d agent rows without a version", n)
	}

	// the setup-registry programs query, after a cumulative update: the setup value comes first in the same snapshot (here from a node
	// still on the config whose query named the key's column sql_setup)
	setup := map[string]string{"name": "", "version": "16.0.4135.4", "publisher": "", "install_date": "",
		"sql_setup": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Setup`}
	w.clock.Advance(6 * time.Minute) // past the source's list window
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", append([]map[string]string{setup}, list...)...)))
	if got := rows(); len(got) != 1 || got[0] != (sqlRow{"Microsoft SQL Server 2022 (64-bit)", "16.0.4135.4"}) {
		t.Fatalf("setup registry: %+v", got)
	}
	if n := count(func(s inventory.MatchSoftware) bool {
		return strings.HasPrefix(s.Display, "HKEY") || strings.HasPrefix(s.Version, "HKEY") || s.Display == ""
	}); n != 0 {
		t.Fatalf("the setup value became %d software rows", n)
	}
	if n := count(func(inventory.MatchSoftware) bool { return true }); n != len(list) {
		t.Fatalf("%d agent rows for %d programs", n, len(list))
	}

	// this config's query: the key's column is reg_key
	setup = map[string]string{"name": "", "version": "16.0.4155.4", "publisher": "", "install_date": "",
		"reg_key": `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Setup`}
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", append([]map[string]string{setup}, list...)...)))
	if got := rows(); len(got) != 1 || got[0] != (sqlRow{"Microsoft SQL Server 2022 (64-bit)", "16.0.4155.4"}) {
		t.Fatalf("setup registry (reg_key): %+v", got)
	}
}
