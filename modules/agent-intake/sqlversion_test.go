package agentintake_test

import (
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
	rows := func() []sqlRow {
		t.Helper()
		q, err := w.db.Reader().QueryContext(t.Context(), `SELECT display, ifnull(version, ''), confidence FROM inv_software s JOIN inv_software_kev k ON k.software_id = s.id
			WHERE k.kev_key = 'microsoft|sql server' AND s.source = 'agent' ORDER BY display`)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = q.Close() }()
		var out []sqlRow
		for q.Next() {
			var r sqlRow
			if err := q.Scan(&r.display, &r.version, &r.confidence); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		if err := q.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// an agent whose config predates D-606: the components give the build (the RsFx Driver stated the same one)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), snap("programs", list...)))
	if got := rows(); len(got) != 1 || got[0].version != rtm {
		t.Fatalf("components: %+v", got)
	}
	if n := w.count(`SELECT count(*) FROM inv_software WHERE source = 'agent' AND version IS NULL`); n != 0 {
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
	if n := w.count(`SELECT count(*) FROM inv_software WHERE display LIKE 'HKEY%' OR version LIKE 'HKEY%' OR display = ''`); n != 0 {
		t.Fatalf("the setup value became %d software rows", n)
	}
	if n := w.count(`SELECT count(*) FROM inv_software WHERE source = 'agent'`); n != len(list) {
		t.Fatalf("%d agent rows for %d programs", n, len(list))
	}
}
