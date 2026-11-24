package inventory_test

import (
	"database/sql"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// lineCase drives the software sources of one device.
type lineCase struct {
	t    *testing.T
	e    *env
	hint observe.AssetHint
}

func newLineCase(t *testing.T) *lineCase {
	t.Helper()
	return &lineCase{t: t, e: newEnv(t), hint: observe.AssetHint{IP: netip.MustParseAddr("192.0.2.70")}}
}

func (c *lineCase) send(src observe.Source, scope []string, items ...observe.Software) {
	c.t.Helper()
	c.e.tick(time.Minute)
	if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, src, scope, items); err != nil {
		c.t.Fatal(err)
	}
}

func (c *lineCase) dev() string { return deviceAt(c.t, c.e, c.hint.IP) }

func ssh(version, instance string) observe.Software {
	return observe.Software{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, Instance: instance, Confidence: 0.9}
}

// line is the device's one line of a product as the device page reads it.
func (c *lineCase) line(product string) inventory.SoftwareLine {
	c.t.Helper()
	l, err := c.e.svc.SoftwareLines(c.e.ctx(), c.dev())
	if err != nil {
		c.t.Fatal(err)
	}
	var out []inventory.SoftwareLine
	for _, s := range l {
		if s.Product == product {
			out = append(out, s)
		}
	}
	if len(out) != 1 {
		c.t.Fatalf("%d lines of %s: %+v", len(out), product, l)
	}
	return out[0]
}

// ver is a line's version, "" when none.
func ver(l inventory.SoftwareLine) string {
	if l.Version == nil {
		return ""
	}
	return *l.Version
}

func (c *lineCase) history(id string) []string {
	c.t.Helper()
	rows, err := c.e.db.Reader().QueryContext(c.e.ctx(), `SELECT kind FROM inv_software_event WHERE software_id = ? ORDER BY id`, id)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			c.t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

// Each agent replaces only its own list; the two rank as one class, and the newer release is the line.
func TestSoftwareLines_AgentSourcesAreApart(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Osquery, nil, ssh("9.6p1", ""))
	c.send(observe.Wazuh, nil, ssh("10.2p1", ""))
	l := c.line("OpenSSH")
	if ver(l) != "10.2p1" || l.Source != "agent" || len(l.AlsoSeen) != 1 || l.AlsoSeen[0].Version != "9.6p1" || !l.Differs {
		t.Fatalf("line %+v", l)
	}
	c.send(observe.Wazuh, nil) // Wazuh's empty list removes only what Wazuh read
	if l2 := c.line("OpenSSH"); l2.ID != l.ID || ver(l2) != "9.6p1" || len(l2.AlsoSeen) != 0 {
		t.Fatalf("after Wazuh's empty list: %+v", l2)
	}
	if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, observe.Agent, nil, []observe.Software{ssh("1", "")}); err == nil {
		t.Fatal("a list from the agent class must name its agent")
	}
}

// A list with a scope replaces only the instances it covers: a scan of port 80 leaves what the scan read on port 22.
func TestSoftwareLines_PartialReplacementByScope(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	nginx := func(v string) observe.Software {
		return observe.Software{Display: "nginx", Vendor: "F5", Product: "nginx", Version: v, Instance: "tcp/80", Confidence: 0.8}
	}
	c.send(observe.Nmap, nil, ssh("9.6p1", "tcp/22"), nginx("1.24.0"))
	c.send(observe.Nmap, []string{"tcp/80"}, nginx("1.26.1"))
	if l := c.line("OpenSSH"); ver(l) != "9.6p1" {
		t.Fatalf("port 22 must stay: %+v", l)
	}
	if l := c.line("nginx"); ver(l) != "1.26.1" {
		t.Fatalf("port 80 must move: %+v", l)
	}
	c.send(observe.Nmap, []string{"tcp/80"})
	if l := c.line("OpenSSH"); ver(l) != "9.6p1" {
		t.Fatalf("an empty list of port 80 leaves port 22: %+v", l)
	}
	if n := c.e.count(`SELECT count(*) FROM inv_software WHERE product = 'nginx' AND state = 'removed'`); n != 1 {
		t.Fatalf("nginx: %d removed lines", n)
	}
}

// Removal is a state: the line keeps its id and comes back with it, and its history says so.
func TestSoftwareLines_RemovalIsAState(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Osquery, nil, ssh("9.6p1", ""), observe.Software{Display: "curl", Vendor: "curl", Product: "curl", Version: "8.5.0", Confidence: 0.9})
	id := c.line("OpenSSH").ID
	c.send(observe.Osquery, nil, observe.Software{Display: "curl", Vendor: "curl", Product: "curl", Version: "8.5.0", Confidence: 0.9})
	if n := c.e.count(`SELECT count(*) FROM inv_software WHERE id = ? AND state = 'removed' AND removed_at IS NOT NULL`, id); n != 1 {
		t.Fatal("a line no source reads must be removed, not deleted")
	}
	if m := matchRows(t, c.e, c.dev()); slices.ContainsFunc(m, func(s inventory.MatchSoftware) bool { return s.ID == id }) {
		t.Fatal("a removed line must not be matched")
	}
	c.send(observe.Osquery, nil, ssh("10.2p1", ""))
	if l := c.line("OpenSSH"); l.ID != id || ver(l) != "10.2p1" {
		t.Fatalf("back: %+v, want the same id %s", l, id)
	}
	if h := c.history(id); !slices.Equal(h, []string{"appeared", "removed", "reappeared"}) {
		t.Fatalf("history %v", h)
	}
}

// A person's version holds against an older reading (said once, with an audit row and a history row) and lapses on a newer one read
// after it, with an audit row and a history row.
func TestSoftwareLines_EntryLapsesOnANewerReading(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	id := c.line("OpenSSH").ID
	c.e.tick(time.Minute)
	v := "9.6p1"
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{Version: &v}); err != nil {
		t.Fatal(err)
	}
	if l := c.line("OpenSSH"); ver(l) != "9.6p1" || l.Source != "manual" || l.SetBy != "op@example.com" {
		t.Fatalf("entry: %+v", l)
	}
	c.e.tick(time.Minute)
	c.send(observe.Nmap, nil, ssh("9.5", "tcp/22")) // older: the entry holds; the older reading still matches
	if l := c.line("OpenSSH"); ver(l) != "9.6p1" || !l.Differs {
		t.Fatalf("an older reading keeps the entry: %+v", l)
	}
	c.e.tick(time.Minute)
	c.send(observe.Nmap, nil, ssh("9.5", "tcp/22")) // the same reading again: said once
	if countOf(c.e.auditActions(), "inventory.software_correction_kept") != 1 || countOf(c.history(id), "entry_kept") != 1 {
		t.Fatalf("the kept entry is said once: audit %v, history %v", c.e.auditActions(), c.history(id))
	}
	c.e.tick(time.Minute)
	c.send(observe.Nmap, nil, ssh("10.2", "tcp/22"))
	if l := c.line("OpenSSH"); l.ID != id || ver(l) != "10.2" || l.Source != "nmap" {
		t.Fatalf("a newer reading ends the entry: %+v", l)
	}
	if countOf(c.e.auditActions(), "inventory.software_correction_lapsed") != 1 || !slices.Contains(c.history(id), "entry_lapsed") {
		t.Fatalf("audit %v, history %v", c.e.auditActions(), c.history(id))
	}
}

// A person who sets a version below a scan's reading has seen that reading: the scan reading the same newer release again keeps the
// entry (it was not first seen after it), and nothing says a reading "not newer" than the entry was kept.
func TestSoftwareLines_EntryBelowASeenReadingIsNotSaidKept(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	id := c.line("OpenSSH").ID
	c.e.tick(time.Minute)
	v := "9.3"
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{Version: &v}); err != nil {
		t.Fatal(err)
	}
	c.e.tick(time.Minute)
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	if l := c.line("OpenSSH"); ver(l) != "9.3" || l.Source != "manual" {
		t.Fatalf("the reading the person saw keeps the entry: %+v", l)
	}
	if n, h := countOf(c.e.auditActions(), "inventory.software_correction_kept"), countOf(c.history(id), "entry_kept"); n != 0 || h != 0 {
		t.Fatalf("a newer reading is not one that is not newer: audit %v, history %v", c.e.auditActions(), c.history(id))
	}
}

// "Not installed" takes the line out of matching (findings read it in NotInstalled) until a source reads something new on it.
func TestSoftwareLines_NotInstalledHoldsUntilANewReading(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	id := c.line("OpenSSH").ID
	c.e.tick(time.Minute)
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{NotInstalled: true}); err != nil {
		t.Fatal(err)
	}
	m, _, err := c.e.svc.MatchInput(c.e.ctx(), c.dev())
	if err != nil || len(m.Software) != 0 || len(m.NotInstalled) != 1 || m.NotInstalled[0].ID != id || m.NotInstalled[0].MarkedAt == "" {
		t.Fatalf("match input %+v %v", m, err)
	}
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22")) // the reading the person saw: the mark holds
	if n := c.e.count(`SELECT count(*) FROM inv_software WHERE id = ? AND state = 'not_installed'`, id); n != 1 {
		t.Fatal("the same reading again must keep the mark")
	}
	c.send(observe.Nmap, nil, ssh("10.2", "tcp/22")) // a new release read: a new install
	if l := c.line("OpenSSH"); l.ID != id || ver(l) != "10.2" {
		t.Fatalf("a new reading ends the mark: %+v", l)
	}
	if h := c.history(id); !slices.Contains(h, "marked_not_installed") || !slices.Contains(h, "unmarked") {
		t.Fatalf("history %v", h)
	}
}

// Merging two rows of one machine loses no reading: the readings of the line both hold go to the line that stays, the other lines
// move with their ids, and the merge maps the folded line to the kept one.
func TestSoftwareLines_MergeLosesNoReading(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.81")}, observe.AssetHint{IP: netip.MustParseAddr("192.0.2.82")}
	for _, s := range []struct {
		h     observe.AssetHint
		src   observe.Source
		items []observe.Software
	}{
		{a, observe.Osquery, []observe.Software{ssh("10.2p1", "")}},
		{b, observe.Nmap, []observe.Software{ssh("9.6", "tcp/22"), {Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.24.0", Instance: "tcp/80", Confidence: 0.8}}},
	} {
		e.tick(time.Minute)
		if err := e.svc.ReplaceSoftware(e.ctx(), s.h, s.src, nil, s.items); err != nil {
			t.Fatal(err)
		}
	}
	into, from := deviceAt(t, e, a.IP), deviceAt(t, e, b.IP)
	readings := e.count(`SELECT count(*) FROM inv_software_reading`)
	if err := e.svc.Merge(e.ctx(), "op@example.com", into, from); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_reading`); n != readings {
		t.Fatalf("%d readings after the merge, want %d", n, readings)
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ?`, into); n != 2 {
		t.Fatalf("%d lines on the kept device, want OpenSSH and nginx", n)
	}
	l, err := e.svc.SoftwareLines(e.ctx(), into)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range l {
		if s.Product == "OpenSSH" && (ver(s) != "10.2p1" || len(s.AlsoSeen) != 1 || s.AlsoSeen[0].Version != "9.6") {
			t.Fatalf("OpenSSH after the merge: %+v", s)
		}
	}
}

// The OS a network device states over SNMP is a software line with the exploited-list keys of that OS.
func TestSoftwareLines_StatedNetworkOSIsALine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.90")
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: "FortiOS 7.0.1", Source: observe.SNMP, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	m := matchRows(t, e, deviceAt(t, e, ip))
	if len(m) != 1 || m[0].Version != "7.0.1" || m[0].Source != "snmp" || !slices.Contains(m[0].KevKeys, "fortinet|fortios") || !slices.Contains(m[0].KevKeys, "fortinet|multiple products") {
		t.Fatalf("match input %+v", m)
	}
	id := m[0].ID
	e.tick(time.Minute)
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: "FortiOS 7.0.15", Source: observe.SNMP, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if m := matchRows(t, e, deviceAt(t, e, ip)); len(m) != 1 || m[0].ID != id || m[0].Version != "7.0.15" {
		t.Fatalf("the update keeps the line: %+v", m)
	}
}

// A person's OS on a network device is what the matcher reads for the stated OS line: SNMP states FortiOS 7.0.1, the person says
// 7.4.5, matching reads 7.4.5 on the same line; clearing the person's OS brings back the statement.
func TestSoftwareLines_PersonsOSReachesTheStatedOSLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.91")
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: "FortiOS 7.0.1", Source: observe.SNMP, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	dev := deviceAt(t, e, ip)
	id := matchRows(t, e, dev)[0].ID
	set := func(os string) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: &os}); err != nil {
			t.Fatal(err)
		}
	}
	set("FortiOS 7.4.5")
	if m := matchRows(t, e, dev); len(m) != 1 || m[0].ID != id || m[0].Version != "7.4.5" || m[0].Source != "manual" || !slices.Contains(m[0].KevKeys, "fortinet|fortios") {
		t.Fatalf("the person's OS must reach the line: %+v", m)
	}
	set("")
	if m := matchRows(t, e, dev); len(m) != 1 || m[0].ID != id || m[0].Version != "7.0.1" || m[0].Source != "snmp" {
		t.Fatalf("cleared: %+v", m)
	}
}

// A person's "not installed" survives the software going away and coming back at the release the person saw (a stale agent list
// pruned, a scan that missed the port); a new release lifts it.
func TestSoftwareLines_NotInstalledSurvivesARemoval(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	id := c.line("OpenSSH").ID
	c.e.tick(time.Minute)
	if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev(), id, inventory.SoftwareEdit{NotInstalled: true}); err != nil {
		t.Fatal(err)
	}
	c.send(observe.Nmap, nil) // gone
	c.send(observe.Nmap, nil, ssh("9.6", "tcp/22"))
	if n := c.e.count(`SELECT count(*) FROM inv_software WHERE id = ? AND state = 'not_installed' AND not_installed_by = 'op@example.com'`, id); n != 1 {
		t.Fatal("the same release read again must keep the person's mark")
	}
	c.send(observe.Nmap, nil, ssh("10.2", "tcp/22"))
	if l := c.line("OpenSSH"); l.ID != id || ver(l) != "10.2" {
		t.Fatalf("a new release lifts the mark: %+v", l)
	}
}

// A merge keeps a person's "not installed" of the folded row's line even when the kept row reads the software, and the folded
// line's history is the kept line's.
func TestSoftwareLines_MergeKeepsTheMarkAndTheHistory(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.83")}, observe.AssetHint{IP: netip.MustParseAddr("192.0.2.84")}
	e.tick(time.Minute)
	if err := e.svc.ReplaceSoftware(e.ctx(), a, observe.Nmap, nil, []observe.Software{ssh("9.6", "tcp/22")}); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	if err := e.svc.ReplaceSoftware(e.ctx(), b, observe.Nmap, nil, []observe.Software{ssh("9.6", "tcp/22")}); err != nil {
		t.Fatal(err)
	}
	into, from := deviceAt(t, e, a.IP), deviceAt(t, e, b.IP)
	gone := matchRows(t, e, from)[0].ID
	e.tick(time.Minute)
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", from, gone, inventory.SoftwareEdit{NotInstalled: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), "op@example.com", into, from); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND state = 'not_installed' AND not_installed_by = 'op@example.com'`, into); n != 1 {
		t.Fatal("the merge lost the person's not installed")
	}
	if n := e.count(`SELECT count(*) FROM inv_software_event WHERE asset_id = ? OR software_id = ?`, from, gone); n != 0 {
		t.Fatalf("%d history rows still name the folded device or line", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_event WHERE asset_id = ? AND kind = 'marked_not_installed'`, into); n != 1 {
		t.Fatal("the person's mark is not in the kept device's history")
	}
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE inv_software_event SET to_version = 'x'`)
		return err
	}); err == nil {
		t.Fatal("history must stay append-only beyond its device and line ids")
	}
}

// A merge dates a reading by when that release was first read on either row, never by when the folded line first appeared: a newer
// release the other row read after a person's mark or version still ends it. The two rows were two addresses of the device: what the
// scan read at each stays (INV-57), the newer release is the line's value and the other address's older one is still matched.
func TestSoftwareLines_MergeDatesReadingsByRelease(t *testing.T) {
	t.Parallel()
	for _, mark := range []bool{true, false} {
		e := newEnv(t)
		a, b := observe.AssetHint{IP: netip.MustParseAddr("192.0.2.85")}, observe.AssetHint{IP: netip.MustParseAddr("192.0.2.86")}
		send := func(h observe.AssetHint, v string) {
			t.Helper()
			e.tick(time.Minute)
			if err := e.svc.ReplaceSoftware(e.ctx(), h, observe.Nmap, nil, []observe.Software{ssh(v, "tcp/22")}); err != nil {
				t.Fatal(err)
			}
		}
		send(b, "8.0") // the other row reads an older release first
		send(a, "9.6")
		into, from := deviceAt(t, e, a.IP), deviceAt(t, e, b.IP)
		id := matchRows(t, e, into)[0].ID
		e.tick(time.Minute)
		edit := inventory.SoftwareEdit{NotInstalled: true}
		if !mark {
			v := "9.6p1"
			edit = inventory.SoftwareEdit{Version: &v}
		}
		if err := e.svc.EditSoftware(e.ctx(), "op@example.com", into, id, edit); err != nil {
			t.Fatal(err)
		}
		send(b, "9.8") // read after the person's word
		if err := e.svc.Merge(e.ctx(), "op@example.com", into, from); err != nil {
			t.Fatal(err)
		}
		if m := matchRows(t, e, into); len(m) != 2 || m[0].ID != id || m[0].Version != "9.8" || m[0].Source != "nmap" || m[1].Version != "9.6" {
			t.Fatalf("mark %v: after the merge %+v, want the line at 9.8 and the other address's 9.6", mark, m)
		}
	}
}

// A newer reading that outgrows the person's OS on its stated-OS line ends the person's OS too, once: later polls of the device
// neither bring it back nor lapse it again.
func TestSoftwareLines_PersonsOSLapsesOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.0.2.92")
	poll := func() {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: "FortiOS 7.0.1", Source: observe.SNMP, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	dev := deviceAt(t, e, ip)
	os := "FortiOS 7.4.5"
	e.tick(time.Minute)
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: &os}); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Minute)
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: ip}, observe.Nmap, []string{"stated"}, []observe.Software{{Display: "FortiOS 7.4.6", Vendor: "fortinet",
		Product: "fortios", Version: "7.4.6", CPE: "cpe:2.3:o:fortinet:fortios:7.4.6:*:*:*:*:*:*:*", Instance: "stated", Confidence: 0.95}}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		poll()
	}
	if n := e.count(`SELECT count(*) FROM inv_software_event WHERE kind = 'entry_lapsed'`); n != 1 {
		t.Fatalf("%d entry_lapsed rows, want 1", n)
	}
	d := e.detail(dev)
	if d.Asset.OSCorrection != nil || d.Asset.OS == nil || d.Asset.OS.Value != "FortiOS 7.0.1" {
		t.Fatalf("the person's OS must have ended: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}
	// the device's SNMP answer is the line again; the scan's newer release still feeds matching
	if m := matchRows(t, e, dev); len(m) != 2 || m[0].Version != "7.0.1" || m[1].Version != "7.4.6" {
		t.Fatalf("matching reads %+v, want SNMP's 7.0.1 and the scan's 7.4.6", m)
	}
	if countOf(e.auditActions(), "inventory.os_correction_lapsed") != 1 {
		t.Fatalf("audit %v", e.auditActions())
	}
}

// The software history is append-only; the one change allowed (the device and line ids, on a merge, and on the split that gives a
// merged device its lines back) is made by join.go and mergedfrom.go alone.
func TestSoftwareLines_OnlyTheMergeRewritesHistory(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`(?i)\bupdate\s+inv_software_event\b`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "join.go" || f == "mergedfrom.go" {
			continue
		}
		b, err := os.ReadFile(f) //nolint:gosec // the package's own source files
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(b) {
			t.Errorf("%s updates inv_software_event: only the merge and its split (join.go, mergedfrom.go) may", f)
		}
	}
}
