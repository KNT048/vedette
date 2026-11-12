package inventory_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/inventory"
)

const (
	macA = "aa:bb:cc:00:00:01"
	macB = "aa:bb:cc:00:00:02"
)

func obsv(mac string, field observe.Field, value string, src observe.Source, conf float64) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: field, Value: value, Source: src, Confidence: conf}
}

func (e *env) record(obs ...observe.Observation) {
	e.t.Helper()
	if err := e.svc.Record(e.ctx(), obs); err != nil {
		e.t.Fatalf("Record: %v", err)
	}
}

// idByMAC finds a device through the list.
func (e *env) idByMAC(mac string) string {
	e.t.Helper()
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.MAC != nil && *d.MAC == mac {
			return d.ID
		}
	}
	e.t.Fatalf("no device with MAC %s", mac)
	return ""
}

func (e *env) detail(id string) inventory.Detail {
	e.t.Helper()
	d, err := e.svc.Detail(e.ctx(), id)
	if err != nil {
		e.t.Fatalf("Detail(%s): %v", id, err)
	}
	return d
}

func currentOf(d inventory.Detail, field string) (inventory.ObservationRow, bool) {
	for _, o := range d.Observations {
		if o.Field == field && o.Current {
			return o, true
		}
	}
	return inventory.ObservationRow{}, false
}

var rank = map[string]int{"manual": 5, "agent": 4, "snmp": 3, "nmap": 2, "scan": 2, "passive": 1}

// foldWinner is the specification of DATA_MODEL 5.1 (2), written again here on purpose (INV1 (i)).
func foldWinner(list []inventory.ObservationRow, field string) (inventory.ObservationRow, bool) {
	var best inventory.ObservationRow
	found := false
	for _, o := range list {
		if o.Field != field {
			continue
		}
		win := !found
		if found {
			switch {
			case rank[o.Source] != rank[best.Source]:
				win = rank[o.Source] > rank[best.Source]
			case o.Confidence != best.Confidence:
				win = o.Confidence > best.Confidence
			case o.SeenAt != best.SeenAt:
				win = o.SeenAt > best.SeenAt
			default:
				win = o.ID < best.ID
			}
		}
		if win {
			best, found = o, true
		}
	}
	return best, found
}

func TestContract_INV1_ObservationsAppendOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(obsv(macA, observe.Vendor, "Acme", observe.Passive, 0.7), obsv(macA, observe.Hostname, "nas01", observe.Passive, 0.7))
	id := e.idByMAC(macA)
	rows := func() int { return e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ?`, id) }
	last := rows()

	steps := []func(){
		func() { e.record(obsv(macA, observe.Vendor, "AcmeCorp", observe.Agent, 0.5)) },    // agent beats passive despite lower confidence
		func() { e.record(obsv(macA, observe.Vendor, "Acme Inc", observe.Passive, 0.99)) }, // weaker source: current must not change
		func() { e.record(obsv(macA, observe.Vendor, "Nmap Vendor", observe.Nmap, 1)) },    // nmap below agent
		func() { e.record(obsv(macA, observe.OS, "Linux 5", observe.Nmap, 0.6)) },
		func() { e.record(obsv(macA, observe.OS, "Linux 6", observe.Scan, 0.6)) }, // scan = nmap: newer seen_at wins
		func() { e.tick(time.Minute); e.record(obsv(macA, observe.OS, "Linux 7", observe.Scan, 0.6)) },
		func() {
			if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Kind: ptr("nas")}); err != nil {
				t.Fatal(err)
			}
		},
		func() { e.record(obsv(macA, observe.Kind, "server", observe.Agent, 1)) }, // manual beats agent
	}
	for i, step := range steps {
		step()
		if n := rows(); n < last {
			t.Fatalf("step %d: observations went from %d to %d", i, last, n)
		} else {
			last = n
		}
		// (i) the current value of every field is the fold of the observations
		d := e.detail(id)
		for _, f := range []string{"kind", "hostname", "mac", "vendor", "model", "os"} {
			want, ok := foldWinner(d.Observations, f)
			got, gotOK := currentOf(d, f)
			if ok != gotOK || (ok && got.ID != want.ID) {
				t.Fatalf("step %d field %s: current = %+v, fold = %+v", i, f, got, want)
			}
		}
	}
	d := e.detail(id)
	if v, _ := currentOf(d, "vendor"); v.Value != "AcmeCorp" || v.Source != "agent" {
		t.Fatalf("vendor = %+v, want the agent's value", v)
	}
	if k, _ := currentOf(d, "kind"); k.Value != "nas" || k.Source != "manual" {
		t.Fatalf("kind = %+v, want the manual value (iv)", k)
	}
	if o, _ := currentOf(d, "os"); o.Value != "Linux 7" {
		t.Fatalf("os = %+v, want the newest scan value", o)
	}
	if d.Asset.Vendor == nil || d.Asset.Vendor.Value != "AcmeCorp" || d.Asset.Kind != "nas" {
		t.Fatalf("device columns = %+v / %s", d.Asset.Vendor, d.Asset.Kind)
	}

	t.Run("an exact repeat moves seen_at and keeps the higher confidence", func(t *testing.T) {
		before := rows()
		e.tick(time.Hour)
		e.record(obsv(macA, observe.Hostname, "nas01", observe.Passive, 0.9))
		e.record(obsv(macA, observe.Hostname, "nas01", observe.Passive, 0.2))
		if rows() != before {
			t.Fatalf("a repeat added a row: %d -> %d", before, rows())
		}
		for _, o := range e.detail(id).Observations {
			if o.Field == "hostname" && o.Value == "nas01" && (o.Confidence != 0.9 || o.SeenAt != "2026-11-09T11:01:00.000Z") {
				t.Fatalf("hostname observation = %+v", o)
			}
		}
	})

	t.Run("the database refuses to change a value in place", func(t *testing.T) {
		err := e.db.Write(e.ctx(), func(tx dbTx) error {
			_, err := tx.ExecContext(e.ctx(), `UPDATE inv_observation SET value = 'x' WHERE asset_id = ?`, id)
			return err
		})
		if err == nil || !contains(err.Error(), "append-only") {
			t.Fatalf("UPDATE value: err = %v", err)
		}
	})
}

func ptr[T any](v T) *T { return &v }

func TestContract_INV2_OnlyTheServiceWritesInvTables(t *testing.T) {
	t.Parallel()
	// FORBID-4: no other Go package touches inv_* tables. The scan is by effect on the source tree: any SQL verb
	// followed by an inv_ table outside modules/inventory fails.
	re := regexp.MustCompile(`(?i)\b(from|join|into|update|delete\s+from)\s+inv_`)
	root := filepath.Join("..", "..")
	var bad []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "web", "inventory":
				if d.Name() == "inventory" && filepath.Base(filepath.Dir(path)) != "modules" {
					return nil
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // walking our own source tree
		if err != nil {
			return err
		}
		if re.Match(b) {
			bad = append(bad, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("these files read or write inv_* tables: %v", bad)
	}
}

func TestContract_INV3_TheBoxIsTheFirstDevice(t *testing.T) {
	t.Parallel()
	box := fakeBox{items: []inventory.SoftwareItem{{Display: "OpenSSH server", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Confidence: 0.2, KevKeys: []string{"openbsd|openssh"}}}}
	e := newEnv(t, withBox(box))
	id, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2", OS: "Ubuntu 24.04"})
	if err != nil {
		t.Fatal(err)
	}
	id2, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2", OS: "Ubuntu 24.04"})
	if err != nil || id2 != id {
		t.Fatalf("second EnsureBox = %q, %v; want the same device %q", id2, err, id)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 1`); n != 1 {
		t.Fatalf("%d boxes, want exactly one", n)
	}
	if err := e.svc.RefreshBoxPackages(e.ctx()); err != nil {
		t.Fatal(err)
	}
	d := e.detail(id)
	if !d.Asset.IsBox || !d.Asset.Approved || d.Asset.Hostname == nil || *d.Asset.Hostname != "vedette-hq" || d.Asset.Kind != "server" || d.Asset.IP != "192.168.10.2" {
		t.Fatalf("box = %+v", d.Asset)
	}
	if len(d.Asset.Software) != 1 || d.Asset.Software[0].Source != "agent" || d.Asset.Software[0].Confidence != 1 {
		t.Fatalf("box software = %+v, want dpkg rows at confidence 1.0", d.Asset.Software)
	}
	// the box leads the list
	e.record(obsv(macA, observe.Hostname, "other", observe.Passive, 0.7))
	l, _ := e.svc.Devices(e.ctx())
	if len(l.Items) != 2 || !l.Items[0].IsBox {
		t.Fatalf("list = %+v, the box must come first", l.Items)
	}
	// FORBID-2
	wantAPIError(t, e.svc.DeleteDevice(e.ctx(), "it@acme.example", id), 409, "box_device")
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE is_box = 1`); n != 1 {
		t.Fatal("the box was deleted")
	}
	// a second box cannot exist (unique index)
	err = e.db.Write(e.ctx(), func(tx dbTx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO inv_asset (id, kind, origin, is_box, first_seen, last_seen) VALUES ('a-x', 'server', 'discovered', 1, '2026-11-09T10:00:00.000Z', '2026-11-09T10:00:00.000Z')`)
		return err
	})
	if err == nil {
		t.Fatal("a second box was accepted")
	}
}

func TestContract_INV4_ManualDeclaration(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	forti := inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", Name: "Branch FW", IP: "192.168.30.1"}
	id := e.addDevice(forti)
	d := e.detail(id)
	if d.Asset.Origin != "manual" || !d.Asset.Approved || d.Asset.IP != "192.168.30.1" || d.Asset.Kind != "firewall" || len(d.Asset.Software) != 1 {
		t.Fatalf("device = %+v", d.Asset)
	}
	if sw := d.Asset.Software[0]; sw.Source != "manual" || sw.Confidence != 1 || sw.Version == nil || *sw.Version != "7.2.5" || sw.Vendor != "Fortinet" {
		t.Fatalf("software = %+v", sw)
	}

	long := strings.Repeat("a", 65)
	bad := []struct {
		name   string
		in     inventory.AddInput
		status int
		code   string
	}{
		{"duplicate IP", inventory.AddInput{CatalogID: "synology-nas-dsm", IP: "192.168.30.1"}, 409, "duplicate_ip"},
		{"bad IP", inventory.AddInput{CatalogID: "synology-nas-dsm", IP: "192.168.30"}, 400, "bad_ip"},
		{"IPv6", inventory.AddInput{CatalogID: "synology-nas-dsm", IP: "::1"}, 400, "bad_ip"},
		{"name with <", inventory.AddInput{CatalogID: "synology-nas-dsm", Name: "a<b"}, 400, "bad_name"},
		{"name with >", inventory.AddInput{CatalogID: "synology-nas-dsm", Name: "a>b"}, 400, "bad_name"},
		{"name too long", inventory.AddInput{CatalogID: "synology-nas-dsm", Name: long}, 400, "bad_name"},
		{"vendor too long", inventory.AddInput{Vendor: long, Product: "x"}, 400, "bad_product"},
		{"product with <", inventory.AddInput{Vendor: "x", Product: "<b>"}, 400, "bad_product"},
		{"vendor only", inventory.AddInput{Vendor: "Fortinet"}, 400, "incomplete_product"},
		{"version with a slash", inventory.AddInput{CatalogID: "synology-nas-dsm", Version: "7/2"}, 400, "bad_version"},
		{"version too long", inventory.AddInput{CatalogID: "synology-nas-dsm", Version: strings.Repeat("1", 41)}, 400, "bad_version"},
		{"unknown catalog id", inventory.AddInput{CatalogID: "nope"}, 400, "unknown_product"},
		{"no product", inventory.AddInput{Name: "x"}, 400, "unknown_product"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.svc.AddDevice(e.ctx(), "it@acme.example", c.in)
			wantAPIError(t, err, c.status, c.code)
		})
	}
	// version may use letters, digits and . - + ( ) space
	e.addDevice(inventory.AddInput{CatalogID: "synology-nas-dsm", Version: "7.2.1-69057 Update 3 (beta+1)", IP: "192.168.30.2"})
	// a vendor + product typed by hand is accepted
	custom := e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo", Name: "gizmo"})
	if d := e.detail(custom); d.Asset.Kind != "unknown" || d.Asset.Software[0].Display != "Contoso Gizmo" {
		t.Fatalf("custom device = %+v", d.Asset)
	}

	t.Run("duplicate software is 409, a different product is fine", func(t *testing.T) {
		_, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "fortigate", Version: "7.4"})
		wantAPIError(t, err, 409, "duplicate_software")
		if _, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "openvpn-access-server"}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("only manual software is removable", func(t *testing.T) {
		box := e.addDevice(inventory.AddInput{CatalogID: "windows-11", IP: "192.168.30.9"})
		if err := e.svc.UpsertSoftware(e.ctx(), box, []inventory.SoftwareItem{{Vendor: "Mozilla", Product: "Firefox", Version: "120", Confidence: 0.9}}, "agent"); err != nil {
			t.Fatal(err)
		}
		var agentSW, manualSW string
		for _, s := range e.detail(box).Asset.Software {
			if s.Source == "agent" {
				agentSW = s.ID
			} else {
				manualSW = s.ID
			}
		}
		wantAPIError(t, e.svc.RemoveSoftware(e.ctx(), "it@acme.example", box, agentSW), 400, "not_manual")
		if err := e.svc.RemoveSoftware(e.ctx(), "it@acme.example", box, manualSW); err != nil {
			t.Fatal(err)
		}
		wantAPIError(t, e.svc.RemoveSoftware(e.ctx(), "it@acme.example", box, manualSW), 404, "not_found")
		wantAPIError(t, e.svc.RemoveSoftware(e.ctx(), "it@acme.example", "a-nope", manualSW), 404, "not_found")
	})
}

func TestContract_INV5_ManualDevicesAreNeverScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.30.0/24")
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.1"})
	d := e.detail(id)
	if d.Asset.FirstScanAt != nil {
		t.Fatalf("first_scan_at = %v, want null", *d.Asset.FirstScanAt)
	}
	dec, err := e.svc.ScanPolicy(e.ctx(), id)
	if err != nil || dec.Allowed || dec.Reason != inventory.ReasonDeclaredByHand {
		t.Fatalf("ScanPolicy = %+v, %v", dec, err)
	}
	// even after a first-scan mark (a scanner that ignored the policy): still no
	if err := e.svc.MarkFirstScan(e.ctx(), id); err != nil {
		t.Fatal(err)
	}
	if dec, _ := e.svc.ScanPolicy(e.ctx(), id); dec.Allowed {
		t.Fatalf("ScanPolicy after a first scan = %+v", dec)
	}
}

func TestContract_INV9_NewDevicesArePendingAndAnnounced(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(obs(netip.MustParseAddr("192.168.10.77"), "", observe.Hostname, "laptop", observe.Passive, 0.7))
	l, _ := e.svc.Devices(e.ctx())
	if len(l.Items) != 1 || l.Items[0].Approved || l.Items[0].Origin != "discovered" || l.Counts.Pending != 1 {
		t.Fatalf("list = %+v", l)
	}
	ev := e.ev.named(inventory.EventAssetDiscovered)
	if len(ev) != 1 || ev[0].Data.(inventory.AssetEvent).AssetID != l.Items[0].ID || !ev[0].Data.(inventory.AssetEvent).Notify {
		t.Fatalf("discovered events = %+v", ev)
	}
	// notify_new off: still announced (sensor-active needs it), with Notify=false
	if err := e.svc.SetNotifyNew(e.ctx(), "it@acme.example", false); err != nil {
		t.Fatal(err)
	}
	e.record(obs(netip.MustParseAddr("192.168.10.78"), "", observe.Hostname, "phone", observe.Passive, 0.7))
	ev = e.ev.named(inventory.EventAssetDiscovered)
	if len(ev) != 2 || ev[1].Data.(inventory.AssetEvent).Notify {
		t.Fatalf("discovered events = %+v", ev)
	}
	// seeing the same device again is not a new discovery
	e.record(obs(netip.MustParseAddr("192.168.10.78"), "", observe.Hostname, "phone", observe.Passive, 0.7))
	if got := len(e.ev.named(inventory.EventAssetDiscovered)); got != 2 {
		t.Fatalf("%d discovered events", got)
	}
	// approve
	if err := e.svc.Approve(e.ctx(), "it@acme.example", l.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	if d := e.detail(l.Items[0].ID); !d.Asset.Approved {
		t.Fatal("not approved")
	}
}

func obs(ip netip.Addr, mac string, field observe.Field, value string, src observe.Source, conf float64) observe.Observation {
	return observe.Observation{AssetHint: observe.AssetHint{IP: ip, MAC: mac}, Field: field, Value: value, Source: src, Confidence: conf}
}

func TestContract_INV10_KEVMatchIsByProductNeverConfirmed(t *testing.T) {
	t.Parallel()
	kev := fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001", "CVE-2024-0002"}, "fortinet|multiple products": {"CVE-2023-0009"}}}
	e := newEnv(t, withKEV(kev))
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.1"})
	got := map[string]string{}
	for _, ev := range e.ev.named(inventory.EventMatchChanged) {
		m := ev.Data.(inventory.MatchEvent)
		if m.AssetID != id {
			t.Fatalf("match for %s, want %s", m.AssetID, id)
		}
		got[m.CVE] = m.Basis
	}
	if len(got) != 3 || got["CVE-2024-0001"] != "product" || got["CVE-2023-0009"] != "product" {
		t.Fatalf("match events = %v, want 3 CVEs with basis product", got)
	}
	for cve, basis := range got {
		if basis != "product" && basis != "version" {
			t.Fatalf("%s has basis %q: only product or version, never confirmed", cve, basis)
		}
	}
	// the detail lists the CVEs of the software
	if cves := e.detail(id).Asset.Software[0].KevCVEs; len(cves) != 3 {
		t.Fatalf("kev_cves = %v", cves)
	}
	// adding more software announces only what is new
	e.ev.reset()
	if _, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "openvpn-access-server"}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.ev.named(inventory.EventMatchChanged)); n != 0 {
		t.Fatalf("%d match events for a product with no CVE", n)
	}
	if n := len(e.ev.named(inventory.EventSoftwareChanged)); n != 1 {
		t.Fatalf("%d software events", n)
	}
	// the count shown when adding comes from the catalog (every CVE ever exploited), not from the recent feed
	r, err := e.svc.AddDevice(e.ctx(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate"})
	if err != nil || r.KevCVEs == 0 {
		t.Fatalf("AddDevice = %+v, %v", r, err)
	}
}

func TestContract_INV11_DeleteRemovesTheDeviceAndAnnouncesIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.1", Name: "fw"})
	e.findg[id] = 3
	l, _ := e.svc.Devices(e.ctx())
	if l.Items[0].FindingsCount != 3 {
		t.Fatalf("findings_count = %d", l.Items[0].FindingsCount)
	}
	if e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ?`, id) == 0 || e.count(`SELECT count(*) FROM inv_software WHERE asset_id = ?`, id) == 0 {
		t.Fatal("no children to delete")
	}
	e.ev.reset()
	if err := e.svc.DeleteDevice(e.ctx(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`SELECT count(*) FROM inv_asset WHERE id = ?`, `SELECT count(*) FROM inv_observation WHERE asset_id = ?`, `SELECT count(*) FROM inv_software WHERE asset_id = ?`} {
		if n := e.count(q, id); n != 0 {
			t.Fatalf("%s = %d after delete", q, n)
		}
	}
	if n := e.count(`SELECT count(*) FROM inv_software_kev`); n != 0 {
		t.Fatalf("%d orphan match keys", n)
	}
	ev := e.ev.named(inventory.EventAssetDeleted)
	if len(ev) != 1 || ev[0].Data.(inventory.AssetEvent).AssetID != id {
		t.Fatalf("deleted events = %+v", ev)
	}
	var detail string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT detail FROM core_audit WHERE action = 'inventory.delete'`).Scan(&detail); err != nil || !contains(detail, "removed 3 findings") {
		t.Fatalf("audit detail = %q, %v", detail, err)
	}
	wantAPIError(t, e.svc.DeleteDevice(e.ctx(), "it@acme.example", id), 404, "not_found")
}

func TestMigrationsUsePrefix(t *testing.T) {
	t.Parallel()
	storetest.AssertMigrationsUsePrefix(t, "inventory", inventory.Migrations, "inv_", storetest.Migration{Module: "core", FS: core.Migrations})
}
