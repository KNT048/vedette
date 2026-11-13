package inventory_test

import (
	"database/sql"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// D-471: approving sets approved_at once (approving again does not move it); a hand-added device has none.
func TestContract_D471_ApprovedAtIsTheFirstApproval(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(obs(netip.MustParseAddr("192.168.10.77"), "", observe.Hostname, "laptop", observe.Passive, 0.7))
	l, _ := e.svc.Devices(e.ctx())
	id := l.Items[0].ID
	if l.Items[0].ApprovedAt != nil {
		t.Fatalf("approved_at before approval = %v", *l.Items[0].ApprovedAt)
	}
	e.tick(time.Minute)
	if err := e.svc.Approve(e.ctx(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	first := e.detail(id).Asset.ApprovedAt
	if first == nil {
		t.Fatal("approved_at not set by Approve")
	}
	e.tick(time.Hour)
	if err := e.svc.Approve(e.ctx(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if again := e.detail(id).Asset.ApprovedAt; again == nil || *again != *first {
		t.Fatalf("approved_at moved on a second approval: %v → %v", *first, again)
	}
	manual := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.1"})
	if d := e.detail(manual).Asset; !d.Approved || d.ApprovedAt != nil {
		t.Fatalf("hand-added device: approved=%v approved_at=%v", d.Approved, d.ApprovedAt)
	}
}

// D-471: one naming rule. A product added by hand with no name and no IP is "<product> (no device)", never nameless or
// its id; with an IP it is the product; a name typed by hand wins; a discovered device keeps make and model, then IP.
func TestContract_D471_OneNamingRule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	office := e.addDevice(inventory.AddInput{Vendor: "Microsoft", Product: "Office"})
	withIP := e.addDevice(inventory.AddInput{Vendor: "Microsoft", Product: "Exchange Server", IP: "192.168.30.5"})
	named := e.addDevice(inventory.AddInput{Vendor: "Contoso", Product: "Gizmo", Name: "gizmo-1"})
	e.record(obs(netip.MustParseAddr("192.168.10.40"), "", observe.Vendor, "Synology", observe.Passive, 0.6))
	names, err := e.svc.Names(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if got := names[office]; got != "Microsoft Office (no device)" {
		t.Fatalf("no-IP hand-added name = %q", got)
	}
	if got := names[withIP]; got != "Microsoft Exchange Server" {
		t.Fatalf("hand-added with IP = %q", got)
	}
	if got := names[named]; got != "gizmo-1" {
		t.Fatalf("named = %q", got)
	}
	l, _ := e.svc.Devices(e.ctx())
	for _, d := range l.Items {
		if d.Name() != names[d.ID] && names[d.ID] != d.ID {
			t.Fatalf("Device.Name %q != Names %q", d.Name(), names[d.ID])
		}
		if d.Origin == "discovered" && !d.IsBox && d.Name() != "Synology" {
			t.Fatalf("discovered device name = %q, want its make", d.Name())
		}
	}
	// the audit names it the same way, not by its id
	if err := e.svc.Approve(e.ctx(), "it@acme.example", office); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve' AND target = 'Microsoft Office (no device)'`); n != 1 {
		t.Fatalf("%d audit rows name the device", n)
	}
}

// D-471 "edit version": only manual software; bad version 400; same version no-op; a change re-matches the device.
func TestContract_D471_SetSoftwareVersion(t *testing.T) {
	t.Parallel()
	kev := fakeKEV{cves: map[string][]string{"fortinet|fortios": {"CVE-2024-0001"}}}
	e := newEnv(t, withKEV(kev))
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "192.168.30.1"})
	if err := e.svc.UpsertSoftware(e.ctx(), id, []inventory.SoftwareItem{{Vendor: "Mozilla", Product: "Firefox", Version: "120", Confidence: 0.9}}, "agent"); err != nil {
		t.Fatal(err)
	}
	var manualSW, agentSW string
	for _, s := range e.detail(id).Asset.Software {
		if s.Source == "manual" {
			manualSW = s.ID
		} else {
			agentSW = s.ID
		}
	}
	wantAPIError(t, e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, agentSW, "121"), 400, "not_manual")
	wantAPIError(t, e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, manualSW, "7.4<script>"), 400, "bad_version")
	wantAPIError(t, e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", "a-nope", manualSW, "7.4.8"), 404, "not_found")
	wantAPIError(t, e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, "s-nope", "7.4.8"), 404, "not_found")

	before := len(e.ev.named(inventory.EventMatchChanged))
	if err := e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, manualSW, " 7.4.8 "); err != nil {
		t.Fatal(err)
	}
	for _, s := range e.detail(id).Asset.Software {
		if s.ID == manualSW && (s.Version == nil || *s.Version != "7.4.8") {
			t.Fatalf("version = %v", s.Version)
		}
	}
	if got := len(e.ev.named(inventory.EventMatchChanged)); got != before+1 {
		t.Fatalf("%d match events after the change, want %d", got, before+1)
	}
	audits := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.set_software_version' AND detail = '7.2.5 → 7.4.8'`)
	if audits != 1 {
		t.Fatalf("%d audit rows", audits)
	}
	// the same version again changes nothing
	if err := e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, manualSW, "7.4.8"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.set_software_version'`); n != 1 {
		t.Fatalf("%d audit rows after a no-op", n)
	}
	// empty removes it
	if err := e.svc.SetSoftwareVersion(e.ctx(), "it@acme.example", id, manualSW, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range e.detail(id).Asset.Software {
		if s.ID == manualSW && s.Version != nil {
			t.Fatalf("version = %v, want none", *s.Version)
		}
	}
}

// W1-3, M5-177: "I have this" (feeds) gets the declared device's id, and that product-only device is named
// "<product> (no device)", not a nameless row.
func TestContract_D471_AddManualDeviceReturnsTheNamedDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	var id string
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		var err error
		id, err = e.svc.AddManualDevice(e.ctx(), tx, "emily@acme.example", inventory.ManualDevice{Vendor: "Microsoft", Product: "Office", Display: "Microsoft Office", Key: "microsoft|office"})
		return err
	})
	if err != nil || id == "" {
		t.Fatalf("AddManualDevice = %q, %v", id, err)
	}
	names, err := e.svc.Names(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if got := names[id]; got != "Microsoft Office (no device)" {
		t.Fatalf("name = %q", got)
	}
}

// M5-186 (walk 1 W1-10): a readable host name beats a UUID-looking one whatever their source; a person's name still wins.
func TestContract_INV1_AReadableHostnameBeatsAUUID(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.18.40")
	e.record(obs(ip, "aa:bb:cc:00:00:40", observe.Hostname, "kiens-macbook-air", observe.Passive, 0.6))
	e.record(obs(ip, "aa:bb:cc:00:00:40", observe.Hostname, "FBAF5191-CC17-4626-A85B-812BC3D7B83B", observe.Agent, 0.95))
	id := e.idByMAC("aa:bb:cc:00:00:40")
	if h := e.detail(id).Asset.Hostname; h == nil || *h != "kiens-macbook-air" {
		t.Fatalf("hostname = %v, want the readable one", h)
	}
}
