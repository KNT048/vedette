package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// discovered returns the data of the inventory.asset.discovered events, by device id.
func (e *env) discovered() map[string]inventory.AssetEvent {
	e.t.Helper()
	out := map[string]inventory.AssetEvent{}
	for _, ev := range e.ev.named(inventory.EventAssetDiscovered) {
		a, ok := ev.Data.(inventory.AssetEvent)
		if !ok {
			e.t.Fatalf("discovered data is %T", ev.Data)
		}
		out[a.AssetID] = a
	}
	return out
}

// idOf is the id of the device at ip.
func (e *env) idOf(ip string) string {
	e.t.Helper()
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE ip = ?`, ip).Scan(&id); err != nil {
		e.t.Fatalf("device at %s: %v", ip, err)
	}
	return id
}

// MK-1, B9a: inventory.asset.discovered says learning when the source that found the device first reported to this box less
// than 36 hours ago, per source: a sensor added on day 3 learns for its own 36 hours, and the box's own data (EnsureBox, its dpkg
// list) is no source's first contact. notify keeps its meaning.
func TestContract_DiscoveredWhileTheSourceIsLearning(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withBox(fakeBox{items: []inventory.SoftwareItem{{Display: "openssl", Vendor: "OpenSSL", Product: "OpenSSL", Version: "3.0.13", Packaged: true}}}))
	if _, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.168.20.2", OS: "Ubuntu 26.04"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RefreshBoxPackages(e.ctx()); err != nil {
		t.Fatal(err)
	}
	passive := func(ip, mac string) {
		t.Helper()
		o := observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip), MAC: mac}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	nmap := func(ip string) {
		t.Helper()
		if err := e.svc.ReplaceServices(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, observe.Nmap, observe.ServiceScope{}, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.8}}); err != nil {
			t.Fatal(err)
		}
	}
	agent := func(ip string) {
		t.Helper()
		if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: netip.MustParseAddr(ip)}, observe.Osquery, nil, []observe.Software{{Display: "htop", Vendor: "htop", Product: "htop", Version: "3.3.0", Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	e.tick(72 * time.Hour) // the box has run for 3 days; no sensor has reported yet

	passive("192.168.20.10", "52:54:00:00:00:10") // the passive sensor's first contact
	e.tick(35 * time.Hour)
	passive("192.168.20.11", "52:54:00:00:00:11") // 35 h later: still learning
	e.tick(2 * time.Hour)
	passive("192.168.20.12", "52:54:00:00:00:12") // 37 h: the passive sensor knows its network
	nmap("192.168.20.13")                         // the active scan's first contact, day 6: learning on its own clock
	agent("192.168.20.14")                        // an osquery agent's first contact: the box's own agent data did not count
	if err := e.svc.SetNotifyNew(e.ctx(), "it@acme.example", false); err != nil {
		t.Fatal(err)
	}
	e.tick(36 * time.Hour)
	nmap("192.168.20.15")  // 36 h after the active scan's first contact: learned
	agent("192.168.20.16") // and the agent's

	got := e.discovered()
	for ip, want := range map[string]struct{ learning, notify bool }{
		"192.168.20.10": {true, true}, "192.168.20.11": {true, true}, "192.168.20.12": {false, true},
		"192.168.20.13": {true, true}, "192.168.20.14": {true, true},
		"192.168.20.15": {false, false}, "192.168.20.16": {false, false},
	} {
		ev, ok := got[e.idOf(ip)]
		if !ok {
			t.Fatalf("%s: no inventory.asset.discovered", ip)
		}
		if ev.Learning != want.learning || ev.Notify != want.notify {
			t.Errorf("%s: learning=%v notify=%v, want learning=%v notify=%v", ip, ev.Learning, ev.Notify, want.learning, want.notify)
		}
	}
	if len(got) != 7 {
		t.Fatalf("%d discovered events, want 7 (the box is no discovery)", len(got))
	}
}

// B9b: a person's Approve publishes inventory.asset.approved {asset_id, actor} after the commit, once per approval (approving
// again to clear a mark is no approval); the osquery enrolment's automatic approval does not. A person's delete names them too.
func TestContract_ApprovedNamesThePerson(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, mac := range []string{"52:54:00:00:01:01", "52:54:00:00:01:02"} {
		o := observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	idByMAC := func(mac string) string {
		var id string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE mac = ?`, mac).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b := idByMAC("52:54:00:00:01:01"), idByMAC("52:54:00:00:01:02")
	e.ev.reset()
	if err := e.svc.Approve(e.ctx(), "an@acme.example", "a-missing"); err == nil {
		t.Fatal("approving a missing device worked")
	}
	if err := e.svc.Approve(e.ctx(), "an@acme.example", a); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetSuspicious(e.ctx(), "an@acme.example", a, true); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Approve(e.ctx(), "bo@acme.example", a); err != nil { // clears the mark; the device was approved already
		t.Fatal(err)
	}
	if _, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{MAC: "52:54:00:00:01:02"}, "52:54:00:00:01:02", "osquery", false); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND approved = 1`, b); n != 1 {
		t.Fatal("the enrolment did not approve the agent's device (the test would prove nothing)")
	}
	approved := e.ev.named(inventory.EventAssetApproved)
	if len(approved) != 1 {
		t.Fatalf("%d asset.approved events, want 1: %+v", len(approved), approved)
	}
	if got, want := approved[0].Data, (inventory.AssetEvent{AssetID: a, Actor: "an@acme.example"}); got != want {
		t.Fatalf("asset.approved = %+v, want %+v", got, want)
	}
	if err := e.svc.DeleteDevice(e.ctx(), "an@acme.example", b); err != nil {
		t.Fatal(err)
	}
	deleted := e.ev.named(inventory.EventAssetDeleted)
	if len(deleted) != 1 || deleted[0].Data != (inventory.AssetEvent{AssetID: b, Actor: "an@acme.example"}) {
		t.Fatalf("asset.deleted = %+v, want the person", deleted)
	}
}

// MK-2: every software row the findings matcher reads says where it came from (agent, manual, scan…) and whether an agent row
// came from the operating system's package database (deb/rpm), so findings says "install your distribution's security updates" only
// for those. A later report of the same row takes the new origin.
func TestContract_MatchSoftwareSaysWhereItCameFrom(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.20.30")}
	sync := func(packaged bool) {
		t.Helper()
		err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Osquery, nil, []observe.Software{
			{Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL", Version: "3.0.13", KevKeys: []string{"openssl|openssl"}, Confidence: 0.9, Packaged: packaged},
			{Display: "Google Chrome", Vendor: "Google", Product: "Chrome", Version: "130.0", Confidence: 0.9},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	sync(false)
	sync(true) // the same rows again, now from dpkg: the origin follows the latest report
	if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Scan, nil, []observe.Software{{Display: "nginx", Vendor: "F5", Product: "nginx", Version: "1.20.1", Confidence: 0.7}}); err != nil {
		t.Fatal(err)
	}
	id := e.idOf("192.168.20.30")
	if _, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{Vendor: "Fortinet", Product: "FortiOS", Version: "7.2.4"}); err != nil {
		t.Fatal(err)
	}
	d, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok {
		t.Fatalf("MatchInput: %v %v", ok, err)
	}
	got := map[string][2]any{}
	for _, sw := range d.Software {
		got[sw.Product] = [2]any{sw.Source, sw.Packaged}
	}
	want := map[string][2]any{"OpenSSL": {"agent", true}, "Chrome": {"agent", false}, "nginx": {"scan", false}, "FortiOS": {"manual", false}}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: source, packaged = %v, want %v", p, got[p], w)
		}
	}
}

// the small extra of #716: DeviceRefs carries the model, the origin and when the device was approved, so notify names a
// device from one batch read.
func TestDeviceRefsCarryModelOriginAndApproval(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.20.40")}
	if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: hint, Field: observe.Model, Value: "EX4200-48T", Source: observe.SNMP, Confidence: 0.9},
		{AssetHint: hint, Field: observe.OS, Value: "JUNOS 15.1R7.9", Source: observe.SNMP, Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	found := e.idOf("192.168.20.40")
	if err := e.svc.Approve(e.ctx(), "an@acme.example", found); err != nil {
		t.Fatal(err)
	}
	manual := e.addDevice(inventory.AddInput{Vendor: "Fortinet", Product: "FortiGate", Name: "edge"})
	refs, err := e.svc.DeviceRefs(e.ctx(), []string{found, manual})
	if err != nil {
		t.Fatal(err)
	}
	f, m := refs[found], refs[manual]
	if f.Model != "EX4200-48T" || f.OS != "JUNOS 15.1R7.9" || f.Origin != "discovered" || f.ApprovedAt == nil || !f.ApprovedAt.Equal(e.now) {
		t.Errorf("discovered device = model %q os %q origin %q approved_at %v, want EX4200-48T, JUNOS 15.1R7.9, discovered, %v", f.Model, f.OS, f.Origin, f.ApprovedAt, e.now)
	}
	if m.Model != "" || m.OS != "" || m.Origin != "manual" || m.ApprovedAt != nil {
		t.Errorf("declared device = model %q os %q origin %q approved_at %v, want none, none, manual, nil", m.Model, m.OS, m.Origin, m.ApprovedAt)
	}
}

// A first contact recorded while the box clock was ahead is moved back to now when the clock is corrected,
// so the window is at most 36 hours of the corrected clock, not 36 hours plus however far ahead the clock was.
func TestContract_AFirstContactInTheFutureIsMovedToNow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	passive := func(mac string) {
		t.Helper()
		o := observe.Observation{AssetHint: observe.AssetHint{MAC: mac}, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}
		if err := e.svc.Record(e.ctx(), []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	passive("52:54:00:00:02:01") // first contact while the clock is 48 h ahead
	e.tick(-48 * time.Hour)      // NTP corrects the clock
	passive("52:54:00:00:02:02")
	e.tick(37 * time.Hour) // 37 h of the corrected clock; still 11 h before the stored first contact
	passive("52:54:00:00:02:03")
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE mac = '52:54:00:00:02:03'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if ev, ok := e.discovered()[id]; !ok || ev.Learning {
		t.Fatalf("a device found 37 h after the corrected first contact: %+v (found %v), want learning=false", ev, ok)
	}
}
