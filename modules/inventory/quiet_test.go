package inventory_test

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// A phone that rotates its private Wi-Fi address (INV-49): one that shows nothing wrong is listed but is no To review item and sends no
// new-device notice; an open service, or a stay of more than a day, makes it one.
const (
	qemuMAC = "52:54:00:76:6e:02" // a QEMU/KVM guest: locally administered but stable
	dockMAC = "02:42:ac:11:00:02" // Docker's default bridge
)

func (e *env) quietEnv() *env {
	e.t.Helper()
	if err := e.svc.SetNotifyNew(e.ctx(), "it@acme.example", true); err != nil {
		e.t.Fatal(err)
	}
	return e
}

func (e *env) review() inventory.DeviceList { return e.list("", "false") }

func (e *env) discoveredNotify() []bool {
	var out []bool
	for _, ev := range e.ev.named(inventory.EventAssetDiscovered) {
		out = append(out, ev.Data.(inventory.AssetEvent).Notify)
	}
	return out
}

func TestPrivateMAC(t *testing.T) {
	t.Parallel()
	for mac, want := range map[string]bool{
		"c2:31:86:3f:8c:a0": true, "86:52:d9:85:7f:a9": true, "7e:ca:40:4d:93:b1": true, "ca:fe:85:f7:61:fb": true,
		"3c:22:fb:00:00:01": false,                                             // burned in
		qemuMAC:             false, dockMAC: false, "0a:00:27:00:00:05": false, // stable virtual prefixes
		"": false, "bad": false,
	} {
		if got := inventory.PrivateMAC(mac); got != want {
			t.Errorf("PrivateMAC(%q) = %v, want %v", mac, got, want)
		}
	}
}

// A quiet random-MAC device: no review item, no notice, but listed in the Devices list and marked private; the page says so.
func TestContract_AQuietPrivateDeviceIsNotToReview(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	e.record(dhcp(phoneMAC, "192.168.18.129", "iPhone")...)
	id := e.idByMAC(phoneMAC)
	if l := e.review(); len(l.Items) != 0 || l.Counts.Pending != 0 || l.Counts.All != 1 {
		t.Fatalf("To review = %v, counts %+v; want none, all 1", ids(l), l.Counts)
	}
	if l := e.list("", "true"); !slices.Contains(ids(l), id) {
		t.Fatalf("Devices list = %v: the quiet device must be listed", ids(l))
	}
	if all, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{}); err != nil || !slices.Contains(ids(all), id) {
		t.Fatalf("All = %v, %v", ids(all), err)
	}
	if total, pending, err := e.svc.DeviceCounts(e.ctx()); err != nil || total != 1 || pending != 0 {
		t.Fatalf("DeviceCounts = %d, %d, %v", total, pending, err)
	}
	d := e.detail(id)
	if !d.Asset.PrivateMAC || !d.Asset.Quiet || d.Asset.Approved {
		t.Fatalf("detail: private %v quiet %v approved %v", d.Asset.PrivateMAC, d.Asset.Quiet, d.Asset.Approved)
	}
	if got := e.discoveredNotify(); !slices.Equal(got, []bool{false}) {
		t.Fatalf("discovered notify flags = %v, want [false]", got)
	}
	if total, err := e.svc.DevicesPage(e.ctx(), mustFilter(t, "q=iphone")); err != nil || len(total.Items) != 1 {
		t.Fatalf("search: %v, %v", total.Items, err)
	}
}

func mustFilter(t *testing.T, _ string) inventory.DeviceFilter {
	t.Helper()
	f, err := inventory.ParseDeviceFilter("", "", "", "", "", "", "iphone")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// An open service is a reason to look: the device joins To review and the notice goes out then, once.
func TestContract_APrivateDeviceWithAServiceIsToReview(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	ip := netip.MustParseAddr("192.168.18.129")
	e.record(dhcp(phoneMAC, ip.String(), "iPhone")...)
	id := e.idByMAC(phoneMAC)
	e.ev.reset()
	e.tick(time.Minute)
	if err := e.svc.AddServices(e.ctx(), observe.AssetHint{IP: ip, MAC: phoneMAC}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if l := e.review(); !slices.Contains(ids(l), id) || l.Counts.Pending != 1 {
		t.Fatalf("To review = %v, counts %+v", ids(l), l.Counts)
	}
	if d := e.detail(id); d.Asset.Quiet || !d.Asset.PrivateMAC {
		t.Fatalf("detail: quiet %v private %v", d.Asset.Quiet, d.Asset.PrivateMAC)
	}
	var notices int
	for _, ev := range e.ev.named(inventory.EventAssetUpdated) {
		if ev.Data.(inventory.AssetEvent).Notify {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("%d new-device notices after the service, want 1", notices)
	}
	e.ev.reset()
	e.tick(time.Minute)
	if err := e.svc.AddServices(e.ctx(), observe.AssetHint{IP: ip, MAC: phoneMAC}, observe.Nmap, []observe.Service{{Port: 22, Proto: "tcp", Name: "ssh", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	for _, ev := range e.ev.named(inventory.EventAssetUpdated) {
		if ev.Data.(inventory.AssetEvent).Notify {
			t.Fatal("a second notice for the same device")
		}
	}
}

// A device that keeps coming back over more than a day is a regular: To review, with its notice at the sighting that crosses the day.
func TestContract_APrivateDeviceThatStaysIsToReview(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	e.record(dhcp(phoneMAC, "192.168.18.129", "Johns-iPhone")...)
	id := e.idByMAC(phoneMAC)
	e.tick(23 * time.Hour)
	e.record(dhcp(phoneMAC, "192.168.18.129", "Johns-iPhone")...)
	if l := e.review(); len(l.Items) != 0 {
		t.Fatalf("after 23 h: To review = %v", ids(l))
	}
	e.ev.reset()
	e.tick(2 * time.Hour)
	e.record(dhcp(phoneMAC, "192.168.18.129", "Johns-iPhone")...)
	if l := e.review(); !slices.Contains(ids(l), id) {
		t.Fatalf("after 25 h: To review = %v", ids(l))
	}
	var notices int
	for _, ev := range e.ev.named(inventory.EventAssetUpdated) {
		if ev.Data.(inventory.AssetEvent).Notify {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("%d notices when the stay passed a day, want 1", notices)
	}
}

// Stable virtual MACs, burned-in MACs and agent or hand-added devices are reviewed at once, as before.
func TestContract_OnlyARandomPrivateAddressIsQuiet(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	e.record(dhcp(qemuMAC, "192.168.18.10", "winlab01")...)
	e.record(dhcp(dockMAC, "192.168.18.11", "runner01")...)
	e.record(dhcp(burnt1, "192.168.18.12", "accounting-pc")...)
	if l := e.review(); len(l.Items) != 3 || l.Counts.Pending != 3 {
		t.Fatalf("To review = %v, counts %+v; want all three", ids(l), l.Counts)
	}
	if got := e.discoveredNotify(); !slices.Equal(got, []bool{true, true, true}) {
		t.Fatalf("discovered notify flags = %v, want all true", got)
	}
	for _, mac := range []string{qemuMAC, dockMAC, burnt1} {
		if d := e.detail(e.idByMAC(mac)); d.Asset.Quiet || d.Asset.PrivateMAC {
			t.Errorf("%s: quiet %v private %v", mac, d.Asset.Quiet, d.Asset.PrivateMAC)
		}
	}
	e.addDevice(inventory.AddInput{Vendor: "Acme", Product: "Branch Printer", Name: "branch-printer"})
	if l := e.review(); l.Counts.Pending != 3 {
		t.Fatalf("a hand-added device changed To review: %+v", l.Counts)
	}
}

// A device with a burned-in MAC among the MACs seen on it is a real machine, not a rotating phone.
func TestContract_APrivateDeviceThatShowedABurnedInMACIsToReview(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	ip := netip.MustParseAddr("192.168.18.50")
	e.record(obs(ip, phoneMAC, observe.Hostname, "gym-tablet", observe.Passive, 0.7))
	e.record(obs(ip, burnt1, observe.MAC, burnt1, observe.Passive, 0.9))
	if l := e.review(); l.Counts.Pending != 1 {
		t.Fatalf("counts %+v, want one to review", l.Counts)
	}
}

// Fold by distinctive name, never by a name many devices share; the folded device keeps its approval and history.
func TestContract_FoldByDistinctiveNameNeverByGenericName(t *testing.T) {
	t.Parallel()
	e := newEnv(t).quietEnv()
	e.record(dhcp(privMac1, "192.168.18.145", "Annas-MacBook-Air")...)
	id := e.idOf("192.168.18.145")
	if err := e.svc.Approve(e.ctx(), "anna", id); err != nil {
		t.Fatal(err)
	}
	e.record(dhcp(privMac3, "192.168.18.150", "iPhone")...)
	e.tick(time.Hour)
	e.record(dhcp(privMac2, "192.168.18.138", "Annas-MacBook-Air")...)
	e.record(dhcp(burnt2, "192.168.18.151", "iPhone")...)
	e.tick(time.Hour)
	e.record(dhcp("86:52:d9:85:7f:a9", "192.168.18.152", "iPhone")...)
	// The laptop folded into its approved device (history kept); the three "iPhone" rows stayed three devices.
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE lower(hostname) LIKE 'annas-macbook-air%'`); n != 1 {
		t.Fatalf("%d laptop rows, want 1", n)
	}
	d := e.detail(id)
	if !d.Asset.Approved || d.Asset.MAC == nil || *d.Asset.MAC != privMac2 || d.Asset.IP != "192.168.18.138" {
		t.Fatalf("laptop: approved %v mac %v ip %s", d.Asset.Approved, d.Asset.MAC, d.Asset.IP)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'mac'`, id); n < 2 {
		t.Fatalf("the folded device kept %d MAC observations, want its history of both", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE hostname = 'iPhone'`); n != 3 {
		t.Fatalf("%d iPhone rows, want 3: a generic name never folds", n)
	}
	// Only the burned-in-MAC one is reviewed at once; the two private ones are quiet.
	if l := e.review(); l.Counts.Pending != 1 {
		t.Fatalf("To review %v, counts %+v; want the burned-in one only", ids(l), l.Counts)
	}
}
