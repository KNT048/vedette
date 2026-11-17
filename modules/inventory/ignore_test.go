package inventory_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// D-630 (kien 2026-11-17: "some devices need no watching, a staff phone"): Ignore keeps a device known but unwatched. The N100's
// "iPhone" at 192.168.18.129 with its private MAC.
const phoneMAC = "c2:31:86:3f:8c:a0"

func (e *env) list(ignored string, approved string) inventory.DeviceList {
	e.t.Helper()
	f, err := inventory.ParseDeviceFilter(approved, "", "", ignored, "", "", "")
	if err != nil {
		e.t.Fatal(err)
	}
	l, err := e.svc.DevicesPage(e.ctx(), f)
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func ids(l inventory.DeviceList) []string {
	out := make([]string, 0, len(l.Items))
	for _, d := range l.Items {
		out = append(out, d.ID)
	}
	return out
}

func TestContract_D630_AnIgnoredDeviceIsKnownButNotWatched(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.confirmScope("192.168.18.0/24")
	const who = "it@acme.example"
	ip := netip.MustParseAddr("192.168.18.129")
	e.record(obs(ip, phoneMAC, observe.Hostname, "iPhone", observe.Passive, 0.7))
	id := e.idByMAC(phoneMAC)
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: ip, MAC: phoneMAC}, observe.Nmap, []observe.Software{
		{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9},
	}); err != nil {
		t.Fatal(err)
	}
	if l := e.list("", "false"); !slices.Contains(ids(l), id) || l.Counts.Pending != 1 {
		t.Fatalf("before: To review = %v, counts %+v", ids(l), l.Counts)
	}

	// Ignore: one audit row, updated (stop what runs on it) then ignored (notify, findings) naming the person.
	e.ev.reset()
	if err := e.svc.SetIgnored(e.ctx(), who, id, true); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.ignore' AND user = ?`, who); n != 1 {
		t.Fatalf("audit rows = %d", n)
	}
	if up, ig := e.ev.named(inventory.EventAssetUpdated), e.ev.named(inventory.EventAssetIgnored); len(up) != 1 || len(ig) != 1 ||
		ig[0].Data.(inventory.AssetEvent) != (inventory.AssetEvent{AssetID: id, Actor: who}) {
		t.Fatalf("events: updated %+v, ignored %+v", up, ig)
	}

	// Not in To review, not in the badge, not in the Devices list or its counts; the ignored filter lists it.
	if l := e.list("", "false"); slices.Contains(ids(l), id) || l.Counts.Pending != 0 || l.Counts.Ignored != 1 {
		t.Fatalf("To review = %v, counts %+v", ids(l), l.Counts)
	}
	if l := e.list("", ""); slices.Contains(ids(l), id) || l.Counts.All != 0 {
		t.Fatalf("Devices = %v, counts %+v", ids(l), l.Counts)
	}
	if l := e.list("true", ""); !slices.Equal(ids(l), []string{id}) || l.Items[0].IgnoredAt == nil {
		t.Fatalf("ignored=true = %+v", l.Items)
	}
	if total, pending, err := e.svc.DeviceCounts(e.ctx()); err != nil || total != 0 || pending != 0 {
		t.Fatalf("Home counts = %d, %d, %v", total, pending, err)
	}
	if l, err := e.svc.Devices(e.ctx()); err != nil || !slices.Contains(ids(l), id) {
		t.Fatalf("the other modules (honeypot names a trap hit's source) still read it: %v, %v", ids(l), err)
	}

	// No scan, no SNMP read, left out of the sweep, refused even as a pick in Scan now.
	if d, _ := e.svc.ScanPolicy(e.ctx(), id); d.Allowed || d.Reason != inventory.ReasonRegularScanNever {
		t.Fatalf("scan: %+v", d)
	}
	if d, _ := e.svc.SNMPPolicy(e.ctx(), id); d.Allowed || d.Reason != inventory.ReasonSNMPOff {
		t.Fatalf("snmp: %+v", d)
	}
	if d, _ := e.svc.VulnScanPolicy(e.ctx(), id, true); d.Allowed {
		t.Fatalf("vulnerability scan: %+v", d)
	}
	if list, _ := e.svc.ProtectedIPs(e.ctx()); !slices.Contains(list, ip) {
		t.Fatalf("protected = %v", list)
	}
	on := inventory.SourceOn
	if _, err := e.svc.SetSources(e.ctx(), "admin@acme.example", id, &on, nil); err == nil {
		t.Fatal("a source turned on for an ignored device")
	} else {
		wantAPIError(t, err, 409, "device_ignored")
	}

	// No findings: outside every vulnerability reader.
	if _, ok, err := e.svc.MatchInput(e.ctx(), id); ok || err != nil {
		t.Fatalf("MatchInput = %v, %v", ok, err)
	}
	if all, err := e.svc.AssetIDs(e.ctx()); err != nil || slices.Contains(all, id) {
		t.Fatalf("AssetIDs = %v, %v", all, err)
	}
	if got, err := e.svc.DevicesRunning(e.ctx(), []inventory.ProductQuery{{Vendor: "OpenBSD", Product: "OpenSSH"}}); err != nil || len(got) != 0 {
		t.Fatalf("DevicesRunning = %+v, %v", got, err)
	}

	// Seen again by its MAC at another address: the same device, still ignored, no new-device alert.
	e.ev.reset()
	e.record(obs(netip.MustParseAddr("192.168.18.140"), phoneMAC, observe.Hostname, "iPhone", observe.Passive, 0.7))
	if e.idByMAC(phoneMAC) != id || len(e.ev.named(inventory.EventAssetDiscovered)) != 0 {
		t.Fatalf("seen again: id %s, discovered %+v", e.idByMAC(phoneMAC), e.ev.named(inventory.EventAssetDiscovered))
	}
	if d := e.detail(id); d.Asset.IgnoredAt == nil || d.Asset.IP != "192.168.18.140" {
		t.Fatalf("seen again: %+v", d.Asset.AssetCore)
	}

	// Saying it again changes nothing.
	e.ev.reset()
	if err := e.svc.SetIgnored(e.ctx(), who, id, true); err != nil || len(e.ev.named(inventory.EventAssetIgnored)) != 0 ||
		e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.ignore'`) != 1 {
		t.Fatalf("again: %v, %+v", err, e.ev.named(inventory.EventAssetIgnored))
	}

	// Undo: back through review (not approved), sources on (a discovered device's default), matched again, queued for a scan.
	e.ev.reset()
	if err := e.svc.SetIgnored(e.ctx(), who, id, false); err != nil {
		t.Fatal(err)
	}
	if up := e.ev.named(inventory.EventAssetUpdated); len(up) != 1 || !up[0].Data.(inventory.AssetEvent).Match || !up[0].Data.(inventory.AssetEvent).ScanOn {
		t.Fatalf("undo events: %+v", up)
	}
	if un := e.ev.named(inventory.EventAssetUnignored); len(un) != 1 || un[0].Data.(inventory.AssetEvent) != (inventory.AssetEvent{AssetID: id, Actor: who}) {
		t.Fatalf("undo publishes unignored (findings reopens what Ignore closed): %+v", un)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.unignore'`) != 1 {
		t.Fatal("no audit row for the undo")
	}
	if l := e.list("", "false"); !slices.Contains(ids(l), id) || l.Counts.Pending != 1 || l.Counts.Ignored != 0 {
		t.Fatalf("after undo: To review = %v, counts %+v", ids(l), l.Counts)
	}
	if d := e.detail(id); d.Asset.IgnoredAt != nil || d.Asset.Approved || d.Asset.ScanSource != inventory.SourceOn || d.Asset.SNMPSource != inventory.SourceOn {
		t.Fatalf("after undo: %+v", d.Asset.AssetCore)
	}
	if _, ok, err := e.svc.MatchInput(e.ctx(), id); !ok || err != nil {
		t.Fatalf("after undo MatchInput = %v, %v", ok, err)
	}
}

// An approved device a person ignores (from its page) and then stops ignoring goes through review again; the box cannot be ignored.
func TestContract_D630_UndoSendsAnApprovedDeviceBackToReview(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(obs(netip.MustParseAddr("192.168.18.20"), macA, observe.Hostname, "laptop-ha", observe.Passive, 0.7))
	id := e.idByMAC(macA)
	if err := e.svc.Approve(e.ctx(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetIgnored(e.ctx(), "it@acme.example", id, true); err != nil {
		t.Fatal(err)
	}
	if l := e.list("", "true"); slices.Contains(ids(l), id) {
		t.Fatal("an ignored approved device stays in the Devices list")
	}
	if err := e.svc.SetIgnored(e.ctx(), "it@acme.example", id, false); err != nil {
		t.Fatal(err)
	}
	if d := e.detail(id); d.Asset.Approved || d.Asset.ApprovedAt != nil {
		t.Fatalf("after undo: approved %v at %v", d.Asset.Approved, d.Asset.ApprovedAt)
	}
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette", IP: "192.168.18.2"})
	if err != nil {
		t.Fatal(err)
	}
	wantAPIError(t, e.svc.SetIgnored(e.ctx(), "it@acme.example", box, true), 409, "box_device")
	wantAPIError(t, e.svc.SetIgnored(e.ctx(), "it@acme.example", "nope", true), 404, "not_found")
}

// An osquery enrolment never approves a device a person ignored: a person's choice wins, as a suspicious mark does (INV-25).
func TestContract_D630_AnOsqueryEnrolmentDoesNotApproveAnIgnoredDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.18.30")
	e.record(obs(ip, macA, observe.Hostname, "staff-pc", observe.Passive, 0.7))
	id := e.idByMAC(macA)
	if err := e.svc.SetIgnored(e.ctx(), "it@acme.example", id, true); err != nil {
		t.Fatal(err)
	}
	if found, err := e.svc.ApproveEnrolled(e.ctx(), observe.AssetHint{IP: ip, MAC: macA}, macA, "test", false); err != nil || !found {
		t.Fatalf("ApproveEnrolled = %v, %v", found, err)
	}
	if d := e.detail(id); d.Asset.Approved || d.Asset.IgnoredAt == nil {
		t.Fatalf("an enrolment approved an ignored device: %+v", d.Asset.AssetCore)
	}
}
