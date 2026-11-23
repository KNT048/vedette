package inventory_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// presentLines is the product of each present software line of a device, with the sources of its readings.
func (e *env) presentLines(id string) map[string][]string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT w.product, r.source FROM inv_software w JOIN inv_software_reading r ON r.software_id = w.id
		WHERE w.asset_id = ? AND w.state = 'present' ORDER BY w.product, r.source`, id)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var p, s string
		if err := rows.Scan(&p, &s); err != nil {
			e.t.Fatal(err)
		}
		out[strings.ToLower(p)] = append(out[strings.ToLower(p)], s)
	}
	return out
}

// A device added by hand with its address and merged into a found VM comes back from Split as it was: added by hand (so it is not
// scanned like a found device), with the ESXi line a person entered for it (so its findings are its own again), and the VM keeps
// none of it.
func TestSplit_GivesBackTheHandAddedDeviceItsSoftwareAndOrigin(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	e.tick(time.Minute)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	vm := e.idOf("192.0.2.131")
	if err := e.svc.Merge(e.ctx(), admin, vm, hand); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.presentLines(vm)["esxi"]; !ok {
		t.Fatalf("the merge did not move the ESXi line: %v", e.presentLines(vm))
	}
	back, err := e.svc.Split(e.ctx(), admin, vm, "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if back != hand {
		t.Fatalf("split gave %s, want %s", back, hand)
	}
	if d := e.device(back); d.Origin != "manual" {
		t.Errorf("origin after the split = %q, want manual", d.Origin)
	}
	if got := e.presentLines(back); !slices.Equal(got["esxi"], []string{"manual"}) {
		t.Errorf("software given back: %v, want the ESXi line entered by hand", got)
	}
	if got := e.presentLines(vm); len(got["esxi"]) > 0 {
		t.Errorf("the VM kept the ESXi line: %v", got)
	}
}

// When both devices of a merge hold a line of one product, the merge folds them into one; the split gives the merged device back its
// own reading of that product and the kept device keeps its own.
func TestSplit_GivesBackTheMergedDevicesReadingOfAFoldedLine(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	e.tick(time.Minute)
	host := esxiHost(e)
	if err := e.svc.Merge(e.ctx(), admin, host, hand); err != nil {
		t.Fatal(err)
	}
	if got := e.presentLines(host)["esxi"]; !slices.Contains(got, "manual") || !slices.Contains(got, "nmap") {
		t.Fatalf("the merge did not fold the ESXi lines: %v", e.presentLines(host))
	}
	back, err := e.svc.Split(e.ctx(), admin, host, "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.presentLines(back)["esxi"]; !slices.Equal(got, []string{"manual"}) {
		t.Errorf("readings given back: %v, want the person's entry", got)
	}
	if got := e.presentLines(host)["esxi"]; slices.Contains(got, "manual") || !slices.Contains(got, "nmap") {
		t.Errorf("readings the host kept: %v, want its scan's only", got)
	}
}

// A person who picked the merged device's name, type and OS for the kept one gets the kept device's own back when the split undoes the
// merge, unless they were changed again since; the device split off keeps its own.
func TestSplit_GivesTheKeptDeviceItsOwnNameTypeAndOSBack(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard2, "192.0.2.130", "vm-b")...)
	kept, gone := e.idOf("192.0.2.131"), e.idOf("192.0.2.130")
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		id string
		p  inventory.Patch
	}{
		{gone, inventory.Patch{Name: str("Build VM"), Kind: str("nas"), OS: str("Debian 12")}},
		{kept, inventory.Patch{Name: str("Kept VM"), Kind: str("server"), OS: str("Ubuntu 24.04")}}, // set later: the merge alone keeps it
	} {
		e.tick(time.Minute)
		if err := e.svc.PatchDevice(e.ctx(), admin, c.id, c.p); err != nil {
			t.Fatal(err)
		}
	}
	e.tick(time.Minute)
	if err := e.svc.MergeMany(e.ctx(), admin, kept, []string{gone}, inventory.MergeChoice{Name: str("Build VM"), Kind: str("nas"), OS: str("Debian 12")}); err != nil {
		t.Fatal(err)
	}
	if d := e.device(kept); e.nameOf(kept) != "Build VM" || d.Kind != "nas" || d.OS == nil || d.OS.Value != "Debian 12" {
		t.Fatalf("the merge did not take the picked values: %q %q %v", e.nameOf(kept), d.Kind, d.OS)
	}
	e.tick(time.Minute)
	back, err := e.svc.Split(e.ctx(), admin, kept, "192.0.2.130")
	if err != nil {
		t.Fatal(err)
	}
	if d := e.device(kept); e.nameOf(kept) != "Kept VM" || d.Kind != "server" || d.OS == nil || d.OS.Value != "Ubuntu 24.04" {
		t.Errorf("kept device after the split: %q %q %v, want Kept VM, server, Ubuntu 24.04", e.nameOf(kept), d.Kind, d.OS)
	}
	if d := e.device(back); e.nameOf(back) != "Build VM" || d.Kind != "nas" || d.OS == nil || d.OS.Value != "Debian 12" {
		t.Errorf("device split off: %q %q %v, want Build VM, nas, Debian 12", e.nameOf(back), d.Kind, d.OS)
	}
	// renamed after the merge: the person's later name stays
	if err := e.svc.Merge(e.ctx(), admin, kept, back); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.MergeMany(e.ctx(), admin, kept, nil, inventory.MergeChoice{}); err == nil {
		t.Fatal("a merge of no device went through")
	}
	if err := e.rename(kept, "Rack VM"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Split(e.ctx(), admin, kept, "192.0.2.130"); err != nil {
		t.Fatal(err)
	}
	if e.nameOf(kept) != "Rack VM" {
		t.Errorf("a name set after the merge was undone by the split: %q", e.nameOf(kept))
	}
}

// A hand-added device without an address is offered against a found device of the same OS release only when that device is the one
// found running it: a fleet of hosts at one build is normal, and offering every one of them is a guess. Once a person kept the others
// separate, the one left is offered. The offer says why: the same OS at the same version and build.
func TestSameDevice_SameOSIsOfferedOnlyWhenOneFoundDeviceRunsIt(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01"})
	e.tick(time.Minute)
	hosts := []string{esxiHost(e), esxiHostWith(e, "192.0.2.68", "3c:a8:2a:10:00:68"), esxiHostWith(e, "192.0.2.69", "00:50:56:20:00:69")}
	if got := e.sameAs(hand); len(got) != 0 {
		t.Errorf("offered against one of three hosts of the same build: %+v", got)
	}
	for _, h := range hosts {
		if got := e.sameAs(h); len(got) != 0 {
			t.Errorf("host %s offered: %+v", h, got)
		}
	}
	for _, h := range hosts[1:] {
		if err := e.svc.KeepSeparate(e.ctx(), admin, hand, h); err != nil {
			t.Fatal(err)
		}
	}
	got := e.sameAs(hand)
	if len(got) != 1 || got[0].ID != hosts[0] || got[0].Reason != inventory.ReasonSameOS {
		t.Fatalf("offered once the others are kept separate: %+v, want %s", got, hosts[0])
	}
	for _, w := range []string{"same OS, version and build", "the only device found"} {
		if !strings.Contains(got[0].Why, w) {
			t.Errorf("offer %q does not say %q", got[0].Why, w)
		}
	}
}

// A merged device with more observations than the merge record holds still comes back with what identifies it: its maker, model,
// host name, type and OS.
func TestSplit_KeepsTheIdentityOfAMergedDeviceWithManyObservations(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard2, "192.0.2.130", "vm-b")...)
	kept, gone := e.idOf("192.0.2.131"), e.idOf("192.0.2.130")
	long := strings.Repeat("x", 190)
	for i := range 32 { // older host names of every source, each near the longest a name may be
		for _, src := range []string{"agent", "snmp", "nmap", "passive", "scan", "manual"} {
			for _, f := range []string{"hostname", "model"} {
				e.exec(`INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at) VALUES (?, ?, ?, ?, ?, 0.1, '2026-01-01T00:00:00.000Z')`,
					fmt.Sprintf("o-old-%s-%s-%d", f, src, i), gone, f, fmt.Sprintf("%s-%02d", long, i), src)
			}
		}
	}
	e.tick(time.Minute)
	e.record(vmCard(vmCard2, "192.0.2.130", "vm-b")...) // the device is decided again over every observation
	ident := func(d inventory.Device) string {
		v := func(o *inventory.Observed) string {
			if o == nil {
				return "-"
			}
			return o.Value
		}
		h := "-"
		if d.Hostname != nil {
			h = *d.Hostname
		}
		return fmt.Sprintf("host %s maker %s model %s type %s", h, v(d.Vendor), v(d.Model), d.Kind)
	}
	wantBack, wantKept := ident(e.device(gone)), ident(e.device(kept))
	if err := e.svc.Merge(e.ctx(), admin, kept, gone); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_merged_from WHERE length(facts) > 1000`); n != 1 {
		t.Fatalf("the merge kept no observations: %d rows with facts", n)
	}
	back, err := e.svc.Split(e.ctx(), admin, kept, "192.0.2.130")
	if err != nil {
		t.Fatal(err)
	}
	if got := ident(e.device(back)); got != wantBack {
		t.Errorf("device given back: %s, want %s", got, wantBack)
	}
	if got := ident(e.device(kept)); got != wantKept {
		t.Errorf("kept device after the split: %s, want %s", got, wantKept)
	}
}

// A device that took a hand-added one in a merge and then joins a third device carries what that merge kept: splitting the
// hand-added device's address off the third gives it back with its software, and no merge record is left behind.
func TestSplit_GivesBackTheSoftwareAfterTheKeptDeviceJoinedAnother(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	e.tick(time.Minute)
	e.record(vmCard("52:54:00:76:6d:01", "192.0.2.132", "")...)
	e.tick(time.Minute)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	third, kept := e.idOf("192.0.2.132"), e.idOf("192.0.2.131")
	if err := e.svc.Merge(e.ctx(), admin, kept, hand); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), admin, third, kept); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_merged_reading WHERE asset_id = ? AND from_id = ?`, third, hand); n == 0 {
		t.Fatal("the hand-added device's readings did not follow its merge record")
	}
	back, err := e.svc.Split(e.ctx(), admin, third, "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if back != hand || e.device(back).Origin != "manual" || !slices.Equal(e.presentLines(back)["esxi"], []string{"manual"}) || len(e.presentLines(third)["esxi"]) > 0 {
		t.Errorf("split off the third device: %s %q %v, third keeps %v", back, e.device(back).Origin, e.presentLines(back), e.presentLines(third))
	}
	if _, err := e.svc.Split(e.ctx(), admin, third, "192.0.2.131"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM inv_merged_reading`) + e.count(`SELECT count(*) FROM inv_merged_from`); n != 0 {
		t.Errorf("%d merge records left after both splits", n)
	}
}
