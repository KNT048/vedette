package scan

import (
	"fmt"
	"strings"
	"testing"
)

// D-472: the target list of 500 devices reads the inventory's policy in two batches (when picked, and for an
// automatic run), never once per device; a pick of many devices starts with the same two batches, and only the
// re-check right before each job (INV-1) reads one device. The picker's search fields come with each target.
func TestContract_D472_TargetsReadThePolicyInOneBatch(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	devs := sampleDevices()
	for i := range 493 {
		devs = append(devs, Device{ID: fmt.Sprintf("a-g%03d", i), Label: fmt.Sprintf("PC-%03d", i), IP: fmt.Sprintf("192.168.%d.%d", 10+i/250, 1+i%250), Kind: "pc", Approved: true,
			MAC: fmt.Sprintf("3c:52:82:00:%02x:%02x", i/256, i%256), Vendor: "Dell", LastSeen: "2026-11-10T09:00:00.000Z"})
	}
	r.inv.mu.Lock()
	r.inv.devices = devs
	r.inv.mu.Unlock()

	ts, err := r.svc.Targets(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	r.inv.mu.Lock()
	single, batches := r.inv.single, r.inv.batches
	r.inv.mu.Unlock()
	if len(ts) != 500 || single != 0 || batches != 2 {
		t.Fatalf("targets %d, single reads %d, batches %d; want 500, 0, 2", len(ts), single, batches)
	}
	var g TargetView
	for _, v := range ts {
		if v.ID == "a-g007" {
			g = v
		}
	}
	if g.MAC == nil || *g.MAC != "3c:52:82:00:00:07" || g.Vendor == nil || *g.Vendor != "Dell" || g.LastSeen == nil || !g.Approved || !g.Selectable {
		t.Errorf("a-g007: %+v", g)
	}
	for _, v := range ts {
		if v.ID == "a-unk" && (v.Approved || v.MAC != nil || v.Vendor != nil || v.LastSeen != nil) {
			t.Errorf("a-unk: unknown fields must be null and approved false: %+v", v)
		}
	}

	ids := []string{"a-nas02", "a-web01", "a-g001", "a-g002"}
	if _, err := r.svc.StartRun(r.ctx(), "it@acme.example", ids); err != nil {
		t.Fatal(err)
	}
	r.wait()
	r.inv.mu.Lock()
	single, batches = r.inv.single, r.inv.batches
	r.inv.mu.Unlock()
	if batches != 4 || single != len(ids) {
		t.Errorf("after the run: batches %d, single reads %d; want 4 (two for the list of Scan now) and %d (one re-check per device)", batches, single, len(ids))
	}
}

// Beta item 27: a product added by hand without an address is listed with the reason no_ip, not out_of_scope, and
// Scan now refuses it with that reason.
func TestContract_INV1_NoIPIsItsOwnReason(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.inv.mu.Lock()
	r.inv.devices = append(r.inv.devices, Device{ID: "a-office", Label: "Microsoft Office (no device)", IP: "—", Kind: "unknown", Approved: true})
	r.inv.mu.Unlock()
	r.inv.setPolicy(func(id string, explicit bool) Decision {
		if id == "a-office" {
			return Decision{Reason: reasonNoIP}
		}
		return samplePolicy(id, explicit)
	})
	ts, err := r.svc.Targets(r.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range ts {
		if v.ID == "a-office" && (v.Reason == nil || *v.Reason != "no_ip" || v.Selectable) {
			t.Errorf("a-office: %+v", v)
		}
	}
	_, err = r.svc.StartRun(r.ctx(), "it@acme.example", []string{"a-office"})
	wantAPI(t, err, 400, "out_of_scope")
	if !strings.Contains(err.Error(), "Microsoft Office (no device) (—) has no IP address; add one on the device first") {
		t.Errorf("refusal: %v", err)
	}
}

// D-472: the batch read used by the list, the schedule and the KEV rescan decides exactly as the per-device consent
// (with explicit=false, D-126 (2)), and a device deleted since the list was read is gone.
func TestContract_D472_BatchDecidesAsPerDevice(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	st, err := loadSettings(r.ctx(), r.db.Reader())
	if err != nil {
		t.Fatal(err)
	}
	devs := r.inv.devices
	auto, err := r.svc.policies(r.ctx(), devs, false)
	if err != nil {
		t.Fatal(err)
	}
	var allowed []string
	for _, d := range devs {
		if why, _ := fold(st, d, auto[d.ID]); why == "" {
			allowed = append(allowed, d.ID)
		}
	}
	// the batch fold equals the per-device consent for every sample device
	for _, d := range devs {
		why, _, err := r.svc.consent(r.ctx(), st, d, false)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := fold(st, d, auto[d.ID]); b != why {
			t.Errorf("%s: batch %q, per device %q", d.ID, b, why)
		}
	}
	if len(allowed) != 2 || allowed[0] != "a-web01" || allowed[1] != "a-srv" {
		t.Errorf("an automatic run may scan %v; want [a-web01 a-srv] (the NAS is fragile, the rest refused)", allowed)
	}
	// a device deleted since the list was read is gone, not allowed
	m, err := r.svc.policies(r.ctx(), []Device{{ID: "a-deleted", IP: "192.168.10.99", Approved: true}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if why, _ := fold(st, Device{ID: "a-deleted", IP: "192.168.10.99", Approved: true}, m["a-deleted"]); why != ReasonGone {
		t.Errorf("deleted device: %q, want %q", why, ReasonGone)
	}
}
