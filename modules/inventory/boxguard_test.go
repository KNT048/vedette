package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Only an agent describes the box (INV-3, M2 of the SP-4 review): what a sensor says about the MAC or the address of the box
// creates no device, sets no MAC on the box and moves nothing.
func TestSensorsCannotChangeTheBox(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	boxIP := netip.MustParseAddr("192.168.10.250")
	id, err := e.svc.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: boxIP.String()})
	if err != nil {
		t.Fatal(err)
	}
	row := func() (mac, ip, host string) {
		var m, i, h *string
		if err := e.db.Reader().QueryRowContext(ctx, `SELECT mac, ip, hostname FROM inv_asset WHERE id = ?`, id).Scan(&m, &i, &h); err != nil {
			t.Fatal(err)
		}
		for _, p := range []**string{&m, &i, &h} {
			if *p == nil {
				v := ""
				*p = &v
			}
		}
		return *m, *i, *h
	}
	m0, ip0, h0 := row()
	hint := observe.AssetHint{IP: boxIP, MAC: "02:00:00:00:0b:0b"}
	for _, source := range []observe.Source{observe.Passive, observe.Scan, observe.Nmap, observe.SNMP} {
		batch := []observe.Observation{
			{AssetHint: hint, Field: observe.MAC, Value: hint.MAC, Source: source, Confidence: 0.9},
			{AssetHint: observe.AssetHint{IP: boxIP}, Field: observe.Hostname, Value: "evil", Source: source, Confidence: 0.9},
		}
		if err := e.svc.Record(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	if m, ip, h := row(); m != m0 || ip != ip0 || h != h0 {
		t.Errorf("the box changed: %q %q %q -> %q %q %q", m0, ip0, h0, m, ip, h)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 1 {
		t.Errorf("%d devices: a sensor's view of the box became one", n)
	}
	// the agent is the one that may: the same observation with source agent sets the MAC
	if err := e.svc.Record(ctx, []observe.Observation{{AssetHint: hint, Field: observe.MAC, Value: hint.MAC, Source: observe.Agent, Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := row(); m != hint.MAC {
		t.Errorf("the agent could not set the MAC of the box: %q", m)
	}
}

// A device a person declared keeps its address against what a sensor sees (L10); an agent may move it.
func TestSensorsCannotMoveADeclaredDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ctx := e.ctx()
	r, err := e.svc.AddDevice(ctx, "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.20"})
	if err != nil {
		t.Fatal(err)
	}
	e.exec(`UPDATE inv_asset SET mac = '02:00:00:00:0d:0d' WHERE id = ?`, r.ID)
	ip := func() string {
		var v *string
		if err := e.db.Reader().QueryRowContext(ctx, `SELECT ip FROM inv_asset WHERE id = ?`, r.ID).Scan(&v); err != nil || v == nil {
			t.Fatalf("ip: %v %v", v, err)
		}
		return *v
	}
	moved := observe.AssetHint{MAC: "02:00:00:00:0d:0d", IP: netip.MustParseAddr("192.168.10.99")}
	obs := func(src observe.Source) []observe.Observation {
		return []observe.Observation{{AssetHint: moved, Field: observe.Hostname, Value: "fw", Source: src, Confidence: 0.6}}
	}
	if err := e.svc.Record(ctx, obs(observe.Passive)); err != nil {
		t.Fatal(err)
	}
	if got := ip(); got != "192.168.10.20" {
		t.Fatalf("a sensor moved the declared device to %s", got)
	}
	if err := e.svc.Record(ctx, obs(observe.Agent)); err != nil {
		t.Fatal(err)
	}
	if got := ip(); got != "192.168.10.99" {
		t.Errorf("an agent could not move it: %s", got)
	}
}
