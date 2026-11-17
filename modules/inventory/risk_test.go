package inventory_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// G4 (kien): every list shows which devices carry risk. Inventory reads it from findings through Config.Risk (RiskSource), never
// from fnd_* tables: exploited = open exploited findings, update = none of those but a likely-exploited or High+ Recommended update,
// nil when clean. The Devices search filters on it.

type fakeRisk map[string]inventory.RiskCounts

func (f fakeRisk) RiskByAsset(_ context.Context, id string) (map[string]inventory.RiskCounts, error) {
	if id == "" {
		return f, nil
	}
	return map[string]inventory.RiskCounts{id: f[id]}, nil
}

func withRisk(r inventory.RiskSource) opt { return func(c *inventory.Config) { c.Risk = r } }

// riskDevices records three devices found on the network: one with exploited findings, one with an update, one clean.
func riskDevices(e *env) (exploited, update, clean string) {
	e.t.Helper()
	for i, mac := range []string{macA, macB, "aa:bb:cc:00:00:03"} {
		e.record(obs(netip.AddrFrom4([4]byte{192, 168, 18, byte(10 + i)}), mac, observe.Kind, "server", observe.Nmap, 0.9))
	}
	return e.idByMAC(macA), e.idByMAC(macB), e.idByMAC("aa:bb:cc:00:00:03")
}

func TestContract_G4_RiskMarkerOnRowsAndDetail(t *testing.T) {
	t.Parallel()
	risk := fakeRisk{}
	e := newEnv(t, withRisk(risk))
	x, u, c := riskDevices(e)
	risk[x] = inventory.RiskCounts{Exploited: 2, Updates: 1}
	risk[u] = inventory.RiskCounts{Updates: 3}
	risk[c] = inventory.RiskCounts{} // counts of zero are clean
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*inventory.Risk{}
	for _, d := range l.Items {
		got[d.ID] = d.Risk
	}
	if r := got[x]; r == nil || *r != (inventory.Risk{Level: "exploited", Exploited: 2, Updates: 1}) {
		t.Errorf("exploited: %+v", r)
	}
	if r := got[u]; r == nil || *r != (inventory.Risk{Level: "update", Updates: 3}) {
		t.Errorf("update: %+v", r)
	}
	if got[c] != nil {
		t.Errorf("clean: %+v", got[c])
	}
	d, err := e.svc.DetailPage(e.ctx(), x)
	if err != nil || d.Risk == nil || d.Risk.Level != "exploited" {
		t.Errorf("detail: %+v, %v", d.Risk, err)
	}
	// No RiskSource (findings off): nothing is marked.
	plain := newEnv(t)
	riskDevices(plain)
	l, _ = plain.svc.DevicesPage(plain.ctx(), inventory.DeviceFilter{})
	for _, d := range l.Items {
		if d.Risk != nil {
			t.Errorf("no risk source, yet %s is marked %+v", d.ID, d.Risk)
		}
	}
}

func TestContract_G4_TheRiskFilter(t *testing.T) {
	t.Parallel()
	risk := fakeRisk{}
	e := newEnv(t, withRisk(risk))
	x, u, c := riskDevices(e)
	risk[x], risk[u] = inventory.RiskCounts{Exploited: 1}, inventory.RiskCounts{Updates: 1}
	ids := func(risks string) map[string]bool {
		t.Helper()
		f, err := inventory.ParseDeviceSearch("", "", "", "", "", risks, "")
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(e.ctx(), f)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, d := range l.Items {
			if !d.IsBox {
				out[d.ID] = true
			}
		}
		return out
	}
	for risks, want := range map[string][]string{
		"exploited": {x}, "update": {u}, "none": {c}, "exploited,update": {x, u}, "update,none": {u, c}, "EXPLOITED, none": {x, c}, "": {x, u, c},
	} {
		got := ids(risks)
		if len(got) != len(want) {
			t.Errorf("risk=%q: %v, want %v", risks, got, want)
		}
		for _, id := range want {
			if !got[id] {
				t.Errorf("risk=%q: %s missing", risks, id)
			}
		}
	}
	_, err := inventory.ParseDeviceSearch("", "", "", "", "", "high", "")
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "bad_filter" {
		t.Errorf("risk=high: %v, want 400 bad_filter", err)
	}
}

func TestHandlers_G4_RiskThroughTheAPI(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	id := a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","ip":"192.168.30.1"}`, 201, "")["id"].(string)
	// newAPI has no RiskSource: the field is there and null
	row := a.want("GET", "/inventory/devices?risk=none", "viewer", "", 200, "")["items"].([]any)
	if len(row) != 2 || row[0].(map[string]any)["risk"] != nil {
		t.Fatalf("risk=none = %v", row)
	}
	if items := a.want("GET", "/inventory/devices?risk=exploited", "viewer", "", 200, "")["items"].([]any); len(items) != 0 {
		t.Fatalf("risk=exploited = %v", items)
	}
	a.want("GET", "/inventory/devices?risk=bad", "viewer", "", 400, "bad_filter")
	if d := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, ""); d["risk"] != nil {
		t.Fatalf("detail risk = %v", d["risk"])
	}
	if _, ok := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")["risk"]; !ok {
		t.Fatal("detail has no risk field")
	}
}
