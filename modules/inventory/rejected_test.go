package inventory_test

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// PRE-1: a batch with an item the boundary check refuses is refused whole and writes nothing, and the error names the item
// (observe.ErrRejected) so a sensor can drop it and send the rest. The reason is still ErrInvalid.
func TestRecordNamesTheRefusedItem(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	good := func(ip string) observe.Observation {
		return observe.Observation{AssetHint: observe.AssetHint{MAC: macA, IP: netip.MustParseAddr(ip)}, Field: observe.Hostname, Value: "printer", Source: observe.Passive, Confidence: 0.6}
	}
	for name, bad := range map[string]observe.Observation{
		"empty value":        {AssetHint: observe.AssetHint{MAC: macB}, Field: observe.Hostname, Value: "", Source: observe.Passive, Confidence: 0.6},
		"control in a value": {AssetHint: observe.AssetHint{MAC: macB}, Field: observe.Model, Value: "x\x01y", Source: observe.Passive, Confidence: 0.6},
		"no hint":            {Field: observe.Hostname, Value: "x", Source: observe.Passive, Confidence: 0.6},
		"manual source":      {AssetHint: observe.AssetHint{MAC: macB}, Field: observe.Hostname, Value: "x", Source: observe.Manual, Confidence: 0.6},
		"unknown kind":       {AssetHint: observe.AssetHint{MAC: macB}, Field: observe.Kind, Value: "toaster", Source: observe.Passive, Confidence: 0.6},
	} {
		before := count(t, e)
		err := e.svc.Record(e.ctx(), []observe.Observation{good("10.0.0.1"), good("10.0.0.2"), bad, good("10.0.0.3")})
		var rej *observe.ErrRejected
		if !errors.As(err, &rej) || rej.Index != 2 {
			t.Errorf("%s: err = %v, want ErrRejected at index 2", name, err)
			continue
		}
		if !errors.Is(err, inventory.ErrInvalid) {
			t.Errorf("%s: the reason is not ErrInvalid: %v", name, err)
		}
		if count(t, e) != before {
			t.Errorf("%s: the refused batch wrote something", name)
		}
	}
}

func count(t *testing.T, e *env) int {
	t.Helper()
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	return len(l.Items)
}

// INV-16: one device that keeps changing a value does not grow inv_observation without limit; each (device, field, source)
// keeps its latest 32 rows, whatever the sensor, and the other series of the device are untouched.
func TestRecordKeepsTheLatest32ObservationsPerSeries(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	host := func(i int, src observe.Source) observe.Observation {
		return observe.Observation{AssetHint: observe.AssetHint{MAC: macA}, Field: observe.Hostname, Value: fmt.Sprintf("name-%04d", i), Source: src, Confidence: 0.6, SeenAt: e.now.Add(time.Duration(i) * time.Second)}
	}
	if err := e.svc.Record(e.ctx(), []observe.Observation{host(0, observe.Agent)}); err != nil {
		t.Fatal(err)
	}
	for batch := range 4 { // 4 batches of 50 distinct names, two sources
		var obs []observe.Observation
		for i := range 50 {
			obs = append(obs, host(1+batch*50+i, observe.Passive))
		}
		if err := e.svc.Record(e.ctx(), obs); err != nil {
			t.Fatal(err)
		}
	}
	q := `SELECT count(*) FROM inv_observation WHERE field = 'hostname' AND source = ?`
	if n := e.count(q, "passive"); n != 32 {
		t.Errorf("passive hostname rows = %d, want 32", n)
	}
	if n := e.count(q, "agent"); n != 1 {
		t.Errorf("the agent series was touched: %d rows", n)
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE field = 'hostname' AND source = 'passive' AND value = 'name-0200'`); n != 1 {
		t.Error("the latest observation was pruned")
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE field = 'hostname' AND source = 'passive' AND value = 'name-0001'`); n != 0 {
		t.Error("an old observation survived")
	}
	if n := e.count(`SELECT count(*) FROM inv_observation WHERE field = 'mac' AND source = 'passive'`); n != 1 {
		t.Errorf("the MAC series has %d rows, want 1", n)
	}
}
