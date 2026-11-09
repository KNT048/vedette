package inventory_test

import (
	"errors"
	"net/netip"
	"testing"

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
