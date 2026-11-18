package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// SimilarDevices: same maker or the same known type, same maker first; never the device itself, an ignored device, or a device that
// is neither; a device of unknown type is not "the same type" as another unknown one.
func TestSimilarDevices(t *testing.T) {
	e := newEnv(t)
	mk := func(last byte, mac, vendor, kind string) string {
		ip := netip.AddrFrom4([4]byte{192, 168, 1, last})
		h := observe.AssetHint{IP: ip, MAC: mac}
		obs := []observe.Observation{{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Passive, Confidence: 0.9}}
		if vendor != "" {
			obs = append(obs, observe.Observation{AssetHint: h, Field: observe.Vendor, Value: vendor, Source: observe.SNMP, Confidence: 0.9})
		}
		if kind != "" {
			obs = append(obs, observe.Observation{AssetHint: h, Field: observe.Kind, Value: kind, Source: observe.SNMP, Confidence: 0.9})
		}
		e.record(obs...)
		return e.idOf(ip.String())
	}
	src := mk(10, "aa:bb:cc:00:00:10", "Fortinet", "switch")
	maker := mk(11, "aa:bb:cc:00:00:11", "fortinet", "")
	same := mk(12, "aa:bb:cc:00:00:12", "Other", "switch")
	both := mk(13, "aa:bb:cc:00:00:13", "Fortinet", "switch")
	ignored := mk(14, "aa:bb:cc:00:00:14", "Fortinet", "switch")
	_ = mk(15, "aa:bb:cc:00:00:15", "Other", "printer")
	if err := e.svc.SetIgnored(e.ctx(), "admin", ignored, true); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.SimilarDevices(e.ctx(), src)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, d := range got {
		ids = append(ids, d.ID)
	}
	want := []string{maker, both, same}
	if len(ids) != 3 || (ids[0] != maker || ids[1] != both) && (ids[0] != both || ids[1] != maker) || ids[2] != same {
		t.Fatalf("similar = %v, want the two of the same maker first (%v), then %s", ids, want, same)
	}
	for _, d := range got {
		if d.ID == both && (!d.SameMaker || !d.SameType) || d.ID == maker && (!d.SameMaker || d.SameType) || d.ID == same && (d.SameMaker || !d.SameType) {
			t.Errorf("flags of %+v", d)
		}
	}
	// a device with no maker and no type is similar to nothing
	bare := mk(16, "aa:bb:cc:00:00:16", "", "")
	if got, err := e.svc.SimilarDevices(e.ctx(), bare); err != nil || len(got) != 0 {
		t.Errorf("a bare device: %v %v", got, err)
	}
}
