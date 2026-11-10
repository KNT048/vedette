package sensorpassive

import (
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
)

// FuzzCheckItem: whatever a sensor puts in an item, checkItem either rejects it with a code of the closed set or hands out an
// observation that satisfies everything core promises about passive observations (sensor-protocol.md 5 and 6.2, INV-3, INV-5).
func FuzzCheckItem(f *testing.F) {
	f.Add("0a:00:00:00:00:01", "192.168.10.5", "hostname", "printer-3f", 0.6, int64(1_800_000_000))
	f.Add("", "10.0.0.1", "vendor", "Acme", 1.0, int64(1_800_000_000))
	f.Add("01:00:5e:00:00:01", "", "hostname", "x", 0.5, int64(0))
	f.Add("0a:00:00:00:00:01", "fe80::1", "os", "evil\u202egpj", 7.0, int64(-5))
	f.Add("0A:00:00:00:00:01", "255.255.255.255", "ip", "", -1.0, int64(1_800_000_000))
	now := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, mac, ip, field, value string, conf float64, secs int64) {
		it := sensorlink.ObservationItem{MAC: mac, IP: ip, Field: field, Value: value, Confidence: conf, SeenAt: time.Unix(secs%4_000_000_000, 0)}
		o, code := checkItem(it, now)
		if code != "" {
			if code != codeInvalidItem && code != codeOutOfWindow {
				t.Fatalf("code %q is not in the closed set", code)
			}
			return
		}
		if o.Source != observe.Passive || !observe.ValidField(o.Field) || o.Value != value || len(o.Value) < 1 || len(o.Value) > capture.MaxValueBytes || !capture.Printable(o.Value) {
			t.Fatalf("accepted %+v", o)
		}
		if o.AssetHint.MAC == "" && !o.AssetHint.IP.IsValid() {
			t.Fatalf("accepted an item about nothing: %+v", o)
		}
		if m := o.AssetHint.MAC; m != "" && (!sensorlink.ValidMAC(m) || firstOctet(m)&1 == 1 || m == "00:00:00:00:00:00") {
			t.Fatalf("accepted MAC %q", o.AssetHint.MAC)
		}
		if a := o.AssetHint.IP; a.IsValid() && (!a.Is4() || !capture.UnicastIP(a)) {
			t.Fatalf("accepted address %v", a)
		}
		if !(o.Confidence >= 0 && o.Confidence <= capture.MaxConfidence(o.Field)) {
			t.Fatalf("confidence %v over the cap of %s", o.Confidence, o.Field)
		}
		if o.SeenAt.Before(now.Add(-seenBack)) || o.SeenAt.After(now.Add(seenAhead)) {
			t.Fatalf("seen_at %v outside the window", o.SeenAt)
		}
	})
}

func firstOctet(m string) byte { b, _ := hexByte(m); return b }
