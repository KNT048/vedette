package response

import "testing"

// D-511: the device_type condition keys on the 13 kinds; a newer device type matches as itself and as the kind it acts as, so the
// template "camera,nvr,iot" still covers an IP phone a person typed, and never a laptop.
func TestDeviceTypeConditionMatchesActsAs(t *testing.T) {
	t.Parallel()
	c := Condition{Op: "device_type", Value: "camera,nvr,iot"}
	for kind, want := range map[string]bool{"camera": true, "ip_phone": true, "dvr": true, "plc": true, "laptop": false, "pc": false, "": false} {
		if got := evalCondition(c, Det{DeviceKind: kind}, nil); got != want {
			t.Errorf("device_type camera,nvr,iot on %q = %v, want %v", kind, got, want)
		}
	}
	if !evalCondition(Condition{Op: "device_type", Value: "ip_phone"}, Det{DeviceKind: "ip_phone"}, nil) {
		t.Error("a type named in the condition matches itself")
	}
}
