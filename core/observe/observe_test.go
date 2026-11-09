package observe_test

import (
	"testing"

	"github.com/knt048/vedette/core/observe"
)

func TestValidSourceAndField(t *testing.T) {
	for _, s := range []observe.Source{observe.Manual, observe.Agent, observe.SNMP, observe.Nmap, observe.Scan, observe.Passive} {
		if !observe.ValidSource(s) {
			t.Errorf("source %q should be valid", s)
		}
	}
	for _, s := range []observe.Source{"", "MANUAL", "telepathy"} {
		if observe.ValidSource(s) {
			t.Errorf("source %q should be invalid", s)
		}
	}
	for _, f := range []observe.Field{observe.Hostname, observe.MAC, observe.Vendor, observe.Model, observe.OS, observe.Kind} {
		if !observe.ValidField(f) {
			t.Errorf("field %q should be valid", f)
		}
	}
	if observe.ValidField("ip") || observe.ValidField("") {
		t.Error("ip is a hint, not a field")
	}
}
