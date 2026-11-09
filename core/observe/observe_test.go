package observe_test

import (
	"errors"
	"fmt"
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

// ErrRejected carries the index of the refused item and still lets errors.Is see the reason.
func TestErrRejectedCarriesTheIndexAndTheReason(t *testing.T) {
	t.Parallel()
	reason := errors.New("value must be printable")
	err := fmt.Errorf("record: %w", &observe.ErrRejected{Index: 7, Err: reason})
	var rej *observe.ErrRejected
	if !errors.As(err, &rej) || rej.Index != 7 || !errors.Is(err, reason) {
		t.Errorf("err = %v", err)
	}
	if rej.Error() != reason.Error() {
		t.Errorf("message %q", rej.Error())
	}
}
