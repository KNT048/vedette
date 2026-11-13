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

// An ErrRejected without a reason prints (sensor-passive logs every refusal it gets from a Sink).
func TestErrRejectedWithoutReasonPrints(t *testing.T) {
	t.Parallel()
	if got := (&observe.ErrRejected{Index: 1}).Error(); got == "" {
		t.Error("empty message")
	}
}

// D-503: the kind of an agent's OS, from its platform (a new report) or from the OS text the inventory stored (the upgrade path); both
// give the same kind for the same system.
func TestAgentKind(t *testing.T) {
	for _, c := range []struct{ platform, name, stored, want string }{
		{"ubuntu", "Ubuntu", "Ubuntu 26.04 LTS (Resolute Raccoon)", "server"},
		{"debian", "Debian GNU/Linux", "Debian GNU/Linux 12 (bookworm)", "server"},
		{"rhel", "Red Hat Enterprise Linux", "Red Hat Enterprise Linux 9.4 (Plow)", "server"},
		{"ol", "Oracle Linux Server", "Oracle Linux Server 9.4", "server"},
		{"sles", "SLES", "SLES 15-SP5", "server"},
		{"windows", "Microsoft Windows Server 2022 Datacenter", "Microsoft Windows Server 2022 Datacenter 10.0.20348 build 20348", "server"},
		{"windows", "Microsoft Windows 11 Pro", "Microsoft Windows 11 Pro 10.0.22631 build 22631", "pc"},
		{"darwin", "macOS", "macOS 15.1", "pc"},
		{"linuxmint", "Linux Mint", "Linux Mint 22", ""},
		{"", "", "", ""},
	} {
		if got := observe.AgentKind(c.platform, c.name); got != c.want {
			t.Errorf("AgentKind(%q, %q) = %q, want %q", c.platform, c.name, got, c.want)
		}
		if got := observe.AgentKindOfOS(c.stored); got != c.want {
			t.Errorf("AgentKindOfOS(%q) = %q, want %q", c.stored, got, c.want)
		}
	}
	for _, os := range []string{"Ubuntusomething 1", "Debianish", "openSUSE Leap 15.6"} {
		if got := observe.AgentKindOfOS(os); got != "" {
			t.Errorf("AgentKindOfOS(%q) = %q, want none", os, got)
		}
	}
}
