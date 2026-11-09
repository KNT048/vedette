package ops

import (
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/host/api"
)

func ifaceName(s string) *string { return &s }

func TestDesiredNetKeepsTheRefusalsForCheck(t *testing.T) {
	t.Parallel()
	base := api.NetApplyArgs{Mgmt: api.NetApplyMgmt{Iface: "eth0", Mode: api.NetModeStatic, Address: "10.0.0.9/24", Gateway: "10.0.0.1"}}
	cfg, window, err := desiredNet(base)
	if err != nil || window != 120*time.Second || cfg.Mgmt.Address.String() != "10.0.0.9/24" {
		t.Fatalf("%+v %v %v", cfg, window, err)
	}
	// same_iface and gateway_outside_subnet are not argument errors: Check answers them with their own codes.
	same := base
	same.SPAN.Iface = ifaceName("eth0")
	if cfg, _, err := desiredNet(same); err != nil || cfg.SPAN != "eth0" {
		t.Fatalf("same iface: %+v %v", cfg, err)
	}
	out := base
	out.Mgmt.Gateway = "10.0.1.1"
	if cfg, _, err := desiredNet(out); err != nil || !gatewayOutside(cfg.Mgmt) {
		t.Fatalf("gateway outside: %+v %v", cfg, err)
	}
	// but a gateway that is no host address at all is
	for _, g := range []string{"10.0.0.9", "127.0.0.1", "224.0.0.1", "0.0.0.0", "::1", "x"} {
		bad := base
		bad.Mgmt.Gateway = g
		if _, _, err := desiredNet(bad); err == nil {
			t.Errorf("gateway %q accepted", g)
		}
	}
	// A field error names its field.
	bad := base
	bad.Mgmt.Address = "nope"
	_, _, err = desiredNet(bad)
	var fe *fieldError
	if !errors.As(err, &fe) || fe.Field != "mgmt.address" {
		t.Fatalf("error %v", err)
	}
	for in, want := range map[int]time.Duration{0: 120 * time.Second, 30: 30 * time.Second, 600: 600 * time.Second} {
		a := base
		a.ConfirmTimeoutS = in
		if _, w, err := desiredNet(a); err != nil || w != want {
			t.Errorf("timeout %d: %v %v", in, w, err)
		}
	}
	for _, in := range []int{-1, 1, 29, 601, 100000} {
		a := base
		a.ConfirmTimeoutS = in
		if _, _, err := desiredNet(a); err == nil {
			t.Errorf("timeout %d accepted", in)
		}
	}
}

func TestPendingNoteMustBeExactlyWhatTheHostWrites(t *testing.T) {
	t.Parallel()
	ok := netPending{
		RunID: "rn_0123456789abcdef", RevertAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
		BootID: "11111111-2222-4333-8444-555555555555", OldSHA: "", NewSHA: shaHex([]byte("x")),
	}
	if !ok.valid() {
		t.Fatal("a good note is invalid")
	}
	ok.OldSHA = shaHex([]byte("y"))
	if !ok.valid() {
		t.Fatal("a note with an old hash is invalid")
	}
	for name, mut := range map[string]func(*netPending){
		"run id":     func(p *netPending) { p.RunID = "rn_0123456789abcdeg" },
		"empty run":  func(p *netPending) { p.RunID = "" },
		"zero time":  func(p *netPending) { p.RevertAt = time.Time{} },
		"boot id":    func(p *netPending) { p.BootID = "x" },
		"new sha":    func(p *netPending) { p.NewSHA = "" },
		"old sha":    func(p *netPending) { p.OldSHA = "ABC" },
		"upper case": func(p *netPending) { p.NewSHA = "AB" + p.NewSHA[2:] },
	} {
		p := ok
		mut(&p)
		if p.valid() {
			t.Errorf("%s: accepted", name)
		}
	}
}
