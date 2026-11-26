package exposure

import (
	"strings"
	"testing"

	corerun "github.com/knt048/vedette/core/run"
)

// The check step of a domain's deep scan never says the disruptive checks are included: they go only to an address of the domain
// that is this box's own public IP (deepGate), so a domain on a hosting provider never gets them. The step says which addresses do.
func TestModeNote_ADomainsDeepScanSaysWhichAddressesGetTheDisruptiveChecks(t *testing.T) {
	t.Parallel()
	d := newDeepEnv(t)
	d.svc.cfg.DomainFence = &fakeFence{}
	d.acceptTerms(d.dom.ID, true)
	d.dns.point("www.acme.example", "9.9.9.1")
	d.run.content = Content{Hosts: []HostRow{{Name: "www.acme.example", IP: "9.9.9.1", Source: "ct", IPs: []HostIP{{IP: "9.9.9.1", Family: "ipv4", Class: ClassPublic}}}}, Ports: []PortRow{}}
	s := d.scan()
	run := d.runDetail(d.ctx(), s.RunID)
	if len(run.Steps) == 0 || run.Steps[0].Note == nil {
		t.Fatal("no check step")
	}
	note := *run.Steps[0].Note
	if run.Steps[0].Status != corerun.Done || strings.Contains(note, "with the disruptive checks") || strings.Contains(note, "are included") {
		t.Fatalf("the check step of a domain on a hosting address claims the disruptive checks: %q", note)
	}
	if !strings.Contains(note, "The disruptive checks run only on an address of this domain that is this box's own public IP; the other addresses get the deep scan without them.") {
		t.Fatalf("the check step does not say which addresses get the disruptive checks: %q", note)
	}
}

func TestModeNote(t *testing.T) {
	t.Parallel()
	deep, all := ScanMode{Full: true}, ScanMode{Full: true, Disruptive: true}
	for _, tc := range []struct {
		t    Target
		m    ScanMode
		want string
	}{
		{Target{Kind: KindIP}, all, "Deep scan with the disruptive checks: the testing terms are accepted."},
		{Target{Kind: KindIP}, deep, "Deep scan: the testing terms are accepted."},
		{Target{Kind: KindIP, Typed: true}, all, "Deep scan: the testing terms are accepted. The disruptive checks run only on this box's own public IP, so this typed-in address gets the deep scan without them."},
		{Target{Kind: KindDomain}, all, "Deep scan: the testing terms are accepted. The disruptive checks run only on an address of this domain that is this box's own public IP; the other addresses get the deep scan without them."},
		{Target{Kind: KindDomain}, deep, "Deep scan: the testing terms are accepted."},
		{Target{Kind: KindDomain}, ScanMode{}, "Standard scan: the testing terms are not accepted, so the deep steps do not run."},
	} {
		if got := modeNote(tc.t, tc.m); got != tc.want {
			t.Errorf("modeNote(%s typed=%v, %+v) = %q, want %q", tc.t.Kind, tc.t.Typed, tc.m, got, tc.want)
		}
	}
}
