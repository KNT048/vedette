package exposure

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// applianceCase is one port as a deep scan saw it and what it should be named: the name ("" = none), the kind, the evidence.
type applianceCase struct {
	name     string
	port     PortRow
	svc      *ServiceRow
	want     string
	kind     string
	evidence string
}

// applianceCases is the class of ports that name an appliance or an admin page from what they state, on any port. Before INV-33 no
// port of a deep scan was an admin interface: only the surface scan's GET of / on its fixed list of web ports read a page, and only
// its title, Server header and body. content/adminpages TestIdentify holds the table itself; these are the deep scan's fields.
var applianceCases = []applianceCase{
	{"FortiGate default certificate on a port nothing identified", PortRow{IP: ipA, Port: 11443, Service: "ssl/unknown", Ident: IdentNone, CertNames: []string{"FortiGate"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiGate 100F serial in the certificate", PortRow{IP: ipA, Port: 4443, Service: "https", CertNames: []string{"FG100FTK20012345"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiWiFi serial in the certificate", PortRow{IP: ipA, Port: 8443, Service: "https", CertNames: []string{"FWF60FTK21000001"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiGate page title on a high port", PortRow{IP: ipA, Port: 18443, Service: "ssl/http", Title: "FortiGate"}, nil, "FortiGate", ApplianceAdmin, EvidenceTitle},
	{"FortiOS Server header behind a public certificate", PortRow{IP: ipA, Port: 10443, Service: "ssl/http", CertNames: []string{"vpn.example.com"}, Server: "xxxxxxxx-xxxxx"}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceServer},
	{"FortiOS CPE from service identification", PortRow{IP: ipA, Port: 541, Service: "ssl/unknown"}, &ServiceRow{IP: ipA, Port: 541, Name: "ssl/http", CPE: "cpe:/o:fortinet:fortios"}, "FortiGate", ApplianceAdminOrVPN, EvidenceProduct},
	{"SSL-VPN redirect behind a public certificate", PortRow{IP: ipA, Port: 10443, Service: "ssl/http", CertNames: []string{"vpn.example.com"}, Location: "https://vpn.example.com:10443/remote/login?lang=en"}, nil, "FortiGate", ApplianceVPN, EvidenceRedirect},
	{"SSL-VPN portal behind the default certificate", PortRow{IP: ipA, Port: 443, Service: "https", Product: "Fortinet SSL VPN", Ident: IdentProbed, CertNames: []string{"FortiGate"}}, nil, "FortiGate", ApplianceVPN, EvidenceProduct},
	{"GlobalProtect portal title", PortRow{IP: ipA, Port: 443, Service: "https", Title: "GlobalProtect Portal"}, nil, "Palo Alto firewall", ApplianceVPN, EvidenceTitle},
	{"PAN-OS admin page title", PortRow{IP: ipA, Port: 4443, Service: "https", Title: "Palo Alto Networks - Login"}, nil, "Palo Alto firewall", ApplianceAdmin, EvidenceTitle},
	{"SonicWall Server header", PortRow{IP: ipA, Port: 8443, Service: "https", Server: "SonicWALL"}, nil, "SonicWall", ApplianceAdminOrVPN, EvidenceServer},
	{"SonicOS product", PortRow{IP: ipA, Port: 4433, Service: "https"}, &ServiceRow{IP: ipA, Port: 4433, Name: "ssl/http", Product: "SonicWALL SonicOS http admin"}, "SonicWall", ApplianceAdminOrVPN, EvidenceProduct},
	{"Cisco ASDM title", PortRow{IP: ipA, Port: 8443, Service: "https", Title: "Cisco ASDM 7.18"}, nil, "Cisco ASA", ApplianceAdmin, EvidenceTitle},
	{"AnyConnect redirect", PortRow{IP: ipA, Port: 443, Service: "https", Location: "/+CSCOE+/logon.html"}, nil, "Cisco ASA", ApplianceVPN, EvidenceRedirect},
	{"Ivanti Connect Secure title", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Ivanti Connect Secure"}, nil, "Ivanti Connect Secure", ApplianceVPN, EvidenceTitle},
	{"Citrix redirect", PortRow{IP: ipA, Port: 443, Service: "https", Location: "/logon/LogonPoint/index.html"}, nil, "Citrix NetScaler", ApplianceVPN, EvidenceRedirect},
	{"Check Point SSL Network Extender", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Check Point SSL Network Extender"}, nil, "Check Point gateway", ApplianceVPN, EvidenceTitle},
	{"F5 configuration utility redirect", PortRow{IP: ipA, Port: 8443, Service: "https", Location: "/tmui/login.jsp"}, nil, "F5 BIG-IP", ApplianceAdmin, EvidenceRedirect},
	{"WatchGuard admin", PortRow{IP: ipA, Port: 8080, Service: "http", Title: "WatchGuard Login"}, nil, "WatchGuard Firebox", ApplianceAdmin, EvidenceTitle},
	{"MikroTik product", PortRow{IP: ipA, Port: 8291, Service: "winbox"}, &ServiceRow{IP: ipA, Port: 8291, Name: "http", Product: "MikroTik router config httpd"}, "MikroTik router", ApplianceAdmin, EvidenceProduct},
	{"Juniper J-Web title", PortRow{IP: ipA, Port: 8443, Service: "https", Title: "Log In - Juniper Web Device Manager"}, nil, "Juniper", ApplianceAdmin, EvidenceTitle},
	{"Synology title on a high port", PortRow{IP: ipA, Port: 15001, Service: "https", Title: "nas01 - Synology DiskStation"}, nil, "Synology DSM", ApplianceAdmin, EvidenceTitle},
	// Not an admin page.
	{"an ordinary web server", PortRow{IP: ipA, Port: 10443, Service: "https", Product: "nginx", CertNames: []string{"git.example.com"}}, nil, "", "", ""},
	{"a shop", PortRow{IP: ipA, Port: 443, Service: "https", Title: "FortiGate 60F price | Example Shop"}, nil, "", "", ""},
	{"a how-to", PortRow{IP: ipA, Port: 443, Service: "https", Title: "How to install GlobalProtect"}, nil, "", "", ""},
	{"a shared certificate", PortRow{IP: ipA, Port: 443, Service: "https", CertNames: []string{"www.example.com", "fortigate.example.com"}}, nil, "", "", ""},
	{"a word like a serial", PortRow{IP: ipA, Port: 443, Service: "https", CertNames: []string{"FGTSDIGITAL"}}, nil, "", "", ""},
	{"OpenSSH", PortRow{IP: ipA, Port: 10022, Service: "ssh", Product: "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20"}, nil, "", "", ""},
}

func TestApplianceOf_Class(t *testing.T) {
	t.Parallel()
	byEvidence := map[string]int{}
	for _, c := range applianceCases {
		got := applianceOf(c.port, c.svc)
		if c.want == "" {
			if got != nil {
				t.Errorf("%s: named %+v, want none", c.name, *got)
			}
			continue
		}
		if got == nil || got.Name != c.want || got.Kind != c.kind || got.Evidence != c.evidence {
			t.Errorf("%s: got %+v, want %s %s from %s", c.name, got, c.want, c.kind, c.evidence)
			continue
		}
		byEvidence[c.evidence]++
	}
	t.Logf("named ports by evidence: %v", byEvidence)
}

// Every port that names an admin page (or a page that may be either) is an admin row, once; a VPN portal and a port kept from an
// earlier scan are not.
func TestApplianceAdmins_CountsAdminPagesOnce(t *testing.T) {
	t.Parallel()
	var ports []PortRow
	var services []ServiceRow
	want := 0
	for i, c := range applianceCases {
		p := c.port
		p.Port = 20000 + i // one port each
		ports = append(ports, p)
		if c.svc != nil {
			s := *c.svc
			s.Port = p.Port
			services = append(services, s)
		}
		if c.want != "" && c.kind != ApplianceVPN {
			want++
		}
	}
	got := applianceAdmins(nil, ports, services)
	if len(got) != want {
		t.Fatalf("admin rows = %d, want %d: %+v", len(got), want, got)
	}
	if again := applianceAdmins(got, ports, services); len(again) != want {
		t.Fatalf("applied twice: %d rows, want %d", len(again), want)
	}
	surface := []AdminRow{{URL: "https://203.0.113.10:20000/", Product: "FortiGate", IP: ipA, Port: 20000, Risk: "danger"}}
	if n := len(applianceAdmins(surface, ports, services)); n != want {
		t.Fatalf("with the surface row: %d rows, want %d", n, want)
	}
	if fg := got[0]; fg.Product != "FortiGate" || fg.Risk != "danger" || fg.URL != "https://"+ipA+":20000/" {
		t.Fatalf("the FortiGate row = %+v", fg)
	}
	kept := ports[0]
	kept.LastSeen = "2026-11-10"
	if n := len(applianceAdmins(nil, []PortRow{kept}, nil)); n != 0 {
		t.Fatalf("a kept port made %d admin rows", n)
	}
}

// A service that is no web page names its device but is no admin page: SSH, FTP and the API of a MikroTik, SSH of a Junos device,
// FortiGate's FGFM port with its certificate. The FortiGate certificate on an unidentified TLS port is one.
func TestApplianceAdmins_OnlyWebPages(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		p     PortRow
		svc   *ServiceRow
		admin bool
	}{
		{"MikroTik SSH", PortRow{IP: ipA, Port: 22, Service: "ssh", Product: "MikroTik RouterOS sshd"}, nil, false},
		{"MikroTik FTP", PortRow{IP: ipA, Port: 21, Service: "ftp", Product: "MikroTik router ftpd"}, nil, false},
		{"MikroTik API", PortRow{IP: ipA, Port: 8728, Service: "mikrotik-api", Product: "MikroTik RouterOS API"}, nil, false},
		{"Junos SSH", PortRow{IP: ipA, Port: 2222, Service: "ssh"}, &ServiceRow{IP: ipA, Port: 2222, Name: "ssh", CPE: "cpe:/o:juniper:junos"}, false},
		{"FGFM", PortRow{IP: ipA, Port: 541, Service: "ssl/unknown", CertNames: []string{"FGT60FTK2109ABCD"}}, nil, false},
		{"FortiGate certificate on 11443", PortRow{IP: ipA, Port: 11443, Service: "ssl/unknown", CertNames: []string{"FortiGate"}}, nil, true},
		{"MikroTik web page", PortRow{IP: ipA, Port: 8080, Service: "http", Product: "MikroTik router config httpd"}, nil, true},
	} {
		var svc []ServiceRow
		if c.svc != nil {
			svc = []ServiceRow{*c.svc}
		}
		ports := []PortRow{c.p}
		got := applianceAdmins(nil, ports, svc)
		if (len(got) == 1) != c.admin {
			t.Errorf("%s: admin rows %+v, want admin %v", c.name, got, c.admin)
		}
		nameAppliances(ports, nil, svc)
		if ports[0].Appliance == nil {
			t.Errorf("%s: the port is not named", c.name)
		}
	}
}

type fakeAppliances struct {
	mu    sync.Mutex
	devs  map[string]ApplianceMatch
	err   error
	calls int
}

func (f *fakeAppliances) ApplianceDevices(_ context.Context, qs []ApplianceQuery) (map[string]ApplianceMatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]ApplianceMatch{}
	for _, q := range qs {
		if q.Device == nil || len(q.KevKeys) == 0 || len(q.Kinds) == 0 {
			return nil, errors.New("a family without its device pattern, KEV keys or device types")
		}
		out[q.Family] = f.devs[q.Family]
	}
	return out, nil
}

// A FortiGate certificate on the box's public IP is an admin interface of the snapshot, tied to the FortiGate of the inventory and
// its open exploited vulnerabilities; the target list says the same on its open ports. The inventory is read once for both pages.
func TestAppliance_SnapshotAndTargetListTieTheDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fa := &fakeAppliances{devs: map[string]ApplianceMatch{"fortigate": {Devices: []ApplianceDevice{{DeviceID: "dev-fw", Name: "Edge firewall", OpenExploited: 2}}, More: 3}}}
	e.svc.cfg.Appliances = fa
	s := e.scanIP(Content{Ports: []PortRow{
		{IP: ipA, Port: 10022, Service: "ssh", Product: "OpenSSH 9.6p1"},
		{IP: ipA, Port: 11443, Service: "ssl/unknown", CertNames: []string{"FortiGate"}},
		{IP: ipA, Port: 8443, Service: "https", Title: "GlobalProtect Portal"},
	}})
	if s.Counts.AdminPanels != 1 || len(s.AdminPanels) != 1 {
		t.Fatalf("admin = %d %+v", s.Counts.AdminPanels, s.AdminPanels)
	}
	a := s.AdminPanels[0]
	if a.Port != 11443 || a.Appliance == nil || a.Appliance.Name != "FortiGate" || a.Appliance.Evidence != EvidenceCert || a.Appliance.More != 3 ||
		len(a.Appliance.Devices) != 1 || a.Appliance.Devices[0] != (ApplianceDevice{DeviceID: "dev-fw", Name: "Edge firewall", OpenExploited: 2}) {
		t.Fatalf("admin row = %+v %+v", a, a.Appliance)
	}
	byPort := map[int]*Appliance{}
	for _, p := range s.Ports {
		byPort[p.Port] = p.Appliance
	}
	if byPort[10022] != nil || byPort[11443] == nil || byPort[11443].Devices[0].DeviceID != "dev-fw" {
		t.Fatalf("ports = %+v", s.Ports)
	}
	// A Palo Alto VPN portal: named and tied, not an admin page; no Palo Alto in the inventory is an empty list, not "cannot tell".
	if pa := byPort[8443]; pa == nil || pa.Kind != ApplianceVPN || pa.Devices == nil || len(pa.Devices) != 0 {
		t.Fatalf("the VPN portal = %+v", pa)
	}
	items, err := e.svc.Targets(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range items {
		if it.Latest == nil {
			continue
		}
		if it.Latest.AdminPanels != 1 {
			t.Fatalf("list counts = %+v", it.Latest)
		}
		for _, p := range it.OpenPorts {
			found = found || p.Port == 11443 && p.Appliance != nil && len(p.Appliance.Devices) == 1 && p.Appliance.Devices[0].OpenExploited == 2
		}
	}
	if !found {
		t.Fatal("the list's port 11443 is not tied to the FortiGate")
	}
	if fa.calls != 1 {
		t.Fatalf("the inventory was read %d times for the two pages, want once", fa.calls)
	}
}

// A failed read keeps the last answer; before any answer the page cannot tell (Devices null). The answer is read again after
// applianceTTL.
func TestAppliance_FailedReadKeepsTheLastAnswer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	e.svc.now = func() time.Time { return at }
	fa := &fakeAppliances{err: errors.New("inventory down")}
	e.svc.cfg.Appliances = fa
	read := func() *Appliance {
		ports := []PortRow{{IP: ipA, Port: 11443, Service: "ssl/unknown", CertNames: []string{"FortiGate"}}}
		nameAppliances(ports, nil, nil)
		e.svc.tieAppliances(t.Context(), ports, nil)
		return ports[0].Appliance
	}
	if a := read(); a.Devices != nil {
		t.Fatalf("no answer yet: %+v", a)
	}
	fa.err = nil
	fa.devs = map[string]ApplianceMatch{"fortigate": {Devices: []ApplianceDevice{{DeviceID: "dev-fw", Name: "Edge firewall", OpenExploited: 2}}}}
	if a := read(); a.Devices != nil || fa.calls != 1 {
		t.Fatalf("a failed read is retried only after applianceRetry: %+v (%d calls)", a, fa.calls)
	}
	at = at.Add(applianceRetry)
	if a := read(); len(a.Devices) != 1 {
		t.Fatalf("after a good read: %+v", a)
	}
	calls := fa.calls
	if read(); fa.calls != calls {
		t.Fatal("read again within applianceTTL")
	}
	at = at.Add(2 * applianceTTL)
	fa.err = errors.New("inventory down")
	if a := read(); len(a.Devices) != 1 || a.Devices[0].DeviceID != "dev-fw" || fa.calls != calls+1 {
		t.Fatalf("a failed read lost the last answer: %+v (%d calls)", a, fa.calls)
	}
}
