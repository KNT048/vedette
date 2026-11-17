package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// applianceCase is one port as a scan saw it and what it should be named: the family ("" = none), the kind, and the evidence.
type applianceCase struct {
	name     string
	port     PortRow
	svc      *ServiceRow
	family   string
	kind     string
	evidence string
}

// applianceCases is the class of ports that name a network appliance from what they state, on any port: the certificate a
// deep scan read, the page title, the Server header, the product or CPE that service identification read. Before appliance.go no
// port of a deep scan was an admin interface: only the surface scan's GET of / on its fixed list of web ports read a page, and
// only its title, Server header and body (TestApplianceOf_Class prints the count of each kind of evidence).
var applianceCases = []applianceCase{
	// FortiGate: its default certificate is issued to "FortiGate" or to its serial number (content/devicetypes fortigate-says).
	{"FortiGate default certificate on a port nothing identified", PortRow{IP: ipA, Port: 11443, Service: "ssl/unknown", Ident: IdentNone, CertNames: []string{"FortiGate"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiGate serial in the certificate", PortRow{IP: ipA, Port: 4443, Service: "https", CertNames: []string{"FGT60FTK2109XXXX"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiGate VM serial in the certificate", PortRow{IP: ipA, Port: 8443, Service: "https", CertNames: []string{"FGVM02TM22000000"}}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceCert},
	{"FortiGate page title on a high port", PortRow{IP: ipA, Port: 18443, Service: "ssl/http", Title: "FortiGate"}, nil, "FortiGate", ApplianceAdminOrVPN, EvidenceTitle},
	{"FortiOS CPE from service identification", PortRow{IP: ipA, Port: 541, Service: "ssl/unknown"}, &ServiceRow{IP: ipA, Port: 541, Name: "ssl/http", CPE: "cpe:/o:fortinet:fortios"}, "FortiGate", ApplianceAdminOrVPN, EvidenceProduct},
	{"Fortinet SSL VPN portal the surface scan named", PortRow{IP: ipA, Port: 443, Service: "https", Product: "Fortinet SSL VPN", Ident: IdentProbed}, nil, "FortiGate", ApplianceVPN, EvidenceProduct},
	// Palo Alto, SonicWall, Cisco ASA, Ivanti, Citrix: words from content/devicetypes and the surface fingerprints.
	{"GlobalProtect portal title", PortRow{IP: ipA, Port: 443, Service: "https", Title: "GlobalProtect Portal"}, nil, "Palo Alto firewall", ApplianceVPN, EvidenceTitle},
	{"PAN-OS admin page title", PortRow{IP: ipA, Port: 4443, Service: "https", Title: "Palo Alto Networks - Login"}, nil, "Palo Alto firewall", ApplianceAdminOrVPN, EvidenceTitle},
	{"SonicWall Server header", PortRow{IP: ipA, Port: 8443, Service: "https", Server: "SonicWALL"}, nil, "SonicWall", ApplianceAdminOrVPN, EvidenceServer},
	{"SonicOS product from service identification", PortRow{IP: ipA, Port: 4433, Service: "https"}, &ServiceRow{IP: ipA, Port: 4433, Name: "ssl/http", Product: "SonicWALL SonicOS http admin"}, "SonicWall", ApplianceAdminOrVPN, EvidenceProduct},
	{"Cisco ASDM title", PortRow{IP: ipA, Port: 8443, Service: "https", Title: "Cisco ASDM 7.18"}, nil, "Cisco ASA", ApplianceAdminOrVPN, EvidenceTitle},
	{"Cisco AnyConnect product", PortRow{IP: ipA, Port: 443, Service: "https"}, &ServiceRow{IP: ipA, Port: 443, Name: "ssl/http", Product: "Cisco AnyConnect VPN"}, "Cisco ASA", ApplianceVPN, EvidenceProduct},
	{"Ivanti Connect Secure title", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Ivanti Connect Secure"}, nil, "Ivanti Connect Secure", ApplianceVPN, EvidenceTitle},
	{"Pulse Secure certificate name", PortRow{IP: ipA, Port: 8443, Service: "https", CertNames: []string{"Pulse Secure"}}, nil, "Ivanti Connect Secure", ApplianceAdminOrVPN, EvidenceCert},
	{"NetScaler gateway title", PortRow{IP: ipA, Port: 443, Service: "https", Title: "NetScaler Gateway"}, nil, "Citrix NetScaler", ApplianceVPN, EvidenceTitle},
	{"NetScaler certificate name", PortRow{IP: ipA, Port: 9443, Service: "ssl/unknown", CertNames: []string{"netscaler.local"}}, nil, "Citrix NetScaler", ApplianceAdminOrVPN, EvidenceCert},
	// MikroTik and Juniper: admin pages only.
	{"MikroTik RouterOS title", PortRow{IP: ipA, Port: 8080, Service: "http", Title: "RouterOS router configuration page"}, nil, "MikroTik router", ApplianceAdmin, EvidenceTitle},
	{"MikroTik product from service identification", PortRow{IP: ipA, Port: 8291, Service: "winbox"}, &ServiceRow{IP: ipA, Port: 8291, Name: "http", Product: "MikroTik router config httpd"}, "MikroTik router", ApplianceAdmin, EvidenceProduct},
	{"Juniper J-Web title", PortRow{IP: ipA, Port: 8443, Service: "https", Title: "Log In - Juniper Web Device Manager"}, nil, "Juniper", ApplianceAdmin, EvidenceTitle},
	{"Junos CPE", PortRow{IP: ipA, Port: 443, Service: "https"}, &ServiceRow{IP: ipA, Port: 443, Name: "ssl/http", CPE: "cpe:/o:juniper:junos"}, "Juniper", ApplianceAdmin, EvidenceProduct},
	// Not an appliance: ordinary sites, words an ordinary site could carry, a VPN title with no vendor.
	{"an ordinary web server", PortRow{IP: ipA, Port: 10443, Service: "https", Product: "nginx", CertNames: []string{"git.example.com"}}, nil, "", "", ""},
	{"a site named after a tree", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Juniper Square investor portal"}, nil, "", "", ""},
	{"a game news page", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Fortnite news"}, nil, "", "", ""},
	{"a name that only starts like Fortinet", PortRow{IP: ipA, Port: 443, Service: "https", CertNames: []string{"forti.example.com"}}, nil, "", "", ""},
	{"a VPN title with no vendor", PortRow{IP: ipA, Port: 443, Service: "https", Title: "SSL VPN Service"}, nil, "", "", ""},
	{"Cisco Webex", PortRow{IP: ipA, Port: 443, Service: "https", Title: "Cisco Webex"}, nil, "", "", ""},
	{"OpenSSH", PortRow{IP: ipA, Port: 10022, Service: "ssh", Product: "OpenSSH 9.6p1 Ubuntu 3ubuntu13.20"}, nil, "", "", ""},
}

// The class: every case is named as expected, and the count by evidence says what the scan used to miss.
func TestApplianceOf_Class(t *testing.T) {
	t.Parallel()
	byEvidence := map[string]int{}
	for _, c := range applianceCases {
		got := applianceOf(c.port, c.svc)
		if c.family == "" {
			if got != nil {
				t.Errorf("%s: named %+v, want none", c.name, *got)
			}
			continue
		}
		if got == nil || got.Name != c.family || got.Kind != c.kind || got.Evidence != c.evidence {
			t.Errorf("%s: got %+v, want %s %s from %s", c.name, got, c.family, c.kind, c.evidence)
			continue
		}
		byEvidence[c.evidence]++
	}
	t.Logf("appliance ports by evidence: %v", byEvidence)
}

// Every port that names an appliance's admin page (or a page that may be either) is an admin row, once; a VPN portal is not.
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
		if c.family != "" && c.kind != ApplianceVPN {
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
	// A page the surface scan already listed keeps its row: no second row for the same port.
	surface := []AdminRow{{URL: "https://203.0.113.10:20000/", Product: "FortiGate", IP: ipA, Port: 20000, Risk: "danger"}}
	if n := len(applianceAdmins(surface, ports, services)); n != want {
		t.Fatalf("with the surface row: %d rows, want %d", n, want)
	}
	fg := got[0]
	if fg.Product != "FortiGate" || fg.Risk != "danger" || fg.URL != "https://"+ipA+":20000/" {
		t.Fatalf("the FortiGate row = %+v", fg)
	}
}

// The KEV keys of each family are pairs of the KEV catalog, so a device's software row with one of them is that family.
func TestApplianceFamilies_KEVKeysAreKEVProducts(t *testing.T) {
	t.Parallel()
	var list []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &list); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, p := range list {
		known[strings.ToLower(p.Vendor)+"|"+strings.ToLower(p.Product)] = true
	}
	for _, f := range applianceFamilies {
		if len(f.kevKeys) == 0 {
			t.Errorf("%s has no KEV key", f.name)
		}
		for _, k := range f.kevKeys {
			if !known[k] {
				t.Errorf("%s: %q is not a KEV vendor|product pair", f.name, k)
			}
		}
	}
}

type fakeAppliances struct {
	devs  map[string][]ApplianceDevice // by the first KEV key of the family
	err   error
	calls int
}

func (f *fakeAppliances) ApplianceDevices(_ context.Context, q ApplianceQuery) ([]ApplianceDevice, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.devs[q.KevKeys[0]], nil
}

// A FortiGate certificate on the box's public IP is an admin interface of the snapshot, tied to the FortiGate of the inventory and
// its open exploited vulnerabilities; the target list says the same on its open ports.
func TestAppliance_SnapshotAndTargetListTieTheDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	fa := &fakeAppliances{devs: map[string][]ApplianceDevice{"fortinet|fortios": {{DeviceID: "dev-fw", Name: "Edge firewall", OpenExploited: 2}}}}
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
	if a.Port != 11443 || a.Appliance == nil || a.Appliance.Name != "FortiGate" || a.Appliance.Evidence != EvidenceCert ||
		!slices.Equal(a.Appliance.Devices, []ApplianceDevice{{DeviceID: "dev-fw", Name: "Edge firewall", OpenExploited: 2}}) {
		t.Fatalf("admin row = %+v %+v", a, a.Appliance)
	}
	byPort := map[int]*Appliance{}
	for _, p := range s.Ports {
		byPort[p.Port] = p.Appliance
	}
	if byPort[10022] != nil || byPort[11443] == nil || byPort[11443].Devices[0].DeviceID != "dev-fw" {
		t.Fatalf("ports = %+v", s.Ports)
	}
	// A Palo Alto VPN portal: named and tied, but not an admin page; no Palo Alto in the inventory is an empty list, not "cannot tell".
	if pa := byPort[8443]; pa == nil || pa.Kind != ApplianceVPN || pa.Devices == nil || len(pa.Devices) != 0 {
		t.Fatalf("the VPN portal = %+v", pa)
	}
	items, err := e.svc.Targets(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	var open []PortRow
	for _, it := range items {
		if it.Latest != nil {
			open = append(open, it.OpenPorts...)
			if it.Latest.AdminPanels != 1 {
				t.Fatalf("list counts = %+v", it.Latest)
			}
		}
	}
	tied := slices.IndexFunc(open, func(p PortRow) bool {
		return p.Port == 11443 && p.Appliance != nil && len(p.Appliance.Devices) == 1 && p.Appliance.Devices[0].OpenExploited == 2
	})
	if tied < 0 {
		t.Fatalf("open ports of the list = %+v", open)
	}
	// Without the port, or when the read fails, the page cannot tell: Devices is null.
	fa.err = errors.New("inventory down")
	snap, err := e.svc.SnapshotOf(e.ctx(), ipTargetID(t, e), s.Date)
	if err != nil {
		t.Fatal(err)
	}
	if a := snap.AdminPanels[0].Appliance; a == nil || a.Devices != nil {
		t.Fatalf("after a failed read: %+v", a)
	}
}

// A snapshot stored before the rule existed (no admin row for the port) counts the FortiGate page when it is read.
func TestAppliance_OlderSnapshotCountsWhenRead(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	s := e.scanIP(Content{Ports: []PortRow{{IP: ipA, Port: 11443, Service: "ssl/unknown", CertNames: []string{"FortiGate"}}}})
	id := ipTargetID(t, e)
	// As an older release stored it: no admin row, admin count 0.
	err := e.svc.cfg.DB.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_snapshot SET admin_panels = '[]', counts = json_set(counts, '$.admin_panels', 0) WHERE target_id = ?`, id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := e.svc.SnapshotOf(e.ctx(), id, s.Date)
	if err != nil || snap.Counts.AdminPanels != 1 || len(snap.AdminPanels) != 1 || snap.AdminPanels[0].Appliance == nil || snap.AdminPanels[0].Appliance.Devices != nil {
		t.Fatalf("read = %+v %v", snap.AdminPanels, err)
	}
	items, err := e.svc.Targets(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.ID == id && (it.Latest == nil || it.Latest.AdminPanels != 1) {
			t.Fatalf("list counts = %+v", it.Latest)
		}
	}
}

// ipTargetID is the id of the IP target scanIP scanned.
func ipTargetID(t *testing.T, e *env) string {
	t.Helper()
	items, err := e.svc.Targets(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Kind == KindIP && it.Value == ipA {
			return it.ID
		}
	}
	t.Fatal("no IP target")
	return ""
}
