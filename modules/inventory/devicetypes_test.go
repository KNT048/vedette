package inventory_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// labDevice is one device of a test box's export (2026-11-13): what the sensors had stored about it,
// observations and open services as they were, and what a person reads from that.
type labDevice struct {
	ip, mac  string
	obs      []observe.Observation // vendor, hostname, model as stored (passive OUI 0.4, nmap 0.6, mDNS model 0.5)
	services []observe.Service     // gentle-scan ports: names only, no product
	want     string                // the guessed type; "" = no guess
	evidence string                // a piece of the evidence sentence
}

func labDevices() []labDevice {
	tcp := func(port int, name string) observe.Service {
		return observe.Service{Port: port, Proto: "tcp", Name: name, Confidence: 0.475}
	}
	v := func(vendor string) []observe.Observation {
		return []observe.Observation{{Field: observe.Vendor, Value: vendor, Source: observe.Nmap, Confidence: 0.6}}
	}
	return []labDevice{
		{"192.168.142.251", "70:4c:a5:fc:2f:50", v("Fortinet"), []observe.Service{tcp(22, "ssh")}, "firewall", "Fortinet network card and port 22 (ssh): most likely a FortiGate firewall"},
		{"192.168.142.252", "70:4c:a5:f6:f8:e4", v("Fortinet"), []observe.Service{tcp(22, "ssh")}, "firewall", "FortiGate"},
		{"192.168.142.47", "3c:8a:b0:9c:85:ff", v("Juniper Networks"), []observe.Service{tcp(22, "ssh"), tcp(80, "http"), tcp(443, "https")}, "switch", "Juniper Networks network card and ports 22 (ssh), 80 (http) and 443 (https): most likely a Juniper switch"},
		{"192.168.142.1", "00:f0:4d:00:9d:60", nil, []observe.Service{tcp(53, "domain"), tcp(443, "https")}, "router", "It is the box's default gateway"},
		{"192.168.142.254", "10:2d:41:cc:a0:1d", v("Sichuan AI-Link Technology"), []observe.Service{tcp(80, "http"), tcp(443, "https"), tcp(554, "rtsp"), tcp(8000, "http-alt"), tcp(8443, "https-alt")}, "camera", "port 554 (rtsp)"},
		{"192.168.142.108", "c8:b5:ad:cf:71:34", []observe.Observation{{Field: observe.Vendor, Value: "Hewlett Packard Enterprise", Source: observe.Passive, Confidence: 0.4}},
			[]observe.Service{tcp(22, "ssh"), tcp(23, "telnet"), tcp(80, "http"), tcp(443, "https"), tcp(8080, "http-proxy")}, "switch", "HPE/Aruba managed switch"},
		{"192.168.142.100", "94:57:a5:68:6c:aa", v("Hewlett Packard"), []observe.Service{tcp(22, "ssh"), tcp(80, "http"), tcp(443, "https")}, "switch", "HP switch"},
		{"192.168.142.67", "94:57:a5:56:9d:cc", v("Hewlett Packard"), []observe.Service{tcp(80, "http"), tcp(443, "https"), tcp(8000, "http-alt")}, "", ""},
		{"192.168.142.109", "00:0b:82:e1:cf:26", v("Grandstream Networks"), []observe.Service{tcp(22, "ssh"), tcp(80, "http")}, "ip_phone", "Grandstream IP phone"},
		{"192.168.142.155", "00:0c:29:4b:9b:f7", v("VMware"), []observe.Service{tcp(22, "ssh"), tcp(443, "https")}, "virtual_machine", "VMware network card"},
		{"192.168.142.140", "2c:6f:c9:33:13:bb", append(v("Hon Hai Precision Ind."), observe.Observation{Field: observe.Hostname, Value: "byn2", Source: observe.Passive, Confidence: 0.6}),
			[]observe.Service{tcp(22, "ssh"), tcp(514, "shell"), tcp(8443, "https-alt")}, "server", "Linux server"},
		{"192.168.142.141", "8c:ec:4b:45:f8:b7", v("Dell"), []observe.Service{tcp(22, "ssh"), tcp(514, "shell"), tcp(8443, "https-alt")}, "server", "Dell network card and port 22 (ssh)"},
		{"192.168.142.145", "b2:f0:09:23:2e:5b", []observe.Observation{
			{Field: observe.Hostname, Value: "annas-macbook-air", Source: observe.Passive, Confidence: 0.6},
			{Field: observe.Model, Value: "Mac14,2", Source: observe.Passive, Confidence: 0.5},
		}, []observe.Service{tcp(5000, "upnp"), tcp(49153, "")}, "laptop", `host name "annas-macbook-air"`},
	}
}

// loadLab records the test box's devices as the sensors did: MAC and the stored fields, then nmap's open ports.
func loadLab(e *env) map[string]string {
	e.t.Helper()
	ids := map[string]string{}
	for _, d := range labDevices() {
		ip := netip.MustParseAddr(d.ip)
		batch := []observe.Observation{obs(ip, d.mac, observe.MAC, d.mac, observe.Passive, 0.9)}
		for _, o := range d.obs {
			o.AssetHint = observe.AssetHint{IP: ip, MAC: d.mac}
			batch = append(batch, o)
		}
		e.record(batch...)
		if err := e.svc.AddServices(e.ctx(), observe.AssetHint{IP: ip}, observe.Nmap, d.services); err != nil {
			e.t.Fatal(err)
		}
	}
	l, err := e.svc.Devices(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, d := range l.Items {
		ids[d.IP] = d.ID
	}
	return ids
}

// Device types on a test box's own rows: each device that was "Unknown" while its card maker and ports told a person what it is now carries
// that type as a guess with its evidence; the HP device with only web ports gets none. The kind stays unknown: scans still treat the
// device as unknown and careful, and a guessed router is no never-touch gateway.
func TestContract_LabDevicesGetTheirType(t *testing.T) {
	t.Parallel()
	asked := 0
	e := newEnv(t, func(c *inventory.Config) {
		c.Gateway = func(context.Context) netip.Addr { asked++; return netip.MustParseAddr("192.168.142.1") }
	})
	ids := loadLab(e)
	// #714 M3: only the Devices page and the device page ask for guesses (and the host for its gateway); every other reader, such as
	// response's Directory inside a write, reads Devices or Device, which never do.
	plain, err := e.svc.Devices(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := e.svc.Device(e.ctx(), ids["192.168.142.251"]); d.Guess != nil || asked != 0 || slices.ContainsFunc(plain.Items, func(d inventory.Device) bool { return d.Guess != nil }) {
		t.Fatalf("Devices/Device computed guesses (asked the gateway %d times)", asked)
	}
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	byIP := map[string]inventory.Device{}
	for _, d := range l.Items {
		byIP[d.IP] = d
	}
	for _, want := range labDevices() {
		d := byIP[want.ip]
		if d.Kind != "unknown" || d.KindSource != nil {
			t.Errorf("%s: kind %q from %v; a guess must never become the kind", want.ip, d.Kind, d.KindSource)
		}
		if want.want == "" {
			if d.Guess != nil {
				t.Errorf("%s: guessed %+v from too little", want.ip, *d.Guess)
			}
			continue
		}
		if d.Guess == nil || d.Guess.Type != want.want || !strings.Contains(strings.ToLower(d.Guess.Evidence), strings.ToLower(want.evidence)) {
			t.Errorf("%s: guess %+v, want %s with evidence containing %q", want.ip, d.Guess, want.want, want.evidence)
		}
		if detail, err := e.svc.DetailPage(e.ctx(), d.ID); err != nil || detail.Asset.Guess == nil || detail.Asset.Guess.Type != want.want {
			t.Errorf("%s: device page guess = %+v, %v", want.ip, detail.Asset.Guess, err)
		}
	}
	// Behaviour is untouched: still unknown for the scan policy, and no never-touch gateway from a guess.
	confirmScope(e)
	dec, err := e.svc.ScanPolicy(e.ctx(), ids["192.168.142.251"])
	if err != nil || !dec.Unclassified {
		t.Fatalf("scan policy of a guessed FortiGate = %+v, %v; want unclassified (careful)", dec, err)
	}
	gws, err := e.svc.DevicesOfKind(e.ctx(), []string{"router", "firewall"})
	if err != nil || len(gws) != 0 {
		t.Fatalf("never-touch gateways from guesses = %+v, %v", gws, err)
	}
	// Without the host's gateway the .1 still reads as the router, from DNS at the first address.
	e2 := newEnv(t)
	loadLab(e2)
	l2, _ := e2.svc.DevicesPage(e2.ctx(), inventory.DeviceFilter{})
	for _, d := range l2.Items {
		if d.IP == "192.168.142.1" && (d.Guess == nil || d.Guess.Type != "router" || !strings.Contains(d.Guess.Evidence, "address ending in .1")) {
			t.Fatalf("gateway unknown: .1 guess = %+v", d.Guess)
		}
	}
}

// confirmScope saves a confirmed scope over the test LAN with scanning on, so ScanPolicy reaches its kind decision.
func confirmScope(e *env) {
	e.t.Helper()
	st, err := e.svc.Settings(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	in := inventory.SettingsInput{Settings: st, ScopeConfirmed: true}
	in.LANRanges = []string{"192.168.142.0/24"}
	in.Active.Enabled = true
	if _, err := e.svc.SaveSettings(e.ctx(), "it@acme.example", in); err != nil {
		e.t.Fatal(err)
	}
}

// A person confirms the guess (the kind the device page's Confirm sends) and it becomes the device's kind, from them; a new type
// behaves as the kind it acts as: an IP phone is fragile like iot, a VPN gateway is a never-touch firewall the person vouched for.
func TestContract_TypesActAsTheirKind(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ids := loadLab(e)
	set := func(ip, kind string) inventory.Device {
		t.Helper()
		if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", ids[ip], inventory.Patch{Kind: &kind}); err != nil {
			t.Fatalf("set %s to %s: %v", ip, kind, err)
		}
		d, err := e.svc.Device(e.ctx(), ids[ip])
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := set("192.168.142.109", "ip_phone"); d.Kind != "ip_phone" || !d.Fragile || d.Guess != nil || d.KindSource == nil || *d.KindSource != "manual" {
		t.Fatalf("confirmed IP phone = kind %q fragile %v guess %v source %v; want ip_phone, fragile (acts as iot), no guess, manual", d.Kind, d.Fragile, d.Guess, d.KindSource)
	}
	if d := set("192.168.142.155", "virtual_machine"); d.Fragile {
		t.Fatal("a virtual machine acts as a server: not fragile")
	}
	set("192.168.142.251", "vpn_gateway")
	gws, err := e.svc.DevicesOfKind(e.ctx(), []string{"router", "firewall"})
	if err != nil || len(gws) != 1 || gws[0].Kind != "vpn_gateway" || !gws[0].TrustedKind() {
		t.Fatalf("never-touch gateways = %+v, %v; want the VPN gateway, trusted", gws, err)
	}
	bad := "fortigate"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", ids["192.168.142.47"], inventory.Patch{Kind: &bad}); err == nil {
		t.Fatal("a kind that is no device type was accepted")
	}
	// A sensor may report a new type too (nmap's VoIP phone), and the fragile setting still lists only the 13 kinds.
	e.record(obs(netip.MustParseAddr("192.168.142.67"), "", observe.Kind, "smartphone", observe.Nmap, 0.5))
	st, _ := e.svc.Settings(e.ctx())
	in := inventory.SettingsInput{Settings: st}
	in.FragileKinds = append(slices.Clone(st.FragileKinds), "ip_phone")
	if _, err := e.svc.SaveSettings(e.ctx(), "it@acme.example", in); err == nil {
		t.Fatal("the fragile setting took a type; it lists the 13 kinds types act as")
	}
}

// CSV import reads a type by id, label or alias.
func TestContract_ImportReadsTypeNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	res, err := e.svc.Import(e.ctx(), "it@acme.example", "d.csv", "name,ip,type\nphone-1,192.168.142.20,IP phone\nnote-1,192.168.142.21,notebook\nrec-1,192.168.142.22,camera_recorder\nx,192.168.142.23,fortigate\n")
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 3 || len(res.Errors) != 1 || !strings.Contains(res.Errors[0].Message, "is not a device type") {
		t.Fatalf("import = %+v", res)
	}
	l, _ := e.svc.Devices(e.ctx())
	got := map[string]string{}
	for _, d := range l.Items {
		got[d.IP] = d.Kind
	}
	if got["192.168.142.20"] != "ip_phone" || got["192.168.142.21"] != "laptop" || got["192.168.142.22"] != "nvr" {
		t.Fatalf("imported kinds = %v", got)
	}
}

// #714 round 2, M1: the devices still waiting for their one gentle scan, which sensor-active queues once per start: unknown,
// not fragile, not "never", discovered, with an IP and no first scan.
func TestContract_PendingGentleScans(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ids := loadLab(e)
	fragile, never := true, "never"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", ids["192.168.142.109"], inventory.Patch{Fragile: &fragile}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", ids["192.168.142.47"], inventory.Patch{RegularScan: &never}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.MarkFirstScan(e.ctx(), ids["192.168.142.251"]); err != nil {
		t.Fatal(err)
	}
	e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.142.250"}) // declared by hand
	got, err := e.svc.PendingGentleScans(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(labDevices())-3 {
		t.Fatalf("%d devices wait for their gentle scan, want %d (13 less the fragile, the never and the scanned one)", len(got), len(labDevices())-3)
	}
	for _, ip := range []string{"192.168.142.109", "192.168.142.47", "192.168.142.251"} {
		if slices.Contains(got, ids[ip]) {
			t.Errorf("%s listed", ip)
		}
	}
}
