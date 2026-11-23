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

// The Devices search (#849, S-INV-1, S-INV-3): two lists and one search box with filters. Each filter narrows the list; the counts
// of the tabs stay over the whole inventory.

func withWazuh(ips, macs []string) opt {
	return func(c *inventory.Config) {
		c.WazuhAgents = func(context.Context) ([]string, []string, error) { return ips, macs, nil }
	}
}

type searchFleet struct {
	fw, sw, srv, hv, wz, prn string
}

// newSearchFleet builds one device of each kind of source:
//   - fw: added manually (FortiGate), approved;
//   - sw: a switch heard by listening (core-sw, Juniper) and read with SNMP (EX4200), approved, with findings;
//   - srv: a server an osquery node reports and is bound to, pending;
//   - hv: a hypervisor found by a scan, typed by a person, approved;
//   - wz: a machine Wazuh reports (no node key), pending;
//   - prn: a printer found by a scan, fragile, pending.
func newSearchFleet(t *testing.T) (*env, searchFleet) {
	t.Helper()
	risk := fakeRisk{}
	e := newEnv(t, withKEV(fakeKEV{}), withWazuh([]string{"192.168.1.30"}, nil), withRisk(risk))
	var f searchFleet
	f.fw = e.addDevice(inventory.AddInput{CatalogID: "fortigate", Name: "Branch FW", IP: "192.168.1.1"})
	rec := func(ip, mac, agent string, src observe.Source, kv ...string) string {
		t.Helper()
		hint := observe.AssetHint{IP: netip.MustParseAddr(ip), Agent: agent}
		if mac != "" {
			hint.MAC = mac
		}
		var batch []observe.Observation
		for i := 0; i < len(kv); i += 2 {
			batch = append(batch, observe.Observation{AssetHint: hint, Field: observe.Field(kv[i]), Value: kv[i+1], Source: src, Confidence: 0.8})
		}
		if err := e.svc.Record(e.ctx(), batch); err != nil {
			t.Fatalf("Record %s: %v", ip, err)
		}
		var id string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_asset WHERE ip = ?`, ip).Scan(&id); err != nil {
			t.Fatalf("device at %s: %v", ip, err)
		}
		return id
	}
	f.sw = rec("192.168.1.2", "aa:bb:cc:00:00:02", "", observe.Passive, "hostname", "core-sw", "vendor", "Juniper", "kind", "switch")
	rec("192.168.1.2", "", "", observe.SNMP, "model", "EX4200")
	f.srv = rec("192.168.1.10", "02:00:00:00:00:10", "osquery:node-1", observe.Agent, "hostname", "db1", "mac", "02:00:00:00:00:10", "os", "Ubuntu 24.04", "kind", "server")
	f.hv = rec("192.168.1.20", "", "", observe.Nmap, "os", "VMware ESXi 8.0")
	f.wz = rec("192.168.1.30", "", "", observe.Agent, "hostname", "win-files", "os", "Windows Server 2022")
	f.prn = rec("192.168.1.40", "", "", observe.Nmap, "kind", "printer", "vendor", "HP")
	hv := "hypervisor"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", f.hv, inventory.Patch{Kind: &hv}); err != nil {
		t.Fatal(err)
	}
	yes := true
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", f.prn, inventory.Patch{Fragile: &yes}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{f.sw, f.hv} {
		if err := e.svc.Approve(e.ctx(), "it@acme.example", id); err != nil {
			t.Fatal(err)
		}
	}
	e.findg[f.sw] = 2                                        // has findings: an open one, so a status
	risk[f.sw] = inventory.Risk{Code: "exploited", Count: 1} // has_findings reads the open findings from the status
	return e, f
}

func search(t *testing.T, e *env, approved, fragile, hasFindings, types, sources, q string) []string {
	t.Helper()
	f, err := inventory.ParseDeviceFilter(approved, fragile, hasFindings, "", types, sources, q)
	if err != nil {
		t.Fatalf("ParseDeviceFilter: %v", err)
	}
	l, err := e.svc.DevicesPage(e.ctx(), f)
	if err != nil {
		t.Fatal(err)
	}
	if l.Counts.All != 6 || l.Counts.Pending != 3 || l.Counts.Fragile != 1 || l.Counts.Manual != 1 {
		t.Fatalf("the counts are over the whole inventory whatever the filter: %+v", l.Counts)
	}
	ids := []string{}
	for _, d := range l.Items {
		ids = append(ids, d.ID)
	}
	slices.Sort(ids)
	return ids
}

func set(ids ...string) []string { slices.Sort(ids); return ids }

func TestDevicesSearchEachFilter(t *testing.T) {
	t.Parallel()
	e, f := newSearchFleet(t)
	all := set(f.fw, f.sw, f.srv, f.hv, f.wz, f.prn)
	cases := []struct {
		name                                         string
		approved, fragile, has, types, sources, text string
		want                                         []string
	}{
		{name: "no filter", want: all},
		{name: "approved", approved: "true", want: set(f.fw, f.sw, f.hv)},
		{name: "to review", approved: "false", want: set(f.srv, f.wz, f.prn)},
		{name: "fragile", fragile: "true", want: set(f.prn)},
		{name: "not fragile", fragile: "false", want: set(f.fw, f.sw, f.srv, f.hv, f.wz)},
		{name: "has findings", has: "true", want: set(f.sw)},
		{name: "no findings", has: "false", want: set(f.fw, f.srv, f.hv, f.wz, f.prn)},
		{name: "type server finds the hypervisor that acts as one", types: "server", want: set(f.srv, f.hv)},
		{name: "type hypervisor only", types: "hypervisor", want: set(f.hv)},
		{name: "types OR", types: "switch, printer", want: set(f.sw, f.prn)},
		{name: "type in capitals", types: "SWITCH", want: set(f.sw)},
		{name: "source manual", sources: "manual", want: set(f.fw)},
		{name: "source passive", sources: "passive", want: set(f.sw)},
		{name: "source snmp", sources: "snmp", want: set(f.sw)},
		{name: "source scan is nmap", sources: "scan", want: set(f.hv, f.prn)},
		{name: "source osquery is the bound node", sources: "osquery", want: set(f.srv)},
		{name: "source wazuh is an agent device at a Wazuh agent's address", sources: "wazuh", want: set(f.wz)},
		{name: "sources OR", sources: "osquery,wazuh", want: set(f.srv, f.wz)},
		{name: "text in the host name, any case", text: "CORE", want: set(f.sw)},
		{name: "text in the IP", text: "192.168.1.3", want: set(f.wz)},
		{name: "IP prefix", text: "192.168.1.4", want: set(f.prn)},
		{name: "MAC with colons", text: "aa:bb:cc:00", want: set(f.sw)},
		{name: "MAC with dashes, capitals", text: "AA-BB-CC-00-00-02", want: set(f.sw)},
		{name: "MAC in Cisco notation", text: "aabb.cc00.0002", want: set(f.sw)},
		{name: "MAC plain", text: "aabbcc", want: set(f.sw)},
		{name: "MAC bytes never match across a byte boundary", text: "bc:c0", want: []string{}},
		{name: "plain hex across a byte boundary", text: "abbcc0", want: []string{}},
		{name: "a range is not a MAC", text: "10-20", want: []string{}},
		{name: "one byte is not a MAC", text: "aa:bb:c", want: []string{}},
		{name: "a hex word is not a MAC", text: "cafe", want: []string{}},
		{name: "vendor", text: "juniper", want: set(f.sw)},
		{name: "model", text: "ex4200", want: set(f.sw)},
		{name: "the product of a device added manually is its name", text: "fortigate", want: set(f.fw)},
		{name: "no match", text: "nothing-like-this", want: []string{}},
	}
	for _, c := range cases {
		if got := search(t, e, c.approved, c.fragile, c.has, c.types, c.sources, c.text); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestDevicesSearchCombinesFilters(t *testing.T) {
	t.Parallel()
	e, f := newSearchFleet(t)
	if got := search(t, e, "true", "false", "true", "switch", "passive,snmp", "core"); !slices.Equal(got, set(f.sw)) {
		t.Fatalf("every filter together = %v", got)
	}
	if got := search(t, e, "false", "", "", "server", "", ""); !slices.Equal(got, set(f.srv)) {
		t.Fatalf("to review and type server = %v", got)
	}
	if got := search(t, e, "true", "", "", "", "osquery", ""); len(got) != 0 {
		t.Fatalf("filters AND: approved and osquery = %v", got)
	}
}

func TestDevicesListSaysEverySourceOfADevice(t *testing.T) {
	t.Parallel()
	e, f := newSearchFleet(t)
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	// The other modules' list does not read the sources (r1 L3).
	if internal, err := e.svc.Devices(e.ctx()); err != nil || len(internal.Items) != 6 || internal.Items[0].Sources != nil {
		t.Fatalf("Devices for the other modules: %v %+v", err, internal.Items)
	}
	want := map[string][]string{
		f.fw: {"manual"}, f.sw: {"passive", "snmp"}, f.srv: {"osquery"}, f.hv: {"scan"}, f.wz: {"wazuh"}, f.prn: {"scan"},
	}
	for _, d := range l.Items {
		if !slices.Equal(d.Sources, want[d.ID]) {
			t.Errorf("%s sources = %v, want %v", d.Name(), d.Sources, want[d.ID])
		}
	}
	// Without a Wazuh connection (no agents) the agent device has no source word: it is neither osquery nor Wazuh.
	e2 := newEnv(t)
	if err := e2.svc.Record(e2.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("192.168.1.30")}, Field: observe.Hostname, Value: "win-files", Source: observe.Agent, Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	l2, err := e2.svc.DevicesPage(e2.ctx(), inventory.DeviceFilter{})
	if err != nil || len(l2.Items) != 1 || l2.Items[0].Sources == nil || len(l2.Items[0].Sources) != 0 {
		t.Fatalf("no Wazuh: %v %+v", err, l2.Items)
	}
}

func TestDevicesSearchRefusesUnknownWords(t *testing.T) {
	t.Parallel()
	for _, c := range [][6]string{
		{"maybe", "", "", "", "", ""},
		{"", "yes", "", "", "", ""},
		{"", "", "1", "", "", ""},
		{"", "", "", "toaster", "", ""},
		{"", "", "", "switch,toaster", "", ""},
		{"", "", "", "", "nmap", ""},
		{"", "", "", "", "agent", ""},
		{"", "", "", "", "", strings.Repeat("x", 81)},
	} {
		_, err := inventory.ParseDeviceFilter(c[0], c[1], c[2], "", c[3], c[4], c[5])
		wantAPIError(t, err, 400, "bad_filter")
	}
	if f, err := inventory.ParseDeviceFilter("", "", "", "", " , ", ",", "  "); err != nil || len(f.Types) != 0 || len(f.Sources) != 0 || f.Q != "" {
		t.Fatalf("empty words are no filter: %+v %v", f, err)
	}
}

func TestDevicesSearchThroughTheAPIAndTheExport(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	a.addDevice(inventory.AddInput{CatalogID: "fortigate", Name: "Branch FW", IP: "192.168.30.1"})
	a.addDevice(inventory.AddInput{CatalogID: "fortigate", Name: "Other FW", IP: "192.168.30.2"})

	l := a.want("GET", "/inventory/devices?source=manual&q=branch", "viewer", "", 200, "")
	items := l["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["hostname"] != "Branch FW" || l["counts"].(map[string]any)["all"] != float64(3) {
		t.Fatalf("filtered list = %v", l)
	}
	if src := items[0].(map[string]any)["sources"].([]any); len(src) != 1 || src[0] != "manual" {
		t.Fatalf("sources = %v", src)
	}
	a.want("GET", "/inventory/devices?type=toaster", "viewer", "", 400, "bad_filter")
	a.want("GET", "/inventory/devices?source=nmap", "viewer", "", 400, "bad_filter")
	a.want("GET", "/inventory/devices?approved=maybe", "viewer", "", 400, "invalid") // the schema's enum
	a.want("GET", "/inventory/export.csv?source=wazuh,bogus", "viewer", "", 400, "bad_filter")

	_, _, raw := a.do("GET", "/inventory/export.csv?approved=true&q=other", "viewer", "")
	lines := strings.Split(strings.TrimSpace(raw), "\r\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "Other FW,192.168.30.2,") {
		t.Fatalf("the export keeps what the search keeps: %q", raw)
	}
	_, _, raw = a.do("GET", "/inventory/export.csv", "viewer", "")
	if n := len(strings.Split(strings.TrimSpace(raw), "\r\n")); n != 4 { // header, the box, two firewalls
		t.Fatalf("no filter exports every device: %d lines", n)
	}
}

// The search finds a device by the maker and model its row shows, and only then: a person's declared OS row gives a discovered device
// its maker and model (INV-45) and the search finds it by them; once the person types the device's OS, the row no longer shows them
// and the search no longer finds it by them.
func TestDevicesSearchFindsWhatTheRowShows(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKEV(fakeKEV{}))
	ctx := e.ctx()
	e.record(observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr("10.0.0.30")}, Field: observe.Hostname, Value: "edge-30", Source: observe.Nmap, Confidence: 0.7})
	id := e.idOf("10.0.0.30")
	if _, err := e.svc.AddSoftware(ctx, "op@example.com", id, inventory.AddInput{CatalogID: "fortigate", Version: "7.2.5"}); err != nil {
		t.Fatal(err)
	}
	find := func(q string) (found bool, model string) {
		t.Helper()
		f, err := inventory.ParseDeviceFilter("", "", "", "", "", "", q)
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range l.Items {
			if d.ID == id {
				if d.Model != nil {
					model = d.Model.Value
				}
				return true, model
			}
		}
		return false, ""
	}
	for _, q := range []string{"fortigate", "fortinet"} {
		if found, model := find(q); !found || model != "FortiGate" {
			t.Fatalf("%q before the typed OS: found %v, model %q", q, found, model)
		}
	}
	os := "FortiOS 7.4.1"
	if err := e.svc.PatchDevice(ctx, "op@example.com", id, inventory.Patch{OS: &os}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"fortigate", "fortinet"} {
		if found, _ := find(q); found {
			t.Errorf("%q after the typed OS: the row shows neither, the search must not find it", q)
		}
	}
	if found, _ := find("edge-30"); !found {
		t.Fatal("the host name still finds it")
	}
}
