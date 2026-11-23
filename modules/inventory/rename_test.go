package inventory_test

import (
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// A person renames any device in Vedette. The name is the device's own (user_name), apart from the host name the
// network reports; set, it wins in the one naming rule every page and module reads (DisplayName, Names, DeviceRefs); empty is the
// default name again.

func TestDisplayName_TheNameInVedetteWins(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, host, vendor, model, ip, origin, product, want string }{
		{"Office firewall", "fw-core", "Fortinet", "FortiGate 60F", "192.168.142.1", "discovered", "", "Office firewall"},
		{"  Office firewall ", "", "", "", "192.168.142.1", "discovered", "", "Office firewall"},
		{"Accounting PC", "", "", "", "—", "manual", "Microsoft Office", "Accounting PC"}, // no "(no device)" once a person named it
		{"", "fw-core", "Fortinet", "", "192.168.142.1", "discovered", "", "fw-core"},     // empty: the naming rule
		{" ", "", "", "", "192.168.142.1", "discovered", "", "192.168.142.1"},
	} {
		if got := inventory.DisplayName(c.name, c.host, c.vendor, c.model, c.ip, c.origin, c.product); got != c.want {
			t.Errorf("DisplayName(%q, %q, …) = %q, want %q", c.name, c.host, got, c.want)
		}
	}
}

// firewall is a device found on the network at 192.168.142.1 with a host name a sensor heard.
func (e *env) firewall() string {
	e.t.Helper()
	ip := netip.MustParseAddr("192.168.142.1")
	e.record(obs(ip, macA, observe.Kind, "firewall", observe.Nmap, 0.9), obs(ip, macA, observe.Hostname, "fw-core", observe.Passive, 0.6))
	return e.idByMAC(macA)
}

func (e *env) rename(id, name string) error {
	return e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Name: &name})
}

func (e *env) nameOf(id string) string {
	e.t.Helper()
	names, err := e.svc.Names(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return names[id]
}

func TestContract_RenameReachesEveryReader(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.firewall()
	if got := e.nameOf(id); got != "fw-core" {
		t.Fatalf("before: Names = %q, want the host name", got)
	}
	e.ev.reset()
	if err := e.rename(id, "  Office firewall  "); err != nil {
		t.Fatal(err)
	}

	// Names: findings, notify, honeypot, reports and exposure read it.
	if got := e.nameOf(id); got != "Office firewall" {
		t.Errorf("Names = %q, want the name in Vedette, trimmed", got)
	}
	// The device page and the list: the name apart from the host name, which stays the observed one.
	d := e.detail(id)
	if d.Asset.UserName == nil || *d.Asset.UserName != "Office firewall" || d.Asset.Hostname == nil || *d.Asset.Hostname != "fw-core" {
		t.Errorf("detail name = %v, hostname = %v", d.Asset.UserName, d.Asset.Hostname)
	}
	if got := e.device(id); got.Name() != "Office firewall" || got.NameOrHost() == nil || *got.NameOrHost() != "Office firewall" {
		t.Errorf("Device.Name() = %q", got.Name())
	}
	// DeviceRefs: notify's refName, audit names, sensor-active, the CVE page.
	refs, err := e.svc.DeviceRefs(e.ctx(), []string{id})
	if err != nil {
		t.Fatal(err)
	}
	if r := refs[id]; r.UserName == nil || *r.UserName != "Office firewall" || *r.NameOrHost() != "Office firewall" {
		t.Errorf("DeviceRef = %+v", r)
	}
	// The findings matcher's evidence names the device the same way, and the rename asks findings to match it again.
	m, ok, err := e.svc.MatchInput(e.ctx(), id)
	if err != nil || !ok || m.Name != "Office firewall" {
		t.Errorf("MatchInput name = %q, %v, %v", m.Name, ok, err)
	}
	if up := e.ev.named(inventory.EventAssetUpdated); len(up) != 1 || !up[0].Data.(inventory.AssetEvent).Match {
		t.Errorf("updated events = %+v, want one with Match", up)
	}
	// The response safety list (KindDevice) names it too.
	kd, err := e.svc.DevicesOfKind(e.ctx(), []string{"firewall"})
	if err != nil || len(kd) != 1 || kd[0].NameOrHost() == nil || *kd[0].NameOrHost() != "Office firewall" {
		t.Errorf("DevicesOfKind = %+v, %v", kd, err)
	}
	// The Devices search finds it by the name in Vedette, and still by its host name.
	for _, q := range []string{"office", "fw-core"} {
		f, err := inventory.ParseDeviceFilter("", "", "", "", "", "", q)
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(e.ctx(), f)
		if err != nil || len(l.Items) != 1 || l.Items[0].ID != id {
			t.Errorf("search %q = %d items, %v", q, len(l.Items), err)
		}
	}
	// One audit row by the person, naming the old and the new name.
	if got := e.auditBy("inventory.rename"); len(got) != 1 || got[0] != "it@acme.example: fw-core → Office firewall" {
		t.Errorf("audit = %v", got)
	}
}

func TestContract_SameNameIsANoOpAndEmptyIsTheDefault(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.firewall()
	if err := e.rename(id, "Office firewall"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename(id, "Office firewall "); err != nil {
		t.Fatal(err)
	}
	if got := e.auditBy("inventory.rename"); len(got) != 1 {
		t.Errorf("the same name again wrote an audit row: %v", got)
	}
	if err := e.rename(id, "   "); err != nil {
		t.Fatal(err)
	}
	if got := e.nameOf(id); got != "fw-core" {
		t.Errorf("after clearing, Names = %q, want the default name (the host name)", got)
	}
	if d := e.detail(id); d.Asset.UserName != nil {
		t.Errorf("after clearing, name = %q, want null", *d.Asset.UserName)
	}
	if n := e.count(`SELECT count(*) FROM inv_asset WHERE id = ? AND user_name IS NULL`, id); n != 1 {
		t.Error("an empty name is stored as NULL")
	}
	if got := e.auditBy("inventory.rename"); len(got) != 2 || got[1] != "it@acme.example: Office firewall → fw-core" {
		t.Errorf("audit = %v", got)
	}
}

func TestContract_BadNamesAreRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.firewall()
	// review r1 of #929 (Medium): the characters the observation path refuses (invisible): bidi overrides, zero-width, C1, U+FEFF.
	for _, bad := range []string{strings.Repeat("x", 65), "a<b", "a>b", "tab\there", "\u202eresu-lawerif", "\u200b", "fw\u200dcore", "f\u0085w", "f\u0090w", "\ufefffw", "fw\u2066x"} {
		err := e.rename(id, bad)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Status != 400 || ae.Code != "bad_name" {
			t.Errorf("rename %q = %v, want 400 bad_name", bad, err)
		}
	}
	if err := e.rename(id, strings.Repeat("é", 64)); err != nil { // 64 characters, not bytes
		t.Errorf("64 characters: %v", err)
	}
	if got := e.nameOf(id); got != strings.Repeat("é", 64) {
		t.Errorf("a refused name changed the name: %q", got)
	}
	missing := "x"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", "a-missing", inventory.Patch{Name: &missing}); err == nil {
		t.Error("renaming a missing device succeeded")
	}
}

func TestContract_AMergeKeepsAName(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	into := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.1"})
	from := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.30.2"})
	if err := e.rename(from, "Branch firewall"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Merge(e.ctx(), admin, into, from); err != nil {
		t.Fatal(err)
	}
	if got := e.nameOf(into); got != "Branch firewall" {
		t.Errorf("after the merge, Names = %q, want the name given to the row that joined", got)
	}
}

func TestHandlers_PatchName(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	id := a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","ip":"192.168.30.1"}`, 201, "")["id"].(string)
	a.want("PATCH", "/inventory/devices/"+id, "viewer", `{"name":"Branch firewall"}`, 403, "forbidden")
	a.want("PATCH", "/inventory/devices/"+id, "operator", `{"name":"a<b"}`, 400, "bad_name")
	a.want("PATCH", "/inventory/devices/"+id, "operator", `{"name":"Branch firewall"}`, 200, "")
	d := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")
	if asset := d["asset"].(map[string]any); asset["name"] != "Branch firewall" || asset["hostname"] != nil {
		t.Fatalf("asset name = %v, hostname = %v", asset["name"], asset["hostname"])
	}
	list := a.want("GET", "/inventory/devices?q=branch", "viewer", "", 200, "")
	if items := list["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "Branch firewall" {
		t.Fatalf("search = %v", items)
	}
	a.want("PATCH", "/inventory/devices/"+id, "operator", `{"name":""}`, 200, "")
	if asset := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")["asset"].(map[string]any); asset["name"] != nil {
		t.Fatalf("after clearing, name = %v", asset["name"])
	}
}

// review r1 of #929 (Low): the export keeps the host name and the name in Vedette in their own columns, and an import reads them back
// the same way: the person's name never becomes a host name observation.
func TestContract_CSVKeepsBothNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.firewall()
	if err := e.rename(id, "Office firewall"); err != nil {
		t.Fatal(err)
	}
	rd, err := e.svc.ExportCSV(e.ctx(), "it@acme.example", inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(rd)
	lines := strings.Split(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n")
	if !strings.HasPrefix(lines[0], "name,ip,") || !strings.HasSuffix(lines[0], ",name_in_vedette,risk") {
		t.Fatalf("header = %q", lines[0])
	}
	var row string
	for _, l := range lines {
		if strings.Contains(l, "192.168.142.1") {
			row = l
		}
	}
	if !strings.HasPrefix(row, "fw-core,192.168.142.1,") || !strings.HasSuffix(row, ",Office firewall,") {
		t.Fatalf("row = %q", row)
	}
	// Imported on a fresh box: the host name is fw-core (typed), the name in Vedette "Office firewall".
	other := newEnv(t)
	if r := other.importCSV(string(raw)); r.Created != 1 || len(r.Errors) != 0 {
		t.Fatalf("import = %+v", r)
	}
	f, err := inventory.ParseDeviceFilter("", "", "", "", "", "", "192.168.142.1")
	if err != nil {
		t.Fatal(err)
	}
	l, err := other.svc.DevicesPage(other.ctx(), f)
	if err != nil || len(l.Items) != 1 {
		t.Fatalf("imported = %+v, %v", l.Items, err)
	}
	d := l.Items[0]
	if d.Hostname == nil || *d.Hostname != "fw-core" || d.UserName == nil || *d.UserName != "Office firewall" {
		t.Errorf("imported host name %v, name %v", d.Hostname, d.UserName)
	}
	if n := other.count(`SELECT count(*) FROM inv_observation WHERE field = 'hostname' AND value = 'Office firewall'`); n != 0 {
		t.Error("the name in Vedette became a host name observation")
	}
	// A refused name in the column is the row's error, as a bad name is.
	if r := other.importCSV("name_in_vedette,ip\n\u202eevil,192.168.142.77\n"); r.Created != 0 || len(r.Errors) != 1 {
		t.Errorf("bad name_in_vedette = %+v", r)
	}
}

// review r1 of #929 (Low): a duplicate address names the device that has it as every page does.
func TestContract_DuplicateIPNamesTheDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.142.1")
	e.record(obs(ip, macA, observe.Kind, "firewall", observe.Nmap, 0.9))
	id := e.idByMAC(macA)
	if err := e.rename(id, "Office firewall"); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.AddDevice(e.ctx(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "192.168.142.1"})
	if err == nil || !strings.Contains(err.Error(), "(Office firewall)") {
		t.Errorf("add = %v", err)
	}
	if r := e.importCSV("name,ip\nfw2,192.168.142.1\n"); len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Message, "Office firewall") {
		t.Errorf("import = %+v", r)
	}
}
