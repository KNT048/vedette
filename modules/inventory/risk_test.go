package inventory_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// Every list shows each device's badge. Inventory reads it from findings' device status through Config.Risk (RiskSource), never
// from fnd_* tables: the most urgent open status with its distinct CVEs, else possible, nil when none. The Devices search filters
// on it.

type fakeRisk map[string]inventory.Risk

func (f fakeRisk) DeviceStatuses(context.Context) (map[string]inventory.Risk, error) {
	return f, nil
}

// countingRisk counts the calls and fails when err is set.
type countingRisk struct {
	calls atomic.Int64
	err   error
	m     fakeRisk
}

func (c *countingRisk) DeviceStatuses(context.Context) (map[string]inventory.Risk, error) {
	c.calls.Add(1)
	if c.err != nil {
		return nil, c.err
	}
	return c.m, nil
}

func withRisk(r inventory.RiskSource) opt { return func(c *inventory.Config) { c.Risk = r } }

// riskDevices records three devices found on the network: one with exploited findings, one with an update, one clean.
func riskDevices(e *env) (exploited, update, clean string) {
	e.t.Helper()
	for i, mac := range []string{macA, macB, "aa:bb:cc:00:00:03"} {
		e.record(obs(netip.AddrFrom4([4]byte{192, 168, 142, byte(10 + i)}), mac, observe.Kind, "server", observe.Nmap, 0.9))
	}
	return e.idByMAC(macA), e.idByMAC(macB), e.idByMAC("aa:bb:cc:00:00:03")
}

func TestContract_RiskMarkerOnRowsAndDetail(t *testing.T) {
	t.Parallel()
	risk := fakeRisk{}
	e := newEnv(t, withRisk(risk))
	x, u, c := riskDevices(e)
	risk[x] = inventory.Risk{Code: "exploited", Count: 2}
	risk[u] = inventory.Risk{Code: "update_recommended", Count: 3}
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*inventory.Risk{}
	for _, d := range l.Items {
		got[d.ID] = d.Risk
	}
	if r := got[x]; r == nil || *r != (inventory.Risk{Code: "exploited", Count: 2}) {
		t.Errorf("exploited: %+v", r)
	}
	if r := got[u]; r == nil || *r != (inventory.Risk{Code: "update_recommended", Count: 3}) {
		t.Errorf("update: %+v", r)
	}
	if got[c] != nil {
		t.Errorf("clean: %+v", got[c])
	}
	d, err := e.svc.DetailPage(e.ctx(), x)
	if err != nil || d.Risk == nil || d.Risk.Code != "exploited" {
		t.Errorf("detail: %+v, %v", d.Risk, err)
	}
	// No RiskSource (findings off): nothing is marked.
	plain := newEnv(t)
	riskDevices(plain)
	l, _ = plain.svc.DevicesPage(plain.ctx(), inventory.DeviceFilter{})
	for _, d := range l.Items {
		if d.Risk != nil {
			t.Errorf("no risk source, yet %s is marked %+v", d.ID, d.Risk)
		}
	}
}

func TestContract_TheRiskFilter(t *testing.T) {
	t.Parallel()
	risk := fakeRisk{}
	e := newEnv(t, withRisk(risk))
	x, u, c := riskDevices(e)
	risk[x], risk[u] = inventory.Risk{Code: "exploited", Count: 1}, inventory.Risk{Code: "update_recommended", Count: 1}
	ids := func(risks string) map[string]bool {
		t.Helper()
		f, err := inventory.ParseDeviceSearch("", "", "", "", "", "", risks, "")
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(e.ctx(), f)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, d := range l.Items {
			if !d.IsBox {
				out[d.ID] = true
			}
		}
		return out
	}
	for risks, want := range map[string][]string{
		"exploited": {x}, "update_recommended": {u}, "none": {c}, "exploited,update_recommended": {x, u}, "update_recommended,none": {u, c}, "EXPLOITED, none": {x, c}, "": {x, u, c},
	} {
		got := ids(risks)
		if len(got) != len(want) {
			t.Errorf("risk=%q: %v, want %v", risks, got, want)
		}
		for _, id := range want {
			if !got[id] {
				t.Errorf("risk=%q: %s missing", risks, id)
			}
		}
	}
	_, err := inventory.ParseDeviceSearch("", "", "", "", "", "", "high", "")
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Code != "bad_filter" {
		t.Errorf("risk=high: %v, want 400 bad_filter", err)
	}
}

func TestHandlers_RiskThroughTheAPI(t *testing.T) {
	t.Parallel()
	a := newAPI(t)
	id := a.want("POST", "/inventory/devices", "operator", `{"catalog_id":"fortigate","ip":"192.168.30.1"}`, 201, "")["id"].(string)
	// newAPI has no RiskSource: the field is there and null
	row := a.want("GET", "/inventory/devices?risk=none", "viewer", "", 200, "")["items"].([]any)
	if len(row) != 2 || row[0].(map[string]any)["risk"] != nil {
		t.Fatalf("risk=none = %v", row)
	}
	if items := a.want("GET", "/inventory/devices?risk=exploited", "viewer", "", 200, "")["items"].([]any); len(items) != 0 {
		t.Fatalf("risk=exploited = %v", items)
	}
	a.want("GET", "/inventory/devices?risk=bad", "viewer", "", 400, "bad_filter")
	if d := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, ""); d["risk"] != nil {
		t.Fatalf("detail risk = %v", d["risk"])
	}
	if _, ok := a.want("GET", "/inventory/devices/"+id, "viewer", "", 200, "")["risk"]; !ok {
		t.Fatal("detail has no risk field")
	}
}

// Review r1 of #949 (High): only the Devices page, the device page and the export with a risk filter read the markers. The other
// readers (honeypot ingest, scans, reports, MCP: Devices, AllDevices, Device, Detail) never call the risk port, and a failing port
// never fails a list: the rows have no marker and RiskUnavailable says so.
func TestContract_RiskIsOptInAndNeverFailsTheList(t *testing.T) {
	t.Parallel()
	src := &countingRisk{m: fakeRisk{}}
	e := newEnv(t, withRisk(src))
	x, _, c := riskDevices(e)
	src.m[x] = inventory.Risk{Code: "exploited", Count: 1}
	if _, err := e.svc.Devices(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AllDevices(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Device(e.ctx(), x); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Detail(e.ctx(), x); err != nil {
		t.Fatal(err)
	}
	if n := src.calls.Load(); n != 0 {
		t.Fatalf("internal device reads called the risk port %d times", n)
	}
	if _, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{}); err != nil || src.calls.Load() != 1 {
		t.Fatalf("the Devices page reads it once: %d calls, %v", src.calls.Load(), err)
	}

	src.err = errors.New("findings: database is locked")
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatalf("a failing risk source failed the list: %v", err)
	}
	if !l.RiskUnavailable || len(l.Items) < 3 {
		t.Errorf("unavailable = %v, %d rows: want the list, saying so", l.RiskUnavailable, len(l.Items))
	}
	for _, d := range l.Items {
		if d.Risk != nil {
			t.Errorf("%s marked while the source failed", d.ID)
		}
	}
	d, err := e.svc.DetailPage(e.ctx(), c)
	if err != nil || !d.RiskUnavailable || d.Risk != nil {
		t.Errorf("detail: %+v, %v", d.Risk, err)
	}
	if _, err := e.svc.ExportCSV(e.ctx(), "it@acme.example", inventory.DeviceFilter{}); err != nil {
		t.Errorf("an unfiltered export while the source fails: %v", err)
	}
	// review r2 of #949 L1: a risk filter that cannot be applied is 503 risk_unavailable, never every device
	f, _ := inventory.ParseDeviceSearch("", "", "", "", "", "", "exploited", "")
	for name, call := range map[string]func() error{
		"list":   func() error { _, err := e.svc.DevicesPage(e.ctx(), f); return err },
		"export": func() error { _, err := e.svc.ExportCSV(e.ctx(), "it@acme.example", f); return err },
	} {
		var ae *apierr.Error
		if err := call(); !errors.As(err, &ae) || ae.Status != 503 || ae.Code != "risk_unavailable" {
			t.Errorf("%s with a risk filter while the source fails: %v, want 503 risk_unavailable", name, err)
		}
	}
}

// Review r2 of #949 (Medium): the CSV says what the marker says, in its words: "2 exploited", "Update recommended", empty when clean.
func TestContract_TheCSVHasTheRisk(t *testing.T) {
	t.Parallel()
	src := fakeRisk{}
	e := newEnv(t, withRisk(src))
	x, u, c := riskDevices(e)
	src[x], src[u] = inventory.Risk{Code: "exploited", Count: 2}, inventory.Risk{Code: "update_recommended", Count: 3}
	rd, err := e.svc.ExportCSV(e.ctx(), "it@acme.example", inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(rd)
	lines := strings.Split(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n")
	if !strings.HasSuffix(lines[0], ",risk") {
		t.Fatalf("header = %q", lines[0])
	}
	want := map[string]string{"10.142.0.10": ",2 exploited", "10.142.0.11": ",Update recommended", "10.142.0.12": ","}
	for _, l := range lines[1:] {
		for ip, end := range want {
			if strings.Contains(l, ","+ip+",") && !strings.HasSuffix(l, end) {
				t.Errorf("%s: %q, want it to end %q", ip, l, end)
			}
		}
	}
	_ = c
}

// The Vedette box is marked by the one rule every device follows: its open findings give it the badge they give any device, on the
// list and on its page (a box with 139 open findings and no badge read as a clean device beside one with 2 marked "Update
// recommended"); a box with none has no marker.
func TestContract_TheBoxIsMarkedLikeAnyDevice(t *testing.T) {
	t.Parallel()
	src := fakeRisk{}
	e := newEnv(t, withRisk(src))
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "boxanna", IP: "10.142.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	src[box] = inventory.Risk{Code: "exploited", Count: 1}
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range l.Items {
		if d.IsBox && (d.Risk == nil || d.Risk.Code != "exploited") {
			t.Errorf("the box is not marked: %+v", d.Risk)
		}
	}
	if d, err := e.svc.DetailPage(e.ctx(), box); err != nil || d.Risk == nil || d.Risk.Code != "exploited" {
		t.Errorf("box detail: %+v, %v", d.Risk, err)
	}
	f, _ := inventory.ParseDeviceSearch("", "", "", "", "", "", "exploited", "")
	if l, _ := e.svc.DevicesPage(e.ctx(), f); len(l.Items) != 1 || !l.Items[0].IsBox {
		t.Errorf("risk=exploited: %+v", l.Items)
	}
	delete(src, box)
	if d, err := e.svc.DetailPage(e.ctx(), box); err != nil || d.Risk != nil {
		t.Errorf("a box with no open finding is marked: %+v, %v", d.Risk, err)
	}
}

// has_findings keeps the devices with open findings, read from their status: a device whose findings are all closed
// (findings_count still counts them) or that only waits for an answer has none. Statuses unreadable: 503, never every device.
func TestContract_HasFindingsIsOpenFindings(t *testing.T) {
	t.Parallel()
	src := &countingRisk{m: fakeRisk{}}
	e := newEnv(t, withRisk(src))
	open, input, closed := riskDevices(e)
	src.m[open] = inventory.Risk{Code: "exploited", Count: 1}
	src.m[input] = inventory.Risk{Code: "possible", Count: 1}
	e.findg[open], e.findg[input], e.findg[closed] = 1, 2, 3 // every state counts in findings_count; closed's are all patched
	ids := func(v string) []string {
		f, err := inventory.ParseDeviceSearch("", "", v, "", "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(e.ctx(), f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, d := range l.Items {
			out = append(out, d.ID)
		}
		return out
	}
	if got := ids("true"); len(got) != 1 || got[0] != open {
		t.Errorf("has_findings=true = %v, want only %s", got, open)
	}
	if got := ids("false"); len(got) != 2 || slices.Contains(got, open) {
		t.Errorf("has_findings=false = %v, want the other two", got)
	}
	src.err = errors.New("findings is down")
	f, _ := inventory.ParseDeviceSearch("", "", "true", "", "", "", "", "")
	var ae *apierr.Error
	if _, err := e.svc.DevicesPage(e.ctx(), f); !errors.As(err, &ae) || ae.Status != 503 || ae.Code != "risk_unavailable" {
		t.Errorf("has_findings while the statuses fail: %v, want 503 risk_unavailable", err)
	}
}

// has_findings reads the box like any device: with open findings it is listed under true, the same answer as the Devices page's "Has
// findings" chip, which reads the row's status.
func TestContract_HasFindingsReadsTheBoxLikeAnyDevice(t *testing.T) {
	t.Parallel()
	src := fakeRisk{}
	e := newEnv(t, withRisk(src))
	box, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "boxanna", IP: "192.0.2.2"})
	if err != nil {
		t.Fatal(err)
	}
	src[box] = inventory.Risk{Code: "exploited", Count: 1}
	e.findg[box] = 1
	for v, want := range map[string]int{"true": 1, "false": 0} {
		f, err := inventory.ParseDeviceSearch("", "", v, "", "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		l, err := e.svc.DevicesPage(e.ctx(), f)
		if err != nil {
			t.Fatal(err)
		}
		if len(l.Items) != want || (want == 1 && !l.Items[0].IsBox) {
			t.Errorf("has_findings=%s: %d rows %+v, want %d (the box only with true)", v, len(l.Items), l.Items, want)
		}
	}
}
