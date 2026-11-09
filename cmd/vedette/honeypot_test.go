package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/honeypot"
)

func field(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: not an object at %q: %v", path, p, cur)
		}
		cur = mm[p]
	}
	return cur
}

func hpLine(logtype int, src string, sport int, at time.Time, data map[string]any) string {
	b, _ := json.Marshal(map[string]any{"dst_host": "192.168.10.240", "dst_port": 22, "src_host": src, "src_port": sport, "logtype": logtype,
		"utc_time": at.UTC().Format("2006-01-02 15:04:05.000000"), "logdata": data})
	return string(b) + "\n"
}

// The module is wired end to end: routes only while it is on, roles from the route table, and on a machine whose host
// cannot run the container a trap that is on never says "listening".
func TestHoneypotIsWiredAndOffByDefault(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.HoneypotDir = t.TempDir() })
	if n := s.count(`SELECT count(*) FROM sqlite_master WHERE name IN ('hp_config', 'hp_trap', 'hp_hits', 'hp_decoys', 'hp_tokens', 'hp_ignored_day')`); n != 6 {
		t.Fatalf("%d hp_ tables", n)
	}
	if code, _ := s.do("GET", "/honeypot", "admin", ""); code != http.StatusNotFound {
		t.Fatalf("module off: %d", code)
	}
	s.setModule("honeypot", true)
	s.saveScope(t)
	if code, _ := s.do("GET", "/honeypot", "viewer", ""); code != 200 {
		t.Fatalf("viewer GET: %d", code)
	}
	if code, _ := s.do("PUT", "/honeypot/config", "operator", `{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}`); code != http.StatusForbidden {
		t.Fatalf("operator PUT config: %d", code)
	}
	if code, b := s.do("PUT", "/honeypot/config", "admin", `{"secondary_ip":"10.1.1.1","hostname":"FILESRV-OLD"}`); code != 400 || field(t, b, "error", "code") != "ip_outside_lan" {
		t.Fatalf("%d %v", code, b)
	}
	code, o := s.do("PUT", "/honeypot/config", "admin", `{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}`)
	if code != 200 || field(t, o, "secondary_ip") != "192.168.10.240" || field(t, o, "lan") != "192.168.10.0/24" {
		t.Fatalf("%d %v", code, o)
	}
	if code, o = s.do("PATCH", "/honeypot/traps/ssh", "admin", `{"enabled":true}`); code != 200 {
		t.Fatalf("%d %v", code, o)
	}
	if err := s.d.Honeypot.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, o = s.do("GET", "/honeypot", "viewer", "")
	traps := field(t, o, "traps").([]any)
	ssh := traps[2].(map[string]any)
	if ssh["service"] != "ssh" || ssh["enabled"] != true || ssh["state"] != "off" {
		t.Fatalf("ssh trap: %v", ssh)
	}
	if ok, why := s.d.Honeypot.HostStatus(); ok || !strings.Contains(why, "appliance") {
		t.Fatalf("host status %v %q", ok, why)
	}
	// the other 13 operations answer with the contract's shapes
	if code, b := s.do("POST", "/honeypot/test-hit", "operator", `{"service":"ssh"}`); code != 200 || field(t, b, "is_test") != true {
		t.Fatalf("%d %v", code, b)
	}
	if code, b := s.do("POST", "/honeypot/decoys", "admin", `{"personality":"nas","name":"NAS-OLD","ip":"192.168.10.241"}`); code != 201 || field(t, b, "id") == "" {
		t.Fatalf("%d %v", code, b)
	}
	if code, b := s.do("POST", "/honeypot/test-scan", "operator", ""); code != 200 || field(t, b, "kind") != "scan" {
		t.Fatalf("%d %v", code, b)
	}
	code, b := s.do("POST", "/honeypot/tokens", "admin", `{"type":"credential","name":"svc-backup-old","plant_at":"wiki"}`)
	if code != 201 || field(t, b, "password") == nil {
		t.Fatalf("%d %v", code, b)
	}
	id := field(t, b, "id").(string)
	if code, b = s.do("POST", "/honeypot/tokens/"+id+"/test", "operator", ""); code != 200 || field(t, b, "kind") != "token" {
		t.Fatalf("%d %v", code, b)
	}
	if code, b = s.do("GET", "/honeypot/tokens", "viewer", ""); code != 200 || len(field(t, b, "items").([]any)) != 1 {
		t.Fatalf("%d %v", code, b)
	}
	if code, b = s.do("GET", "/honeypot/decoys", "viewer", ""); code != 200 || len(field(t, b, "items").([]any)) != 1 {
		t.Fatalf("%d %v", code, b)
	}
	_, b = s.do("GET", "/honeypot/hits", "viewer", "")
	items := field(t, b, "items").([]any)
	if len(items) != 3 {
		t.Fatalf("%d hits", len(items))
	}
	hid := items[0].(map[string]any)["id"].(string)
	if code, b = s.do("GET", "/honeypot/hits/"+hid, "viewer", ""); code != 200 || field(t, b, "window_minutes") != float64(60) {
		t.Fatalf("%d %v", code, b)
	}
	if code, _ = s.do("DELETE", "/honeypot/hits/"+hid, "admin", ""); code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("a hit can be deleted through the API: %d", code)
	}
	if code, _ = s.do("PATCH", "/honeypot/decoys/nope", "admin", `{"enabled":false}`); code != 404 {
		t.Fatalf("%d", code)
	}
	if code, _ = s.do("DELETE", "/honeypot/tokens/"+id, "admin", ""); code != 204 {
		t.Fatalf("%d", code)
	}
	if code, b = s.do("GET", "/honeypot/decoys", "viewer", ""); code != 200 {
		t.Fatalf("%d", code)
	}
	did := field(t, b, "items").([]any)[0].(map[string]any)["id"].(string)
	if code, _ = s.do("PATCH", "/honeypot/decoys/"+did, "admin", `{"enabled":false}`); code != 200 {
		t.Fatalf("%d", code)
	}
	if code, _ = s.do("DELETE", "/honeypot/decoys/"+did, "admin", ""); code != 204 {
		t.Fatalf("%d", code)
	}
	if s.count(`SELECT count(*) FROM core_audit WHERE action LIKE 'honeypot.%'`) < 10 {
		t.Fatal("mutations were not audited")
	}
	// off again: the routes go
	s.setModule("honeypot", false)
	if code, _ := s.do("GET", "/honeypot/hits", "admin", ""); code != http.StatusNotFound {
		t.Fatalf("module off again: %d", code)
	}
}

// A line in the shared volume becomes a hit, named from the inventory, and announced once with the 3-segment name that
// notify listens to; the scanner of the box and a module that is off are ignored.
func TestHoneypotReadsTheLogOfTheContainer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s := newStackWith(t, func(d *deps) { d.HoneypotDir = dir })
	s.saveScope(t)
	s.seen(t, "192.168.10.107", "aa:bb:cc:00:00:07", "pc")
	var got []honeypot.HitEventData
	s.d.Bus.Subscribe("honeypot.hit.created", func(_ context.Context, e events.Event) error {
		got = append(got, e.Data.(honeypot.HitEventData))
		return nil
	})
	s.setModule("honeypot", true)
	if code, _ := s.do("PUT", "/honeypot/config", "admin", `{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}`); code != 200 {
		t.Fatal(code)
	}
	if code, _ := s.do("PATCH", "/honeypot/traps/ssh", "admin", `{"enabled":true}`); code != 200 {
		t.Fatal(code)
	}
	if err := s.d.Honeypot.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, HoneypotConfigDir, "opencanary.conf")); err != nil {
		t.Fatalf("no configuration written in the folder of core: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, HoneypotLogDir), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, HoneypotLogDir, "opencanary.jsonl"), []byte(hpLine(4000, "192.168.10.107", 40000, time.Now(), map[string]any{})+hpLine(4000, "192.168.10.108", 40001, time.Now(), nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.d.Honeypot.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Service != "ssh" || got[0].SrcIP != "192.168.10.107" {
		t.Fatalf("%+v", got)
	}
	_, b := s.do("GET", "/honeypot/hits", "viewer", "")
	items := field(t, b, "items").([]any)
	names := []string{}
	for _, it := range items {
		n, _ := it.(map[string]any)["src_name"].(string)
		names = append(names, fmt.Sprint(n))
	}
	slices.Sort(names)
	if len(items) != 2 || names[0] != "" || names[1] == "" {
		t.Fatalf("%v: only the known device has a name", names)
	}
}

// The decoy addresses the honeypot handed to the host are the box, not devices: the inventory ignores what the sensors
// see there (the trap answers ARP itself) and the active sensor must not probe them (WP-14 review, CONTRACT open question 2).
func TestHoneypotDecoyAddressesAreNotDevices(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.HoneypotDir = t.TempDir() })
	s.saveScope(t)
	owned := func() bool {
		for _, a := range s.d.Honeypot.DecoyIPs(t.Context()) {
			if a.String() == "192.168.10.240" {
				return true
			}
		}
		return false
	}
	if owned() {
		t.Fatal("setup: the address is owned before the host has it")
	}
	s.seen(t, "192.168.10.240", "aa:bb:cc:00:02:40", "pc") // a real device on the address before the traps: a device
	devices := func() int {
		l, err := s.d.Inventory.Devices(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return len(l.Items)
	}
	before := devices()
	// The state the honeypot keeps once the host took the address (a fake host is not wired in cmd/vedette).
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('applied', '["192.168.10.241"]', '2026-11-09T10:00:00.000Z', 'system')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	obs := []observe.Observation{{AssetHint: observe.AssetHint{IP: mustAddr(t, "192.168.10.241"), MAC: "02:00:00:00:02:41"}, Field: observe.MAC, Value: "02:00:00:00:02:41", Source: observe.Passive, Confidence: 0.9}}
	if err := s.d.Inventory.Record(t.Context(), obs); err != nil {
		t.Fatal(err)
	}
	if after := devices(); after != before {
		t.Fatalf("the answer of the trap itself became a device (%d devices, %d before)", after, before)
	}
	prot, err := sensorInventory{inv: s.d.Inventory}.ProtectedIPs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(prot, mustAddr(t, "192.168.10.241")) {
		t.Fatalf("a sweep could probe the decoy address: %v", prot)
	}
}

func TestHoneypotJobsAndHostStandIn(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	var names []string
	for _, j := range honeypotJobs(*s.d) {
		if j.Module != "honeypot" {
			t.Errorf("job %s of module %s", j.Name, j.Module)
		}
		names = append(names, j.Name)
	}
	if !slices.Equal(names, []string{"run", "prune"}) {
		t.Fatalf("jobs = %v", names)
	}
	if honeypotJobs(deps{}) != nil {
		t.Fatal("jobs without a service")
	}
	st, err := notAnAppliance{}.Status(t.Context())
	if err != nil || st.Available || st.Running || st.Reason == "" {
		t.Fatalf("%+v %v", st, err)
	}
	if err := (notAnAppliance{}).StartContainer(t.Context()); err == nil {
		t.Fatal("the stand-in started a container")
	}
	var _ honeypot.Host = notAnAppliance{}
	var _ honeypot.Inventory = honeypotInventory{}
}

// The box is found from the inventory, falling back to one of its own addresses inside a declared range.
func TestHoneypotInventoryAdapter(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.saveScope(t)
	id := s.seen(t, "192.168.10.30", "aa:bb:cc:00:00:30", "nas")
	a := honeypotInventory{inv: s.d.Inventory}
	devs, err := a.Devices(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range devs {
		if d.ID == id {
			found = d.IP.String() == "192.168.10.30" && d.Kind == "nas" && d.Name == "192.168.10.30"
		}
	}
	if !found {
		t.Fatalf("%+v", devs)
	}
	rs, err := a.LANRanges(t.Context())
	if err != nil || len(rs) != 1 || rs[0].String() != "192.168.10.0/24" {
		t.Fatalf("%v %v", rs, err)
	}
	if b, err := a.Box(t.Context()); err != nil || b.Name == "" {
		t.Fatalf("%+v %v", b, err)
	}
}
