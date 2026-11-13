package agentintake_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
	"github.com/knt048/vedette/modules/inventory"
)

// intervals is the interval of each query in a config answer.
func (w *world) intervals(key string) map[string]float64 {
	w.t.Helper()
	r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key})
	sch, _ := r.body["schedule"].(map[string]any)
	if r.code != 200 || r.invalid() || len(sch) != 6 {
		w.t.Fatalf("config: %d %s", r.code, r.raw)
	}
	out := map[string]float64{}
	for name, q := range sch {
		out[name], _ = q.(map[string]any)["interval"].(float64)
	}
	return out
}

func wantIntervals(t *testing.T, step string, got map[string]float64, want map[string]float64) {
	t.Helper()
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s: %s every %v s, want %v (all: %v)", step, name, got[name], v, got)
		}
	}
}

// D-503 (W2-1): a new machine is asked every minute for each answer of its first report the inventory has not taken yet, and goes back
// to the hourly schedule answer by answer; an answer written for nobody (no matched address) does not count; after an hour a node that
// never matched is not asked every minute any more.
func TestContract_D503_FirstReportIsAskedEveryMinute(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	all := map[string]float64{"os_version": 60, "system_info": 60, "interfaces": 60, "deb_packages": 60, "rpm_packages": 60, "programs": 60}
	wantIntervals(t, "enrolled", w.intervals(key), all)

	// The OS before the interfaces: nothing can be written yet, so nothing is taken.
	w.post("/intake/osquery/log", peerA, logBody(key, snap("os_version", map[string]string{"name": "Ubuntu", "version": "26.04.1 LTS", "platform": "ubuntu"})))
	wantIntervals(t, "os without interfaces", w.intervals(key), all)

	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key,
		snap("interfaces", ifaceRow(macA, peerA)),
		snap("os_version", map[string]string{"name": "Ubuntu", "version": "26.04.1 LTS", "platform": "ubuntu"})))
	wantIntervals(t, "os and interfaces", w.intervals(key),
		map[string]float64{"os_version": 3600, "interfaces": 3600, "system_info": 60, "deb_packages": 60, "rpm_packages": 60, "programs": 60})

	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key,
		snap("system_info", map[string]string{"hostname": "byn", "hardware_vendor": "Dell Inc.", "hardware_model": "Vostro 3669"}),
		snap("deb_packages", debRow("openssh-server", "1:9.6p1-3ubuntu13.5")), snap("rpm_packages")))
	wantIntervals(t, "first report complete", w.intervals(key),
		map[string]float64{"os_version": 3600, "interfaces": 3600, "system_info": 86400, "deb_packages": 3600, "rpm_packages": 3600, "programs": 3600})
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE reported = 'os_version,system_info,interfaces,packages'`); n != 1 {
		t.Fatalf("reported list not canonical: %d", n)
	}

	// A node that never matches its address (NAT) asks every minute for its first hour only.
	nat := w.enroll(secret, "behind-nat", peerA)
	w.post("/intake/osquery/log", peerA, logBody(nat, snap("interfaces", ifaceRow("52:54:00:aa:bb:09", "10.1.1.1"))))
	wantIntervals(t, "unmatched", w.intervals(nat), all)
	w.clock.Advance(61 * time.Minute)
	wantIntervals(t, "unmatched after an hour", w.intervals(nat),
		map[string]float64{"os_version": 3600, "interfaces": 3600, "system_info": 86400, "deb_packages": 3600})
}

// D-503 (W2-1, W2-12): the agent claims the row the passive sensor made for the same machine (one device), types it from its OS with
// the agent's rank (a passive guess never overrides it, a person's choice does), and the enrolment approves it once, in the name of
// whoever made the token.
func TestContract_D503_AgentClaimsThePassiveRowTypedAndApproved(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	passive := func(f observe.Field, v string) {
		t.Helper()
		err := w.inv.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{MAC: macA, IP: netip.MustParseAddr(peerA)}, Field: f, Value: v, Source: observe.Passive, Confidence: 0.6}})
		if err != nil {
			t.Fatal(err)
		}
	}
	passive(observe.Vendor, "Hon Hai Precision")
	passive(observe.Kind, "iot")
	if d, ok := w.device(peerA); !ok || d.Approved || d.Kind != "iot" || w.deviceCount() != 1 {
		t.Fatalf("passive row %+v", d.AssetCore)
	}

	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "byn", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	d, _ := w.device(peerA)
	if w.deviceCount() != 1 || !d.Approved || d.Kind != "server" || d.OS == nil || d.OS.Source != "agent" || len(d.Software) == 0 {
		t.Fatalf("after the agent: %d devices, %+v os=%+v software=%d", w.deviceCount(), d.AssetCore, d.OS, len(d.Software))
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled' AND user = 'system' AND detail LIKE '%token "srv", made by admin@acme.example%'`); n != 1 {
		t.Fatalf("approval audit rows naming the token's maker: %d", n)
	}

	passive(observe.Kind, "printer") // a later passive guess
	if d, _ := w.device(peerA); d.Kind != "server" {
		t.Fatalf("a passive guess overrode the agent's kind: %s", d.Kind)
	}
	nas := "nas"
	if err := w.inv.PatchDevice(ctx, "admin@acme.example", d.ID, inventory.Patch{Kind: &nas}); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(6 * time.Minute)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	if d, _ := w.device(peerA); d.Kind != "nas" || !d.Approved {
		t.Fatalf("the next report undid a person's kind: %s approved=%v", d.Kind, d.Approved)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`); n != 1 {
		t.Fatalf("approved again: %d audit rows", n)
	}
}

// D-503: a machine a person marked suspicious keeps waiting after it enrols (a person's flag wins) and is not tried again at every report.
func TestContract_D503_SuspiciousStaysForAPerson(t *testing.T) {
	w := newWorld(t)
	if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{MAC: macA, IP: netip.MustParseAddr(peerA)}, Field: observe.Hostname, Value: "odd", Source: observe.Passive, Confidence: 0.6}}); err != nil {
		t.Fatal(err)
	}
	d, _ := w.device(peerA)
	if err := w.inv.SetSuspicious(t.Context(), "admin@acme.example", d.ID, true); err != nil {
		t.Fatal(err)
	}
	_, secret := w.token("srv", 7)
	w.exec(`UPDATE intake_agent_tokens SET created_by = NULL`) // a token made before created_by
	key := w.enroll(secret, "odd", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	if d, _ := w.device(peerA); d.Approved {
		t.Fatal("the enrolment approved a device a person marked suspicious")
	}
	if w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`) != 0 || w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE approved_at IS NOT NULL`) != 1 {
		t.Fatal("the suspicious device was approved, or the node will try again at every report")
	}
}

// D-503: a token made before created_by still approves; the audit line says who made it is not known.
func TestContract_D503_OldTokenSaysItsMakerIsUnknown(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("old", 7)
	w.exec(`UPDATE intake_agent_tokens SET created_by = NULL`)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	var detail string
	if err := w.db.Reader().QueryRowContext(t.Context(), `SELECT detail FROM core_audit WHERE action = 'inventory.approve_enrolled'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, `token "old", made before Vedette recorded who makes tokens`) {
		t.Fatalf("detail %q", detail)
	}
}

// D-503, review #665 (HIGH): DHCP gave the address of an old machine to a new one and no sensor has seen the move yet, so the agent's
// address still resolves to the old machine's row. The agent's MAC observation makes the agent's MAC that row's MAC (agent outranks
// passive), so a check of the MAC column alone would pass; the old MAC's observation is what says it is another machine. The row is
// not approved in the token maker's name, the node does not try again at every report, and the server log says why.
func TestContract_D503_AnAddressDHCPReusedApprovesNothing(t *testing.T) {
	w := newWorld(t)
	const oldMAC = "52:54:00:00:00:99"
	if err := w.inv.Record(t.Context(), []observe.Observation{{AssetHint: observe.AssetHint{MAC: oldMAC, IP: netip.MustParseAddr(peerA)}, Field: observe.Hostname, Value: "old-laptop", Source: observe.Passive, Confidence: 0.6}}); err != nil {
		t.Fatal(err)
	}
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(key))
	d, ok := w.device(peerA)
	if !ok || d.MAC == nil || *d.MAC != macA {
		t.Fatalf("setup: the agent's report should have landed on the old row and taken its MAC column: %+v", d.AssetCore)
	}
	if d.Approved {
		t.Fatal("the enrolment approved a row seen with another machine's MAC")
	}
	if w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`) != 0 || w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE approved_at IS NOT NULL`) != 1 {
		t.Fatal("approved, or the node will try again at every report")
	}
	if !strings.Contains(w.logs.String(), "seen with another MAC") {
		t.Fatalf("no log line says why: %s", w.logs.String())
	}
}

// D-503, review #665 (LOW 3): the 5-minute window of package lists is per source address, not per node. A list the window dropped was
// not taken from this node, so its first hour keeps asking for it; the next list after the window counts.
func TestContract_D503_APackageListTheWindowDroppedIsAskedAgain(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	first := w.enroll(secret, "srv-1", peerA)
	w.post("/intake/osquery/log", peerA, fullLog(first))
	second := w.enroll(secret, "srv-1-again", peerA) // a second node on the same machine
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, fullLog(second))
	if got := w.intervals(second)["deb_packages"]; got != 60 {
		t.Fatalf("a dropped list counted as taken: deb_packages every %v s", got)
	}
	w.clock.Advance(5 * time.Minute)
	w.post("/intake/osquery/log", peerA, fullLog(second))
	if got := w.intervals(second)["deb_packages"]; got != 3600 {
		t.Fatalf("the list after the window was not taken: deb_packages every %v s", got)
	}
}

// D-503, the upgrade path (N100 walk): a machine enrolled before the upgrade has a binding and an OS in the inventory but was never
// approved, and its next report may be an hour away. The approve-enrolled job, at start, approves and types it from what the inventory
// already has, with no new report; a row seen with another MAC is still left for a person, a person's kind still wins, a node with no
// binding waits for its report, and a second run changes nothing.
func TestContract_D503_UpgradeApprovesAndTypesEnrolledMachines(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	const (
		peerB, peerC, peerD = "192.0.2.11", "192.0.2.12", "192.0.2.13"
		macC, macD          = "52:54:00:aa:bb:03", "52:54:00:aa:bb:04"
		oldMAC              = "52:54:00:00:00:99"
	)
	record := func(ip string, src observe.Source, f observe.Field, v string) {
		t.Helper()
		o := observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: f, Value: v, Source: src, Confidence: 0.95}
		if err := w.inv.Record(ctx, []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	// What an agent wrote before the upgrade: its OS and its card's MAC, no kind.
	old := func(ip, mac string) {
		t.Helper()
		record(ip, observe.Agent, observe.OS, "Ubuntu 26.04 LTS (Resolute Raccoon)")
		record(ip, observe.Agent, observe.MAC, mac)
	}
	_, secret := w.token("srv", 7)
	for host, peer := range map[string]string{"byn": peerA, "dhcp": peerB, "kept": peerC, "nat": peerD} {
		w.enroll(secret, host, peer)
	}
	old(peerA, macA)
	if err := w.inv.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{MAC: oldMAC, IP: netip.MustParseAddr(peerB)}, Field: observe.Hostname, Value: "old-laptop", Source: observe.Passive, Confidence: 0.6}}); err != nil {
		t.Fatal(err)
	}
	old(peerB, macC)
	old(peerC, macD)
	kept, _ := w.device(peerC)
	nas := "nas"
	if err := w.inv.PatchDevice(ctx, "admin@acme.example", kept.ID, inventory.Patch{Kind: &nas}); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(2 * time.Hour) // enrolled two hours before the upgrade: past the first-report window
	w.bind("byn", peerA, macA, time.Hour)
	w.bind("dhcp", peerB, macC, time.Hour)
	w.bind("kept", peerC, macD, time.Hour)
	const peerE, macE = "192.0.2.14", "52:54:00:aa:bb:06"
	w.enroll(secret, "silent", peerE)
	w.agentWrote(peerE, macE)
	w.bind("silent", peerE, macE, 8*24*time.Hour) // last result 8 days ago: its address may be another machine's by now
	if d, _ := w.device(peerA); d.Approved || d.Kind != "unknown" {
		t.Fatalf("setup: %+v", d.AssetCore)
	}

	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	d, _ := w.device(peerA)
	if !d.Approved || d.Kind != "server" || d.OS == nil || d.OS.Source != "agent" {
		t.Fatalf("the old machine after the upgrade: %+v os=%+v", d.AssetCore, d.OS)
	}
	if d, _ := w.device(peerB); d.Approved {
		t.Fatal("the upgrade approved a row seen with another machine's MAC")
	}
	if d, _ := w.device(peerC); !d.Approved || d.Kind != "nas" {
		t.Fatalf("a person's kind: %s approved=%v", d.Kind, d.Approved)
	}
	if d, _ := w.device(peerE); d.Approved || d.Kind != "unknown" {
		t.Fatalf("a node silent for 8 days: %s approved=%v", d.Kind, d.Approved)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled' AND user = 'system' AND detail LIKE '%"byn" enrolled with the token "srv", made by admin@acme.example, approved from its earlier reports after an upgrade'`); n != 1 {
		t.Fatalf("approval audit rows of byn: %d", n)
	}
	if n := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE approved_at IS NOT NULL`); n != 3 {
		t.Fatalf("%d nodes marked done, want 3 (the node with no binding and the silent one wait for a report)", n)
	}

	snapshot := func() string {
		var done string
		if err := w.db.Reader().QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM core_audit) || ' ' ||
			(SELECT group_concat(host_identifier || '=' || coalesce(approved_at, '-'), ' ') FROM (SELECT host_identifier, approved_at FROM intake_osquery_nodes ORDER BY host_identifier))`).Scan(&done); err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{peerA, peerB, peerC} {
			d, _ := w.device(ip)
			done += fmt.Sprintf(" %s:%s:%v", ip, d.Kind, d.Approved)
		}
		return done
	}
	before := snapshot()
	w.clock.Advance(time.Minute)
	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	if after := snapshot(); after != before {
		t.Fatalf("a second run changed something: %v -> %v", before, after)
	}
	if w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE approved_at IS NULL AND host_identifier IN ('nat', 'silent')`) != 2 {
		t.Fatal("the node with no binding or the silent one was marked done")
	}
}

// bind stores the binding a node got from its reports, and its last result ago before now (what markResult writes).
func (w *world) bind(host, ip, mac string, ago time.Duration) {
	w.t.Helper()
	w.exec(`UPDATE intake_osquery_nodes SET bound_ip = '` + ip + `', bound_mac = '` + mac + `', last_result_at = '` +
		store.FormatTS(w.clock.Now().Add(-ago)) + `' WHERE host_identifier = '` + host + `'`)
}

// agentWrote records what an agent wrote on the device at ip before D-503: its OS and its card's MAC, no kind.
func (w *world) agentWrote(ip, mac string) {
	w.t.Helper()
	h := observe.AssetHint{IP: netip.MustParseAddr(ip)}
	err := w.inv.Record(w.t.Context(), []observe.Observation{
		{AssetHint: h, Field: observe.OS, Value: "Ubuntu 26.04 LTS", Source: observe.Agent, Confidence: 0.95},
		{AssetHint: h, Field: observe.MAC, Value: mac, Source: observe.Agent, Confidence: 0.9},
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// Review #673 H1: a stored binding is no live connection. A machine decommissioned (its device deleted, its node not revoked) leaves
// its address to a new machine that sensors see only by IP, with no MAC: the job approves it neither from a binding a month old nor
// from a fresh one, because the agent never reported its MAC on that row.
func TestContract_D503_UpgradeNeverApprovesARowTheAgentDidNotReport(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	_, secret := w.token("srv", 0) // never expires
	w.enroll(secret, "gone", peerA)
	w.bind("gone", peerA, macA, 0)
	w.clock.Advance(30 * 24 * time.Hour)
	if err := w.svc.ApproveBound(ctx); err != nil { // no device yet
		t.Fatal(err)
	}
	nmap := func(ip string) {
		t.Helper()
		o := observe.Observation{AssetHint: observe.AssetHint{IP: netip.MustParseAddr(ip)}, Field: observe.OS, Value: "Windows 10", Source: observe.Nmap, Confidence: 0.6}
		if err := w.inv.Record(ctx, []observe.Observation{o}); err != nil {
			t.Fatal(err)
		}
	}
	nmap(peerA)
	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := w.device(peerA); d.Approved {
		t.Fatal("a machine the agent never saw was approved from a binding a month old")
	}

	const peerB = "192.0.2.11"
	w.enroll(secret, "fresh", peerB)
	w.bind("fresh", peerB, "52:54:00:aa:bb:05", time.Minute) // reported a minute ago, but its row holds no MAC of the agent
	nmap(peerB)
	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := w.device(peerB); d.Approved {
		t.Fatal("a row the agent never reported its MAC on was approved")
	}
	if w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE approved_at IS NOT NULL`) != 0 || w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`) != 0 {
		t.Fatal("a node was marked done or an approval was audited")
	}
}

// Review #673 L3: the job path keeps the inventory's guards. An address the box answers on is no device (the node waits); a device a
// person marked suspicious keeps waiting (the node is done, no audit row).
func TestContract_D503_UpgradeKeepsTheBoxAndSuspiciousGuards(t *testing.T) {
	var decoy atomic.Bool
	w := newWorld(t, func(c *agentintake.Config) {
		inv, err := inventory.New(inventory.Config{DB: c.DB, Audit: c.Audit, Clock: c.Clock, Log: c.Log, BoxOwnedIPs: func(context.Context) []netip.Addr {
			if decoy.Load() {
				return []netip.Addr{netip.MustParseAddr(peerA)}
			}
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		c.Approver = inv
	})
	ctx := t.Context()
	const peerB, macB = "192.0.2.11", "52:54:00:aa:bb:02"
	_, secret := w.token("srv", 7)
	w.enroll(secret, "decoy", peerA)
	w.enroll(secret, "odd", peerB)
	w.agentWrote(peerA, macA) // made before the address became a decoy
	w.agentWrote(peerB, macB)
	odd, _ := w.device(peerB)
	if err := w.inv.SetSuspicious(ctx, "admin@acme.example", odd.ID, true); err != nil {
		t.Fatal(err)
	}
	w.bind("decoy", peerA, macA, time.Hour)
	w.bind("odd", peerB, macB, time.Hour)
	decoy.Store(true)
	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := w.device(peerA); d.Approved || w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE host_identifier = 'decoy' AND approved_at IS NULL`) != 1 {
		t.Fatalf("an address the box answers on: approved=%v, or the node was marked done", d.Approved)
	}
	if d, _ := w.device(peerB); d.Approved || w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE host_identifier = 'odd' AND approved_at IS NOT NULL`) != 1 {
		t.Fatalf("a suspicious device: approved=%v, or the node will try again every day", d.Approved)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`); n != 0 {
		t.Fatalf("%d approval audit rows", n)
	}
}

// revokeFirst is an Approver that revokes a token on its first call, before handing the call on: a token revoked while the job runs.
type revokeFirst struct {
	observe.Approver
	once   sync.Once
	revoke func(reason string)
}

func (r *revokeFirst) ApproveEnrolled(ctx context.Context, hint observe.AssetHint, mac, reason string, agentSaw bool) (bool, error) {
	r.once.Do(func() { r.revoke(reason) })
	return r.Approver.ApproveEnrolled(ctx, hint, mac, reason, agentSaw)
}

// Review #673 L3: a node whose token is revoked while the job runs is skipped and the run goes on with the next node.
func TestContract_D503_UpgradeSkipsANodeRevokedDuringTheRun(t *testing.T) {
	r := &revokeFirst{}
	w := newWorld(t, func(c *agentintake.Config) { r.Approver = c.Approver; c.Approver = r })
	ctx := t.Context()
	const peerB, macB = "192.0.2.11", "52:54:00:aa:bb:02"
	idA, secretA := w.token("a", 7)
	idB, secretB := w.token("b", 7)
	w.enroll(secretA, "a", peerA)
	w.enroll(secretB, "b", peerB)
	w.agentWrote(peerA, macA)
	w.agentWrote(peerB, macB)
	w.bind("a", peerA, macA, time.Hour)
	w.bind("b", peerB, macB, time.Hour)
	revoked := ""
	r.revoke = func(reason string) { // the first node's call revokes the other node's token
		id, host := idB, "b"
		if strings.Contains(reason, `token "b"`) {
			id, host = idA, "a"
		}
		if err := w.svc.RevokeToken(ctx, "admin@acme.example", id); err != nil {
			t.Error(err)
		}
		revoked = host
	}
	if err := w.svc.ApproveBound(ctx); err != nil {
		t.Fatal(err)
	}
	ips := map[string]string{"a": peerA, "b": peerB}
	for host, ip := range ips {
		d, _ := w.device(ip)
		if d.Approved == (host == revoked) {
			t.Errorf("%s (revoked: %v): approved=%v", host, host == revoked, d.Approved)
		}
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.approve_enrolled'`); n != 1 {
		t.Fatalf("%d approval audit rows, want 1", n)
	}
}
