package agentintake_test

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
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
