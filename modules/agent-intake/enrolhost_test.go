package agentintake_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	agentintake "github.com/knt048/vedette/modules/agent-intake"
)

// W-2 (D-548, TUNE-5b walk): a machine whose system_info answer has not reached the inventory is named by the host name osquery gave at
// enrolment, not by its network card's maker; the system_info answer then replaces it.
func TestContract_D548_EnrolmentHostNameNamesTheDevice(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("lab", 7)
	key := w.enroll(secret, "WIN-LAB", peerA)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)),
		snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025 Standard Evaluation", "version": "10.0.26100", "build": "26100", "platform": "windows"})))
	if d, ok := w.device(peerA); !ok || d.Hostname == nil || *d.Hostname != "WIN-LAB" {
		t.Fatalf("before system_info: %+v", d.AssetCore)
	}
	w.clock.Advance(time.Minute)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("system_info", map[string]string{"hostname": "win-lab.corp", "hardware_vendor": "QEMU", "hardware_model": "Standard PC"})))
	if d, _ := w.device(peerA); d.Hostname == nil || *d.Hostname != "win-lab.corp" {
		t.Fatalf("after system_info: %+v", d.AssetCore)
	}
}

// N52 W-2: a machine enrolled before D-548, or whose first hour passed without system_info, is named by its enrolment's host name too, but
// once per node (review r1 #8: a node whose system_info never comes is not written to at every request); system_info still renames it.
func TestContract_D548_EnrolmentHostNameOncePerNodeAtAnyAge(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("lab", 7)
	key := w.enroll(secret, "WIN-LAB", peerA)
	w.clock.Advance(3 * time.Hour)
	osRow := snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025 Standard Evaluation", "version": "10.0.26100", "build": "26100", "platform": "windows"})
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osRow))
	if d, ok := w.device(peerA); !ok || d.Hostname == nil || *d.Hostname != "WIN-LAB" {
		t.Fatalf("after the first hour: %+v", d.AssetCore)
	}
	seen := func() int {
		return w.count(`SELECT count(*) FROM inv_observation WHERE field = 'hostname' AND value = 'WIN-LAB'`)
	}
	before := w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE ',' || reported || ',' LIKE '%,hostname,%'`)
	if before != 1 || seen() != 1 {
		t.Fatalf("hostname answer recorded %d, observations %d", before, seen())
	}
	var at1 string
	if err := w.db.Reader().QueryRowContext(t.Context(), `SELECT seen_at FROM inv_observation WHERE field = 'hostname'`).Scan(&at1); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(time.Hour)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osRow))
	var at2 string
	if err := w.db.Reader().QueryRowContext(t.Context(), `SELECT seen_at FROM inv_observation WHERE field = 'hostname'`).Scan(&at2); err != nil {
		t.Fatal(err)
	}
	if at2 != at1 {
		t.Fatalf("the enrolment's name was written again: seen_at %s -> %s", at1, at2)
	}
	w.post("/intake/osquery/log", peerA, logBody(key, snap("system_info", map[string]string{"hostname": "win-lab-2", "hardware_vendor": "QEMU", "hardware_model": "Standard PC"})))
	if d, _ := w.device(peerA); d.Hostname == nil || *d.Hostname != "win-lab-2" {
		t.Fatalf("after system_info: %+v", d.AssetCore)
	}
}

// N52 W-2: a node whose enrolment carried no system_info host name is named by its host_identifier when that is a host name (the install
// scripts enrol under it), never by a UUID identifier.
func TestContract_D548_EnrolmentNameFromTheHostIdentifier(t *testing.T) {
	for _, tc := range []struct{ id, want string }{{"WIN-SRV01", "WIN-SRV01"}, {"8c2f6a1e-3b4d-4c5e-9f60-7a8b9c0d1e2f", ""}} {
		w := newWorld(t)
		_, secret := w.token("lab", 7)
		body := enrollBody(secret, tc.id)
		body["host_details"] = map[string]any{"os_version": map[string]any{"platform": "windows", "name": "Microsoft Windows Server 2025"}}
		r := w.post("/intake/osquery/enroll", peerA, body)
		key, _ := r.body["node_key"].(string)
		w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)),
			snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025", "version": "10.0.26100", "build": "26100", "platform": "windows"})))
		d, ok := w.device(peerA)
		got := ""
		if ok && d.Hostname != nil {
			got = *d.Hostname
		}
		if got != tc.want {
			t.Errorf("host_identifier %q: device host name %q, want %q", tc.id, got, tc.want)
		}
	}
}

// refuseHostname is the inventory refusing the enrolment host names it is sent (as it refuses a value it cannot take): the first `limit`
// of them, or every one when limit is 0.
type refuseHostname struct {
	observe.Sink
	limit, refused int
}

func (r *refuseHostname) Record(ctx context.Context, obs []observe.Observation) error {
	if len(obs) == 1 && obs[0].Field == observe.Hostname && (r.limit == 0 || r.refused < r.limit) {
		r.refused++
		return &observe.ErrRejected{Index: 0, Err: errors.New("refused")}
	}
	return r.Sink.Record(ctx, obs)
}

// Review r1 #4 and r2 #3 of #801: a refused enrolment name goes on to the host_identifier in the same request; when every name is refused
// the mark is set all the same, so nothing is sent again at each request.
func TestContract_D548_EnrolmentHostNameRefusedFallsBack(t *testing.T) {
	enrol := func(w *world, secret string) string {
		body := enrollBody(secret, "WIN-ID")
		body["host_details"].(map[string]any)["system_info"] = map[string]any{"hostname": "WIN-LAB"}
		r := w.post("/intake/osquery/enroll", peerA, body)
		k, _ := r.body["node_key"].(string)
		return k
	}
	osRow := snap("os_version", map[string]string{"name": "Microsoft Windows Server 2025", "version": "10.0.26100", "build": "26100", "platform": "windows"})
	marked := func(w *world) int {
		return w.count(`SELECT count(*) FROM intake_osquery_nodes WHERE ',' || reported || ',' LIKE '%,hostname,%'`)
	}

	var ref *refuseHostname
	w := newWorld(t, func(c *agentintake.Config) { ref = &refuseHostname{Sink: c.Sink, limit: 1}; c.Sink = ref })
	_, secret := w.token("lab", 7)
	key := enrol(w, secret)
	w.post("/intake/osquery/log", peerA, logBody(key, snap("interfaces", ifaceRow(macA, peerA)), osRow))
	if d, ok := w.device(peerA); ref.refused != 1 || !ok || d.Hostname == nil || *d.Hostname != "WIN-ID" || marked(w) != 1 {
		t.Fatalf("refused %d, marked %d, %+v", ref.refused, marked(w), d.AssetCore)
	}

	all := &refuseHostname{}
	w2 := newWorld(t, func(c *agentintake.Config) { all.Sink = c.Sink; c.Sink = all })
	_, secret2 := w2.token("lab", 7)
	key2 := enrol(w2, secret2)
	w2.post("/intake/osquery/log", peerA, logBody(key2, snap("interfaces", ifaceRow(macA, peerA)), osRow))
	if all.refused != 2 || marked(w2) != 1 {
		t.Fatalf("every name refused: refused %d, marked %d", all.refused, marked(w2))
	}
	w2.clock.Advance(time.Minute)
	w2.post("/intake/osquery/log", peerA, logBody(key2, snap("interfaces", ifaceRow(macA, peerA)), osRow))
	if all.refused != 2 {
		t.Fatalf("names sent again after every one was refused: %d", all.refused)
	}
}
