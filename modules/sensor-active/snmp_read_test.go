package sensoractive_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// #849 SNMP by range: Read now reads every approved device of the inventory in a credential's scope at once, outside the window, and
// never anything else (D-512).

// waitRead waits for the read of credential id to end and returns it.
func (w *snmpWorld) waitRead(id string) sa.SNMPRead {
	w.t.Helper()
	done := w.svc.SNMPReadDone(id)
	if done == nil {
		w.t.Fatal("no read started")
	}
	select {
	case <-done:
	case <-w.t.Context().Done():
		w.t.Fatal("the read did not end")
	}
	r, err := w.svc.SNMPReadOf(w.t.Context(), id)
	if err != nil || r == nil {
		w.t.Fatalf("read of %s: %v %v", id, r, err)
	}
	return *r
}

func TestSNMPReadNowReadsOnlyApprovedDevicesOfTheScope(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	// The credential's own scope holds the LAN devices and 10.9.9.9, which is outside the scan scope.
	c := w.add(v2cInput("Core switches", "s3cret-community", "192.168.10.0/24", "10.9.9.0/24"))
	if got, err := w.svc.SNMPReadOf(t.Context(), c.ID); err != nil || got != nil {
		t.Fatalf("no read yet: %v %v", got, err)
	}
	run, err := w.svc.ReadSNMP(t.Context(), "admin@example.com", c.ID)
	if err != nil || run.Status != "running" || run.CredentialID != c.ID || run.By != "admin@example.com" || run.Total != 2 || run.Skipped != 4 {
		t.Fatalf("started %v %+v", err, run)
	}
	got := w.waitRead(c.ID)
	if got.Status != "done" || got.Done != 2 || got.Answered != 2 || got.FinishedAt.IsZero() || got.Message != "" || len(got.Results) != 2 {
		t.Fatalf("finished %+v", got)
	}
	for i, want := range []struct{ ip, id string }{{"192.168.10.20", "a-sw"}, {"192.168.10.24", "a-printer"}} {
		res := got.Results[i]
		if res.IP != want.ip || res.DeviceID != want.id || !res.OK || res.Reason != "ok" || res.Answer == nil || res.Answer.Vendor != "Juniper Networks" {
			t.Errorf("result %d: %+v", i, res)
		}
	}
	// Only the approved devices the policy allows got a packet: not the new device (.21), the one set to never (.23), the box (.2)
	// or the device outside the scan scope (10.9.9.9); a fragile printer is read (a few GETs are gentler than its one gentle scan).
	var sent []string
	for _, j := range r.sent() {
		for _, tg := range j.Targets {
			sent = append(sent, tg.IP)
		}
		if len(j.Credentials) != 1 || j.Credentials[0].Community != "s3cret-community" {
			t.Errorf("job credentials %+v", j.Credentials)
		}
	}
	if !slices.Equal(sent, []string{"192.168.10.20", "192.168.10.24"}) {
		t.Fatalf("sent to %v", sent)
	}
	recorded := map[netip.Addr]bool{}
	for _, o := range w.sink.observations() {
		if o.Source != observe.SNMP {
			t.Errorf("observation %+v", o)
		}
		recorded[o.AssetHint.IP] = true
	}
	if len(recorded) != 2 {
		t.Errorf("what the devices said is not recorded: %v", recorded)
	}
	if w.count(`SELECT count(*) FROM sa_job WHERE kind = 'snmp' AND reason = 'snmp_read' AND status = 'done' AND targets = 2`) != 1 ||
		w.count(`SELECT count(*) FROM sa_probe WHERE shape = 'snmp' AND targets = '192.168.10.20,192.168.10.24' AND flags NOT LIKE '%s3cret%'`) != 1 ||
		w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_read' AND target = 'Core switches' AND detail = '2 approved devices, 4 skipped'`) != 1 {
		t.Fatal("job, probe row or audit row")
	}
	// The window's round is not counted as done by a read: it still runs in the window.
	if w.count(`SELECT count(*) FROM sa_job WHERE reason = 'window'`) != 0 {
		t.Fatal("a read counted as the window's round")
	}
}

func TestSNMPReadNowWithNothingApprovedSendsNothing(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("new only", "s3cret-community", "192.168.10.21", "192.168.10.50")) // .21 is not approved, .50 is no device
	run, err := w.svc.ReadSNMP(t.Context(), "admin@example.com", c.ID)
	if err != nil || run.Total != 0 || run.Skipped != 1 {
		t.Fatalf("%v %+v", err, run)
	}
	if got := w.waitRead(c.ID); got.Status != "done" || got.Done != 0 || len(got.Results) != 0 {
		t.Fatalf("finished %+v", got)
	}
	if len(r.sent()) != 0 || w.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatal("something was sent")
	}
}

func TestSNMPReadNowRefusesWhenNothingCanBeSent(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("all", "s3cret-community"))
	if _, err := w.svc.ReadSNMP(t.Context(), "a", "snmp-nope"); apiCode(err) != "not_found" {
		t.Errorf("unknown credential: %v", err)
	}
	if _, err := w.svc.SNMPReadOf(t.Context(), "snmp-nope"); apiCode(err) != "not_found" {
		t.Errorf("unknown credential's read: %v", err)
	}
	w.inv.set(func(s *sa.Settings) { s.Enabled = false })
	if _, err := w.svc.ReadSNMP(t.Context(), "a", c.ID); apiCode(err) != "scanning_off" {
		t.Errorf("scanning off: %v", err)
	}
	w.inv.set(func(s *sa.Settings) { s.Enabled, s.ScopeConfirmed = true, false })
	if _, err := w.svc.ReadSNMP(t.Context(), "a", c.ID); apiCode(err) != "scope_not_confirmed" {
		t.Errorf("scope not confirmed: %v", err)
	}
	w.inv.set(func(s *sa.Settings) { s.ScopeConfirmed = true })
	r.mu.Lock()
	r.health = "the scan worker has not reported for 90 seconds"
	r.mu.Unlock()
	if _, err := w.svc.ReadSNMP(t.Context(), "a", c.ID); apiCode(err) != "unavailable" {
		t.Errorf("unavailable: %v", err)
	}
	if len(r.sent()) != 0 || w.svc.SNMPReadDone(c.ID) != nil {
		t.Fatal("a refused read started or sent something")
	}
}

// One SNMP job at a time: a second Read now while one waits for the worker is busy; turning the module off stops the read.
func TestSNMPReadNowIsOneAtATimeAndStops(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	r := &fakeReader{answer: func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("all", "s3cret-community"))
	other := w.add(v2cInput("other", "s3cret-community-2"))
	if _, err := w.svc.ReadSNMP(t.Context(), "a", c.ID); err != nil {
		t.Fatal(err)
	}
	<-started
	if _, err := w.svc.ReadSNMP(t.Context(), "a", other.ID); apiCode(err) != "busy" {
		t.Fatalf("a second read: %v", err)
	}
	if run, _ := w.svc.SNMPReadOf(t.Context(), c.ID); run == nil || run.Status != "running" {
		t.Fatalf("while it runs: %+v", run)
	}
	w.svc.Stop()
	got := w.waitRead(c.ID)
	if got.Status != "stopped" || !strings.Contains(got.Message, "stopped") || got.Answered != 0 || len(w.sink.observations()) != 0 {
		t.Fatalf("stopped read %+v", got)
	}
	if w.count(`SELECT count(*) FROM sa_job WHERE reason = 'snmp_read' AND status = 'stopped'`) != 1 {
		t.Fatal("the job is not closed as stopped")
	}
	// The next read may start once the first ended.
	r.mu.Lock()
	r.answer = nil
	r.mu.Unlock()
	if _, err := w.svc.ReadSNMP(t.Context(), "a", other.ID); err != nil {
		t.Fatalf("after the first ended: %v", err)
	}
	if got := w.waitRead(other.ID); got.Status != "done" || got.Answered != 2 {
		t.Fatalf("second read %+v", got)
	}
}
