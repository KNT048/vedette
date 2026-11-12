package sensorpassive_test

// The passive half of the sensor protocol as core serves it (SP-4): what a sensor may say, what core believes of it, and what
// stops a sensor that has been taken over. Direct calls to the Backend methods where the wire adds nothing, the real link where
// it does (roles, long poll, the capture at the far end).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/inventory"
	sp "github.com/knt048/vedette/modules/sensor-passive"
	"github.com/knt048/vedette/modules/sensor-passive/capture"
	"github.com/knt048/vedette/modules/sensor-passive/internal/pktgen"
)

var (
	epochA = strings.Repeat("a", 32)
	epochB = strings.Repeat("b", 32)
	epochC = strings.Repeat("c", 32)
)

func item(mac, field, value string, conf float64) sensorlink.ObservationItem {
	return sensorlink.ObservationItem{MAC: mac, Field: field, Value: value, Confidence: conf, SeenAt: pktgen.T0}
}

func request(epoch string, seq int64, items ...sensorlink.ObservationItem) *sensorlink.ObservationsRequest {
	return &sensorlink.ObservationsRequest{Epoch: epoch, Seq: seq, Items: items}
}

// macN is the n-th MAC of a flood: unicast, locally administered, all different.
func netipAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(s)
}

func macN(n int) string { return fmt.Sprintf("0a:00:00:00:%02x:%02x", n>>8&0xff, n&0xff) }

func codes(rep sensorlink.ObservationsReply) map[int]string {
	out := map[int]string{}
	for _, r := range rep.Rejected {
		out[r.Index] = r.Code
	}
	return out
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *sensorlink.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("got %v, want an error with code %s", err, code)
	}
}

// A role's certificate opens the routes of that role only (D-111): an active certificate gets 403 on the passive routes and the
// reverse; the heartbeat route is shared but its body is the role's (the other role's fields are unknown fields).
func TestRolesAreSeparate(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	link := linktest.New(t, linktest.Passive(e.svc))
	ctx := t.Context()
	act, pas := link.Client(t, sensorlink.Active), link.Client(t, sensorlink.Passive)
	_, err := act.Config(ctx, "", time.Second)
	wantCode(t, err, sensorlink.CodeForbiddenRoute)
	_, err = act.PostObservations(ctx, request(epochA, 1, item(macN(1), "hostname", "x", 0.5)))
	wantCode(t, err, sensorlink.CodeForbiddenRoute)
	_, err = pas.Jobs(ctx, nil, time.Second)
	wantCode(t, err, sensorlink.CodeForbiddenRoute)
	wantCode(t, pas.PostResult(ctx, strings.Repeat("a", 32), &sensorlink.JobResult{Status: "done"}), sensorlink.CodeForbiddenRoute)
	_, err = act.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.0.0", Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{}})
	wantCode(t, err, sensorlink.CodeInvalidRequest)
	_, err = pas.ActiveHeartbeat(ctx, &sensorlink.ActiveHeartbeat{Version: "1.0.0"})
	wantCode(t, err, sensorlink.CodeInvalidRequest)
	if list, _ := e.svc.Status(ctx); list[0].LastSeen != nil || len(e.devices()) != 0 {
		t.Errorf("a refused call changed something: %+v", list[0])
	}
	// and the passive role does work on its own routes
	if _, err := pas.PostObservations(ctx, request(epochA, 1, item(macN(1), "hostname", "x", 0.5))); err != nil {
		t.Errorf("passive on its own route: %v", err)
	}
}

// A sensor that has been taken over and floods new devices gets at most 60 in a minute and 200 in an hour into the inventory; the
// rest is rejected budget_exhausted, and the work core does for one batch is bounded by the batch (500 items), not by what the
// sensor wanted (D-111 (2), SYS-6).
func TestBudgetsStopAFloodOfNewDevices(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	var buf syncBuffer
	e := newEnv(t, nil, false, withLog(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	flood := func(seq int64, from int) sensorlink.ObservationsReply {
		items := make([]sensorlink.ObservationItem, 500)
		for i := range items {
			items[i] = item(macN(from+i), "hostname", "flood", 0.6)
		}
		rep, err := e.svc.Observations(ctx, request(epochA, seq, items...))
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	rep := flood(1, 0)
	if len(rep.Rejected) != 440 || rep.AckSeq != 1 {
		t.Fatalf("the first minute: %d rejected, want 440", len(rep.Rejected))
	}
	for _, r := range rep.Rejected {
		if r.Code != "budget_exhausted" || r.Index < 60 {
			t.Fatalf("rejection %+v: the first 60 new devices fit, the rest does not", r)
		}
	}
	if n := len(e.devices()); n != 60 {
		t.Fatalf("%d devices after the first batch, want 60", n)
	}
	if rep := flood(2, 1000); len(rep.Rejected) != 500 {
		t.Fatalf("the same minute again: %d rejected, want 500", len(rep.Rejected))
	}
	// the hour: three more minutes of 60 and one of 20, then nothing until the hour is over
	total := 60
	for i := range 6 {
		now = now.Add(61 * time.Second)
		rep := flood(int64(3+i), 2000+i*1000)
		got := 500 - len(rep.Rejected)
		if want := min(60, 200-total); got != want {
			t.Fatalf("minute %d: %d admitted, want %d", i+2, got, want)
		}
		total += got
	}
	if n := len(e.devices()); n != 200 {
		t.Fatalf("%d devices in the hour, want 200", n)
	}
	// 8 batches in 7 different minutes: the second one is in the first one's minute and says nothing
	if n := strings.Count(buf.String(), "over the budget"); n != 7 {
		t.Errorf("the budget was logged %d times, want once for each of the 7 minutes\n%s", n, buf.String())
	}
	now = now.Add(time.Hour)
	if rep := flood(20, 50000); len(rep.Rejected) != 440 {
		t.Errorf("the next hour: %d rejected, want 440", len(rep.Rejected))
	}
}

// One device may bring 4 new values per field in an hour: a sensor that makes up names for a MAC it already reported writes at
// most that many rows. A value that was passed before is a repeat, not a new one.
func TestBudgetsStopAFloodOfNewValues(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	names := func(prefix string, n int) []sensorlink.ObservationItem {
		items := make([]sensorlink.ObservationItem, n)
		for i := range items {
			items[i] = item(macN(7), "hostname", fmt.Sprintf("%s-%d", prefix, i), 0.6)
		}
		return items
	}
	rep, err := e.svc.Observations(ctx, request(epochA, 1, names("a", 20)...))
	if err != nil || len(rep.Rejected) != 16 {
		t.Fatalf("20 new names: %d rejected, %v; want 16", len(rep.Rejected), err)
	}
	for _, r := range rep.Rejected {
		if r.Code != "budget_exhausted" || r.Index < 4 {
			t.Fatalf("rejection %+v", r)
		}
	}
	if rep, err := e.svc.Observations(ctx, request(epochA, 2, names("a", 4)...)); err != nil || len(rep.Rejected) != 0 {
		t.Errorf("the same 4 names again: %+v %v: repeats are not new values", rep, err)
	}
	if rep, err := e.svc.Observations(ctx, request(epochA, 3, names("b", 4)...)); err != nil || len(rep.Rejected) != 4 {
		t.Errorf("4 more new names in the same hour: %+v %v", rep, err)
	}
	// another field of the same device has a budget of its own
	if rep, err := e.svc.Observations(ctx, request(epochA, 4, item(macN(7), "model", "m1", 0.5), item(macN(7), "model", "m2", 0.5))); err != nil || len(rep.Rejected) != 0 {
		t.Errorf("model: %+v %v", rep, err)
	}
	distinct := map[string]bool{}
	for _, o := range e.observations() {
		if o.Field == "hostname" {
			distinct[o.Value] = true
		}
	}
	if len(distinct) != 4 {
		t.Errorf("%d distinct names recorded, want 4: %v", len(distinct), distinct)
	}
	now = now.Add(time.Hour + time.Second)
	if rep, err := e.svc.Observations(ctx, request(epochA, 5, names("c", 4)...)); err != nil || len(rep.Rejected) != 0 {
		t.Errorf("after the hour: %+v %v", rep, err)
	}
}

// When the store fails, a batch has used none of the budget and nothing is saved: the sensor sends it again (503 store_busy).
func TestAFailedBatchUsesNoBudget(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false, withFlakyStore(1))
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	sixty := func(from int) []sensorlink.ObservationItem {
		items := make([]sensorlink.ObservationItem, 60)
		for i := range items {
			items[i] = item(macN(from+i), "hostname", "h", 0.6)
		}
		return items
	}
	_, err := e.svc.Observations(ctx, request(epochA, 1, sixty(0)...))
	var se *sensorlink.Error
	if !errors.As(err, &se) || se.Code != sensorlink.CodeStoreBusy || se.RetryAfter < time.Second {
		t.Fatalf("a failing store: %v", err)
	}
	if rep, err := e.svc.Observations(ctx, request(epochA, 2, sixty(1000)...)); err != nil || len(rep.Rejected) != 0 {
		t.Fatalf("a different 60 new devices after the failure: %+v %v: the failed batch used budget", rep, err)
	}
	// The failed batch again, under a new seq: these 60 are new devices to core, the minute is spent by the second batch, so they
	// are all over budget. Had the failed attempt committed them they would be known and pass.
	rep, err := e.svc.Observations(ctx, request(epochA, 3, sixty(0)...))
	if err != nil || len(rep.Rejected) != 60 {
		t.Fatalf("the failed batch again: %+v %v: want 60 rejected, so that the first attempt used no budget", rep, err)
	}
	if n := len(e.devices()); n != 60 {
		t.Errorf("%d devices, want the 60 of the second batch", n)
	}
	var last int64
	if err := e.db.Reader().QueryRowContext(ctx, `SELECT last_seq FROM sp_seq WHERE epoch = ?`, epochA).Scan(&last); err != nil || last != 3 {
		t.Errorf("last_seq %d %v: the failed seq 1 must not have been saved, the others were", last, err)
	}
}

// Core clamps the confidence of each field to the top of the passive scale (INV-5): a sensor that says 1.0 for a name gets what a
// passive observation of a name can know. Outside 0..1 the item is no good.
func TestConfidenceIsClampedPerField(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	m := macN(3)
	rep, err := e.svc.Observations(ctx, request(epochA, 1,
		item(m, "hostname", "h", 1), item(m, "mac", m, 1), item(m, "vendor", "Acme", 1), item(m, "model", "M", 1), item(m, "kind", "printer", 1), item(m, "os", "linux", 1),
		item(macN(4), "hostname", "low", 0.2),
		item(macN(5), "hostname", "high", 1.5), item(macN(6), "hostname", "neg", -0.1), item(macN(8), "hostname", "nan", math.NaN())))
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); len(c) != 3 || c[7] != "invalid_item" || c[8] != "invalid_item" || c[9] != "invalid_item" {
		t.Fatalf("rejected %+v: only the three outside 0..1 are no good", rep.Rejected)
	}
	want := map[string]float64{"hostname": 0.7, "mac": 0.9, "vendor": 0.4, "model": 0.5, "kind": 0.5, "os": 0.3} // kind printer: only mDNS says it, at 0.5
	got := map[string]float64{}
	for _, o := range e.observations() {
		if o.Source != "passive" { // the inventory has rows of its own for a new device
			continue
		}
		if o.Value == "low" {
			if o.Confidence != 0.2 {
				t.Errorf("a confidence under the cap was changed: %v", o.Confidence)
			}
			continue
		}
		if o.Field == "mac" && o.Value != m {
			continue
		}
		got[o.Field] = o.Confidence
	}
	for f, c := range want {
		if got[f] != c {
			t.Errorf("%s: confidence %v, want %v", f, got[f], c)
		}
	}
}

// Every item is checked at the edge, one by one: a bad one is rejected with its index and the rest goes on (sensor-protocol.md 6.2).
func TestItemsAreCheckedAtTheEdge(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	long := strings.Repeat("x", 201)
	cases := []struct {
		name string
		it   sensorlink.ObservationItem
		code string
	}{
		{"good", item(macN(1), "hostname", "ok", 0.5), ""},
		{"ip only", sensorlink.ObservationItem{IP: "192.168.10.77", Field: "hostname", Value: "ip-only", Confidence: 0.5, SeenAt: pktgen.T0}, ""},
		{"upper case MAC", item("0A:00:00:00:00:02", "hostname", "x", 0.5), "invalid_item"},
		{"group MAC", item("01:00:5e:00:00:01", "hostname", "x", 0.5), "invalid_item"},
		{"zero MAC", item("00:00:00:00:00:00", "hostname", "x", 0.5), "invalid_item"},
		{"short MAC", item("0a:00:00:00:00", "hostname", "x", 0.5), "invalid_item"},
		{"no MAC and no IP", item("", "hostname", "x", 0.5), "invalid_item"},
		{"IPv6", sensorlink.ObservationItem{MAC: macN(2), IP: "fe80::1", Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0}, "invalid_item"},
		{"broadcast IP", sensorlink.ObservationItem{MAC: macN(2), IP: "255.255.255.255", Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0}, "invalid_item"},
		{"IP that is not an IP", sensorlink.ObservationItem{MAC: macN(2), IP: "not-an-ip", Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0}, "invalid_item"},
		{"unknown field", item(macN(2), "service", "x", 0.5), "invalid_item"},
		{"mac row about another MAC", item(macN(2), "mac", macN(3), 0.5), "invalid_item"},
		{"mac row with no MAC", sensorlink.ObservationItem{IP: "192.168.10.8", Field: "mac", Value: macN(3), Confidence: 0.5, SeenAt: pktgen.T0}, "invalid_item"},
		{"mac row about itself", item(macN(10), "mac", macN(10), 0.5), ""},
		{"kind no parser emits", item(macN(2), "kind", "toaster", 0.5), "invalid_item"},
		{"kind a parser emits", item(macN(11), "kind", "switch", 0.5), ""},
		{"empty value", item(macN(2), "hostname", "", 0.5), "invalid_item"},
		{"201 bytes", item(macN(2), "hostname", long, 0.5), "invalid_item"},
		{"200 bytes", item(macN(9), "hostname", long[:200], 0.5), ""},
		{"bidi override", item(macN(2), "hostname", "evil\u202egpj.exe", 0.5), "invalid_item"},
		{"control character", item(macN(2), "hostname", "a\x00b", 0.5), "invalid_item"},
		{"not UTF-8", item(macN(2), "hostname", "a\xffb", 0.5), "invalid_item"},
		{"two days old", sensorlink.ObservationItem{MAC: macN(2), Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0.Add(-48 * time.Hour)}, "out_of_window"},
		{"an hour ahead", sensorlink.ObservationItem{MAC: macN(2), Field: "hostname", Value: "x", Confidence: 0.5, SeenAt: pktgen.T0.Add(2 * time.Hour)}, "out_of_window"},
		{"no time at all", sensorlink.ObservationItem{MAC: macN(2), Field: "hostname", Value: "x", Confidence: 0.5}, "out_of_window"},
	}
	items := make([]sensorlink.ObservationItem, len(cases))
	for i, c := range cases {
		items[i] = c.it
	}
	rep, err := e.svc.Observations(ctx, request(epochA, 1, items...))
	if err != nil {
		t.Fatal(err)
	}
	got := codes(rep)
	for i, c := range cases {
		if got[i] != c.code {
			t.Errorf("%s: code %q, want %q", c.name, got[i], c.code)
		}
	}
	for _, r := range rep.Rejected {
		if r.Index < 0 || r.Index >= len(cases) {
			t.Errorf("index %d names no item", r.Index)
		}
	}
	if !slices.IsSortedFunc(rep.Rejected, func(a, b sensorlink.Rejected) int { return a.Index - b.Index }) {
		t.Error("rejected[] is not in the order of the items")
	}
}

// An item the inventory refuses at its boundary is rejected as refused, and the rest of the batch is recorded in the same call.
func TestAnItemTheInventoryRefusesIsRejectedAsRefused(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false, withReject("refused-name"))
	rep, err := e.svc.Observations(t.Context(), request(epochA, 1,
		item(macN(1), "hostname", "one", 0.5), item(macN(2), "hostname", "refused-name", 0.5), item(macN(3), "hostname", "three", 0.5)))
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); len(c) != 1 || c[1] != "refused" {
		t.Fatalf("rejected %+v, want index 1 refused", rep.Rejected)
	}
	if n := e.obsCount(func(o inventory.ObservationRow) bool { return o.Field == "hostname" }); n != 2 {
		t.Errorf("%d names recorded, want the 2 good ones", n)
	}
	if len(e.devices()) != 2 {
		t.Errorf("%d devices: a refused item must not create one", len(e.devices()))
	}
}

// Epochs: a replay is not applied twice; a new epoch (the sensor restarted) is accepted from seq 1; only the two newest epochs are kept.
func TestEpochsAreKeptTwoAtATime(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	link := linktest.New(t, linktest.Passive(e.svc))
	c := link.Client(t, sensorlink.Passive)
	ctx := t.Context()
	post := func(epoch string, seq int64, v string) {
		t.Helper()
		// a MAC of its own for every batch: the budget of values per device is not what this test is about
		rep, err := c.PostObservations(ctx, request(epoch, seq, item(macN(int(epoch[0])*10+int(seq)), "hostname", v, 0.5)))
		if err != nil || rep.AckSeq != seq {
			t.Fatalf("%s/%d: %+v %v", epoch[:1], seq, rep, err)
		}
	}
	post(epochA, 1, "a1")
	post(epochA, 1, "replay") // the answer was lost and the sensor sent it again
	post(epochA, 2, "a2")
	post(epochB, 1, "b1") // the sensor restarted
	post(epochA, 3, "a3") // the old process had a request in flight
	if n := e.obsCount(func(o inventory.ObservationRow) bool { return o.Value == "replay" }); n != 0 {
		t.Errorf("a replayed seq was applied")
	}
	if n := e.count(`SELECT count(*) FROM sp_seq`); n != 2 {
		t.Errorf("%d epochs kept, want 2", n)
	}
	post(epochC, 1, "c1")
	if n := e.count(`SELECT count(*) FROM sp_seq`); n != 2 {
		t.Errorf("%d epochs kept after a third, want 2", n)
	}
	if n := e.count(`SELECT count(*) FROM sp_seq WHERE epoch = '` + epochA + `'`); n != 0 {
		t.Error("the oldest epoch was not forgotten")
	}
	if n := e.obsCount(func(o inventory.ObservationRow) bool {
		return strings.HasPrefix(o.Value, "a") || strings.HasPrefix(o.Value, "b") || strings.HasPrefix(o.Value, "c")
	}); n < 5 {
		t.Errorf("%d rows: every batch of every epoch should have been applied once", n)
	}
}

// The card of the capture is chosen against the cards of the box as the host reports them (D-118), never against a list a
// sensor sent: it can be chosen before the sensor has said anything and while the module is off (the capture uses it once it
// runs), a sensor that lists cards the box does not have steers nothing, and a SPAN card has no IP in the host's list.
func TestTheCardIsChosenAgainstTheHostNotTheSensor(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	link := linktest.New(t, linktest.Passive(e.svc))
	pas := link.Client(t, sensorlink.Passive)
	ctx := t.Context()
	set := func(iface string, span bool) error {
		return e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, iface, span)
	}
	e.off.Store(true) // the module is off and no sensor has ever sent a heartbeat
	for name, c := range map[string]struct {
		iface string
		span  bool
	}{"a card the host does not have": {"eth9", false}, "a SPAN card with an IP": {"eth0", true}, "SPAN with no card": {"", true}} {
		if err := set(c.iface, c.span); !errors.Is(err, sp.ErrBadInterface) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := set("eth1", true); err != nil {
		t.Fatalf("a card of the host, before the first heartbeat and with the module off: %v", err)
	}
	e.off.Store(false)
	cfg, err := pas.Config(ctx, "", time.Second)
	if err != nil || cfg.Config.Interface != "eth1" || !cfg.Config.Span {
		t.Fatalf("config %+v %v: the choice made with the module off is what the capture is told", cfg, err)
	}
	// a sensor that lists a card the host does not have, or none, changes what Status shows, never what can be chosen
	card := func(name string, ips ...string) sensorlink.HeartbeatIface {
		if ips == nil {
			ips = []string{}
		}
		return sensorlink.HeartbeatIface{Name: name, MAC: "02:00:00:00:00:" + fmt.Sprintf("%02x", len(name)), Link: true, IPv4: ips}
	}
	if _, err := pas.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.2.3", Interfaces: []sensorlink.HeartbeatIface{card("eth7"), card("eth1", "10.0.0.1/24")}, Drops: map[string]int64{}}); err != nil {
		t.Fatal(err)
	}
	if err := set("eth7", false); !errors.Is(err, sp.ErrBadInterface) {
		t.Errorf("a card only the sensor claims: %v", err)
	}
	if err := set("eth1", true); err != nil {
		t.Errorf("the sensor says eth1 has an IP; the host says it has none: %v", err)
	}
	cfg2, err := pas.Config(ctx, "", time.Second)
	if err != nil || cfg2.Config.Interface != "eth1" || cfg2.ETag != cfg.ETag {
		t.Fatalf("the choice moved with a heartbeat: %+v %v", cfg2, err)
	}
	list, _ := e.svc.Status(ctx)
	if !slices.Equal(list[0].Interfaces, []string{"eth1", "eth7"}) || list[0].Version == nil || *list[0].Version != "1.2.3" {
		t.Errorf("status %+v: the cards it shows are the sensor's", list[0])
	}
}

// Container-only install (D-168): no host answers, so the card is chosen against the cards in the sensor's latest heartbeat
// (the real SPAN card of the host network), not against the container's own interfaces. Before the first heartbeat a card
// cannot be chosen (bad_interface with a plain sentence); stopping the capture needs no heartbeat; a SPAN card with an IP in
// the heartbeat is refused; the card in the heartbeat the host would have refused is accepted only because there is no host.
func TestNoHostTheCardIsChosenAgainstTheHeartbeat(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	e.host.setNoHost(true)
	link := linktest.New(t, linktest.Passive(e.svc))
	pas := link.Client(t, sensorlink.Passive)
	ctx := t.Context()
	set := func(iface string, span bool) error {
		return e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, iface, span)
	}
	err := set("enp3s0", true)
	if !errors.Is(err, sp.ErrBadInterface) || !strings.Contains(err.Error(), "has not reported its network cards") {
		t.Fatalf("no heartbeat yet: %v", err)
	}
	if err := set("", false); err != nil {
		t.Fatalf("stopping the capture needs no heartbeat: %v", err)
	}
	card := func(name string, ips ...string) sensorlink.HeartbeatIface {
		if ips == nil {
			ips = []string{}
		}
		return sensorlink.HeartbeatIface{Name: name, MAC: "02:00:00:00:00:" + fmt.Sprintf("%02x", len(name)), Link: true, IPv4: ips}
	}
	if _, err := pas.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.2.3", Interfaces: []sensorlink.HeartbeatIface{card("enp3s0"), card("eno1", "10.0.0.5/24")}, Drops: map[string]int64{}}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		iface string
		span  bool
	}{"a card the sensor does not report": {"eth0", false}, "SPAN on a card with an IP": {"eno1", true}, "SPAN with no card": {"", true}, "a name that is not an interface name": {"en p3s0;rm", false}} {
		err := set(c.iface, c.span)
		if !errors.Is(err, sp.ErrBadInterface) {
			t.Errorf("%s: %v", name, err)
		}
		if c.iface == "en p3s0;rm" && (err == nil || !strings.Contains(err.Error(), "is not an interface name")) {
			t.Errorf("%s: the edge check did not refuse it: %v", name, err)
		}
	}
	if err := set("enp3s0", true); err != nil {
		t.Fatalf("the card the sensor reported: %v", err)
	}
	cfg, err := pas.Config(ctx, "", time.Second)
	if err != nil || cfg.Config.Interface != "enp3s0" || !cfg.Config.Span {
		t.Fatalf("config %+v %v", cfg, err)
	}
	e.host.setNoHost(false) // with a host nothing changes: the host's list decides, the heartbeat does not
	if err := set("enp3s0", true); !errors.Is(err, sp.ErrBadInterface) {
		t.Errorf("with a host, a card only the sensor reports: %v", err)
	}
	if err := set("eth1", true); err != nil {
		t.Errorf("with a host, a card of the host: %v", err)
	}
}

// What GET /inventory/sensors and the SPAN card show comes from the heartbeat, nothing else (D-112 (5)): online within 90 seconds,
// version, devices, cards, the verdicts off / no_link / no_traffic / own_only / ok.
func TestHeartbeatDrivesTheViews(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	var mu sync.Mutex
	now := pktgen.T0.Add(time.Minute)
	e.setClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	at := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	never := time.Time{}
	ago := func(d time.Duration) time.Time { mu.Lock(); defer mu.Unlock(); return now.Add(-d) }
	beat := func(up bool, pps, others int64, last time.Time, devices int64) {
		t.Helper()
		hb := &sensorlink.PassiveHeartbeat{Version: "1.2.3", Interfaces: []sensorlink.HeartbeatIface{
			{Name: "eth1", MAC: "02:00:00:00:00:02", Link: up, IPv4: []string{}}, {Name: "eth0", MAC: "02:00:00:00:00:01", Link: true, IPv4: []string{"192.168.10.5/24"}}},
			Span: sensorlink.HeartbeatSpan{PPS: pps, OtherMACs: others}, Drops: map[string]int64{"excluded": 3}, DevicesSeen: devices}
		if !last.IsZero() {
			hb.Span.LastPacketAt = &last
		}
		if _, err := e.svc.PassiveHeartbeat(ctx, hb); err != nil {
			t.Fatal(err)
		}
	}
	verdict := func() sp.SpanStats {
		t.Helper()
		st, err := e.svc.SpanStats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	beat(true, 0, 0, never, 0)
	if v := verdict().Verdict; v != sp.VerdictOff {
		t.Errorf("SPAN not configured: %s", v)
	}
	if err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, "eth1", true); err != nil {
		t.Fatal(err)
	}
	if st := verdict(); st.Verdict != sp.VerdictNoTraffic {
		t.Errorf("no packet yet: %+v", st)
	}
	beat(true, 1200, 37, ago(2*time.Second), 214)
	if st := verdict(); st.Verdict != sp.VerdictOK || st.PPS != 1200 || st.OtherMACs != 37 || !st.LastPacket.Equal(ago(2*time.Second)) {
		t.Errorf("a mirror with other devices: %+v", st)
	}
	list, _ := e.svc.Status(ctx)
	s := list[0]
	if s.Status != "online" || s.DevicesSeen != 214 || *s.Version != "1.2.3" || !slices.Equal(s.Interfaces, []string{"eth0", "eth1"}) || s.SpanStatus.Verdict != "ok" || s.SpanStatus.PacketsPerS != 1200 || s.LastSeen == nil {
		t.Errorf("status %+v", s)
	}
	if d := e.svc.Drops(); d["excluded"] != 3 {
		t.Errorf("drops %v", d)
	}
	beat(true, 50, 0, ago(2*time.Second), 214)
	if st := verdict(); st.Verdict != sp.VerdictOwnOnly {
		t.Errorf("only the box's own frames: %+v", st)
	}
	beat(true, 50, 4, ago(45*time.Second), 214)
	if st := verdict(); st.Verdict != sp.VerdictNoTraffic || st.PPS != 0 {
		t.Errorf("silent for 45 s: %+v", st)
	}
	beat(false, 0, 0, never, 214)
	if st := verdict(); st.Verdict != sp.VerdictNoLink {
		t.Errorf("cable out: %+v", st)
	}
	beat(true, 50, 4, ago(time.Second), 214)
	at(91 * time.Second) // the sensor goes quiet
	st := verdict()
	list, _ = e.svc.Status(ctx)
	if st.Verdict != sp.VerdictNoTraffic || list[0].Status != "offline" || list[0].LastSeen == nil || list[0].DevicesSeen != 214 {
		t.Errorf("no heartbeat for 91 s: %+v, status %+v: offline, the data stays", st, list[0])
	}
	// a SPAN heartbeat with a packet time from the future is no better than now
	beat(true, 50, 4, ago(-time.Hour), 1)
	if st := verdict(); st.LastPacket.After(now) {
		t.Errorf("a packet from the future: %+v", st)
	}
}

// GET /config is a long poll on the ETag: at once when it differs, 304 after the wait when it does not, and SetInterface wakes
// it. When the filters cannot be read it says "do not capture" (D-80 (3)).
func TestConfigLongPoll(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	e.sensorBeat()
	link := linktest.New(t, linktest.Passive(e.svc))
	pas := link.Client(t, sensorlink.Passive)
	ctx := t.Context()
	first, err := pas.Config(ctx, "", time.Second)
	if err != nil || first.NotModified || first.ETag == "" || first.Config.Interface != "" || first.Config.Filters == nil {
		t.Fatalf("first config %+v %v", first, err)
	}
	start := time.Now()
	again, err := pas.Config(ctx, first.ETag, time.Second)
	if err != nil || !again.NotModified || again.ETag != first.ETag || time.Since(start) < 800*time.Millisecond {
		t.Fatalf("an unchanged config: %+v %v after %v", again, err, time.Since(start))
	}
	got := make(chan sensorlink.ConfigReply, 1)
	go func() {
		rep, _ := pas.Config(ctx, first.ETag, 20*time.Second)
		got <- rep
	}()
	pause(t, 150*time.Millisecond)
	e.setInterface("eth1", true)
	select {
	case rep := <-got:
		if rep.NotModified || rep.Config.Interface != "eth1" || !rep.Config.Span || !rep.Config.Extract.DNS || len(rep.Config.Filters) != 0 {
			t.Errorf("woken config %+v", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetInterface did not wake the long poll")
	}
	e.host.setOptErr(errors.New("the settings table is locked"))
	broken, err := pas.Config(ctx, "", time.Second)
	if err != nil || broken.Config.Interface != "" || broken.Config.Span {
		t.Errorf("filters unreadable: %+v %v: want no capture", broken, err)
	}
	e.host.setOptErr(nil)
	e.host.setFilters(sensorlink.Filter{Type: "port", Value: "443"})
	fixed, err := pas.Config(ctx, "", time.Second)
	if err != nil || fixed.Config.Interface != "eth1" || len(fixed.Config.Filters) != 1 {
		t.Errorf("filters readable again: %+v %v", fixed, err)
	}
}

// End to end over the real link: the fixture recording goes through the capture, the client, the server and the Backend into the
// inventory, and the devices are the same as with the capture inside the process (the same assertions as the contract tests).
func TestReplayOverTheLinkGivesTheSameInventory(t *testing.T) {
	t.Parallel()
	collect := func(e *env) map[string]bool {
		e.setInterface("eth0", false)
		stop := e.run()
		waitFor(t, "every device", func() bool {
			for _, m := range []pktgen.MAC{pktgen.PC, pktgen.Printer, pktgen.Router, pktgen.Switch} {
				if e.device(m.String()) == nil {
					return false
				}
			}
			return true
		})
		// The rest of the recording: wait until the source has handed out its last frame and the observations stop changing
		// (flushes are 10-40 ms apart), rather than a fixed pause that a starved runner outlasts (#193 CI: one device short).
		waitFor(t, "the whole recording read", e.src.drained)
		for n, deadline := -1, time.Now().Add(waitBound); ; {
			now := len(e.observations())
			if now == n {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the observations never settled (%d)", now)
			}
			n = now
			pause(t, 500*time.Millisecond)
		}
		stop()
		out := map[string]bool{}
		for _, o := range e.observations() {
			out[fmt.Sprintf("%s|%s|%s|%.2f", o.Field, o.Value, o.Source, o.Confidence)] = true
		}
		return out
	}
	local := newEnv(t, frames(), true)
	remote := newEnv(t, frames(), true, withRemote())
	l := collect(local)
	r := collect(remote)
	if len(r) < 10 {
		t.Fatalf("only %d observations arrived over the link", len(r))
	}
	for k := range l {
		if !r[k] {
			t.Errorf("%s arrived in process and not over the link", k)
		}
	}
	for k := range r {
		if !l[k] {
			t.Errorf("%s arrived over the link and not in process", k)
		}
	}
	if len(local.devices()) != len(remote.devices()) {
		t.Errorf("%d devices in process, %d over the link", len(local.devices()), len(remote.devices()))
	}
}

// A 503 is retried with the same items until core takes them: nothing is lost, nothing is recorded twice.
func TestAFailingStoreIsRetriedOverTheLink(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string][]pktgen.Frame{"eth0": pktgen.LANDiscovery()}, true, withRemote(), withFlakyStore(3))
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "every device after the store came back", func() bool {
		for _, m := range []pktgen.MAC{pktgen.PC, pktgen.Printer, pktgen.Router, pktgen.Switch} {
			if e.device(m.String()) == nil {
				return false
			}
		}
		return true
	})
	e.sink.mu.Lock()
	calls := e.sink.calls
	e.sink.mu.Unlock()
	if calls < 4 {
		t.Errorf("%d store calls: the first three were meant to fail", calls)
	}
	seen := map[string]int{}
	for _, d := range e.devices() {
		if d.MAC != nil {
			seen[*d.MAC]++
		}
	}
	for m, n := range seen {
		if n != 1 {
			t.Errorf("%s is %d devices", m, n)
		}
	}
}

// An item that makes the store fail every time, with an error that names no item, is found by splitting the batch and dropped; the
// others are recorded and the queue is not blocked for ever. The sensor says so in its heartbeat (observation_failed).
func TestAPoisonItemIsHuntedDownOverTheLink(t *testing.T) {
	t.Parallel()
	zero, bcast := netipAddr("0.0.0.0"), netipAddr("255.255.255.255")
	fr := []pktgen.Frame{
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.PC, pktgen.PCIP, pktgen.MAC{}, pktgen.RouterIP)},
		{At: pktgen.T0, Data: pktgen.UDPFrame(pktgen.Bcast, pktgen.Phone, zero, bcast, 68, 67,
			pktgen.DHCP(1, pktgen.Phone, netipAddr(""), netipAddr(""), pktgen.DHCPOpts{Type: 1, Hostname: "poison-name"}))},
		{At: pktgen.T0, Data: pktgen.ARP(pktgen.Bcast, 1, pktgen.Printer, pktgen.PrinterIP, pktgen.MAC{}, pktgen.RouterIP)},
	}
	e := newEnv(t, map[string][]pktgen.Frame{"eth0": fr}, true, withRemote(), withPoison("poison-name"))
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "the two good devices and the phone's MAC", func() bool { return len(e.devices()) == 3 })
	waitFor(t, "the poison item in a heartbeat", func() bool { return e.svc.Drops()["observation_failed"] == 1 })
	for _, o := range e.observations() {
		if o.Value == "poison-name" {
			t.Error("the poison observation was recorded")
		}
	}
}

// module_off stops the capture at once, with no last flush, and the sensor keeps asking: when the module is on again it captures.
func TestModuleOffStopsTheRemoteCaptureWithoutAFinalFlush(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), true, withRemote(), func(c *sp.Config, _ *env) { c.FlushEvery = time.Hour })
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "the card to open", func() bool { return len(e.src.opens()) == 1 })
	pause(t, 60*time.Millisecond) // frames are read, nothing is due to be sent
	if e.sink.count() != 0 {
		t.Fatalf("%d observations arrived before any flush was due", e.sink.count())
	}
	e.off.Store(true)
	waitFor(t, "the card to close", func() bool { return e.src.closes() == 1 })
	pause(t, 150*time.Millisecond)
	if e.sink.count() != 0 {
		t.Errorf("%d observations arrived after module_off: the queue must be dropped, not flushed", e.sink.count())
	}
	e.off.Store(false)
	waitFor(t, "the capture to start again once the module is on", func() bool { return len(e.src.opens()) == 2 })
}

// Filters core cannot read go to the sensor as "do not capture"; filters the sensor cannot read make it refuse to capture and
// say so in its heartbeat. Neither ends up reading traffic the admin excluded.
func TestUnreadableFiltersMeanNoCaptureOverTheLink(t *testing.T) {
	t.Parallel()
	e := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, true, withRemote())
	e.host.setFilters(sensorlink.Filter{Type: "port", Value: "nope"})
	e.setInterface("eth1", true)
	e.run()
	waitFor(t, "filters_invalid in the heartbeat", func() bool { return e.svc.Drops()["filters_invalid"] >= 1 })
	if len(e.src.opens()) != 0 || e.sink.count() != 0 {
		t.Errorf("opened %v, %d observations: a capture ran with a filter that could not be read", e.src.opens(), e.sink.count())
	}
	e2 := newEnv(t, map[string][]pktgen.Frame{"eth1": pktgen.SpanMetadata()}, true, withRemote())
	e2.setInterface("eth1", true)
	e2.host.setOptErr(errors.New("settings unreadable")) // core cannot read the filters at all
	e2.run()
	waitFor(t, "a heartbeat", func() bool { l, _ := e2.svc.Status(context.Background()); return l[0].LastSeen != nil })
	pause(t, 100*time.Millisecond)
	if len(e2.src.opens()) != 0 {
		t.Errorf("opened %v although core could not read the filters", e2.src.opens())
	}
}

func boxItem(field, value string, mac string, ip string) sensorlink.ObservationItem {
	return sensorlink.ObservationItem{MAC: mac, IP: ip, Field: field, Value: value, Confidence: 0.6, SeenAt: pktgen.T0}
}

// M2: core refuses what a sensor says about the box, by the cards the host reports (not by a heartbeat), and the box record does
// not change. A sensor that does not know its own MAC gets no further than core's check.
func TestItemsAboutTheBoxAreRefused(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	if _, err := e.inv.EnsureBox(ctx, inventory.BoxInfo{Hostname: "vedette", IP: pktgen.BoxIP.String()}); err != nil {
		t.Fatal(err)
	}
	box := func() inventory.Device {
		for _, d := range e.devices() {
			if d.IsBox {
				return d
			}
		}
		t.Fatal("no box")
		return inventory.Device{}
	}
	before := box()
	rep, err := e.svc.Observations(ctx, request(epochA, 1,
		boxItem("hostname", "evil", pktgen.Box.String(), ""),                      // the box's MAC
		boxItem("hostname", "evil", "", pktgen.BoxIP.String()),                    // the box's address
		boxItem("mac", pktgen.Box.String(), pktgen.Box.String(), "192.168.10.99"), // the box's MAC bound to another address
		boxItem("hostname", "fine", macN(1), "192.168.10.99"),                     // an ordinary device
		boxItem("hostname", "stolen", macN(2), pktgen.BoxIP.String()),             // another MAC claiming the box's address
		boxItem("hostname", "upper", "0A:00:00:00:00:77", ""),                     // upper case is not a MAC of the protocol
	))
	if err != nil {
		t.Fatal(err)
	}
	c := codes(rep)
	for _, i := range []int{0, 1, 2, 4} {
		if c[i] != "refused" {
			t.Errorf("item %d: %q, want refused", i, c[i])
		}
	}
	if c[3] != "" || c[5] != "invalid_item" {
		t.Errorf("codes %v", c)
	}
	after := box()
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	if str(after.Hostname) != str(before.Hostname) || after.IP != before.IP || str(after.MAC) != str(before.MAC) {
		t.Errorf("the box changed: hostname %q -> %q, ip %q -> %q, mac %q -> %q", str(before.Hostname), str(after.Hostname), before.IP, after.IP, str(before.MAC), str(after.MAC))
	}
	if n := len(e.devices()); n != 2 {
		t.Errorf("%d devices, want the box and the ordinary one", n)
	}
}

// Container-only (D-385): without a host the box's own cards are those of the sensor's heartbeat of the last 90 s, never the
// core container's. No such heartbeat → the batch is not applied (503 not_ready: the sensor sends it again whole), and an old
// heartbeat lets no card be chosen either. With a host, the host's cards decide and the heartbeat's do not (D-118).
func TestNoHostTheBoxIsWhatTheFreshHeartbeatReports(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	e.host.setNoHost(true)
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	const hostMAC, hostIP = "0a:00:00:00:99:01", "192.168.10.141"
	batch := func(seq int64) (sensorlink.ObservationsReply, error) {
		return e.svc.Observations(ctx, request(epochA, seq,
			boxItem("hostname", "evil", hostMAC, ""),             // the MAC of the real host card
			boxItem("hostname", "evil", macN(1), hostIP),         // another MAC claiming its address
			boxItem("hostname", "fine", pktgen.Box.String(), ""), // the card the fake host would report: not the box here
		))
	}
	busy := func(what string, err error) {
		t.Helper()
		var se *sensorlink.Error
		if !errors.As(err, &se) || se.Code != sensorlink.CodeNotReady || se.Status != 503 || se.RetryAfter <= 0 {
			t.Fatalf("%s: %v, want 503 not_ready with a Retry-After", what, err)
		}
	}
	_, err := batch(1)
	busy("before any heartbeat", err)
	beat := func() {
		t.Helper()
		hb := &sensorlink.PassiveHeartbeat{Version: "1.0.0", Drops: map[string]int64{}, Interfaces: []sensorlink.HeartbeatIface{
			{Name: "enp2s0", MAC: hostMAC, Link: true, IPv4: []string{hostIP + "/24"}}, {Name: "enp3s0", MAC: "0a:00:00:00:99:02", Link: true, IPv4: []string{}}}}
		if _, err := e.svc.PassiveHeartbeat(ctx, hb); err != nil {
			t.Fatal(err)
		}
	}
	beat()
	now = now.Add(89 * time.Second)
	rep, err := batch(1)
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); c[0] != "refused" || c[1] != "refused" || c[2] != "" {
		t.Fatalf("codes %v: the heartbeat's cards are the box, the fake host's are not", c)
	}
	now = now.Add(time.Second) // 90 s after the heartbeat: the sensor is offline, its list is too old
	_, err = batch(2)
	busy("a heartbeat 90 s old", err)
	if err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, "enp3s0", true); !errors.Is(err, sp.ErrBadInterface) || !strings.Contains(err.Error(), "has not reported its network cards") {
		t.Fatalf("a card from a heartbeat 90 s old: %v", err)
	}
	beat()
	if err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, "enp3s0", true); err != nil {
		t.Fatalf("a card of the fresh heartbeat: %v", err)
	}
	e.host.setNoHost(false) // with a host, its cards decide; the heartbeat's do not
	rep, err = batch(2)
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); c[0] != "" || c[1] != "" || c[2] != "refused" {
		t.Fatalf("codes %v with a host: the host's cards are the box", c)
	}
}

// The same through the real link, from a sensor that does not know which MAC is the box's (its own view of the cards lacks it):
// the capture reads the box's frames and reports them, and it is core's check that stops them.
func TestASensorThatDoesNotKnowTheBoxIsStillRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, frames(), true, withRemote())
	e.sensorCards = func(context.Context) ([]capture.Interface, error) {
		return []capture.Interface{{Name: "eth1", MAC: "02:00:00:00:00:02", Link: true}}, nil // no eth0: the box's MAC and address are unknown to it
	}
	e.setInterface("eth0", false)
	e.run()
	waitFor(t, "the devices of the LAN", func() bool { return e.device(pktgen.PC.String()) != nil && e.device(pktgen.Router.String()) != nil })
	waitFor(t, "core's rejections counted by the sensor", func() bool { return e.svc.Drops()["observation_rejected"] >= 1 })
	for _, d := range e.devices() {
		if (d.MAC != nil && *d.MAC == pktgen.Box.String()) || d.IP == pktgen.BoxIP.String() {
			t.Errorf("the box became a device through a sensor that did not know it: %+v", d)
		}
	}
}

// M4: one MAC that claims many addresses is over budget after four.
func TestBudgetStopsOneMACWithManyAddresses(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	items := make([]sensorlink.ObservationItem, 20)
	for i := range items {
		items[i] = boxItem("hostname", "h", macN(5), fmt.Sprintf("10.0.0.%d", i+1))
	}
	rep, err := e.svc.Observations(t.Context(), request(epochA, 1, items...))
	if err != nil || len(rep.Rejected) != 16 {
		t.Fatalf("%d rejected, %v: want 16", len(rep.Rejected), err)
	}
	for _, r := range rep.Rejected {
		if r.Code != "budget_exhausted" || r.Index < 4 {
			t.Fatalf("rejection %+v", r)
		}
	}
}

// M5: an observation written in the last quarter of an hour is acknowledged and not written again; a flood of repeats costs the
// store nothing; after the TTL it is written again.
func TestARepeatFloodDoesNotWrite(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	batch := func(seq int64) *sensorlink.ObservationsRequest {
		return request(epochA, seq, item(macN(1), "hostname", "h", 0.6), item(macN(2), "hostname", "g", 0.6))
	}
	if rep, err := e.svc.Observations(ctx, batch(1)); err != nil || len(rep.Rejected) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	e.sink.mu.Lock()
	calls := e.sink.calls
	e.sink.mu.Unlock()
	for seq := int64(2); seq < 12; seq++ {
		now = now.Add(time.Second)
		rep, err := e.svc.Observations(ctx, batch(seq))
		if err != nil || len(rep.Rejected) != 0 || rep.AckSeq != seq {
			t.Fatalf("repeat %d: %+v %v", seq, rep, err)
		}
	}
	e.sink.mu.Lock()
	n := e.sink.calls
	e.sink.mu.Unlock()
	if n != calls {
		t.Errorf("%d writes for 10 batches of repeats, want none", n-calls)
	}
	now = now.Add(16 * time.Minute)
	if _, err := e.svc.Observations(ctx, batch(20)); err != nil {
		t.Fatal(err)
	}
	e.sink.mu.Lock()
	n = e.sink.calls
	e.sink.mu.Unlock()
	if n != calls+1 {
		t.Errorf("%d writes after the TTL, want one more", n-calls)
	}
	// a batch the store failed was not remembered as written: the retry is written
	e2 := newEnv(t, nil, false, withFlakyStore(1))
	if _, err := e2.svc.Observations(ctx, request(epochA, 1, item(macN(1), "hostname", "h", 0.6))); err == nil {
		t.Fatal("the store did not fail")
	}
	if _, err := e2.svc.Observations(ctx, request(epochA, 2, item(macN(1), "hostname", "h", 0.6))); err != nil || len(e2.devices()) != 1 {
		t.Errorf("the retry of a failed batch was taken for a repeat: %d devices", len(e2.devices()))
	}
}

// M5: core takes at most 6000 items a minute from the passive role, whatever they say; the rest is over budget without being read.
func TestItemsPerMinuteAreCapped(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	junk := make([]sensorlink.ObservationItem, 500) // empty values: each one is rejected, and each one counts
	for i := range junk {
		junk[i] = item(macN(1), "hostname", "", 0.5)
	}
	for seq := int64(1); seq <= 12; seq++ {
		rep, err := e.svc.Observations(ctx, request(epochA, seq, junk...))
		if err != nil || codes(rep)[0] != "invalid_item" {
			t.Fatalf("batch %d: %+v %v", seq, rep.Rejected[:1], err)
		}
	}
	rep, err := e.svc.Observations(ctx, request(epochA, 13, junk...))
	if err != nil || len(rep.Rejected) != 500 || codes(rep)[0] != "budget_exhausted" || codes(rep)[499] != "budget_exhausted" {
		t.Fatalf("batch 13 (item 6001 on): %v: want every item budget_exhausted", err)
	}
	now = now.Add(61 * time.Second)
	rep, err = e.svc.Observations(ctx, request(epochA, 14, junk...))
	if err != nil || codes(rep)[0] != "invalid_item" {
		t.Errorf("the next minute: %v", err)
	}
}

// L3: a batch the listener let in just before the module was turned off is not recorded (SYS-5).
func TestAModuleThatIsOffRecordsNothing(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	e.off.Store(true)
	_, err := e.svc.Observations(t.Context(), request(epochA, 1, item(macN(1), "hostname", "h", 0.6)))
	wantCode(t, err, sensorlink.CodeModuleOff)
	e.sink.mu.Lock()
	calls := e.sink.calls
	e.sink.mu.Unlock()
	if calls != 0 || len(e.devices()) != 0 || e.count(`SELECT count(*) FROM sp_seq`) != 0 {
		t.Errorf("%d writes, %d devices: nothing may be written for a module that is off", calls, len(e.devices()))
	}
	e.off.Store(false)
	if _, err := e.svc.Observations(t.Context(), request(epochA, 1, item(macN(1), "hostname", "h", 0.6))); err != nil || len(e.devices()) != 1 {
		t.Errorf("the same batch with the module on: %v", err)
	}
}

// L4: the row of the sensor is created once, not on every poll of the config or every read.
func TestTheSensorRowIsCreatedOnce(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	if _, err := e.svc.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `CREATE TRIGGER no_sensor_update BEFORE UPDATE ON sp_sensor BEGIN SELECT RAISE(FAIL, 'written again'); END`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := e.svc.Config(ctx, 0, ""); err != nil {
			t.Fatalf("Config wrote the sensor row again: %v", err)
		}
		if _, err := e.svc.Status(ctx); err != nil {
			t.Fatalf("Status wrote the sensor row again: %v", err)
		}
	}
}

// L6: after a restart the devices of the inventory are known to the budget: a flood that spends the minute does not make them new.
func TestTheBudgetKnowsTheDevicesTheInventoryHas(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	var now time.Time
	e.setClock(func() time.Time { return now })
	now = pktgen.T0.Add(time.Minute)
	if err := e.inv.Record(ctx, []observe.Observation{{AssetHint: observe.AssetHint{MAC: macN(900)}, Field: observe.Hostname, Value: "old", Source: observe.Passive, Confidence: 0.6, SeenAt: pktgen.T0}}); err != nil {
		t.Fatal(err)
	}
	flood := make([]sensorlink.ObservationItem, 100)
	for i := range flood {
		flood[i] = item(macN(i), "hostname", "h", 0.6)
	}
	if _, err := e.svc.Observations(ctx, request(epochA, 1, flood...)); err != nil { // spends the minute
		t.Fatal(err)
	}
	rep, err := e.svc.Observations(ctx, request(epochA, 2, item(macN(900), "hostname", "renamed", 0.6), item(macN(901), "hostname", "new", 0.6)))
	if err != nil {
		t.Fatal(err)
	}
	if c := codes(rep); len(c) != 1 || c[1] != "budget_exhausted" {
		t.Errorf("rejected %+v: the device that exists passes, the new one is over budget", rep.Rejected)
	}
}

// L9: a counter this core does not know is ignored and said once, so that a newer sensor's heartbeat is not refused; what is not
// a counter is still refused by the listener.
func TestUnknownDropCountersAreIgnoredAndLoggedOnce(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	var buf syncBuffer
	e := newEnv(t, nil, false, withLog(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	link := linktest.New(t, linktest.Passive(e.svc))
	pas := link.Client(t, sensorlink.Passive)
	hb := &sensorlink.PassiveHeartbeat{Version: "9.0.0", Interfaces: []sensorlink.HeartbeatIface{}, Drops: map[string]int64{"excluded": 2, "from_the_future": 7}}
	for range 3 {
		if _, err := pas.PassiveHeartbeat(t.Context(), hb); err != nil {
			t.Fatal(err)
		}
	}
	if d := e.svc.Drops(); d["excluded"] != 2 || len(d) != 1 {
		t.Errorf("drops %v", d)
	}
	if n := strings.Count(buf.String(), "from_the_future"); n != 1 {
		t.Errorf("the unknown counter was logged %d times, want once\n%s", n, buf.String())
	}
	hb.Drops = map[string]int64{"excluded": -1}
	_, err := pas.PassiveHeartbeat(t.Context(), hb)
	wantCode(t, err, sensorlink.CodeInvalidRequest)
}

// D-380 (#471): with no card chosen the sensor listens on the management card the host reports, with no setup (S-INV-1);
// a chosen card wins and the default comes back when the choice is cleared. A name that is not an interface name is never
// passed on. Without a host the default is the one wired card with an address in the sensor's heartbeat.
func TestDefaultCardIsTheManagementCard(t *testing.T) {
	t.Parallel()
	backendOnly(t)
	e := newEnv(t, nil, false)
	ctx := t.Context()
	listensOn := func() (string, bool) {
		t.Helper()
		rep, err := e.svc.Config(ctx, 0, "")
		if err != nil {
			t.Fatal(err)
		}
		list, err := e.svc.Status(ctx)
		if err != nil || len(list) != 1 {
			t.Fatalf("status %v %v", list, err)
		}
		if shown := list[0].Interface; (shown == nil) != (rep.Config.Interface == "") || shown != nil && *shown != rep.Config.Interface {
			t.Errorf("GET /inventory/sensors shows %v, the sensor is told %q", shown, rep.Config.Interface)
		}
		return rep.Config.Interface, rep.Config.Span
	}
	if got, _ := listensOn(); got != "" {
		t.Errorf("no management card known yet: %q", got)
	}
	e.host.setMgmt("eth0")
	if got, span := listensOn(); got != "eth0" || span {
		t.Errorf("nothing chosen: %q span=%v, want the management card", got, span)
	}
	if err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, "eth1", true); err != nil {
		t.Fatal(err)
	}
	if got, span := listensOn(); got != "eth1" || !span {
		t.Errorf("the SPAN port chosen: %q span=%v", got, span)
	}
	if err := e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, "", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := listensOn(); got != "eth0" {
		t.Errorf("SPAN off again: %q, want the management card", got)
	}
	e.host.setMgmt("en p3s0;rm")
	if got, _ := listensOn(); got != "" {
		t.Errorf("a name that is not an interface name was passed on: %q", got)
	}

	e.host.setNoHost(true)
	card := func(name string, ips ...string) sensorlink.HeartbeatIface {
		return sensorlink.HeartbeatIface{Name: name, MAC: "02:00:00:00:00:01", Link: true, IPv4: append([]string{}, ips...)}
	}
	for name, c := range map[string]struct {
		cards []sensorlink.HeartbeatIface
		want  string
	}{
		"the wired card with an address": {[]sensorlink.HeartbeatIface{card("enp2s0", "192.168.18.141/24"), card("wlp3s0", "192.168.18.142/24"), card("enp3s0"), card("eno2", "169.254.3.4/16")}, "enp2s0"},
		"only a wireless card":           {[]sensorlink.HeartbeatIface{card("wlp3s0", "192.168.18.142/24"), card("enp3s0")}, "wlp3s0"},
		"two wired cards: not clear":     {[]sensorlink.HeartbeatIface{card("enp2s0", "192.168.18.141/24"), card("eno1", "10.0.0.5/24")}, ""},
	} {
		if _, err := e.svc.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.0.0", Interfaces: c.cards, Drops: map[string]int64{}}); err != nil {
			t.Fatal(err)
		}
		if got, _ := listensOn(); got != c.want {
			t.Errorf("no host, %s: %q, want %q", name, got, c.want)
		}
	}
}
