package sensorpassive_test

// The passive half of the sensor protocol as core serves it (SP-4): what a sensor may say, what core believes of it, and what
// stops a sensor that has been taken over. Direct calls to the Backend methods where the wire adds nothing, the real link where
// it does (roles, long poll, the capture at the far end).

import (
	"context"
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

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/modules/inventory"
	sp "github.com/knt048/vedette/modules/sensor-passive"
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
	e := newEnv(t, nil, false)
	link := linktest.New(t, linktest.Passive(e.svc))
	ctx := t.Context()
	act, pas := link.Client(t, sensorlink.Active), link.Client(t, sensorlink.Passive)
	_, err := act.Config(ctx, "", time.Second)
	wantCode(t, err, sensorlink.CodeForbiddenRoute)
	_, err = act.PostObservations(ctx, request(epochA, 1, item(macN(1), "hostname", "x", 0.5)))
	wantCode(t, err, sensorlink.CodeForbiddenRoute)
	_, err = pas.Jobs(ctx, "", time.Second)
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
	// and the failed seq was not saved: the same batch again is applied (these 60 are new devices, so the minute is now spent: they are rejected, but not as a replay)
	rep, err := e.svc.Observations(ctx, request(epochA, 1, sixty(0)...))
	if err != nil || rep.AckSeq != 1 {
		t.Fatalf("the failed batch again: %+v %v", rep, err)
	}
	if n := len(e.devices()); n != 60 {
		t.Errorf("%d devices, want the 60 of the second batch", n)
	}
}

// Core clamps the confidence of each field to the top of the passive scale (INV-5): a sensor that says 1.0 for a name gets what a
// passive observation of a name can know. Outside 0..1 the item is no good.
func TestConfidenceIsClampedPerField(t *testing.T) {
	t.Parallel()
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
	want := map[string]float64{"hostname": 0.7, "mac": 0.9, "vendor": 0.4, "model": 0.5, "kind": 0.6, "os": 0.3}
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

// A sensor cannot steer the capture onto a card it does not have: SetInterface accepts only a card the sensor reported in its
// heartbeat, a SPAN card has no IP address in that report, and what core tells the sensor is core's choice, not the sensor's.
func TestInterfacesCannotBeSpoofed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil, false)
	link := linktest.New(t, linktest.Passive(e.svc))
	pas := link.Client(t, sensorlink.Passive)
	ctx := t.Context()
	beat := func(ifaces ...sensorlink.HeartbeatIface) {
		t.Helper()
		if _, err := pas.PassiveHeartbeat(ctx, &sensorlink.PassiveHeartbeat{Version: "1.2.3", Interfaces: ifaces, Drops: map[string]int64{}}); err != nil {
			t.Fatal(err)
		}
	}
	card := func(name string, up bool, ips ...string) sensorlink.HeartbeatIface {
		if ips == nil {
			ips = []string{}
		}
		return sensorlink.HeartbeatIface{Name: name, MAC: "02:00:00:00:00:" + fmt.Sprintf("%02x", len(name)), Link: up, IPv4: ips}
	}
	set := func(iface string, span bool) error {
		return e.svc.SetInterface(ctx, "admin@example.org", sp.SensorID, iface, span)
	}
	if err := set("eth1", false); !errors.Is(err, sp.ErrBadInterface) {
		t.Fatalf("no heartbeat yet: %v", err)
	}
	beat(card("eth1", true), card("eth0", true, "192.168.10.5/24"))
	for name, c := range map[string]struct {
		iface string
		span  bool
	}{"a card the sensor did not report": {"eth9", false}, "a SPAN card with an IP": {"eth0", true}, "SPAN with no card": {"", true}} {
		if err := set(c.iface, c.span); !errors.Is(err, sp.ErrBadInterface) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := set("eth1", true); err != nil {
		t.Fatal(err)
	}
	cfg, err := pas.Config(ctx, "", time.Second)
	if err != nil || cfg.Config.Interface != "eth1" || !cfg.Config.Span {
		t.Fatalf("config %+v %v", cfg, err)
	}
	// a later heartbeat that names other cards, or none, changes what core believes about the cards, never the choice
	beat(card("eth7", true))
	cfg2, err := pas.Config(ctx, "", time.Second)
	if err != nil || cfg2.Config.Interface != "eth1" || cfg2.ETag != cfg.ETag {
		t.Fatalf("the choice moved with a heartbeat: %+v %v", cfg2, err)
	}
	if err := set("eth1", true); !errors.Is(err, sp.ErrBadInterface) {
		t.Errorf("eth1 is no longer a card the sensor reported: %v", err)
	}
	list, _ := e.svc.Status(ctx)
	if !slices.Equal(list[0].Interfaces, []string{"eth7"}) || list[0].Version == nil || *list[0].Version != "1.2.3" {
		t.Errorf("status %+v", list[0])
	}
}

// What GET /inventory/sensors and the SPAN card show comes from the heartbeat, nothing else (D-112 (5)): online within 90 seconds,
// version, devices, cards, the verdicts off / no_link / no_traffic / own_only / ok.
func TestHeartbeatDrivesTheViews(t *testing.T) {
	t.Parallel()
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
		pause(t, 300*time.Millisecond) // the rest of the recording
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
