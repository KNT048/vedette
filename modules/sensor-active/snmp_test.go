package sensoractive_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/core/sensorlink/linktest"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/internal/snmptest"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// SNMP reads (SNMP set up per device). No test here sends a packet off the machine: the reads go to a fake SNMPReader,
// or, end to end, through the real Dispatcher, link and worker to fake agents on loopback (snmptest).

const junos = "Juniper Networks, Inc. ex4200-48t Ethernet Switch, kernel JUNOS 15.1R7.9, Build date: 2019-08-30 12:00:00 UTC Copyright (c) 1996-2019 Juniper Networks, Inc."

// fakeReader is an SNMPReader that answers from a function and remembers the jobs it was given.
type fakeReader struct {
	mu     sync.Mutex
	health string
	jobs   []sensorlink.SNMPJob
	answer func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error)
}

func (f *fakeReader) SNMPHealth() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.health
}

func (f *fakeReader) RunSNMP(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
	f.mu.Lock()
	f.jobs = append(f.jobs, j)
	fn := f.answer
	f.mu.Unlock()
	if fn == nil {
		return juniperAnswers(j), nil
	}
	return fn(ctx, j)
}

func (f *fakeReader) sent() []sensorlink.SNMPJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.jobs)
}

// juniperAnswers answers every target as the Juniper switch.
func juniperAnswers(j sensorlink.SNMPJob) []sensorlink.SNMPAnswer {
	var out []sensorlink.SNMPAnswer
	for _, t := range j.Targets {
		out = append(out, sensorlink.SNMPAnswer{Target: t.IP, Status: sensorlink.SNMPStatusOK, Values: sensorlink.SNMPValues{
			SysDescr: junos, SysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.31", SysName: "SW-CORE-01"}})
	}
	return out
}

type snmpWorld struct {
	t      *testing.T
	db     *store.DB
	sec    *secrets.Store
	inv    *fakeInv
	sink   *sink
	reader *fakeReader
	svc    *sa.Service
	nm     *fakeNmap
}

// newSNMPWorld is a service with real secrets and audit over the fake inventory: 192.168.10.0/26 in scope, the window open (Monday
// 02:00 in 01:00-05:00). Devices: the switch .20 (approved), a new device .21 (not approved), a fragile printer .24 after its
// gentle scan (approved), one set to never .23 (approved), the box .2, a device outside the scope 10.9.9.9 (approved).
func newSNMPWorld(t *testing.T, reader sa.SNMPReader) *snmpWorld {
	t.Helper()
	db := storetest.New(t)
	if err := store.Migrate(t.Context(), db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(t.Context(), db, "sensor-active", sa.Migrations); err != nil {
		t.Fatal(err)
	}
	runViews(t, db)
	sec, err := secrets.New(bytes.Repeat([]byte{9}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	w := &snmpWorld{t: t, db: db, sec: sec, sink: &sink{}}
	if r, ok := reader.(*fakeReader); ok {
		w.reader = r
	}
	ip := netip.MustParseAddr
	w.inv = &fakeInv{
		st: sa.Settings{Enabled: true, ScopeConfirmed: true, LANRanges: []string{"192.168.10.0/26"}, Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "01:00", To: "05:00", Rate: 100},
		assets: map[string]netip.Addr{"a-sw": ip("192.168.10.20"), "a-new": ip("192.168.10.21"), "a-never": ip("192.168.10.23"), "a-printer": ip("192.168.10.24"),
			"a-box": ip("192.168.10.2"), "a-far": ip("10.9.9.9")},
		decision: map[string]sa.Decision{
			"a-never":   {Allowed: true, Rate: 1, Reason: "first_gentle_scan", FirstGentle: true, Never: true},
			"a-printer": {Reason: "fragile_passive_only", Fragile: true},
			"a-box":     {Reason: "box"},
			"a-far":     {Reason: "out_of_scope"},
		},
		approved:  map[string]bool{"a-sw": true, "a-never": true, "a-printer": true, "a-box": true, "a-far": true},
		protected: []netip.Addr{ip("192.168.10.2"), ip("192.168.10.23"), ip("192.168.10.24")},
		box:       []netip.Addr{ip("192.168.10.2")},
	}
	w.inv.addrs = map[netip.Addr]string{}
	for id, a := range w.inv.assets {
		w.inv.addrs[a] = id
	}
	w.nm = writeFakeNmap(t, fakeOpts{})
	base, t0 := local(9, 2, 0), time.Now()
	svc, err := sa.New(sa.Config{DB: db, Inventory: w.inv, Observe: w.sink, Software: w.sink, Services: w.sink, NmapPath: w.nm.path,
		Clock: func() time.Time { return base.Add(time.Since(t0)) }, Secrets: sec, Audit: audit.New(time.Now), SNMP: reader})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	w.svc = svc
	return w
}

func (w *snmpWorld) count(q string) int {
	w.t.Helper()
	var n int
	if err := w.db.Reader().QueryRowContext(w.t.Context(), q).Scan(&n); err != nil {
		w.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func v2c(community string) sa.SNMPInput {
	return sa.SNMPInput{Version: "v2c", Community: secrets.NewValue(community)}
}

// set sets up the SNMP of device id, or fails the test.
func (w *snmpWorld) set(id string, in sa.SNMPInput) sa.SNMPDevice {
	w.t.Helper()
	d, err := w.svc.SetSNMP(w.t.Context(), "admin@example.com", id, in)
	if err != nil {
		w.t.Fatalf("set up %s: %v", id, err)
	}
	return d
}

// setUpAll sets up every device of inv with an address that is not the box, with one community (the "many switches share one
// community" case).
func setUpAll(t *testing.T, svc *sa.Service, inv *fakeInv) {
	const community = "community-1"
	t.Helper()
	inv.mu.Lock()
	var ids []string
	for id, ip := range inv.assets {
		if ip.IsValid() && !slices.Contains(inv.box, ip) {
			ids = append(ids, id)
		}
	}
	inv.mu.Unlock()
	for _, id := range ids {
		if _, err := svc.SetSNMP(t.Context(), "admin@example.com", id, v2c(community)); err != nil {
			t.Fatalf("set up %s: %v", id, err)
		}
	}
}

func apiCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func ipsOf(j sensorlink.SNMPJob) []string {
	out := make([]string, len(j.Targets))
	for i, tg := range j.Targets {
		out[i] = tg.IP
	}
	return out
}

// a device's secrets are sealed in core/secrets; the device shows their last 4 characters only (none for a secret of under
// 8); a blank secret on an edit keeps it; removing deletes the secrets too; every change is audited without the secret; saving
// turns the device's SNMP switch on (the person's consent).
func TestSNMPSettingsAreSealedAndShownByTheirLastFour(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	d := w.set("a-sw", v2c("s3cret-community"))
	if d.SecretLast4 != "nity" || d.Version != "v2c" || d.ReadFrom != netip.MustParseAddr("192.168.10.20") || !d.ReadFromDefault || d.State != sa.SNMPWaiting || d.Port != 161 {
		t.Fatalf("set up %+v", d)
	}
	if short := w.set("a-printer", v2c("public")); short.SecretLast4 != "" {
		t.Fatalf("a short community shows %q", short.SecretLast4)
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp_device WHERE read_from || secret_last4 || coalesce(username, '') LIKE '%s3cret%'`); n != 0 {
		t.Fatal("the community is in sa_snmp_device")
	}
	if n := w.count(`SELECT count(*) FROM core_secret WHERE purpose = 'sa_snmp.secret'`); n != 2 {
		t.Fatalf("%d sealed secrets, want 2", n)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_set' AND detail NOT LIKE '%s3cret%' AND detail LIKE 'v2c, read from 192.168.10.20, port 161'`); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	if !slices.Equal(w.inv.turnedOn, []string{"a-sw", "a-printer"}) {
		t.Fatalf("the SNMP switch was turned on for %v", w.inv.turnedOn)
	}
	// An edit with the community left blank keeps it.
	if e, err := w.svc.SetSNMP(ctx, "a", "a-sw", v2c("")); err != nil || e.SecretLast4 != "nity" {
		t.Fatalf("edit: %v %+v", err, e)
	}
	// To v3: the passwords are needed; then the privacy password is sealed too.
	v3 := sa.SNMPInput{Version: "v3", Username: "vedette", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-1"), Priv: "aes128"}
	if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", v3); apiCode(err) != "secret_required" {
		t.Fatalf("v3 without a privacy password: %v", err)
	}
	v3.PrivPassword = secrets.NewValue("priv-pass-1")
	e, err := w.svc.SetSNMP(ctx, "a", "a-sw", v3)
	if err != nil || e.Version != "v3" || e.Username != "vedette" || e.Auth != "sha256" || e.Priv != "aes128" || e.SecretLast4 != "ss-1" || e.PrivLast4 != "ss-1" {
		t.Fatalf("to v3: %v %+v", err, e)
	}
	// No privacy: its password goes.
	v3.Priv, v3.AuthPassword, v3.PrivPassword = "none", secrets.NewValue(""), secrets.NewValue("")
	if e, err = w.svc.SetSNMP(ctx, "a", "a-sw", v3); err != nil || e.Priv != "none" || e.PrivLast4 != "" || w.count(`SELECT count(*) FROM core_secret WHERE purpose = 'sa_snmp.priv'`) != 0 {
		t.Fatalf("no privacy: %v %+v", err, e)
	}
	if err := w.svc.DeleteSNMP(ctx, "a", "a-sw"); err != nil || w.count(`SELECT count(*) FROM core_secret`) != 1 || w.count(`SELECT count(*) FROM sa_snmp_device`) != 1 {
		t.Fatalf("remove: %v", err)
	}
	if err := w.svc.DeleteSNMP(ctx, "a", "a-sw"); apiCode(err) != "not_found" {
		t.Fatalf("remove twice: %v", err)
	}
	if d, err := w.svc.SNMPDeviceOf(ctx, "a-sw"); err != nil || d.State != sa.SNMPNotSetUp || d.IP != netip.MustParseAddr("192.168.10.20") {
		t.Fatalf("after remove: %v %+v", err, d)
	}
	if _, err := w.svc.SNMPDeviceOf(ctx, "a-nobody"); apiCode(err) != "not_found" {
		t.Fatalf("an unknown device: %v", err)
	}
}

// the form is checked as the contract says, the read address at the boundary (an IPv4 address of a local network, not
// multicast, broadcast or a LAN range's network or broadcast address, not the box or a trap address); a saved secret is never sent
// to a new read address unless it is typed again.
func TestSNMPFormIsChecked(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	withRead := func(in sa.SNMPInput, at string) sa.SNMPInput { in.ReadFrom = at; return in }
	bad := map[string]struct {
		id string
		in sa.SNMPInput
	}{
		"bad_version":         {"a-sw", sa.SNMPInput{Version: "v1", Community: secrets.NewValue("public")}},
		"secret_required":     {"a-sw", v2c("")},
		"bad_secret":          {"a-sw", v2c("pub\nlic")},
		"bad_user":            {"a-sw", sa.SNMPInput{Version: "v3", Username: "a b", Auth: "sha", AuthPassword: secrets.NewValue("12345678"), Priv: "none"}},
		"bad_auth":            {"a-sw", sa.SNMPInput{Version: "v3", Username: "u", Auth: "md5", AuthPassword: secrets.NewValue("12345678"), Priv: "none"}},
		"bad_priv":            {"a-sw", sa.SNMPInput{Version: "v3", Username: "u", Auth: "sha", AuthPassword: secrets.NewValue("12345678"), Priv: "des", PrivPassword: secrets.NewValue("12345678")}},
		"bad_port":            {"a-sw", sa.SNMPInput{Version: "v2c", Community: secrets.NewValue("public"), Port: 65536}},
		"bad_read_from":       {"a-sw", withRead(v2c("public"), "printer.local")},
		"read_from_not_local": {"a-sw", withRead(v2c("public"), "8.8.8.8")},
		"read_from_box":       {"a-sw", withRead(v2c("public"), "192.168.10.2")},
		"box_device":          {"a-box", v2c("public")},
		"not_found":           {"a-nobody", v2c("public")},
		"copy_from_self":      {"a-sw", sa.SNMPInput{CopyFrom: "a-sw"}},
		"copy_from_not_found": {"a-sw", sa.SNMPInput{CopyFrom: "a-printer"}},
	}
	for code, c := range bad {
		if _, err := w.svc.SetSNMP(ctx, "a", c.id, c.in); apiCode(err) != code {
			t.Errorf("%s: %v", code, err)
		}
	}
	for _, at := range []string{"224.0.0.1", "255.255.255.255", "0.0.0.0", "127.0.0.1", "192.168.10.63", "192.168.10.0", "169.254.1.1"} {
		if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", withRead(v2c("public"), at)); apiCode(err) != "bad_read_from" {
			t.Errorf("read from %s: %v", at, err)
		}
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp_device`) + w.count(`SELECT count(*) FROM core_secret`); n != 0 {
		t.Fatalf("a refused form left %d rows", n)
	}
	// A device without an address cannot be set up; an ignored one is refused by the inventory, and nothing is saved.
	w.inv.mu.Lock()
	w.inv.assets["a-lldp"] = netip.Addr{}
	w.inv.mu.Unlock()
	if _, err := w.svc.SetSNMP(ctx, "a", "a-lldp", v2c("public")); apiCode(err) != "no_ip" {
		t.Errorf("no address: %v", err)
	}
	w.inv.mu.Lock()
	w.inv.turnOnErr = apierr.New(409, "device_ignored", "This device is ignored.")
	w.inv.mu.Unlock()
	if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", v2c("public")); apiCode(err) != "device_ignored" || w.count(`SELECT count(*) FROM sa_snmp_device`) != 0 {
		t.Errorf("an ignored device: %v", err)
	}
	w.inv.mu.Lock()
	w.inv.turnOnErr = nil
	w.inv.mu.Unlock()
	// Outside the LAN ranges is allowed (the person set it on this device): a firewall read at its management interface.
	d := w.set("a-sw", withRead(v2c("c0mmunity"), "100.66.253.1"))
	if d.ReadFrom != netip.MustParseAddr("100.66.253.1") || d.ReadFromDefault {
		t.Fatalf("read from outside the LAN: %+v", d)
	}
	// The secret goes to a new address only when it is typed again.
	if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", withRead(v2c(""), "192.168.10.40")); apiCode(err) != "secret_required" {
		t.Errorf("a new read address without the secret: %v", err)
	}
	if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", v2c("")); apiCode(err) != "secret_required" { // back to the device's IP: a new address too
		t.Errorf("back to the IP without the secret: %v", err)
	}
	if d, err := w.svc.SetSNMP(ctx, "a", "a-sw", withRead(v2c("c0mmunity"), "192.168.10.40")); err != nil || d.ReadFrom != netip.MustParseAddr("192.168.10.40") {
		t.Errorf("a new read address with the secret: %v %+v", err, d)
	}
	if d, err := w.svc.SetSNMP(ctx, "a", "a-sw", withRead(v2c(""), "192.168.10.40")); err != nil || d.SecretLast4 != "nity" {
		t.Errorf("the same read address, secret kept: %v %+v", err, d)
	}
}

// a Check now sends nothing to a device it may not read, and says why in plain words.
func TestSNMPCheckRefusesBeforeSendingAnything(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	for _, id := range []string{"a-new", "a-never", "a-far", "a-sw"} {
		w.set(id, v2c("s3cret-community"))
	}
	w.inv.set(func(s *sa.Settings) { s.Exclusions = []string{"192.168.10.20"} })
	for _, c := range []struct{ id, reason, words string }{
		{"a-new", "not_approved", "not approved yet"},
		{"a-never", "regular_scan_never", "never be scanned"},
		{"a-far", "out_of_scope", "outside the LAN ranges"},
		{"a-sw", "excluded", "never touches it, not even with SNMP"},
	} {
		res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", c.id)
		if err != nil || res.OK || res.Reason != c.reason || !strings.Contains(res.Message, c.words) {
			t.Errorf("%s: %v %+v", c.id, err, res)
		}
		if d, _ := w.svc.SNMPDeviceOf(t.Context(), c.id); d.Blocked == nil || d.Blocked.Reason != c.reason {
			t.Errorf("%s: the device does not say it is blocked: %+v", c.id, d.Blocked)
		}
	}
	if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-printer"); apiCode(err) != "not_set_up" {
		t.Errorf("not set up: %v", err)
	}
	if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-nobody"); apiCode(err) != "not_found" {
		t.Errorf("unknown: %v", err)
	}
	w.inv.set(func(s *sa.Settings) { s.Exclusions = nil })
	r.mu.Lock()
	r.health = "the scan worker has not reported for 90 seconds; SNMP reads cannot run until it does"
	r.mu.Unlock()
	if res, _ := w.svc.CheckSNMP(t.Context(), "a", "a-sw"); res.Reason != "unavailable" || !strings.Contains(res.Message, "90 seconds") {
		t.Errorf("unavailable: %+v", res)
	}
	if n := len(r.sent()); n != 0 || w.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatalf("%d jobs sent, %d probe rows", n, w.count(`SELECT count(*) FROM sa_probe`))
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_check'`); n != 5 {
		t.Errorf("%d audit rows of a check, want 5", n)
	}
}

// Check now reads the device at its read address (its management address, not its IP), logs the probe
// before the job leaves (versions and ports, never a secret), and records what answered on that device, by its id: never by the
// read address, so no device is found, made or joined there. The device then says working, with what answered.
func TestSNMPCheckReadsTheReadAddressAndRecordsOnTheDevice(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	in := v2c("s3cret-community")
	in.ReadFrom = "192.168.10.40" // a management address; another device could even sit there
	w.set("a-sw", in)
	r.answer = func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		var n int
		if err := w.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_probe WHERE shape = 'snmp' AND result = 'started'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the probe row is not written before the job leaves (%d, %v)", n, err)
		}
		return juniperAnswers(j), nil
	}
	res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-sw")
	if err != nil || !res.OK || res.Answer == nil || !strings.Contains(res.Message, "192.168.10.40 answered on UDP port 161") {
		t.Fatalf("%v %+v", err, res)
	}
	if a := res.Answer; a.Vendor != "Juniper Networks" || a.Model != "EX4200-48T" || a.OS != "JUNOS 15.1R7.9" || a.Kind != "switch" || a.Hostname != "SW-CORE-01" {
		t.Errorf("answer %+v", a)
	}
	jobs := r.sent()
	if len(jobs) != 1 || len(jobs[0].Targets) != 1 || jobs[0].Targets[0].IP != "192.168.10.40" || jobs[0].Targets[0].Credential.Community != "s3cret-community" {
		t.Fatalf("jobs %+v", jobs)
	}
	got := map[observe.Field]string{}
	for _, o := range w.sink.observations() {
		if o.Source != observe.SNMP || o.AssetHint != (observe.AssetHint{Device: "a-sw"}) {
			t.Errorf("observation %+v: want the device a-sw, and no address", o)
		}
		got[o.Field] = o.Value
	}
	if got[observe.OS] != "JUNOS 15.1R7.9" || got[observe.Model] != "EX4200-48T" || got[observe.Hostname] != "SW-CORE-01" {
		t.Errorf("recorded %v", got)
	}
	if w.count(`SELECT count(*) FROM sa_probe WHERE shape = 'snmp' AND hosts = 1 AND targets = '192.168.10.40' AND result = 'ok: 1 of 1 answered' AND flags LIKE '%v2c UDP 161 ×1%' AND flags NOT LIKE '%s3cret%'`) != 1 ||
		w.count(`SELECT count(*) FROM jobs_v WHERE kind = 'snmp' AND reason = 'snmp_test' AND status = 'done'`) != 1 {
		t.Fatal("probe row or job is missing")
	}
	d := res.Device
	if d.State != sa.SNMPWorking || d.LastAnswerAt.IsZero() || d.Answer == nil || d.Answer.SysName != "SW-CORE-01" || d.Answer.Model != "EX4200-48T" ||
		d.IP != netip.MustParseAddr("192.168.10.20") || d.ReadFrom != netip.MustParseAddr("192.168.10.40") || d.Blocked != nil {
		t.Fatalf("device after the check %+v", d)
	}
	// A wrong community: the device says nothing; the state says not answering, the last answer stays.
	r.answer = func(_ context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		return []sensorlink.SNMPAnswer{{Target: j.Targets[0].IP, Status: sensorlink.SNMPStatusNoAnswer}}, nil
	}
	res, err = w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-sw")
	if err != nil || res.OK || res.Reason != "no_answer" || !strings.Contains(res.Message, "community is wrong") || !strings.Contains(res.Message, "No answer from 192.168.10.40") {
		t.Fatalf("no answer: %v %+v", err, res)
	}
	if d := res.Device; d.State != sa.SNMPNotAnswering || d.LastReason != "no_answer" || !strings.Contains(d.Error, "No answer") || d.Answer == nil {
		t.Fatalf("device after no answer %+v", d)
	}
}

// once per window, after the sweep and the queue, every device with SNMP set up that the policy lets be read is read (a
// fragile printer too), each at its read address with its own settings; a device not approved, or set to never, is not.
func TestSNMPRoundOncePerWindow(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	w.set("a-sw", v2c("community-1"))
	w.set("a-printer", v2c("community-2"))
	w.set("a-new", v2c("community-3"))
	w.set("a-never", v2c("community-4"))
	if err := w.svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs := r.sent()
	if len(jobs) != 1 {
		t.Fatalf("%d jobs", len(jobs))
	}
	if !slices.Equal(ipsOf(jobs[0]), []string{"192.168.10.20", "192.168.10.24"}) {
		t.Fatalf("targets %v", ipsOf(jobs[0]))
	}
	if jobs[0].Targets[0].Credential.Community != "community-1" || jobs[0].Targets[1].Credential.Community != "community-2" {
		t.Fatalf("a device got another's community: %+v", jobs[0].Targets)
	}
	if err := w.svc.Tick(t.Context()); err != nil || len(r.sent()) != 1 {
		t.Fatalf("a second tick in the same window read again: %v, %d jobs", err, len(r.sent()))
	}
	if w.count(`SELECT count(*) FROM jobs_v WHERE kind = 'snmp' AND reason = 'window' AND status = 'done' AND targets = 2`) != 1 {
		t.Fatal("no done round")
	}
	if w.count(`SELECT count(*) FROM sa_snmp_device WHERE last_status = 'ok' AND last_answer_at IS NOT NULL`) != 2 {
		t.Fatal("the round did not record the state of the devices it read")
	}
}

// INV-1: scanning turned off while a batch waits for the worker stops it; nothing is recorded.
func TestSNMPSettingsChangeStopsTheRead(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	r := &fakeReader{answer: func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	w := newSNMPWorld(t, r)
	w.set("a-sw", v2c("community-1"))
	go func() {
		<-started
		w.inv.set(func(s *sa.Settings) { s.Enabled = false })
		_ = w.svc.SettingsChanged(context.Background())
	}()
	if _, err := w.svc.CheckSNMP(t.Context(), "a", "a-sw"); apiCode(err) != "stopped" {
		t.Fatalf("%v", err)
	}
	if len(w.sink.observations()) != 0 || w.count(`SELECT count(*) FROM sa_probe WHERE result LIKE 'stopped%'`) != 1 {
		t.Fatal("recorded, or the probe row does not say stopped")
	}
}

// startWorker runs the real worker over the mutual-TLS link with a Dispatcher; dial says where each request goes.
func startWorker(t *testing.T, dial func(netip.Addr, uint16) (string, uint16)) *sa.Dispatcher {
	t.Helper()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, activeBackend{d})
	wk, err := worker.New(worker.Config{Link: link.Client(t, sensorlink.Active), NmapPath: "/nonexistent/nmap", Version: "1.0.0", Wait: time.Second,
		SNMPTimeout: 50 * time.Millisecond, SNMPDial: dial})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = wk.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the worker's heartbeat", func() bool { return d.SNMPHealth() == "" })
	return d
}

// End to end: the Dispatcher, the mutual-TLS link and the real worker read a fake agent (v2c, then v3 authPriv) at the
// device's read address, and only there; a wrong community is "no answer" with the plain reason; a custom port is the port read.
func TestSNMPThroughTheWorker(t *testing.T) {
	t.Parallel()
	sw := &snmptest.Agent{Community: "s3cret-community", V3: &gosnmp.UsmSecurityParameters{UserName: "vedette", AuthenticationProtocol: gosnmp.SHA,
		AuthenticationPassphrase: "auth-pass-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-1"},
		Values: map[string]any{snmptest.SysDescr: junos, snmptest.SysObjectID: snmptest.Object(".1.3.6.1.4.1.2636.1.1.1.2.31"), snmptest.SysName: "SW-CORE-01"}}
	port := sw.Start(t)
	closed := (&snmptest.Agent{}).Start(t)
	var mu sync.Mutex
	var asked []string
	d := startWorker(t, func(ip netip.Addr, p uint16) (string, uint16) {
		mu.Lock()
		asked = append(asked, ip.String())
		mu.Unlock()
		if ip == netip.MustParseAddr("100.66.253.1") && (p == 161 || p == 1161) {
			return "127.0.0.1", port
		}
		return "127.0.0.1", closed
	})
	w := newSNMPWorld(t, d)
	in := v2c("s3cret-community")
	in.ReadFrom = "100.66.253.1"
	w.set("a-sw", in)
	check := func(what, reason string) sa.SNMPCheckResult {
		t.Helper()
		res, err := w.svc.CheckSNMP(t.Context(), "admin@example.com", "a-sw")
		if err != nil || res.Reason != reason {
			t.Fatalf("%s: %v %+v", what, err, res)
		}
		return res
	}
	if res := check("v2c", "ok"); res.Answer == nil || res.Answer.OS != "JUNOS 15.1R7.9" || res.Answer.Model != "EX4200-48T" {
		t.Fatalf("v2c answer %+v", res.Answer)
	}
	w.set("a-sw", sa.SNMPInput{ReadFrom: "100.66.253.1", Version: "v3", Username: "vedette", Auth: "sha", AuthPassword: secrets.NewValue("auth-pass-1"),
		Priv: "aes128", PrivPassword: secrets.NewValue("priv-pass-1"), Port: 1161})
	if res := check("v3 on port 1161", "ok"); !strings.Contains(res.Message, "UDP port 1161") {
		t.Fatalf("v3: %+v", res)
	}
	w.set("a-sw", sa.SNMPInput{ReadFrom: "100.66.253.1", Version: "v2c", Community: secrets.NewValue("not-the-community")})
	if res := check("wrong community", "no_answer"); !strings.Contains(res.Message, "community") {
		t.Fatalf("wrong community: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, a := range asked {
		if a != "100.66.253.1" {
			t.Fatalf("the worker asked %s: a read went to an address other than the device's read address (%v)", a, asked)
		}
	}
}

// The limit of limits.go: core sends an snmp job only to a worker whose heartbeat says snmp, so a worker of protocol 4 never gets one
// (its jobs reply keeps the shape of protocol 4); an answer for a target the job did not name is refused.
func TestSNMPNeverGoesToAWorkerOfProtocol4(t *testing.T) {
	t.Parallel()
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 10 * time.Millisecond})
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", Nmap: sensorlink.HeartbeatNmap{Present: true}}); err != nil {
		t.Fatal(err)
	}
	job := sensorlink.SNMPJob{Rate: 10, Targets: []sensorlink.SNMPTarget{{IP: "192.168.10.20", Credential: sensorlink.SNMPCredential{Version: "v2c", Community: "c"}}}}
	if msg := d.SNMPHealth(); !strings.Contains(msg, "older") {
		t.Errorf("health %q", msg)
	}
	if _, err := d.RunSNMP(t.Context(), job); !errors.Is(err, sa.ErrSNMPUnavailable) {
		t.Fatalf("%v", err)
	}
	if rep, _ := d.Jobs(t.Context(), 10*time.Millisecond, nil); len(rep.Jobs) != 0 {
		t.Fatalf("a job went out: %+v", rep.Jobs)
	}
	if _, err := d.ActiveHeartbeat(t.Context(), &sensorlink.ActiveHeartbeat{Version: "1.0.0", SNMP: true}); err != nil {
		t.Fatal(err)
	}
	type out struct {
		a   []sensorlink.SNMPAnswer
		err error
	}
	ch := make(chan out, 1)
	go func() { a, err := d.RunSNMP(t.Context(), job); ch <- out{a, err} }()
	rep, _ := d.Jobs(t.Context(), 5*time.Second, nil)
	if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindSNMP || rep.Jobs[0].SNMP.Targets[0].Credential.Community != "c" {
		t.Fatalf("jobs %+v", rep.Jobs)
	}
	_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "done", SNMP: []sensorlink.SNMPAnswer{{Target: "192.168.10.99", Status: "ok"}}})
	if o := <-ch; !errors.Is(o.err, sa.ErrResultRejected) {
		t.Fatalf("an answer for another target: %+v", o)
	}
}
