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

// SNMP reads (D-512). No test here sends a packet off the machine: the reads go to a fake SNMPReader, or, end to end, through the
// real Dispatcher, link and worker to fake agents on loopback (snmptest).

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

// juniperAnswers answers every target as the Juniper switch, with the first credential it names.
func juniperAnswers(j sensorlink.SNMPJob) []sensorlink.SNMPAnswer {
	var out []sensorlink.SNMPAnswer
	for _, t := range j.Targets {
		out = append(out, sensorlink.SNMPAnswer{Target: t.IP, Status: sensorlink.SNMPStatusOK, Credential: t.Credentials[0], Values: sensorlink.SNMPValues{
			SysDescr: junos, SysObjectID: ".1.3.6.1.4.1.2636.1.1.1.2.31", SysName: "SW-CORE-01"}})
	}
	return out
}

type snmpWorld struct {
	t      *testing.T
	db     *store.DB
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
	sec, err := secrets.New(bytes.Repeat([]byte{9}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	w := &snmpWorld{t: t, db: db, sink: &sink{}}
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

func v2cInput(name, community string, scope ...string) sa.SNMPCredentialInput {
	return sa.SNMPCredentialInput{Name: name, Version: "v2c", Community: secrets.NewValue(community), Scope: scope}
}

func (w *snmpWorld) add(in sa.SNMPCredentialInput) sa.SNMPCredential {
	w.t.Helper()
	c, err := w.svc.AddSNMP(w.t.Context(), "admin@example.com", in)
	if err != nil {
		w.t.Fatal(err)
	}
	return c
}

func apiCode(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// D-512: a credential's secrets are sealed in core/secrets; the list shows the last 4 characters only (none for a secret of under
// 8); a blank secret on an edit keeps it; deleting removes the secrets too; every change is audited without the secret.
func TestSNMPCredentialsAreSealedAndShownByTheirLastFour(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	c := w.add(v2cInput("Core switches", "s3cret-community"))
	if c.SecretLast4 != "nity" || c.Version != "v2c" || len(c.Scope) != 0 || c.Username != "" {
		t.Fatalf("added %+v", c)
	}
	short := w.add(v2cInput("Printers", "public", "192.168.10.24", "192.168.10.0/28"))
	if short.SecretLast4 != "" || !slices.Equal(short.Scope, []string{"192.168.10.24", "192.168.10.0/28"}) {
		t.Fatalf("a short community shows %q, scope %v", short.SecretLast4, short.Scope)
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp WHERE name || scope || secret_last4 || coalesce(username, '') LIKE '%s3cret%'`); n != 0 {
		t.Fatal("the community is in sa_snmp")
	}
	if n := w.count(`SELECT count(*) FROM core_secret WHERE purpose = 'sa_snmp.secret'`); n != 2 {
		t.Fatalf("%d sealed secrets, want 2", n)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_add' AND detail NOT LIKE '%s3cret%'`); n != 2 {
		t.Fatalf("%d audit rows", n)
	}
	// An edit with the community left blank keeps it; the name is unique whatever the case.
	e, err := w.svc.EditSNMP(ctx, "admin@example.com", c.ID, v2cInput("Core switches (HQ)", ""))
	if err != nil || e.SecretLast4 != "nity" || e.Name != "Core switches (HQ)" {
		t.Fatalf("edit: %v %+v", err, e)
	}
	if _, err := w.svc.AddSNMP(ctx, "a", v2cInput("core SWITCHES (hq)", "x")); apiCode(err) != "name_taken" {
		t.Fatalf("same name: %v", err)
	}
	// To v3: the passwords are needed; then the privacy password is sealed too.
	v3 := sa.SNMPCredentialInput{Name: "Core switches (HQ)", Version: "v3", Username: "vedette", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-1"), Priv: "aes128"}
	if _, err := w.svc.EditSNMP(ctx, "a", c.ID, v3); apiCode(err) != "secret_required" {
		t.Fatalf("v3 without a privacy password: %v", err)
	}
	v3.PrivPassword = secrets.NewValue("priv-pass-1")
	e, err = w.svc.EditSNMP(ctx, "a", c.ID, v3)
	if err != nil || e.Version != "v3" || e.Username != "vedette" || e.Auth != "sha256" || e.Priv != "aes128" || e.SecretLast4 != "ss-1" || e.PrivLast4 != "ss-1" {
		t.Fatalf("to v3: %v %+v", err, e)
	}
	// No privacy: its password goes.
	v3.Priv, v3.AuthPassword, v3.PrivPassword = "none", secrets.NewValue(""), secrets.NewValue("")
	if e, err = w.svc.EditSNMP(ctx, "a", c.ID, v3); err != nil || e.Priv != "none" || e.PrivLast4 != "" || w.count(`SELECT count(*) FROM core_secret WHERE purpose = 'sa_snmp.priv'`) != 0 {
		t.Fatalf("no privacy: %v %+v", err, e)
	}
	if err := w.svc.DeleteSNMP(ctx, "a", c.ID); err != nil || w.count(`SELECT count(*) FROM core_secret`) != 1 || w.count(`SELECT count(*) FROM sa_snmp`) != 1 {
		t.Fatalf("delete: %v", err)
	}
	if err := w.svc.DeleteSNMP(ctx, "a", c.ID); apiCode(err) != "not_found" {
		t.Fatalf("delete twice: %v", err)
	}
}

// D-512: the form is checked as the contract says; a saved secret is never sent to more addresses unless it is typed again.
func TestSNMPFormIsChecked(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	bad := map[string]sa.SNMPCredentialInput{
		"bad_version":     {Name: "x", Version: "v1", Community: secrets.NewValue("public")},
		"secret_required": v2cInput("x", ""),
		"bad_secret":      v2cInput("x", "pub\nlic"),
		"bad_name":        v2cInput("<b>", "public"),
		"bad_scope":       v2cInput("x", "public", "8.8.8.8"),
		"bad_user":        {Name: "x", Version: "v3", Username: "a b", Auth: "sha", AuthPassword: secrets.NewValue("12345678"), Priv: "none"},
		"bad_auth":        {Name: "x", Version: "v3", Username: "u", Auth: "md5", AuthPassword: secrets.NewValue("12345678"), Priv: "none"},
		"bad_priv":        {Name: "x", Version: "v3", Username: "u", Auth: "sha", AuthPassword: secrets.NewValue("12345678"), Priv: "des", PrivPassword: secrets.NewValue("12345678")},
	}
	short := sa.SNMPCredentialInput{Name: "x", Version: "v3", Username: "u", Auth: "sha", AuthPassword: secrets.NewValue("1234567"), Priv: "none"}
	for code, in := range bad {
		if _, err := w.svc.AddSNMP(ctx, "a", in); apiCode(err) != code {
			t.Errorf("%s: %v", code, err)
		}
	}
	if _, err := w.svc.AddSNMP(ctx, "a", short); apiCode(err) != "bad_secret" {
		t.Errorf("a v3 password of 7: %v", err)
	}
	c := w.add(v2cInput("narrow", "c0mmunity", "192.168.10.20"))
	if _, err := w.svc.EditSNMP(ctx, "a", c.ID, v2cInput("narrow", "", "192.168.10.0/24")); apiCode(err) != "secret_required" {
		t.Errorf("widened without the secret: %v", err)
	}
	if _, err := w.svc.EditSNMP(ctx, "a", c.ID, v2cInput("narrow", "")); apiCode(err) != "secret_required" {
		t.Errorf("to every address without the secret: %v", err)
	}
	if _, err := w.svc.EditSNMP(ctx, "a", c.ID, v2cInput("narrow", "c0mmunity", "192.168.10.0/24")); err != nil {
		t.Errorf("widened with the secret: %v", err)
	}
	for i := range 7 {
		w.add(v2cInput("c"+string(rune('a'+i)), "public"))
	}
	if _, err := w.svc.AddSNMP(ctx, "a", v2cInput("ninth", "public")); apiCode(err) != "too_many" {
		t.Errorf("a ninth: %v", err)
	}
}

// D-512: a Test sends nothing to a device it may not read, and says why in plain words.
func TestSNMPTestRefusesBeforeSendingAnything(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	all := w.add(v2cInput("all", "s3cret-community"))
	only30 := w.add(v2cInput("only .30", "s3cret-community", "192.168.10.30"))
	for _, c := range []struct{ cred, ip, reason, words string }{
		{all.ID, "192.168.10.50", "not_in_inventory", "not a device in the inventory"},
		{all.ID, "192.168.10.21", "not_approved", "not approved yet"},
		{all.ID, "192.168.10.2", "box", "Vedette box itself"},
		{all.ID, "192.168.10.23", "regular_scan_never", "never be scanned"},
		{all.ID, "10.9.9.9", "out_of_scope", "outside the scan scope"},
		{only30.ID, "192.168.10.20", "not_for_this_credential", "outside the scope of this credential"},
	} {
		res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", c.cred, c.ip)
		if err != nil || res.OK || res.Reason != c.reason || !strings.Contains(res.Message, c.words) {
			t.Errorf("%s: %v %+v", c.ip, err, res)
		}
	}
	if _, err := w.svc.TestSNMP(t.Context(), "a", all.ID, "printer.local"); apiCode(err) != "bad_ip" {
		t.Errorf("a name: %v", err)
	}
	r.mu.Lock()
	r.health = "the scan worker has not reported for 90 seconds; SNMP reads cannot run until it does"
	r.mu.Unlock()
	if res, _ := w.svc.TestSNMP(t.Context(), "a", all.ID, "192.168.10.20"); res.Reason != "unavailable" || !strings.Contains(res.Message, "90 seconds") {
		t.Errorf("unavailable: %+v", res)
	}
	if n := len(r.sent()); n != 0 || w.count(`SELECT count(*) FROM sa_probe`) != 0 {
		t.Fatalf("%d jobs sent, %d probe rows", n, w.count(`SELECT count(*) FROM sa_probe`))
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_test'`); n != 7 {
		t.Errorf("%d audit rows of a test, want 7", n)
	}
}

// D-512: a Test of an approved device reads it, records what it said with source snmp, logs the probe before the job leaves and
// names the credential there, never its secret.
func TestSNMPTestReadsAndRecords(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("Core switches", "s3cret-community"))
	r.answer = func(ctx context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		var n int
		if err := w.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sa_probe WHERE shape = 'snmp' AND result = 'started'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("the probe row is not written before the job leaves (%d, %v)", n, err)
		}
		return juniperAnswers(j), nil
	}
	res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", c.ID, "192.168.10.20")
	if err != nil || !res.OK || res.DeviceID != "a-sw" || res.Answer == nil {
		t.Fatalf("%v %+v", err, res)
	}
	if a := res.Answer; a.Vendor != "Juniper Networks" || a.Model != "EX4200-48T" || a.OS != "JUNOS 15.1R7.9" || a.Kind != "switch" || a.Hostname != "SW-CORE-01" || a.Product != "Junos" {
		t.Errorf("answer %+v", a)
	}
	jobs := r.sent()
	if len(jobs) != 1 || jobs[0].Credentials[0].Community != "s3cret-community" || len(jobs[0].Targets) != 1 || jobs[0].Targets[0].IP != "192.168.10.20" {
		t.Fatalf("jobs %+v", jobs)
	}
	got := map[observe.Field]string{}
	for _, o := range w.sink.observations() {
		if o.Source != observe.SNMP || o.AssetHint.IP != netip.MustParseAddr("192.168.10.20") {
			t.Errorf("observation %+v", o)
		}
		got[o.Field] = o.Value
	}
	if got[observe.OS] != "JUNOS 15.1R7.9" || got[observe.Vendor] != "Juniper Networks" || got[observe.Model] != "EX4200-48T" || got[observe.Hostname] != "SW-CORE-01" || got[observe.Kind] != "switch" {
		t.Errorf("recorded %v", got)
	}
	if w.count(`SELECT count(*) FROM sa_probe WHERE shape = 'snmp' AND hosts = 1 AND targets = '192.168.10.20' AND result = 'ok: 1 of 1 answered' AND flags LIKE '%Core switches (v2c)%' AND flags NOT LIKE '%s3cret%'`) != 1 ||
		w.count(`SELECT count(*) FROM sa_job WHERE kind = 'snmp' AND reason = 'snmp_test' AND status = 'done'`) != 1 ||
		w.count(`SELECT count(*) FROM sa_snmp WHERE last_answer_at IS NOT NULL AND answered = 1`) != 1 {
		t.Fatal("probe row, job or the credential's last answer is missing")
	}
	// A wrong community: the device says nothing; the reason says the community may be wrong.
	r.answer = func(_ context.Context, j sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		return []sensorlink.SNMPAnswer{{Target: j.Targets[0].IP, Status: sensorlink.SNMPStatusNoAnswer}}, nil
	}
	res, err = w.svc.TestSNMP(t.Context(), "admin@example.com", c.ID, "192.168.10.20")
	if err != nil || res.OK || res.Reason != "no_answer" || !strings.Contains(res.Message, "community is wrong") {
		t.Fatalf("no answer: %v %+v", err, res)
	}
}

// D-512: once per window, after the sweep and the queue, every approved device of the scope that is not the box or set to never is
// read (a fragile printer too), with the credentials whose scope holds it, in order.
func TestSNMPRoundOncePerWindow(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	w.add(v2cInput("all", "community-1"))
	w.add(v2cInput("printers", "community-2", "192.168.10.24"))
	if err := w.svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs := r.sent()
	if len(jobs) != 1 {
		t.Fatalf("%d jobs", len(jobs))
	}
	var targets []string
	for _, tg := range jobs[0].Targets {
		targets = append(targets, tg.IP)
		if tg.IP == "192.168.10.24" && !slices.Equal(tg.Credentials, []int{0, 1}) || tg.IP == "192.168.10.20" && !slices.Equal(tg.Credentials, []int{0}) {
			t.Errorf("%s tries %v", tg.IP, tg.Credentials)
		}
	}
	if !slices.Equal(targets, []string{"192.168.10.20", "192.168.10.24"}) {
		t.Fatalf("targets %v", targets)
	}
	if err := w.svc.Tick(t.Context()); err != nil || len(r.sent()) != 1 {
		t.Fatalf("a second tick in the same window read again: %v, %d jobs", err, len(r.sent()))
	}
	if w.count(`SELECT count(*) FROM sa_job WHERE kind = 'snmp' AND reason = 'window' AND status = 'done' AND targets = 2`) != 1 {
		t.Fatal("no done round")
	}
}

// D-512 (INV-1): scanning turned off while a batch waits for the worker stops it; nothing is recorded.
func TestSNMPSettingsChangeStopsTheRead(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	r := &fakeReader{answer: func(ctx context.Context, _ sensorlink.SNMPJob) ([]sensorlink.SNMPAnswer, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("all", "community-1"))
	go func() {
		<-started
		w.inv.set(func(s *sa.Settings) { s.Enabled = false })
		_ = w.svc.SettingsChanged(context.Background())
	}()
	if _, err := w.svc.TestSNMP(t.Context(), "a", c.ID, "192.168.10.20"); apiCode(err) != "stopped" {
		t.Fatalf("%v", err)
	}
	if len(w.sink.observations()) != 0 || w.count(`SELECT count(*) FROM sa_probe WHERE result LIKE 'stopped%'`) != 1 {
		t.Fatal("recorded, or the probe row does not say stopped")
	}
}

// D-512 end to end: the Dispatcher, the mutual-TLS link and the real worker read fake agents (v2c and v3 authPriv); a wrong
// community is "no answer" with the plain reason.
func TestSNMPThroughTheWorker(t *testing.T) {
	t.Parallel()
	sw := &snmptest.Agent{Community: "s3cret-community", V3: &gosnmp.UsmSecurityParameters{UserName: "vedette", AuthenticationProtocol: gosnmp.SHA,
		AuthenticationPassphrase: "auth-pass-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "priv-pass-1"},
		Values: map[string]any{snmptest.SysDescr: junos, snmptest.SysObjectID: snmptest.Object(".1.3.6.1.4.1.2636.1.1.1.2.31"), snmptest.SysName: "SW-CORE-01"}}
	port := sw.Start(t)
	d := sa.NewDispatcher(sa.DispatcherOptions{Tick: 20 * time.Millisecond})
	link := linktest.New(t, activeBackend{d})
	wk, err := worker.New(worker.Config{Link: link.Client(t, sensorlink.Active), NmapPath: "/nonexistent/nmap", Version: "1.0.0", Wait: time.Second,
		SNMPTimeout: 50 * time.Millisecond, SNMPDial: func(netip.Addr) (string, uint16) { return "127.0.0.1", port }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = wk.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "the worker's heartbeat", func() bool { return d.SNMPHealth() == "" })

	w := newSNMPWorld(t, d)
	v2 := w.add(v2cInput("v2c", "s3cret-community"))
	v3 := w.add(sa.SNMPCredentialInput{Name: "v3", Version: "v3", Username: "vedette", Auth: "sha", AuthPassword: secrets.NewValue("auth-pass-1"), Priv: "aes128", PrivPassword: secrets.NewValue("priv-pass-1")})
	wrong := w.add(v2cInput("wrong", "not-the-community"))
	for _, id := range []string{v2.ID, v3.ID} {
		res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", id, "192.168.10.20")
		if err != nil || !res.OK || res.Answer == nil || res.Answer.OS != "JUNOS 15.1R7.9" || res.Answer.Model != "EX4200-48T" {
			t.Fatalf("%s: %v %+v", id, err, res)
		}
	}
	res, err := w.svc.TestSNMP(t.Context(), "admin@example.com", wrong.ID, "192.168.10.20")
	if err != nil || res.Reason != "no_answer" || !strings.Contains(res.Message, "community") {
		t.Fatalf("wrong community: %v %+v", err, res)
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
	job := sensorlink.SNMPJob{Rate: 10, Credentials: []sensorlink.SNMPCredential{{Version: "v2c", Community: "c"}}, Targets: []sensorlink.SNMPTarget{{IP: "192.168.10.20", Credentials: []int{0}}}}
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
	if len(rep.Jobs) != 1 || rep.Jobs[0].Kind != sensorlink.KindSNMP || rep.Jobs[0].SNMP.Credentials[0].Community != "c" {
		t.Fatalf("jobs %+v", rep.Jobs)
	}
	_ = d.JobResult(t.Context(), rep.Jobs[0].ID, &sensorlink.JobResult{Status: "done", SNMP: []sensorlink.SNMPAnswer{{Target: "192.168.10.99", Status: "ok"}}})
	if o := <-ch; !errors.Is(o.err, sa.ErrResultRejected) {
		t.Fatalf("an answer for another target: %+v", o)
	}
}
