package response_test

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/response"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakeUsers struct{ m map[string]response.User }

func (f *fakeUsers) Lookup(_ context.Context, id string) (response.User, bool, error) {
	u, ok := f.m[id]
	return u, ok, nil
}

type fakeNotifier struct {
	mu        sync.Mutex
	chs       []response.NotifyChannel
	msgs      []string
	fail      bool
	approvers map[string][]response.Approver // by channel type
	asked     []response.ApprovalMessage     // every RequestApproval call
	sendSent  []string                       // what RequestApproval answers
	sendErr   error                          // and the error it answers
	onSend    func()                         // runs inside RequestApproval (what is open while a send runs)
	block     chan struct{}                  // RequestApproval waits for it to close (or for its context to end)
}

func (f *fakeNotifier) Approvers(_ context.Context, ch string) ([]response.Approver, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approvers[ch], nil
}

func (f *fakeNotifier) RequestApproval(ctx context.Context, m response.ApprovalMessage) ([]string, error) {
	f.mu.Lock()
	f.asked = append(f.asked, m)
	hook, sent, err, block := f.onSend, f.sendSent, f.sendErr, f.block
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	if block != nil { // a mail server that does not answer: wait until released, or until the budget or the shutdown ends the context
		select {
		case <-block:
		case <-ctx.Done():
			return sent, ctx.Err()
		}
	}
	return sent, err
}

func (f *fakeNotifier) requests() []response.ApprovalMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

func (f *fakeNotifier) Channels(context.Context) ([]response.NotifyChannel, error) { return f.chs, nil }
func (f *fakeNotifier) Message(_ context.Context, id, title, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("notify is off")
	}
	f.msgs = append(f.msgs, id+"|"+title+"|"+text)
	return nil
}

type fakeDirectory struct {
	devices   map[string]response.DeviceInfo
	findings  map[string]response.FindingInfo
	listErr   error // DevicesOfKind fails with it
	deviceErr error // Device fails with it
}

func (f *fakeDirectory) DevicesOfKind(_ context.Context, kinds ...string) ([]response.DeviceInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []response.DeviceInfo
	for _, d := range f.devices {
		for _, k := range kinds {
			if d.Kind == k {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

func (f *fakeDirectory) Device(_ context.Context, id string) (response.DeviceInfo, bool, error) {
	if f.deviceErr != nil {
		return response.DeviceInfo{}, false, f.deviceErr
	}
	d, ok := f.devices[id]
	return d, ok, nil
}
func (f *fakeDirectory) Finding(_ context.Context, id string) (response.FindingInfo, bool, error) {
	d, ok := f.findings[id]
	return d, ok, nil
}

type fakeConns struct{ list []response.ConnectionInfo }

func (f *fakeConns) List(context.Context) ([]response.ConnectionInfo, error) { return f.list, nil }

// fakeExecutor records every step it is asked to carry out; it never talks to a network. A check before answers "all clear" (pre), the
// read-back after a run holds present and after an undo does not; a read before any run (D-356) does not hold it either (after, when set).
// status[phase] and err make a phase fail; status["readback"] makes only a verify after a run fail, not the read before the run.
type fakeExecutor struct {
	mu      sync.Mutex
	steps   []response.DeviceStep
	err     error
	status  map[string]response.StepStatus // by phase; unset = ok
	pre     string                         // output of the check before; "" = "all clear"
	present string                         // output of the read-back after a run (what the read-back is looked at for)
	after   string                         // output of the read-back after an undo (a device that still shows the change holds the text here)
	last    string                         // the last write phase seen
	hold    chan struct{}                  // a "run" step waits for it to close (or for its context to end): a device that is slow to answer
}

func (f *fakeExecutor) Execute(ctx context.Context, s response.DeviceStep) (response.DeviceResult, error) {
	f.mu.Lock()
	hold := f.hold
	f.mu.Unlock()
	if hold != nil && s.Phase == "run" {
		select {
		case <-hold:
		case <-ctx.Done():
			return response.DeviceResult{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, s)
	if f.err != nil {
		return response.DeviceResult{}, f.err
	}
	r := response.DeviceResult{Status: response.StepOK, Detail: s.Phase + " done"}
	if s.Phase == "run" || s.Phase == "rollback" {
		f.last = s.Phase
	}
	if st, ok := f.status["readback"]; ok && s.Phase == "verify" && f.last == "run" {
		r.Status = st
		return r, nil
	}
	if st, ok := f.status[s.Phase]; ok {
		r.Status = st
		return r, nil
	}
	switch s.Phase {
	case "precheck":
		r.Output = "all clear"
		if f.pre != "" {
			r.Output = f.pre
		}
	case "run", "rollback":
		f.last = s.Phase
	case "verify":
		if f.last == "run" {
			r.Output = f.present
		} else {
			r.Output = "nothing of the kind is listed" // a device that answers, and the text is not in it
			if f.after != "" {
				r.Output = f.after
			}
		}
	}
	return r, nil
}
func (f *fakeExecutor) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.steps) }

// runStep is the first run step sent (the read before it comes first, D-356).
func (f *fakeExecutor) runStep() response.DeviceStep {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.steps {
		if s.Phase == "run" {
			return s
		}
	}
	return response.DeviceStep{}
}
func (f *fakeExecutor) phases() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, s := range f.steps {
		out = append(out, s.Phase)
	}
	return out
}

type fakeWebhooks struct {
	t  response.WebhookTarget
	ok bool
}

func (f *fakeWebhooks) Target(context.Context) (response.WebhookTarget, bool, error) {
	return f.t, f.ok, nil
}

type env struct {
	t     *testing.T
	cfg   response.Config
	db    *store.DB
	svc   *response.Service
	clock *fakeClock
	users *fakeUsers
	note  *fakeNotifier
	dir   *fakeDirectory
	conns *fakeConns
	exec  *fakeExecutor
	hooks *fakeWebhooks
	bus   *events.Bus
	seen  *seenEvents
}

type seenEvents struct {
	mu    sync.Mutex
	names []string
}

func (s *seenEvents) count(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, x := range s.names {
		if x == name {
			n++
		}
	}
	return n
}

var (
	admin = response.Actor{ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Via: response.ViaApp}
	oper  = response.Actor{ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Via: response.ViaApp}
	oper2 = response.Actor{ID: "u-op2", Name: "IT Operator Two", Email: "it2@acme.example", Via: response.ViaApp}
)

const riskPhrase = "I ACCEPT THE RISK"

func (e *env) ctx() context.Context { return e.t.Context() }

func newEnv(t *testing.T, opts ...func(*response.Config)) *env {
	t.Helper()
	db := storetest.New(t)
	ctx := t.Context()
	if err := store.Migrate(ctx, db, "core", core.Migrations); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "response", response.Migrations); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, db: db, clock: &fakeClock{t: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)}, note: &fakeNotifier{}, exec: &fakeExecutor{}, hooks: &fakeWebhooks{}, seen: &seenEvents{},
		dir:   &fakeDirectory{devices: map[string]response.DeviceInfo{}, findings: map[string]response.FindingInfo{}},
		conns: &fakeConns{},
		users: &fakeUsers{m: map[string]response.User{
			"u-admin":  {ID: "u-admin", Name: "Admin", Email: "admin@acme.example", Role: "admin", TwoStep: true},
			"u-admin2": {ID: "u-admin2", Name: "Admin Two", Email: "admin2@acme.example", Role: "admin", TwoStep: true},
			"u-nofa":   {ID: "u-nofa", Name: "No 2FA", Email: "nofa@acme.example", Role: "admin"},
			"u-op":     {ID: "u-op", Name: "IT Operator", Email: "it@acme.example", Role: "operator", TwoStep: true},
			"u-op2":    {ID: "u-op2", Name: "IT Operator Two", Email: "it2@acme.example", Role: "operator", TwoStep: true},
		}}}
	log := slog.New(slog.DiscardHandler)
	e.bus = events.NewBus(log)
	for _, n := range []string{response.EventRequestCreated, response.EventDecisionMade, response.EventActionExecuted, response.EventActionRolledBack, response.EventBreakerTripped} {
		e.bus.Subscribe(n, func(_ context.Context, ev events.Event) error {
			e.seen.mu.Lock()
			e.seen.names = append(e.seen.names, ev.Name)
			e.seen.mu.Unlock()
			return nil
		})
	}
	cfg := response.Config{DB: db, Secrets: sec, Audit: audit.New(e.clock.Now), Users: e.users, Log: log, Bus: e.bus, Directory: e.dir, Notifier: e.note, Connections: e.conns,
		Executor: e.exec, Webhooks: e.hooks, Clock: e.clock.Now, BaseURL: "https://box.example:8443"}
	for _, o := range opts {
		o(&cfg)
	}
	e.cfg = cfg
	e.svc, err = response.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Registered after storetest.New, so it runs first: background sends and detached runs finish before the
	// database closes and t.TempDir is removed ("TempDir RemoveAll cleanup: directory not empty" otherwise).
	svc := e.svc
	t.Cleanup(svc.Close)
	return e
}

func apiCode(err error) (int, string) {
	if ae, ok := apierr.As(err); ok {
		return ae.Status, ae.Code
	}
	return 0, ""
}

func wantCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	if s, c := apiCode(err); s != status || c != code {
		t.Fatalf("error = %v (%d %s), want %d %s", err, s, c, status, code)
	}
}

func (e *env) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.Reader().QueryRowContext(e.ctx(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) exec1(q string, args ...any) {
	e.t.Helper()
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error { _, err := tx.ExecContext(e.ctx(), q, args...); return err }); err != nil {
		e.t.Fatal(err)
	}
}

// logHas reports whether a resp_log line of the kind exists whose detail holds text.
func (e *env) logHas(kind, text string) bool {
	return e.count(`SELECT COUNT(*) FROM resp_log WHERE kind = ? AND detail LIKE '%' || ? || '%'`, kind, text) > 0
}

func (e *env) turnOn() {
	e.t.Helper()
	if _, err := e.svc.SetExecution(e.ctx(), admin, true, riskPhrase); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) settings() response.Settings {
	e.t.Helper()
	v, err := e.svc.Settings(e.ctx())
	e.must(err)
	return v.Settings
}

func (e *env) saveSettings(f func(in *response.SettingsInput)) {
	e.t.Helper()
	st := e.settings()
	in := response.SettingsInput{MaxPerHour: st.MaxPerHour, ExpiryMin: st.ExpiryMin, ApprovalChannels: st.ApprovalChannels, BreakerMaxPerHour: st.BreakerMaxPerHour, MultiTargetMax: st.MultiTargetMax, Maintenance: st.Maintenance}
	in.AI.Triggers, in.AI.BudgetHour, in.AI.BudgetDay = st.AI.Triggers, st.AI.BudgetHour, st.AI.BudgetDay
	f(&in)
	if _, err := e.svc.SaveSettings(e.ctx(), admin, in); err != nil {
		e.t.Fatal(err)
	}
}

func intp(n int) *int { return &n }

// iocRule is a rule that blocks the destination of a known-bad connection.
func (e *env) rule(name, trigger string, actions []response.RuleAction, f func(in *response.RuleInput)) response.Rule {
	e.t.Helper()
	in := response.RuleInput{Name: name, Enabled: true, Live: true, Trigger: trigger, Match: "all", Conditions: []response.Condition{}, Actions: actions, MaxPerHour: 10}
	if f != nil {
		f(&in)
	}
	r, err := e.svc.AddRule(e.ctx(), admin, in)
	e.must(err)
	if in.Live { // a new rule is dry run; go live like an admin would
		in.Live = true
		r, err = e.svc.ChangeRule(e.ctx(), admin, r.ID, in)
		e.must(err)
	}
	return r
}

func blockAction(ttl int) []response.RuleAction {
	return []response.RuleAction{{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(ttl)}}
}

func (e *env) iocEvent(id, destIP string) response.Det {
	return response.Det{ID: id, Trigger: "ioc_connection", TS: store.FormatTS(e.clock.Now()), Summary: "PC-SALES-02 connected to " + destIP,
		Fields: map[string]string{"src_ip": "192.168.10.105", "device": "PC-SALES-02", "dest": destIP, "dest_kind": "ip", "dest_ip": destIP, "dest_domain": "", "feeds": "IPsum", "confidence": "0.92", "switch_port": ""}}
}

// fire stores an event, evaluates it and waits for the approval requests it sent in the background, so a test that reads
// resp_log afterwards sees every line the run will write.
func (e *env) fire(d response.Det) response.RunSummary {
	e.t.Helper()
	sum := e.fireNoWait(d)
	e.svc.WaitSendsForTest()
	return sum
}

// fireNoWait is fire without waiting for the background sends (tests of the send queue itself).
func (e *env) fireNoWait(d response.Det) response.RunSummary {
	e.t.Helper()
	e.must(e.svc.StoreEvent(e.ctx(), d))
	sum, err := e.svc.Evaluate(e.ctx())
	e.must(err)
	return sum
}

func (e *env) actions() []response.ActionRequest {
	e.t.Helper()
	l, err := e.svc.Actions(e.ctx())
	e.must(err)
	return l
}

func (e *env) only() response.ActionRequest {
	e.t.Helper()
	l := e.actions()
	if len(l) != 1 {
		e.t.Fatalf("%d requests, want 1", len(l))
	}
	return l[0]
}

func hasKind(l []response.LogEntry, kind string) bool {
	for _, x := range l {
		if x.Kind == kind {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// firewall adds an HTTP connection with one write tool and binds a built-in device action to it.
func (e *env) firewall(actionID string) {
	e.t.Helper()
	e.conns.list = []response.ConnectionInfo{{Connection: response.Connection{ID: "cn-fw", Name: "Office firewall", Enabled: true, Kind: "http", WriteTools: []string{"write", "block_address", "disable_virtual_ip", "disable_firewall_policy"}}, Target: "https://fw.lan"}}
	cid, enabled := "cn-fw", true
	_, err := e.svc.ChangeAction(e.ctx(), admin, actionID, response.CatalogUpdate{ConnectionID: &cid, Enabled: &enabled, Present: map[string]bool{"connection_id": true, "enabled": true}})
	e.must(err)
}

type netipAddr = netip.Addr

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func hasEntry(l []response.AllowEntry, v string) bool {
	for _, e := range l {
		if e.Value == v {
			return true
		}
	}
	return false
}

func mustRules(e *env) []response.Rule {
	e.t.Helper()
	l, err := e.svc.Rules(e.ctx())
	e.must(err)
	return l
}

func (e *env) trap(id, src string) response.Det {
	return response.Det{ID: id, Trigger: "honeypot", TS: store.FormatTS(e.clock.Now()), Summary: "PC-HR-01 touched a trap from " + src,
		Fields: map[string]string{"source_ip": src, "source_device": "PC-HR-01", "decoy": "FILESRV-OLD", "kind": "service", "switch_port": "Gi1/0/12"}}
}

func twoBlocks() []response.RuleAction {
	return []response.RuleAction{
		{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)},
		{ActionID: "blocklist_add", Params: map[string]string{"ip": "{{trigger.src_ip}}"}, TTLMin: intp(60)},
	}
}
func strp(s string) *string { return &s }

// linkAll records a proof (D-191) for every approver the fake notifier lists now, as if each had linked in My account. A test about
// something else than the proof calls it after it sets the lists.
func (e *env) linkAll() {
	e.t.Helper()
	e.note.mu.Lock()
	lists := maps.Clone(e.note.approvers)
	e.note.mu.Unlock()
	for ch, list := range lists {
		for _, a := range list {
			if err := e.svc.LinkForTest(e.ctx(), a.UserID, ch, a.Address); err != nil {
				e.t.Fatal(err)
			}
		}
	}
}
