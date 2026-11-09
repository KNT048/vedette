package response_test

import (
	"context"
	"database/sql"
	"strconv"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/response"
)

// realConns is what cmd/vedette gives response (responseConnections): the connections of core/conn, not a fake list.
type realConns struct{ svc *conn.Service }

func (r *realConns) List(ctx context.Context) ([]response.ConnectionInfo, error) {
	list, err := r.svc.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]response.ConnectionInfo, len(list))
	for i, c := range list {
		out[i] = response.ConnectionInfo{Connection: response.Connection{ID: c.ID, Name: c.Name, Enabled: c.Enabled, Kind: c.Kind, WriteTools: conn.WriteTools(c)}, Target: c.Target, UpdatedAt: c.UpdatedAt}
	}
	return out, nil
}

// The fingerprint of a request is conn.Fingerprint (the shared vector), so editing the secret of a connection after the request was
// made is 409 connection_changed on approve (INV-9), while editing only its name or its status is not.
func TestContract_INV9_EditingTheSecretAfterTheRequestIsConnectionChanged(t *testing.T) {
	late := &realConns{}
	e := newEnv(t, func(c *response.Config) { c.Connections = late })
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	e.must(err)
	late.svc, err = conn.New(conn.Config{DB: e.db, Secrets: sec, Audit: audit.New(e.clock.Now), Clock: e.clock.Now})
	e.must(err)
	tok := "tok-0123456789-abcdef"
	in := conn.Input{Name: "Office firewall", Kind: "http", Target: "https://fw.lan", AuthType: "token", Secret: secrets.NewValue(tok), Allow: []string{"https://fw.lan/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
	var c conn.Connection
	e.must(e.db.Write(e.ctx(), func(tx *sql.Tx) (err error) { c, err = late.svc.Create(e.ctx(), tx, "admin@acme.example", in); return }))
	update := func(f func(in *conn.Input)) {
		e.t.Helper()
		next := in
		next.Secret = secrets.Value{}
		f(&next)
		e.must(e.db.Write(e.ctx(), func(tx *sql.Tx) error {
			_, err := late.svc.Update(e.ctx(), tx, "admin@acme.example", c.ID, next)
			return err
		}))
	}

	cid, enabled := c.ID, true
	_, err = e.svc.ChangeAction(e.ctx(), admin, "fgt_ban_ip", response.CatalogUpdate{ConnectionID: &cid, Enabled: &enabled, Present: map[string]bool{"connection_id": true, "enabled": true}})
	e.must(err)
	e.turnOn()
	e.rule("Ban", "ioc_connection", []response.RuleAction{{ActionID: "fgt_ban_ip", Params: map[string]string{"ip": "{{trigger.dest_ip}}"}, TTLMin: intp(60)}}, nil)
	e.fire(e.iocEvent("e1", "198.51.100.7"))
	e.fire(e.iocEvent("e2", "198.51.100.8"))
	l := e.actions()
	if len(l) != 2 {
		t.Fatalf("%d requests, want 2", len(l))
	}

	// The name and the status are not what a request depends on.
	update(func(in *conn.Input) { in.Name = "Office firewall (HQ)" })
	e.exec1(`UPDATE core_connection SET status = 'ok', last_test = '2026-11-09T09:00:00.000Z'`)
	_, err = e.svc.Approve(e.ctx(), oper, l[1].ID, nil, "")
	e.must(err)

	// A new secret is another version of the connection: nothing is sent.
	newTok := "tok-9876543210-zyxwvu"
	update(func(in *conn.Input) { in.Name = "Office firewall (HQ)"; in.Secret = secrets.NewValue(newTok) })
	before := e.exec.count()
	_, err = e.svc.Approve(e.ctx(), oper, l[0].ID, nil, "")
	wantCode(t, err, 409, "connection_changed")
	if e.exec.count() != before {
		t.Fatal("a step was sent to a connection whose secret changed after the request")
	}
}

// ChangesInForce (what core/conn asks before it deletes a connection, D-93): an item that was executed and not rolled back, or
// that was sent and whose outcome is not known; not a pending one, a failed one, a rolled back one, or another connection's.
func TestChangesInForce(t *testing.T) {
	e := newEnv(t)
	add := func(n int, item string) {
		e.t.Helper()
		e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES (?, 'rule', 'p', 'FW', 'Block', 'low', 'approved', '2026-11-09T10:00:00.000Z', '2026-11-10T10:00:00.000Z', 1, ?)`, "act-"+strconv.Itoa(n), "["+item+"]")
	}
	inForce := func(id string) bool {
		e.t.Helper()
		v, err := e.svc.ChangesInForce(e.ctx(), id)
		e.must(err)
		return v
	}
	if inForce("cn-1") {
		t.Fatal("a change in force with no request at all")
	}
	add(0, `{"id":"i","connector_id":"cn-1","status":"pending"}`)
	add(1, `{"id":"i","connector_id":"cn-1","status":"failed"}`)
	add(2, `{"id":"i","connector_id":"cn-1","status":"rolled_back"}`)
	add(3, `{"id":"i","connector_id":null,"status":"executed"}`)
	add(4, `{"id":"i","connector_id":"cn-2","status":"executed"}`)
	if inForce("cn-1") {
		t.Fatal("a pending, failed, rolled back or box item counts as a change in force")
	}
	if !inForce("cn-2") {
		t.Fatal("an executed item does not count")
	}
	add(5, `{"id":"i","connector_id":"cn-1","status":"pending","running_at":"2026-11-09T10:00:00.000Z"}`)
	if !inForce("cn-1") {
		t.Fatal("an item that was sent, with no known outcome, does not count")
	}
}

// A step that was sent and not answered in time is recorded as failed with "State unknown", but its change may be in force: the
// item carries an explicit flag (not the text) and ChangesInForce counts it, so core/conn does not delete the connection while the
// late result of the step can still arrive and turn the item into an executed change on it.
func TestChangesInForceCountsAnItemWhoseOutcomeIsUnknown(t *testing.T) {
	var se *slowExec
	e, _, id := banEnv(t, func(c *response.Config) {
		se = &slowExec{fakeExecutor: &fakeExecutor{}}
		c.Executor = se
	})
	var during bool
	var derr error
	se.inFlight = func() {
		e.clock.Advance(5 * time.Minute)
		if err := e.svc.SweepStuckForTest(context.Background()); err != nil {
			t.Error(err)
		}
		during, derr = e.svc.ChangesInForce(context.Background(), "cn-fw")
	}
	got, err := e.svc.Approve(e.ctx(), oper, id, nil, "")
	e.must(err)
	e.must(derr)
	it := got.Items[0]
	if it.Status != response.ItemExecuted {
		t.Fatalf("the late result did not correct the sweep (item %s %q)", it.Status, resultOf(it))
	}
	if !during {
		t.Error("while the step was in flight and recorded as state unknown, ChangesInForce was false: the connection could be deleted under it")
	}
	// The late result cleared the flag; the item is executed now, which counts by itself.
	if n := e.count(`SELECT COUNT(*) FROM resp_actions WHERE items LIKE '%"state_unknown":true%'`); n != 0 {
		t.Errorf("%d requests still carry the state-unknown flag after the late result", n)
	}
	if v, err := e.svc.ChangesInForce(e.ctx(), "cn-fw"); err != nil || !v {
		t.Errorf("an executed item after the correction: %v %v", v, err)
	}

	// The record alone: the flag counts, the text of a result does not.
	insert := func(id, items string) {
		e.exec1(`INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES (?, 'rule', 'p', 'FW', 'Block', 'low', 'failed', '2026-11-09T10:00:00.000Z', '2026-11-10T10:00:00.000Z', 1, ?)`, id, items)
	}
	insert("act-flag", `[{"id":"i","connector_id":"cn-flagged","status":"failed","state_unknown":true,"result":"x"}]`)
	insert("act-text", `[{"id":"i","connector_id":"cn-texty","status":"failed","result":"The connection did not answer in time. State unknown: check the device."}]`)
	if v, _ := e.svc.ChangesInForce(e.ctx(), "cn-flagged"); !v {
		t.Error("a failed item with the state-unknown flag is not a change in force")
	}
	if v, _ := e.svc.ChangesInForce(e.ctx(), "cn-texty"); v {
		t.Error("the words of a result decide whether a change is in force; only the flag may")
	}
}
