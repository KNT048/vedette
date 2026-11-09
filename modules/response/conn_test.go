package response_test

import (
	"context"
	"database/sql"
	"strconv"
	"testing"

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
	in := conn.Input{Name: "Office firewall", Kind: "http", Target: "https://fw.lan", AuthType: "token", Secret: &tok, Allow: []string{"https://fw.lan/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
	var c conn.Connection
	e.must(e.db.Write(e.ctx(), func(tx *sql.Tx) (err error) { c, err = late.svc.Create(e.ctx(), tx, "admin@acme.example", in); return }))
	update := func(f func(in *conn.Input)) {
		e.t.Helper()
		next := in
		next.Secret = nil
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
	update(func(in *conn.Input) { in.Name = "Office firewall (HQ)"; in.Secret = &newTok })
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
