package main

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/conn"
)

func (s *stack) connCreate(in conn.Input) conn.Connection {
	s.t.Helper()
	var c conn.Connection
	err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) (err error) {
		c, err = s.d.Conn.Create(s.t.Context(), tx, "admin@acme.example", in)
		return err
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}

func connInput(name, secret string) conn.Input {
	sec := secret
	return conn.Input{Name: name, Kind: "http", Target: "https://192.168.10.1", AuthType: "token", Secret: &sec, Allow: []string{"https://192.168.10.1/api/"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "send_request", Enabled: true}}}
}

func flow12(s *stack) string {
	s.t.Helper()
	code, v := s.do("GET", "/core/privacy", "viewer", "")
	if code != 200 {
		s.t.Fatalf("privacy = %d %v", code, v)
	}
	for _, f := range v["flows"].([]any) {
		if m := f.(map[string]any); m["id"] == float64(12) {
			return m["state"].(string)
		}
	}
	s.t.Fatal("no flow 12")
	return ""
}

// The connection store in the real wiring (D-93): the Privacy page follows the enabled connections (flow 12), the response
// catalog lists them with the write tools that are on, and response's fingerprint is core/conn's.
func TestWiringConnections(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.setModule("notify", true)
	s.setModule("inventory", true)
	s.setModule("response", true)

	if got := flow12(s); got != "off" {
		t.Fatalf("flow 12 with no connection = %s", got)
	}
	c := s.connCreate(connInput("Office firewall", "tok-0123456789-abcdef"))
	if got := flow12(s); got != "on" {
		t.Errorf("flow 12 with an enabled connection = %s", got)
	}
	_, cat := s.do("GET", "/response/catalog", "admin", "")
	list, _ := cat["connections"].([]any)
	if len(list) != 1 {
		t.Fatalf("catalog connections = %v", cat["connections"])
	}
	got := list[0].(map[string]any)
	if got["id"] != c.ID || got["name"] != "Office firewall" || got["enabled"] != true || got["kind"] != "http" || got["read_only"] != false {
		t.Errorf("catalog connection = %v", got)
	}
	if w, _ := got["write_tools"].([]any); len(w) != 1 || w[0] != "send_request" {
		t.Errorf("write tools = %v", got["write_tools"])
	}
	// What the response module fingerprints is what core/conn says.
	infos, err := responseConnections{s.d.Conn}.List(t.Context())
	if err != nil || len(infos) != 1 || infos[0].Target != c.Target || infos[0].UpdatedAt != c.UpdatedAt {
		t.Fatalf("adapter = %+v %v", infos, err)
	}

	// Turning it off ends flow 12; the catalog still lists it, off.
	off := connInput("Office firewall", "")
	off.Secret, off.Enabled = nil, false
	if err := s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := s.d.Conn.Update(t.Context(), tx, "admin@acme.example", c.ID, off)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := flow12(s); got != "off" {
		t.Errorf("flow 12 with every connection off = %s", got)
	}

	// Delete is refused while response has a change in force on it (409 in_use), and goes through when it is rolled back.
	items := `[{"id":"it-1","connector_id":"` + c.ID + `","status":"executed"}]`
	err = s.d.DB.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO resp_actions (id, source, proposal_id, asset_name, title, risk, status, requested_at, expires_at, requires_approvals, items)
			VALUES ('act-1', 'rule', 'p-1', 'FW', 'Block', 'low', 'executed', '2026-11-09T10:00:00.000Z', '2026-11-10T10:00:00.000Z', 1, ?)`, items)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	del := func() error {
		return s.d.DB.Write(t.Context(), func(tx *sql.Tx) error { return s.d.Conn.Delete(t.Context(), tx, "admin@acme.example", c.ID) })
	}
	err = del()
	if ae, ok := apierr.As(err); !ok || ae.Status != 409 || ae.Code != "in_use" || !strings.Contains(ae.Message, "Office firewall") {
		t.Fatalf("delete with a change in force = %v", err)
	}
	s.exec(`UPDATE resp_actions SET items = REPLACE(items, '"executed"', '"rolled_back"'), status = 'rolled_back'`)
	if err := del(); err != nil {
		t.Fatalf("delete after the rollback: %v", err)
	}
	if n := s.count(`SELECT count(*) FROM core_connection`) + s.count(`SELECT count(*) FROM core_secret WHERE purpose = 'core_connection'`); n != 0 {
		t.Errorf("%d rows left", n)
	}
}

func (s *stack) exec(q string, args ...any) {
	s.t.Helper()
	if err := s.d.DB.Write(s.t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(s.t.Context(), q, args...); return err }); err != nil {
		s.t.Fatal(err)
	}
}
