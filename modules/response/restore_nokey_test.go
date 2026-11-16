package response_test

import (
	"bytes"
	"database/sql"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/modules/response"
)

// resealUnderOtherKey seals every core_secret row of purpose again under another master key, as a backup restored without its
// decryption key leaves them (J7 #812, #847): the rows are there, this box's key opens none of them.
func (e *env) resealUnderOtherKey(purpose string) {
	e.t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	e.must(err)
	ctx := e.ctx()
	e.must(e.db.Write(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM core_secret WHERE purpose = ?`, purpose)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(ids) == 0 {
			e.t.Fatalf("no %s secret to reseal", purpose)
		}
		for _, id := range ids {
			if _, err := other.Replace(ctx, tx, id, purpose, bytes.Repeat([]byte{1}, 32), false); err != nil {
				return err
			}
		}
		return nil
	}))
}

// #847: a block list token sealed under another master key is never replaced on a read. GET /response/blocklist is 409 secret_lost
// with a sentence that says the firewall keeps its address and Regenerate makes a new one; the firewall's pull of the old address keeps
// working (only the token's hash is checked). Regenerate, the administrator's own act, replaces it: the old address stops, the new one
// works, with one WARN and one audit row box-key.replace by that administrator.
func TestRestoreWithoutKeyBlocklistTokenIsKeptUntilRegenerate(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	e := newEnv(t, func(c *response.Config) { c.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	old := tokenOf(v.URL)
	e.resealUnderOtherKey("response.blocklist.token")

	for range 2 {
		_, err = e.svc.Blocklist(e.ctx())
		ae := wantErr(t, err, 409, "secret_lost")
		for _, w := range []string{"could not be read on this box", "restored without the decryption key, or the box key changed", "Your firewall keeps using its current address", "Press Regenerate"} {
			if !strings.Contains(ae.Message, w) {
				t.Errorf("message %q does not say %q", ae.Message, w)
			}
		}
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), old, "203.0.113.1"); err != nil {
		t.Fatalf("the firewall's pull of the old address stopped working: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'box-key.replace'`); n != 0 || strings.Contains(logs.String(), "level=WARN") {
		t.Fatalf("a read replaced the token: %d audit rows, log %s", n, logs.String())
	}

	v, err = e.svc.RegenerateToken(e.ctx(), admin)
	e.must(err)
	tok := tokenOf(v.URL)
	if len(tok) != 32 || tok == old || v.TokenLast4 != tok[28:] {
		t.Fatalf("view after Regenerate: %+v (old token %s)", v, old)
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), old, "203.0.113.2"); err == nil {
		t.Fatal("the old address still works after Regenerate")
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), tok, "203.0.113.3"); err != nil {
		t.Fatalf("the new address: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'box-key.replace' AND target = 'response.blocklist.token' AND user = ?`, admin.Email); n != 1 {
		t.Fatalf("audit rows box-key.replace by the administrator: %d, want 1", n)
	}
	if strings.Count(logs.String(), "level=WARN") != 1 {
		t.Fatalf("want one WARN, log:\n%s", logs.String())
	}
	if n := e.count(`SELECT count(*) FROM core_secret WHERE purpose = 'response.blocklist.token'`); n != 1 {
		t.Fatalf("%d token secrets, want the one new one (the unreadable one deleted)", n)
	}
	// A plain Regenerate of a token the box can open is not a box key replacement.
	_, err = e.svc.RegenerateToken(e.ctx(), admin)
	e.must(err)
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'box-key.replace'`); n != 1 {
		t.Fatalf("a normal Regenerate wrote box-key.replace: %d rows", n)
	}
	if strings.Contains(e.dumpAudit(), tok) || strings.Contains(logs.String(), tok) {
		t.Fatal("the token is in the audit log or the log")
	}
}

func wantErr(t *testing.T, err error, status int, code string) *apierr.Error {
	t.Helper()
	ae, ok := apierr.As(err)
	if !ok || ae.Status != status || ae.Code != code {
		t.Fatalf("error = %v, want %d %s", err, status, code)
	}
	return ae
}

func (e *env) dumpAudit() string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT ifnull(target, '') || ' ' || ifnull(detail, '') FROM core_audit`)
	e.must(err)
	defer func() { _ = rows.Close() }()
	var b strings.Builder
	for rows.Next() {
		var s string
		e.must(rows.Scan(&s))
		b.WriteString(s + "\n")
	}
	e.must(rows.Err())
	return b.String()
}
