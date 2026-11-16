package response_test

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/secrets"
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

// #847: the block list token is a box key (the box made it, nobody typed it). Sealed under another master key it is replaced, like
// every box key (#846): GET /response/blocklist answers a new address instead of a 500, the old address stops working, the new one
// works, and one audit row box-key.replace and one log line tell the administrator to paste the new address into the firewall. The
// next read keeps the new token: nothing is replaced again.
func TestRestoreWithoutKeyBlocklistTokenIsReplaced(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	old := tokenOf(v.URL)
	e.resealUnderOtherKey("response.blocklist.token")

	v, err = e.svc.Blocklist(e.ctx())
	if err != nil {
		t.Fatalf("GET /response/blocklist with a token the box cannot open: %v", err)
	}
	tok := tokenOf(v.URL)
	if len(tok) != 32 || tok == old || v.TokenLast4 != tok[28:] {
		t.Fatalf("view after the restore: %+v (old token %s)", v, old)
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), old, "203.0.113.1"); err == nil {
		t.Fatal("the old address still works")
	}
	if _, err := e.svc.FetchBlocklist(e.ctx(), tok, "203.0.113.2"); err != nil {
		t.Fatalf("the new address: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'box-key.replace' AND target = 'response.blocklist.token' AND user = 'system'`); n != 1 {
		t.Fatalf("audit rows box-key.replace: %d, want 1", n)
	}
	if !e.logHas("blocklist_token", "Paste the new address into your firewall") {
		t.Fatal("no log line tells the administrator to paste the new address")
	}
	if n := e.count(`SELECT count(*) FROM core_secret WHERE purpose = 'response.blocklist.token'`); n != 1 {
		t.Fatalf("%d token secrets, want the one new one (the unreadable one deleted)", n)
	}
	again, err := e.svc.Blocklist(e.ctx())
	e.must(err)
	if again.URL != v.URL || e.count(`SELECT count(*) FROM core_audit WHERE action = 'box-key.replace'`) != 1 {
		t.Fatalf("a second read replaced the token again: %s, was %s", again.URL, v.URL)
	}
	if strings.Contains(e.dumpAudit(), tok) {
		t.Fatal("the new token is in the audit log")
	}
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
