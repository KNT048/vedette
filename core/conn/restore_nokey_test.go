package conn_test

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
)

// #847 (#812): after a backup is restored without its decryption key, a connection's credential is sealed under another master key.
// Test is 409 secret_lost with a sentence that says to enter it again, never a 500; nothing is sent to the device; the failure is saved
// like any other (status error, a connection.test audit row). Typing the credential again in Edit makes Test work.
func TestTestOfACredentialSealedUnderAnotherKeyIsSecretLost(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.httpTo(f, "http")
	ctx := t.Context()
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.env.DB.Write(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM core_connection WHERE id = ?`, c.ID).Scan(&id); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, id, "core_connection", []byte(secret1), true)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	_, err = r.test(c.ID)
	ae := want(t, err, 409, "secret_lost", "")
	for _, w := range []string{"was not restored", "restored without its decryption key, or the box key changed", "enter it again"} {
		if !strings.Contains(ae.Message, w) {
			t.Errorf("message %q does not say %q", ae.Message, w)
		}
	}
	if n := len(f.Requests()); n != 0 {
		t.Fatalf("%d requests reached the device without a credential", n)
	}
	if got := r.get(c.ID); got.Status != "error" || got.LastTest == nil {
		t.Fatalf("saved %+v: the failure must be on the card", got)
	}
	if a := r.auditTests(); len(a) != 1 || !strings.Contains(a[0], "failed: secret_lost") {
		t.Fatalf("audit %v", a)
	}

	// The administrator types the credential again: Test works.
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Secret: secrets.NewValue(secret1), Allow: c.Allow, Enabled: true}
	if _, err := r.update(c.ID, in); err != nil {
		t.Fatal(err)
	}
	if _, err := r.test(c.ID); err != nil {
		t.Fatalf("Test after the credential was typed again: %v", err)
	}
	if got := r.get(c.ID); got.Status != "ok" {
		t.Fatalf("status after the credential was typed again: %s", got.Status)
	}
}
