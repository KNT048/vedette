package sensoractive_test

import (
	"bytes"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/secrets"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// #868 (J7): a credential whose saved secret is sealed under another master key (a backup restored without its decryption key, or the
// box key changed) is sent nowhere: Test and Read now answer 409 secret_lost, the window's round skips it and reads with the others,
// the list says it needs typing again, and an edit that types it again fixes it.

// loseSecret seals the saved secret of credential id (column secret_id or priv_secret_id) again under another master key, as a
// restore without the key leaves it.
func (w *snmpWorld) loseSecret(id, column string) {
	w.t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		w.t.Fatal(err)
	}
	ctx := w.t.Context()
	err = w.db.Write(ctx, func(tx *sql.Tx) error {
		var sid, purpose string
		if err := tx.QueryRowContext(ctx, `SELECT s.id, s.purpose FROM sa_snmp c JOIN core_secret s ON s.id = c.`+column+` WHERE c.id = ?`, id).Scan(&sid, &purpose); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, sid, purpose, []byte("sealed-elsewhere"), true)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// lostOf is the SecretLost of each listed credential, by name.
func (w *snmpWorld) lostOf() map[string]bool {
	w.t.Helper()
	list, err := w.svc.SNMPCredentials(w.t.Context())
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[string]bool{}
	for _, c := range list {
		out[c.Name] = c.SecretLost
	}
	return out
}

func wantLost(t *testing.T, what string, err error) {
	t.Helper()
	var e *apierr.Error
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "secret_lost" || !strings.Contains(e.Message, "not restored") || !strings.Contains(strings.ToLower(e.Message), "enter it again") {
		t.Fatalf("%s: want 409 secret_lost in plain words, got %v", what, err)
	}
}

func TestSNMPTestAndReadNowWithASecretNotRestoredSendNothing(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	lost := w.add(v2cInput("Core switches", "s3cret-community"))
	ok := w.add(v2cInput("Printers", "community-2"))
	v3 := w.add(sa.SNMPCredentialInput{Name: "v3 priv", Version: "v3", Username: "ro", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-1"),
		Priv: "aes128", PrivPassword: secrets.NewValue("priv-pass-1"), Scope: []string{worldScope}})
	w.loseSecret(lost.ID, "secret_id")
	w.loseSecret(v3.ID, "priv_secret_id") // only the privacy password: the credential cannot be sent either
	if got := w.lostOf(); !got["Core switches"] || got["Printers"] || !got["v3 priv"] {
		t.Fatalf("lost %v", got)
	}
	for _, id := range []string{lost.ID, v3.ID} {
		_, err := w.svc.TestSNMP(ctx, "admin@example.com", id, "192.168.10.20")
		wantLost(t, "Test", err)
		_, err = w.svc.ReadSNMP(ctx, "admin@example.com", id)
		wantLost(t, "Read now", err)
	}
	if len(r.sent()) != 0 || w.count(`SELECT count(*) FROM sa_probe`) != 0 || w.count(`SELECT count(*) FROM sa_job`) != 0 {
		t.Fatalf("something was sent or started: %d jobs to the worker", len(r.sent()))
	}
	// The others still work.
	if res, err := w.svc.TestSNMP(ctx, "admin@example.com", ok.ID, "192.168.10.20"); err != nil || !res.OK {
		t.Fatalf("the other credential: %v %+v", err, res)
	}
}

func TestSNMPRoundSkipsACredentialWhoseSecretWasNotRestored(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	w.add(v2cInput("all", "community-1"))
	lost := w.add(v2cInput("printers", "community-2", "192.168.10.24"))
	w.loseSecret(lost.ID, "secret_id")
	if err := w.svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	jobs := r.sent()
	if len(jobs) != 1 || len(jobs[0].Credentials) != 1 || jobs[0].Credentials[0].Community != "community-1" {
		t.Fatalf("jobs %+v", jobs)
	}
	for _, tg := range jobs[0].Targets {
		if names := credNames(jobs[0].Credentials, tg.Credentials); !slices.Equal(names, []string{"community-1"}) {
			t.Errorf("%s tries %v", tg.IP, names)
		}
	}
	if w.count(`SELECT count(*) FROM sa_job WHERE kind = 'snmp' AND reason = 'window' AND status = 'done' AND targets = 2`) != 1 {
		t.Fatal("no done round")
	}
}

func TestSNMPRoundWithEveryCredentialLostStartsNothingUntilOneIsTypedAgain(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	lost := w.add(v2cInput("all", "community-1"))
	w.loseSecret(lost.ID, "secret_id")
	if err := w.svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(r.sent()) != 0 || w.count(`SELECT count(*) FROM sa_job WHERE kind = 'snmp'`) != 0 {
		t.Fatalf("a round with no usable credential: %d jobs", len(r.sent()))
	}
	// Typed again: the same window reads with it.
	if _, err := w.svc.EditSNMP(t.Context(), "admin@example.com", lost.ID, v2cInput("all", "community-new")); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if jobs := r.sent(); len(jobs) != 1 || jobs[0].Credentials[0].Community != "community-new" {
		t.Fatalf("jobs %+v", jobs)
	}
}

func TestSNMPEditWithTheSecretTypedAgainFixesALostCredential(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	c := w.add(v2cInput("Core switches", "s3cret-community"))
	w.loseSecret(c.ID, "secret_id")
	// A blank community would keep the one that cannot be opened: refused, nothing saved.
	_, err := w.svc.EditSNMP(ctx, "admin@example.com", c.ID, v2cInput("Renamed", ""))
	wantLost(t, "Edit keeping the lost community", err)
	if got := w.lostOf(); !got["Core switches"] {
		t.Fatalf("after a refused edit %v", got)
	}
	e, err := w.svc.EditSNMP(ctx, "admin@example.com", c.ID, v2cInput("Core switches", "n3w-community"))
	if err != nil || e.SecretLost || e.SecretLast4 != "nity" {
		t.Fatalf("typed again: %v %+v", err, e)
	}
	if got := w.lostOf(); got["Core switches"] {
		t.Fatalf("still lost after the edit %v", got)
	}
	res, err := w.svc.TestSNMP(ctx, "admin@example.com", c.ID, "192.168.10.20")
	if err != nil || !res.OK {
		t.Fatalf("Test after the edit: %v %+v", err, res)
	}
	if jobs := r.sent(); len(jobs) != 1 || jobs[0].Credentials[0].Community != "n3w-community" {
		t.Fatalf("jobs %+v", jobs)
	}

	// v3 with its privacy password lost: typing only the authentication password still keeps the lost one; typing both fixes it.
	v3in := sa.SNMPCredentialInput{Name: "v3", Version: "v3", Username: "ro", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-1"),
		Priv: "aes128", PrivPassword: secrets.NewValue("priv-pass-1"), Scope: []string{worldScope}}
	v3 := w.add(v3in)
	w.loseSecret(v3.ID, "priv_secret_id")
	v3in.PrivPassword = secrets.NewValue("")
	_, err = w.svc.EditSNMP(ctx, "admin@example.com", v3.ID, v3in)
	wantLost(t, "Edit keeping the lost privacy password", err)
	v3in.PrivPassword = secrets.NewValue("priv-pass-2")
	if _, err := w.svc.EditSNMP(ctx, "admin@example.com", v3.ID, v3in); err != nil {
		t.Fatal(err)
	}
	if got := w.lostOf(); got["v3"] {
		t.Fatalf("v3 still lost %v", got)
	}
	// Choosing no privacy drops the lost password: nothing left to open.
	w.loseSecret(v3.ID, "priv_secret_id")
	v3in.Priv, v3in.AuthPassword, v3in.PrivPassword = "none", secrets.NewValue(""), secrets.NewValue("")
	if _, err := w.svc.EditSNMP(ctx, "admin@example.com", v3.ID, v3in); err != nil {
		t.Fatal(err)
	}
	if got := w.lostOf(); got["v3"] {
		t.Fatalf("v3 without privacy still lost %v", got)
	}
}

// A secret lost after Test's own check (between the check and the job) is still never sent: the job is not built, the probe row says
// why, and the Test answers 409 secret_lost (review r1 L3).
func TestSNMPASecretLostRightBeforeTheJobIsNeverSent(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	c := w.add(v2cInput("Core switches", "s3cret-community"))
	sa.SetBeforeSNMPBatch(w.svc, func() { w.loseSecret(c.ID, "secret_id") })
	_, err := w.svc.TestSNMP(t.Context(), "admin@example.com", c.ID, "192.168.10.20")
	wantLost(t, "Test", err)
	if len(r.sent()) != 0 || w.count(`SELECT count(*) FROM sa_probe WHERE result = 'failed: a saved SNMP secret was not restored'`) != 1 {
		t.Fatalf("sent %d jobs; probe rows %d", len(r.sent()), w.count(`SELECT count(*) FROM sa_probe`))
	}
}

// Only a secret sealed under another master key is "lost": a secret row that is gone is another failure, and the list does not call
// it lost (review r1 L4).
func TestSNMPOnlyAWrongKeyIsLost(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	c := w.add(v2cInput("Core switches", "s3cret-community"))
	err := w.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `DELETE FROM core_secret WHERE id = (SELECT secret_id FROM sa_snmp WHERE id = ?)`, c.ID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := w.lostOf(); got["Core switches"] {
		t.Fatalf("a missing secret row is called lost: %v", got)
	}
}
