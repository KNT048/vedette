package agentintake_test

import (
	"bytes"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/secrets"
)

// resealWazuhPassword seals the saved Wazuh password again under another master key, as a backup restored without its decryption
// key leaves it (J7 #812, #847).
func (r *wzRig) resealWazuhPassword() {
	r.t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{0x42}, secrets.KeySize)) // not the world's key (7s)
	if err != nil {
		r.t.Fatal(err)
	}
	r.sealWazuhPasswordWith(other)
}

// sealWazuhPasswordWith seals the saved Wazuh password with store: another master key, or the box's own (the key file put back).
func (r *wzRig) sealWazuhPasswordWith(other *secrets.Store) {
	r.t.Helper()
	ctx := r.t.Context()
	if err := r.db.Write(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM intake_wazuh WHERE id = 1`).Scan(&id); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, id, "intake_wazuh.password", []byte(wzPassword), true)
		return err
	}); err != nil {
		r.t.Fatal(err)
	}
}

const wzLost = "was not restored (the backup was restored without its decryption key, or the box key changed)"

// #847: a saved Wazuh password sealed under another master key. Test and Save with the field left blank are 409 secret_lost with a
// sentence that says to type it again, never a 500, and nothing reaches the server.
func TestWazuh_RestoreWithoutKeyTestAndSaveAskForThePassword(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.resealWazuhPassword()
	logins := r.fake.logins
	for _, c := range []struct{ method, path string }{{"POST", "/inventory/agents/wazuh/test"}, {"PUT", "/inventory/agents/wazuh"}} {
		res := r.admin(c.method, c.path, r.form(""))
		if res.code != 409 || !strings.Contains(res.raw, `"secret_lost"`) || !strings.Contains(res.raw, wzLost) || !strings.Contains(res.raw, "enter the password again") {
			t.Fatalf("%s %s with a blank password: %d %s", c.method, c.path, res.code, res.raw)
		}
	}
	if r.fake.logins != logins {
		t.Fatal("a request reached the Wazuh server without a password")
	}
	// Typing the password again works at once.
	if res := r.admin("POST", "/inventory/agents/wazuh/test", r.form(wzPassword)); res.code != 200 {
		t.Fatalf("test with the password typed again: %d %s", res.code, res.raw)
	}
	r.save()
	if res := r.admin("POST", "/inventory/agents/wazuh/test", r.form("")); res.code != 200 {
		t.Fatalf("test with a blank password after it was typed again: %d %s", res.code, res.raw)
	}
}

// #847: the pull job with a password it cannot open says so on the card (status error, the sentence in error) and stops: no later
// tick tries again or fails, until the password is typed again; then the pull runs and the card is clean.
func TestWazuh_RestoreWithoutKeyPullStopsAndSaysSo(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.resealWazuhPassword()
	r.pull() // no error: the job does not fail at every tick
	status, errText, _, _ := r.state()
	if status != "error" || !strings.Contains(errText, wzLost) || !strings.Contains(errText, "enter the password again") {
		t.Fatalf("card after the pull: %s %q", status, errText)
	}
	if res := r.admin("GET", "/inventory/agents", nil); res.code != 200 || !strings.Contains(res.raw, wzLost) {
		t.Fatalf("GET /inventory/agents does not show the lost password: %d %s", res.code, res.raw)
	}
	if !strings.Contains(r.logs.String(), "level=WARN") || !strings.Contains(r.logs.String(), "Wazuh password cannot be opened") {
		t.Fatalf("no WARN in the log:\n%s", r.logs.String())
	}
	// Later ticks do nothing: nothing is due until the password is typed again.
	warns := strings.Count(r.logs.String(), "level=WARN")
	for range 3 {
		r.clock.Advance(25 * time.Hour)
		r.pull()
	}
	if strings.Count(r.logs.String(), "level=WARN") != warns || r.fake.logins != 1 {
		t.Fatalf("later ticks tried again: %d logins, log:\n%s", r.fake.logins, r.logs.String())
	}
	// Typing the password again clears it and the next tick pulls.
	r.save()
	if status, errText, _, _ := r.state(); status == "error" || errText != "" {
		t.Fatalf("card after Save: %s %q", status, errText)
	}
	r.pull()
	if status, errText, agents, _ := r.state(); status != "connected" || errText != "" || agents == 0 {
		t.Fatalf("card after the pull: %s %q %d agents", status, errText, agents)
	}
}

// #847 review F3: the original key file is put back after the pull stopped. The next tick notices on its own (no Save): the password
// opens, the pull runs and the card is clean.
func TestWazuh_RestoreWithoutKeyPullStartsAgainWhenTheKeyComesBack(t *testing.T) {
	r := newWzRig(t)
	r.save()
	r.resealWazuhPassword()
	r.pull()
	if status, errText, _, _ := r.state(); status != "error" || !strings.Contains(errText, wzLost) {
		t.Fatalf("card after the pull: %s %q", status, errText)
	}
	r.sealWazuhPasswordWith(r.cfg.Secrets) // the box's own key again
	r.clock.Advance(time.Minute)
	r.pull()
	if status, errText, agents, _ := r.state(); status != "connected" || errText != "" || agents == 0 {
		t.Fatalf("card after the key came back: %s %q %d agents", status, errText, agents)
	}
	if r.fake.logins != 2 { // the Save, then this pull
		t.Fatalf("%d logins, want 2", r.fake.logins)
	}
}
