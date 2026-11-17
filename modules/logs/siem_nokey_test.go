package logs

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/secrets"
)

// #847 (#812): a backup restored without its decryption key leaves the SIEM signing key sealed under another master key.

// resealSiemKey seals the saved signing key again under another master key, as such a restore leaves it.
func (e *env) resealSiemKey() {
	e.t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{0x42}, secrets.KeySize)) // not the env's key (zeros)
	if err != nil {
		e.t.Fatal(err)
	}
	ctx := e.t.Context()
	if err := e.cfg.Write(ctx, func(tx *sql.Tx) error {
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM logs_siem WHERE id = 1`).Scan(&id); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, id, siemSecretPurpose, []byte("super-secret-key-1234"), false)
		return err
	}); err != nil {
		e.t.Fatal(err)
	}
}

const siemLostWords = "was not restored (the backup was restored without its decryption key, or the box key changed)"

func webhookInput() SiemInput {
	return SiemInput{Enabled: true, Format: "json", URL: "https://siem.example.com/hooks/vedette", Events: []string{"alerts", "honeypot"}, Secret: "super-secret-key-1234"}
}

// warnCounter counts the WARN lines of a logger.
type warnCounter struct {
	mu    sync.Mutex
	warns []string
}

func (w *warnCounter) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level == slog.LevelWarn {
		w.mu.Lock()
		w.warns = append(w.warns, r.Message)
		w.mu.Unlock()
	}
	return nil
}
func (w *warnCounter) WithAttrs([]slog.Attr) slog.Handler { return w }
func (w *warnCounter) WithGroup(string) slog.Handler      { return w }
func (w *warnCounter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.warns)
}

// The page says the key is lost, Test is 409 secret_lost with the sentence and sends nothing, and Save with the key left blank is refused
// the same way; never a 500. Typing the key again makes Test send.
func TestSiemRestoredWithoutTheKeyTestAndSaveAskForTheKey(t *testing.T) {
	e := newSiemEnv(t)
	e.saveSiem(webhookInput())
	e.resealSiemKey()
	ctx := t.Context()

	v, err := e.svc.Siem(ctx)
	if err != nil || !v.SecretLost || v.SecretLast4 == nil || *v.SecretLast4 != "1234" {
		t.Fatalf("GET with a lost key: %+v, %v", v, err)
	}
	sends := 0
	e.svc.siemSendFn = func(context.Context, siemRow, []siemRecord) (string, error) {
		sends++
		return "The destination returned HTTP 200.", nil
	}

	_, err = e.svc.TestSiem(ctx, "admin@acme.example")
	if code(err) != "secret_lost" || !strings.Contains(err.Error(), siemLostWords) || !strings.Contains(err.Error(), "Enter the signing key again") {
		t.Fatalf("Test with a lost key: %v", err)
	}
	if sends != 0 {
		t.Fatal("Test sent with a key the box cannot open")
	}
	if n := count(t, e.cfg, `SELECT count(*) FROM core_audit WHERE action = 'logs.siem_test' AND detail = 'failed: secret_lost'`); n != 1 {
		t.Fatalf("%d audit rows for the refused test", n)
	}
	in := webhookInput()
	in.Secret = ""
	if _, err := e.svc.SetSiem(ctx, "admin@acme.example", in); code(err) != "secret_lost" {
		t.Fatalf("Save with the key left blank: %v", err)
	}
	// a Save that does not turn the webhook on with the lost key is not refused: forwarding off, another URL, other events
	off := in
	off.Enabled, off.URL, off.Events = false, "https://siem2.example.com/hooks/vedette", []string{"findings"}
	if v, err := e.svc.SetSiem(ctx, "admin@acme.example", off); err != nil || !v.SecretLost || v.Enabled || v.URL != off.URL {
		t.Fatalf("Save with forwarding off and the key left blank: %+v, %v", v, err)
	}
	// syslog and CEF send no key: they still work, and the page still says the key is lost (it matters again on a switch to JSON)
	if v := e.saveSiem(syslogInput("192.168.10.50", 514, "udp")); !v.SecretLost {
		t.Fatalf("the answer of a Save that keeps the lost key: %+v", v)
	}
	if _, err := e.svc.TestSiem(ctx, "admin@acme.example"); err != nil || sends != 1 {
		t.Fatalf("syslog test with a lost webhook key: %v, %d sends", err, sends)
	}
	if v, _ := e.svc.Siem(ctx); !v.SecretLost {
		t.Fatal("the lost key is no longer shown")
	}

	// the key typed again: Test sends, and the page no longer says lost
	e.saveSiem(webhookInput())
	if v, _ := e.svc.Siem(ctx); v.SecretLost {
		t.Fatal("still lost after the key was typed again")
	}
	if r, err := e.svc.TestSiem(ctx, "admin@acme.example"); err != nil || !r.OK || sends != 2 {
		t.Fatalf("Test after the key was typed again: %+v, %v, %d sends", r, err, sends)
	}
}

// The running forwarder with a lost key sends nothing, queues nothing, writes one warning and does not retry; a Save with the key
// typed again starts it at once.
func TestSiemForwarderStopsOnALostKeyAndResumesOnSave(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newSiemEnv(t)
		w := &warnCounter{}
		e.svc.cfg.Log = slog.New(w)
		bus := events.NewBus(slog.New(slog.DiscardHandler))
		e.svc.Subscribe(bus)
		e.saveSiem(webhookInput())
		e.resealSiemKey()
		var sent []string
		e.svc.siemSendFn = func(_ context.Context, cfg siemRow, recs []siemRecord) (string, error) {
			if cfg.key.Reveal() != "super-secret-key-1234" {
				t.Errorf("sent with the key %q", cfg.key.Reveal())
			}
			for _, r := range recs {
				sent = append(sent, r.Name)
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = e.svc.runSiem(ctx); close(done) }()
		synctest.Wait()
		publish(t, bus, siemEventHoneypot, map[string]any{"id": "h-1", "service": "ssh"})
		<-time.After(3 * time.Hour) // a retry loop would send or warn many times in this
		synctest.Wait()
		if r, _ := e.svc.siemQ.peek(10); len(sent) != 0 || len(r) != 0 {
			t.Fatalf("sent %v, queued %d with a lost key", sent, len(r))
		}
		if n := w.count(); n != 1 {
			t.Fatalf("%d warnings, want one: %v", n, w.warns)
		}

		e.saveSiem(webhookInput()) // typed again
		synctest.Wait()
		publish(t, bus, siemEventHoneypot, map[string]any{"id": "h-2", "service": "ssh"})
		synctest.Wait()
		cancel()
		<-done
		if len(sent) != 1 || sent[0] != "honeypot.hit" || w.count() != 1 {
			t.Fatalf("after the key was typed again: sent %v, %d warnings", sent, w.count())
		}
	})
}

// syslog and CEF send no key: with a lost webhook key kept, the forwarder sends as before and writes no warning.
func TestSiemForwarderSendsSyslogWithALostWebhookKey(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newSiemEnv(t)
		w := &warnCounter{}
		e.svc.cfg.Log = slog.New(w)
		bus := events.NewBus(slog.New(slog.DiscardHandler))
		e.svc.Subscribe(bus)
		e.saveSiem(webhookInput())
		e.saveSiem(syslogInput("192.168.10.50", 514, "udp")) // the key stays saved
		e.resealSiemKey()
		var sent []string
		e.svc.siemSendFn = func(_ context.Context, _ siemRow, recs []siemRecord) (string, error) {
			for _, r := range recs {
				sent = append(sent, r.Name)
			}
			return "", nil
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { _ = e.svc.runSiem(ctx); close(done) }()
		synctest.Wait()
		publish(t, bus, siemEventHoneypot, map[string]any{"id": "h-1", "service": "ssh"})
		synctest.Wait()
		cancel()
		<-done
		if len(sent) != 1 || w.count() != 0 {
			t.Fatalf("syslog with a lost webhook key: sent %v, warnings %v", sent, w.warns)
		}
	})
}

// Over HTTP: GET says secret_lost, Test is 409 with the code and the sentence, never 500.
func TestSiemRestoredWithoutTheKeyOverHTTP(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	sec, err := secrets.New(make([]byte, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.cfg.Secrets = sec
	e.gate.Set("logs", true)
	body := `{"enabled":true,"format":"json","host":"","port":514,"proto":"udp","url":"https://siem.example.com/hooks/vedette","events":["alerts"],"secret":"super-secret-key-1234"}`
	if code, b := e.call("PUT", "/logs/siem", "admin", body); code != 200 || b["secret_lost"] != false {
		t.Fatalf("save %d %v", code, b)
	}
	e.resealSiemKey()
	if code, b := e.call("GET", "/logs/siem", "admin", ""); code != 200 || b["secret_lost"] != true || b["secret_last4"] != "1234" {
		t.Fatalf("GET with a lost key: %d %v", code, b)
	}
	code, b := e.call("POST", "/logs/siem/test", "admin", "")
	if code != 409 || errCode(b) != "secret_lost" {
		t.Fatalf("Test with a lost key: %d %v", code, b)
	}
	if code, b := e.call("PUT", "/logs/siem", "admin", strings.Replace(body, `,"secret":"super-secret-key-1234"`, "", 1)); code != 409 || errCode(b) != "secret_lost" {
		t.Fatalf("Save with the key left blank: %d %v", code, b)
	}
}
