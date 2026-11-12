package notify_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The webhook URL is a bearer secret (SYS-4): the token parts are built at run time, like every fake secret in these tests.
var (
	whToken  = strings.Join([]string{"tok", "path", "7f3a9c"}, "-")
	whQuery  = strings.Join([]string{"qk", "91d2e8"}, "-")
	whURL    = "https://hooks.company.com/vedette/" + whToken + "?key=" + whQuery
	whURL2   = "https://hooks.company.com/other/" + strings.Join([]string{"tok", "second", "5b1d44"}, "-")
	whMasked = "https://hooks.company.com/…" + "1d44" // masked form of whURL2 with its last 4 characters
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func webhookEnv(t *testing.T) (*env, *lockedBuf) {
	t.Helper()
	buf := &lockedBuf{}
	e := newEnv(t, func(c *notify.Config) {
		c.Log = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})
	e.svc.SetWebhookClientForTest(&http.Client{Transport: e.net})
	return e, buf
}

func saveWebhook(e *env, url string) notify.Channel {
	return e.save(channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": url}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
}

// dbHolds reports a table of notify, the audit log or the secrets that holds text in a column (as stored: ciphertext is not plaintext).
func (e *env) dbHolds(marker string) string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT name FROM sqlite_master WHERE type = 'table' AND (name LIKE 'notify\_%' ESCAPE '\' OR name IN ('core_audit', 'core_secret'))`)
	if err != nil {
		e.t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			e.t.Fatal(err)
		}
		tables = append(tables, n)
	}
	_ = rows.Close()
	for _, tb := range tables {
		r, err := e.db.Reader().QueryContext(e.ctx(), `SELECT * FROM `+tb)
		if err != nil {
			e.t.Fatal(err)
		}
		cols, _ := r.Columns()
		for r.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				e.t.Fatal(err)
			}
			for i, v := range vals {
				if strings.Contains(fmt.Sprint(v), marker) {
					_ = r.Close()
					return tb + "." + cols[i]
				}
			}
		}
		_ = r.Close()
	}
	return ""
}

func TestContract_SYS4_WebhookURLIsSealedAndOnlyItsMaskIsReturned(t *testing.T) {
	e, logs := webhookEnv(t)
	saved := saveWebhook(e, whURL)
	if saved.Fields["url"] != "https://hooks.company.com/…"+whURL[len(whURL)-4:] {
		t.Fatalf("PUT shows %q", saved.Fields["url"])
	}
	view, err := e.svc.Channels(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]any{saved, view})
	for _, m := range []string{whToken, whQuery, "?key="} {
		if strings.Contains(string(raw), m) {
			t.Fatalf("the response holds %q: %s", m, raw)
		}
	}
	if got := view.Channels[5].Fields["url"]; got != saved.Fields["url"] {
		t.Fatalf("GET shows %q, PUT showed %q", got, saved.Fields["url"])
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_channel c JOIN core_secret s ON s.id = c.url_secret_id WHERE c.type = 'webhook' AND s.purpose = 'notify_channel.url'`); n != 1 {
		t.Fatalf("sealed URL rows = %d", n)
	}
	// the URL is sent to, the test result, the history, the audit log, the logs and the stored rows never carry it
	res, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook)
	if err != nil || !res.OK {
		t.Fatalf("test = %+v, %v", res, err)
	}
	if c := e.net.to("hooks.company.com"); len(c) != 1 || c[0].Path != "/vedette/"+whToken {
		t.Fatalf("the sender did not use the saved URL: %+v", c)
	}
	for _, m := range []string{whToken, whQuery} {
		if where := e.dbHolds(m); where != "" {
			t.Fatalf("%q is stored in clear in %s", m, where)
		}
		if strings.Contains(logs.String(), m) || strings.Contains(fmt.Sprint(res), m) {
			t.Fatalf("%q reached a log or the test result", m)
		}
	}
}

func TestWebhookURLEmptyOrMaskedOnEditKeepsTheSavedURL(t *testing.T) {
	e, _ := webhookEnv(t)
	saved := saveWebhook(e, whURL)
	for _, in := range []string{"", "  ", saved.Fields["url"]} {
		again := saveWebhook(e, in)
		if again.Fields["url"] != saved.Fields["url"] {
			t.Fatalf("input %q: shows %q", in, again.Fields["url"])
		}
	}
	if _, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook); err != nil {
		t.Fatal(err)
	}
	if c := e.net.to("hooks.company.com"); len(c) != 1 || c[0].Path != "/vedette/"+whToken {
		t.Fatalf("an edit that left the URL empty changed where it goes: %+v", c)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret WHERE purpose = 'notify_channel.url'`); n != 1 {
		t.Fatalf("%d sealed URLs", n)
	}
}

func TestWebhookURLWithoutASavedOneIsRequiredAndANewOneReplaces(t *testing.T) {
	e, _ := webhookEnv(t)
	if _, err := e.svc.SaveChannel(e.ctx(), "admin@x", channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": ""}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low}); err == nil {
		t.Fatal("a webhook with no URL was saved")
	}
	saveWebhook(e, whURL)
	got := saveWebhook(e, whURL2)
	if got.Fields["url"] != whMasked {
		t.Fatalf("shows %q, want %q", got.Fields["url"], whMasked)
	}
	if _, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook); err != nil {
		t.Fatal(err)
	}
	if c := e.net.to("hooks.company.com"); len(c) != 1 || !strings.HasPrefix(c[0].Path, "/other/") {
		t.Fatalf("calls %+v", c)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret WHERE purpose = 'notify_channel.url'`); n != 1 {
		t.Fatalf("the old sealed URL stays: %d", n)
	}
	// a URL that is not valid is refused and the saved one stays
	if _, err := e.svc.SaveChannel(e.ctx(), "admin@x", channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": "https://localhost/x"}, Secret: "", MinSeverity: notify.Low}); err == nil {
		t.Fatal("a loopback URL was saved")
	}
	if got := e.dbHolds("localhost"); got != "" {
		t.Fatalf("a refused URL is stored in %s", got)
	}
}

func TestWebhookDeleteRemovesTheSealedURL(t *testing.T) {
	e, _ := webhookEnv(t)
	saveWebhook(e, whURL)
	if err := e.svc.DeleteChannel(e.ctx(), "admin@x", channel.Webhook); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT COUNT(*) FROM core_secret WHERE purpose = 'notify_channel.url'`); n != 0 {
		t.Fatalf("%d sealed URLs left", n)
	}
	view, _ := e.svc.Channels(e.ctx())
	if view.Channels[5].Configured || view.Channels[5].Fields["url"] != "" {
		t.Fatalf("channel after delete: %+v", view.Channels[5])
	}
}

// A row saved before the URL was sealed: every read masks it at once, and the next Flush seals it. Nothing is sent to a changed address.
func TestWebhookURLSavedBeforeSealingIsMaskedThenSealed(t *testing.T) {
	e, logs := webhookEnv(t)
	fj, _ := json.Marshal(map[string]string{"url": whURL})
	e.write(func(tx *sql.Tx) error {
		id, _, err := e.sec.Seal(e.ctx(), tx, "notify_channel.secret", []byte("0123456789abcdef0123"), true)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(e.ctx(), `INSERT INTO notify_channel (type, configured, enabled, fields, secret_id, secret_last4, min_severity, updated_at)
			VALUES ('webhook', 1, 1, ?, ?, '0123', 'low', '2026-11-09T10:00:00.000Z')`, string(fj), id)
		return err
	})
	if e.dbHolds(whToken) == "" {
		t.Fatal("the fixture is not a legacy row")
	}
	v, err := e.svc.Channels(e.ctx()) // a read masks it
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Channels[5].Fields["url"]; got != "https://hooks.company.com/…"+whURL[len(whURL)-4:] {
		t.Fatalf("shows %q", got)
	}
	e.flush() // the deliver job seals it
	if where := e.dbHolds(whToken); where != "" {
		t.Fatalf("still in clear in %s", where)
	}
	if res, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook); err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	if c := e.net.to("hooks.company.com"); len(c) != 1 || c[0].Path != "/vedette/"+whToken {
		t.Fatalf("sealing changed where it goes: %+v", c)
	}
	u, key, ok, err := e.svc.WebhookTarget(e.ctx())
	if err != nil || !ok || u != whURL || key == "" {
		t.Fatalf("WebhookTarget = %q %v %v", u, ok, err)
	}
	if strings.Contains(logs.String(), whToken) {
		t.Fatal("the URL was logged")
	}
}

// The Flush of the deliver job seals too, with nobody reading the channels.
func TestWebhookURLSavedBeforeSealingIsSealedByTheDeliverJob(t *testing.T) {
	e, _ := webhookEnv(t)
	fj, _ := json.Marshal(map[string]string{"url": whURL})
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_channel (type, configured, enabled, fields, min_severity, updated_at) VALUES ('webhook', 1, 1, ?, 'low', '2026-11-09T10:00:00.000Z')`, string(fj))
		return err
	})
	e.flush()
	if where := e.dbHolds(whToken); where != "" {
		t.Fatalf("still in clear in %s", where)
	}
}

// Channels is called inside another module's write transaction (response's breaker check): it must never open a write of its own,
// or it would wait for the one writer conn it is already holding. A legacy row is masked by the read and sealed by the next Flush.
func TestChannelsInsideAWriteTransactionReturnsPromptlyEvenWithALegacyURL(t *testing.T) {
	e, _ := webhookEnv(t)
	fj, _ := json.Marshal(map[string]string{"url": whURL})
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_channel (type, configured, enabled, fields, min_severity, updated_at) VALUES ('webhook', 1, 1, ?, 'low', '2026-11-09T10:00:00.000Z')`, string(fj))
		return err
	})
	ctx, cancel := context.WithTimeout(e.ctx(), 5*time.Second)
	defer cancel()
	var got string
	err := e.db.Write(ctx, func(_ *sql.Tx) error {
		v, err := e.svc.Channels(ctx)
		if err == nil {
			got = v.Channels[5].Fields["url"]
		}
		return err
	})
	if err != nil {
		t.Fatalf("Channels inside a write transaction: %v", err)
	}
	if strings.Contains(got, whToken) || got == "" {
		t.Fatalf("shows %q", got)
	}
	e.flush()
	if where := e.dbHolds(whToken); where != "" {
		t.Fatalf("still in clear in %s after the Flush", where)
	}
}

// A sealed URL that cannot be opened (the key changed) is 400 url_unreadable, not secret_required: the GUI puts that one under the
// signing key. Entering the URL again saves.
func TestWebhookSavedURLUnreadableIsItsOwnCode(t *testing.T) {
	e, _ := webhookEnv(t)
	saveWebhook(e, whURL)
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE core_secret SET key_version = key_version + 100 WHERE purpose = 'notify_channel.url'`)
		return err
	})
	_, err := e.svc.SaveChannel(e.ctx(), "admin@x", channel.Webhook, notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": ""}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low})
	wantCode(t, err, 400, "url_unreadable")
	if got := saveWebhook(e, whURL2); got.Fields["url"] != whMasked {
		t.Fatalf("entered again: shows %q", got.Fields["url"])
	}
}
