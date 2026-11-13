package notify_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// W1-19: the first matching after a product was added made one Telegram message per CVE, then Telegram answered 429. The burst is one
// digest per channel, and a finding counts as notified only when the message named it (W1-11).
func TestBurstOfMatchesIsOneDigestAndNamesOnlyWhatItLists(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.rules(notify.Quiet{From: "22:00", To: "06:30"}, notify.Grouping{Enabled: true, WindowMin: 60})
	for i := range 20 {
		e.critical(fmt.Sprintf("o%d", i), "Microsoft Office", fmt.Sprintf("CVE-2009-%04d", i))
	}
	for i := range 5 {
		if err := e.svc.Publish(e.ctx(), e.vulnNotice(fmt.Sprintf("p%d", i), "Apple iOS", fmt.Sprintf("CVE-2016-%04d", i), notify.Critical, "iPhone")); err != nil {
			t.Fatal(err)
		}
	}
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 1 || !strings.Contains(calls[0].Body, "25 exploited vulnerabilities match your devices") ||
		!strings.Contains(calls[0].Body, "Microsoft Office (20), Apple iOS (5)") || !strings.Contains(calls[0].Body, "and 5 more") {
		t.Fatalf("calls = %d, first = %.600s", len(calls), func() string {
			if len(calls) == 0 {
				return ""
			}
			return calls[0].Body
		}())
	}
	told := func(f string) int {
		l, err := e.svc.FindingNotices(e.ctx(), f)
		if err != nil {
			t.Fatal(err)
		}
		return len(l)
	}
	if told("f-o0") != 1 || told("f-o19") != 1 || told("f-p0") != 0 || told("f-p4") != 0 {
		t.Fatalf("notified: o0 %d, o19 %d, p0 %d, p4 %d: only the 20 lines the message names count", told("f-o0"), told("f-o19"), told("f-p0"), told("f-p4"))
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatal("the digest left notices in the queue")
	}
}

// W1-19: a 429 is waited for as the provider asked, recorded once as "Delayed (rate limited)", and the message goes out after the wait;
// the finding says notified only after that.
func TestRateLimitedSendWaitsAndIsSentLater(t *testing.T) {
	var mu sync.Mutex
	limited := true
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if limited {
			_, _ = io.ReadAll(r.Body)
			return &http.Response{StatusCode: 429, Header: http.Header{}, Request: r,
				Body: io.NopCloser(strings.NewReader(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 30","parameters":{"retry_after":30}}`))}, nil
		}
		return ok200(r), nil
	}))
	e.telegram(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	e.incident("i1", notify.Critical)
	e.flush()
	h, _ := e.svc.History(e.ctx())
	if len(h.Items) != 1 || h.Items[0].OK || !h.Items[0].Delayed || !strings.HasPrefix(h.Items[0].Error, "Delayed (rate limited): Telegram asked Vedette to wait 30s") {
		t.Fatalf("history = %+v", h.Items)
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending WHERE state = 'pending'`) != 2 {
		t.Fatal("the refused message and the one behind it must both wait in the queue")
	}
	if l, _ := e.svc.FindingNotices(e.ctx(), "f-c1"); len(l) != 0 {
		t.Fatalf("a delayed message is not a notification: %+v", l)
	}
	mu.Lock()
	limited = false
	mu.Unlock()
	e.clock.Add(10 * time.Second)
	e.flush()
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`) != 0 {
		t.Fatal("sent before the wait Telegram asked for")
	}
	e.critical("c2", "QNAP", "CVE-2026-32") // new while c1 waits: it does not join the refused message (its own count, its own Delayed row)
	e.clock.Add(25 * time.Second)
	e.flush()
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`) != 3 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
		t.Fatalf("after the wait: ok = %d, pending = %d", e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`), e.count(`SELECT COUNT(*) FROM notify_pending`))
	}
	if l, _ := e.svc.FindingNotices(e.ctx(), "f-c1"); len(l) != 1 || !l[0].OK {
		t.Fatalf("finding notices = %+v", l)
	}
}

// A provider that never lets go: after the bounded tries the message is recorded as failed, never dropped silently.
func TestRateLimitGivesUpAfterBoundedTries(t *testing.T) {
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		_, _ = io.ReadAll(r.Body)
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": {"5"}}, Request: r, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}))
	e.telegram(notify.Low)
	e.plain()
	e.critical("c1", "WordPress", "CVE-2026-31")
	for range 6 {
		e.flush()
		e.clock.Add(6 * time.Second)
	}
	if e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 || e.count(`SELECT COUNT(*) FROM notify_send WHERE delayed = 1`) != 1 ||
		e.count(`SELECT COUNT(*) FROM notify_send WHERE delayed = 0 AND ok = 0 AND error LIKE '%kept asking Vedette to send more slowly%'`) != 1 {
		t.Fatalf("pending %d, history %d", e.count(`SELECT COUNT(*) FROM notify_pending`), e.count(`SELECT COUNT(*) FROM notify_send`))
	}
}

// W1-11: on a new box every device is new; the first discovery is one summary incident with every device, not one incident each. A
// device found later in the window is told in one short update; after the window, and on a box that ran before, a device is news alone.
func TestFirstDiscoveryIsOneSummaryIncident(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"a1": "PC-01", "a2": "NAS-01", "a3": "192.168.10.9", "a4": "PRINTER-2", "a5": "PRINTER-3", "a9": "LAPTOP-NEW"}
	})
	e.write(func(tx *sql.Tx) error { // the box was installed now (the migration takes the real clock)
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_box SET first_run_at = ?`, store.FormatTS(e.clock.Now()))
		return err
	})
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	found := func(id string) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"a1", "a2", "a3"} {
		found(id)
		e.clock.Add(10 * time.Minute)
	}
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Title != "3 devices found on your network: approve them in Devices" || len(l[0].Devices) != 3 || l[0].Link != "/devices" {
		t.Fatalf("incidents = %+v", l)
	}
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("messages = %d, want the one summary", n)
	}
	e.clock.Add(20 * time.Hour) // hour 20: two more devices; the first tells people again, the second waits for the next hour
	found("a4")
	found("a5")
	e.flush()
	calls := e.net.to("api.telegram.org")
	if len(calls) != 2 || !strings.Contains(calls[1].Body, "4 devices found on your network") || !strings.Contains(calls[1].Body, "3 more devices found since the last message") {
		t.Fatalf("calls = %d, last = %.300s", len(calls), calls[len(calls)-1].Body)
	}
	if l, _ = e.svc.Incidents(e.ctx()); len(l) != 1 || l[0].Title != "5 devices found on your network: approve them in Devices" {
		t.Fatalf("incidents = %+v", l)
	}
	e.clock.Add(16 * time.Hour) // the first discovery is over: a new device is news again
	found("a9")
	if l, _ = e.svc.Incidents(e.ctx()); len(l) != 2 || l[0].Title != "A new unknown device appeared: LAPTOP-NEW" {
		t.Fatalf("incidents = %+v", l)
	}
}

// A box that ran before (an upgrade, or new-device alerts turned on later) never opens the first-discovery window.
func TestFirstDiscoveryNeverOpensOnABoxThatRanBefore(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) { c.Devices = fakeDevices{"a1": "PC-01", "a2": "NAS-01"} })
	e.write(func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE notify_box SET first_run_at = ?`, store.FormatTS(e.clock.Now().AddDate(0, -2, 0)))
		return err
	})
	e.svc.Subscribe(e.bus)
	for _, id := range []string{"a1", "a2"} {
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})); err != nil {
			t.Fatal(err)
		}
	}
	if l, _ := e.svc.Incidents(e.ctx()); len(l) != 2 || !strings.HasPrefix(l[0].Title, "A new unknown device appeared: ") {
		t.Fatalf("incidents = %+v", l)
	}
}

// W1-20: a Zalo OA channel saved with App ID, Secret key and refresh token gets its access token from the token endpoint, keeps the
// rotated refresh token (single use), and refreshes again when Zalo says the token is invalid.
func TestZaloOARefreshTokenFlow(t *testing.T) {
	var mu sync.Mutex
	var forms []url.Values
	var keys []string
	n, rejectAccess := 0, ""
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		answer := func(s string) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r, Body: io.NopCloser(strings.NewReader(s))}, nil
		}
		switch r.URL.Host + r.URL.Path {
		case "oauth.zaloapp.com/v4/oa/access_token":
			f, _ := url.ParseQuery(string(body))
			forms, keys = append(forms, f), append(keys, r.Header.Get("secret_key"))
			n++
			return answer(fmt.Sprintf(`{"access_token":"access-token-number-%02d-abcdefghij","refresh_token":"refresh-token-number-%02d-abcdefghij","expires_in":"90000"}`, n, n))
		case "openapi.zalo.me/v3.0/oa/message/cs":
			if r.Header.Get("access_token") == rejectAccess {
				return answer(`{"error":-216,"message":"Access token is invalid"}`)
			}
			return answer(`{"error":0,"message":"Success"}`)
		}
		return ok200(r), nil
	}))
	saved := e.save(channel.Zalo, notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, SecretKey: "app-secret-key-123", //nolint:gosec // fake test secrets
		RefreshToken: "refresh-token-first-0123456789", Fields: map[string]string{"oa_id": "1234567890", "user_id": "987654321", "app_id": "4318650137000000000"}})
	if saved.SecretLast4 == nil || *saved.SecretLast4 != "6789" || saved.Fields["app_id"] != "4318650137000000000" {
		t.Fatalf("saved = %+v", saved)
	}
	e.plain()
	e.incident("i1", notify.Critical)
	e.flush()
	e.svc.WaitRotationsForTest()
	mu.Lock()
	if len(forms) != 1 || forms[0].Get("refresh_token") != "refresh-token-first-0123456789" || forms[0].Get("app_id") != "4318650137000000000" ||
		forms[0].Get("grant_type") != "refresh_token" || keys[0] != "app-secret-key-123" {
		t.Fatalf("token requests = %v, keys %v", forms, keys)
	}
	rejectAccess = "access-token-number-01-abcdefghij" // revoked early: Zalo says -216
	mu.Unlock()
	if c, _ := e.svc.Channels(e.ctx()); !hasLast4(c, channel.Zalo, "ghij") {
		t.Fatal("the rotated refresh token was not saved")
	}
	e.incident("i2", notify.Critical)
	e.flush()
	e.svc.WaitRotationsForTest()
	mu.Lock()
	defer mu.Unlock()
	if len(forms) != 2 || forms[1].Get("refresh_token") != "refresh-token-number-01-abcdefghij" {
		t.Fatalf("second refresh used %v: a refresh token works once, the rotated one must be used", forms)
	}
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'zalo' AND ok = 1`) != 2 {
		t.Fatal("the message after the forced refresh was not sent")
	}
}

func hasLast4(v notify.ChannelsView, t channel.Type, l4 string) bool {
	for _, c := range v.Channels {
		if c.Type == t {
			return c.SecretLast4 != nil && *c.SecretLast4 == l4
		}
	}
	return false
}

func eventOf(name string, data any) events.Event { return events.Event{Name: name, Data: data} }

// D-483 review: Zalo cuts its text at 2000 characters. With long lines, only the lines that are sent whole count as told, and the
// "and N more" line counts the rest.
func TestZaloDigestNamesOnlyTheLinesThatFit(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		var body struct {
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
		}
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		texts = append(texts, body.Message.Text)
		mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r, Body: io.NopCloser(strings.NewReader(`{"error":0,"message":"Success"}`))}, nil
	}))
	e.save(channel.Zalo, notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, Secret: "zalo-access-token-0123456789-abcdef",
		Fields: map[string]string{"oa_id": "1234567890", "user_id": "987654321"}})
	e.plain()
	device := strings.Repeat("WORKSTATION-OF-THE-ACCOUNTING-DEPARTMENT-", 3)
	for i := range 25 {
		e.critical(fmt.Sprintf("z%d", i), "Microsoft Office", fmt.Sprintf("CVE-2026-%05d", i))
		e.write(func(tx *sql.Tx) error { // a long device name makes each line long
			_, err := tx.ExecContext(e.ctx(), `UPDATE notify_pending SET notice = json_set(notice, '$.Devices', json_array(?)) WHERE notice_id = ?`, device, fmt.Sprintf("z%d", i))
			return err
		})
	}
	e.flush()
	mu.Lock()
	defer mu.Unlock()
	if len(texts) != 1 || utf8.RuneCountInString(texts[0]) > 2000 {
		t.Fatalf("texts = %d, first %d runes", len(texts), utf8.RuneCountInString(texts[0]))
	}
	lines := strings.Count(texts[0], "\n- CVE-2026-")
	told := 0
	for i := range 25 {
		if l, _ := e.svc.FindingNotices(e.ctx(), fmt.Sprintf("f-z%d", i)); len(l) == 1 {
			told++
			if !strings.Contains(texts[0], fmt.Sprintf("CVE-2026-%05d on %s", i, device)) {
				t.Fatalf("z%d counts as told but its line is not whole in the text", i)
			}
		}
	}
	if lines == 0 || lines >= 20 || told != lines || !strings.Contains(texts[0], fmt.Sprintf("- and %d more: open Vedette to see them all", 25-lines)) {
		t.Fatalf("lines %d, told %d, text:\n%s", lines, told, texts[0])
	}
}

// D-483 review: a rotated refresh token is saved before it is used; a failed save keeps it in memory and is tried again before the
// next send, and a sender built meanwhile, or a save of only the Secret key, starts from it, never from the used token.
func TestZaloRotationSurvivesAFailedSave(t *testing.T) {
	var mu sync.Mutex
	var forms []url.Values
	var keys []string
	n, rejectAccess := 0, ""
	e := newEnv(t, withNet(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		answer := func(s string) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Request: r, Body: io.NopCloser(strings.NewReader(s))}, nil
		}
		if r.URL.Host == "oauth.zaloapp.com" {
			f, _ := url.ParseQuery(string(body))
			forms, keys = append(forms, f), append(keys, r.Header.Get("secret_key"))
			n++
			return answer(fmt.Sprintf(`{"access_token":"access-token-number-%02d-abcdefghij","refresh_token":"refresh-token-number-%02d-abcdefghij","expires_in":"90000"}`, n, n))
		}
		if r.Header.Get("access_token") == rejectAccess {
			return answer(`{"error":-216,"message":"Access token is invalid"}`)
		}
		return answer(`{"error":0,"message":"Success"}`)
	}))
	in := notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, SecretKey: "app-secret-key-123", //nolint:gosec // fake test secrets
		RefreshToken: "refresh-token-first-0123456789", Fields: map[string]string{"oa_id": "1234567890", "user_id": "987654321", "app_id": "4318650137000000000"}}
	e.save(channel.Zalo, in)
	e.plain()
	var fail atomic.Int32
	fail.Store(1)
	e.svc.SetZaloSaveFaultForTest(func() error {
		if fail.Add(-1) >= 0 {
			return errors.New("database busy")
		}
		return nil
	})
	e.incident("i1", notify.Critical)
	e.flush() // refreshes; the save fails; the message still goes with the new access token
	if c, _ := e.svc.Channels(e.ctx()); !hasLast4(c, channel.Zalo, "6789") {
		t.Fatal("the failed save changed the channel")
	}
	e.incident("i2", notify.Critical)
	e.flush() // the same sender saves the rotation before it sends again
	if c, _ := e.svc.Channels(e.ctx()); !hasLast4(c, channel.Zalo, "ghij") {
		t.Fatal("the rotation was not saved before the next send")
	}
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'zalo' AND ok = 1`) != 2 {
		t.Fatal("a failed save must not stop the alerts")
	}

	fail.Store(1) // the next rotation fails to save; then the admin saves only a new Secret key and a new sender is built
	mu.Lock()
	rejectAccess = "access-token-number-01-abcdefghij"
	mu.Unlock()
	e.incident("i3", notify.Critical)
	e.flush()                                                                                                              // -216 forces refresh 2 (refresh token 01); its save fails, memory keeps refresh token 02
	key := notify.ChannelInput{Enabled: true, MinSeverity: notify.Low, SecretKey: "app-secret-key-456", Fields: in.Fields} //nolint:gosec // fake test secret
	e.save(channel.Zalo, key)
	mu.Lock()
	rejectAccess = "access-token-number-02-abcdefghij"
	mu.Unlock()
	e.incident("i4", notify.Critical)
	e.flush() // a new sender (new revision): Zalo refuses access token 02, so it refreshes with the newest refresh token and the new key
	mu.Lock()
	defer mu.Unlock()
	if len(forms) != 3 || forms[1].Get("refresh_token") != "refresh-token-number-01-abcdefghij" || forms[2].Get("refresh_token") != "refresh-token-number-02-abcdefghij" || keys[2] != "app-secret-key-456" {
		t.Fatalf("refreshes = %v, keys %v: the used refresh token came back", forms, keys)
	}
}
