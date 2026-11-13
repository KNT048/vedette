package notify_test

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
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
		!strings.Contains(calls[0].Body, "Microsoft Office (20), Apple iOS (5)") || !strings.Contains(calls[0].Body, "and 6 more") {
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
	if told("f-o0") != 1 || told("f-o18") != 1 || told("f-o19") != 0 || told("f-p4") != 0 {
		t.Fatalf("notified: o0 %d, o18 %d, o19 %d, p4 %d: only the 19 lines the message names count", told("f-o0"), told("f-o18"), told("f-o19"), told("f-p4"))
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
	e.clock.Add(25 * time.Second)
	e.flush()
	if e.count(`SELECT COUNT(*) FROM notify_send WHERE ok = 1`) != 2 || e.count(`SELECT COUNT(*) FROM notify_pending`) != 0 {
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

// W1-11: on a new box every device is new; the first discovery is one summary incident with every device, not one incident each.
func TestFirstDiscoveryIsOneSummaryIncident(t *testing.T) {
	e := newEnv(t, func(c *notify.Config) {
		c.Devices = fakeDevices{"a1": "PC-01", "a2": "NAS-01", "a3": "192.168.10.9", "a9": "LAPTOP-NEW"}
	})
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	for _, id := range []string{"a1", "a2", "a3"} {
		if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: id, Notify: true})); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Hour)
	}
	l, _ := e.svc.Incidents(e.ctx())
	if len(l) != 1 || l[0].Title != "3 devices found on your network: approve them in Devices" || len(l[0].Devices) != 3 || l[0].Link != "/devices" {
		t.Fatalf("incidents = %+v", l)
	}
	e.flush()
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("messages = %d, want the one summary", n)
	}
	e.clock.Add(36 * time.Hour) // the first discovery is over: a new device is news again
	if err := e.bus.Publish(e.ctx(), eventOf(inventory.EventAssetDiscovered, inventory.AssetEvent{AssetID: "a9", Notify: true})); err != nil {
		t.Fatal(err)
	}
	l, _ = e.svc.Incidents(e.ctx())
	if len(l) != 2 || l[0].Title != "A new unknown device appeared: LAPTOP-NEW" {
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
