package notify_test

import (
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// #157 (INV-8, SYS-2): while Config.BoxAddrs says the box addresses are unknown, saving a webhook is 503 host_unreachable (retry
// later) and nothing is saved; a webhook already saved sends nothing until they are known, and the attempt is recorded.
func TestContract_INV8_WebhookWhileBoxAddrsUnknown(t *testing.T) {
	var mu sync.Mutex
	known := false
	setKnown := func(k bool) { mu.Lock(); known = k; mu.Unlock() }
	e := newEnv(t, func(c *notify.Config) {
		c.BoxAddrs = func() ([]netip.Addr, bool) { mu.Lock(); defer mu.Unlock(); return nil, known }
	})
	e.svc.SetWebhookClientForTest(&http.Client{Transport: e.net})
	in := notify.ChannelInput{Enabled: true, Fields: map[string]string{"url": "https://hooks.company.com/vedette"}, Secret: "0123456789abcdef0123", MinSeverity: notify.Low}
	_, err := e.svc.SaveChannel(e.ctx(), "admin@x", channel.Webhook, in)
	if s, c := apiCode(err); s != http.StatusServiceUnavailable || c != "host_unreachable" {
		t.Fatalf("save while the box addresses are unknown: %v", err)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_channel WHERE type = 'webhook' AND configured = 1`); n != 0 {
		t.Fatal("the webhook was saved")
	}
	// The test button builds the sender too: no message, a friendly result.
	setKnown(true)
	e.save(channel.Webhook, in)
	setKnown(false)
	res, err := e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook)
	if err != nil || res.OK || !strings.Contains(res.Detail, "own network addresses") {
		t.Fatalf("test while unknown: %+v %v", res, err)
	}
	// A notice queued now is attempted, recorded as failed, and never reaches the network.
	if _, _, err := e.svc.OpenIncident(e.ctx(), notify.IncidentInput{Kind: notify.IncidentTrap, Source: "s", Target: "t", Title: "x touched the trap", Severity: notify.Critical, Link: "/honeypot/hits/h1"}); err != nil {
		t.Fatal(err)
	}
	e.flush()
	if n := len(e.net.to("hooks.company.com")); n != 0 {
		t.Fatalf("%d webhook calls while the box addresses are unknown", n)
	}
	if n := e.count(`SELECT COUNT(*) FROM notify_send WHERE channel = 'webhook' AND ok = 0 AND error LIKE '%own network addresses%'`); n != 1 {
		t.Fatalf("%d failed webhook records that say why", n)
	}
	// Known again: the next send goes out.
	setKnown(true)
	res, err = e.svc.TestChannel(e.ctx(), "admin@x", channel.Webhook)
	if err != nil || !res.OK {
		t.Fatalf("test once known: %+v %v", res, err)
	}
}
