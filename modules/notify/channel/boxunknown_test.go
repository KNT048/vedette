package channel

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/secrets"
)

// #157: while the box does not know its own addresses (vedette-host has not answered since the start), a webhook is neither
// built nor connected: fail closed, not the empty set.
func TestWebhookUnknownBoxAddrsFailClosed(t *testing.T) {
	t.Parallel()
	unknown := func() ([]netip.Addr, bool) { return nil, false }
	for _, u := range []string{"https://hooks.company.com/vedette", "https://192.168.10.9/x", "http://siem.lan/in"} {
		_, err := NewWebhook(WebhookConfig{URL: secrets.NewValue(u), SigningKey: secrets.NewValue(whKey), BoxAddrsFunc: unknown})
		if !errors.Is(err, ErrBoxAddrsUnknown) {
			t.Errorf("NewWebhook(%s) with unknown box addresses: %v", u, err)
		}
	}
	// A URL that is wrong anyway keeps its own error: the person fixes it first.
	_, err := NewWebhook(WebhookConfig{URL: secrets.NewValue("ftp://hooks.company.com/x"), SigningKey: secrets.NewValue(whKey), BoxAddrsFunc: unknown})
	if !errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrBoxAddrsUnknown) {
		t.Errorf("a bad URL with unknown box addresses: %v", err)
	}

	var mu sync.Mutex
	known := false
	get := func() ([]netip.Addr, bool) { mu.Lock(); defer mu.Unlock(); return nil, known }
	ctl := dialControl(false, get)
	err = ctl("tcp", "192.168.10.9:443", nil)
	if err == nil || !strings.Contains(err.Error(), "not known yet") {
		t.Fatalf("a connection while the box addresses are unknown: %v", err)
	}
	mu.Lock()
	known = true
	mu.Unlock()
	if err := ctl("tcp", "192.168.10.9:443", nil); err != nil {
		t.Fatalf("a connection once the box addresses are known: %v", err)
	}
	// Known with an empty list is still known (a box without vedette-host addresses beyond its interfaces).
	if _, err := NewWebhook(WebhookConfig{URL: secrets.NewValue("https://hooks.company.com/v"), SigningKey: secrets.NewValue(whKey), BoxAddrsFunc: get}); err != nil {
		t.Fatalf("known and empty: %v", err)
	}
}
