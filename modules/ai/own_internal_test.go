package ai

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/ai/provider"
)

// D-446 (walk 4): a model server on the machine that runs Vedette, at the machine's LAN address and its own port, is accepted;
// Vedette's own ports there, loopback and localhost are refused with the one sentence for Vedette itself.
func TestD446_ProfileOnTheMachine(t *testing.T) {
	t.Parallel()
	own := provider.OwnSources{Machine: func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("10.77.0.9")}, true },
		Self: func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("10.89.0.5")} }} // core's container address, as the decoys come in
	for base, refused := range map[string]bool{
		"http://10.77.0.9:18080/v1": false, "http://10.77.0.9:11434/v1": false, "https://10.77.0.9/v1": false, "http://ollama.lan:11434/v1": false,
		"https://10.77.0.9:8443/v1": true, "http://10.77.0.9:8765/v1": true, "http://127.0.0.1:11434/v1": true, "http://localhost:11434/v1": true,
		"http://ollama.localhost/v1": true, "http://10.89.0.5:11434/v1": true, "http://10.89.0.5:8443/v1": true,
		"http://host.containers.internal:8443/v1": true, "https://HOST.docker.internal:8765/v1": true, "http://host.containers.internal:11434/v1": false,
	} {
		p := Profile{ID: "x", Name: "Local", Kind: "openai-compatible", BaseURL: base, Model: "qwen3:8b", Location: LocationInternal, DailyCap: 10_000}
		err := p.checkOwn(own)
		var pe *ProfileError
		if got := err != nil; got != refused || (refused && (!errors.As(err, &pe) || pe.Code != "invalid_base_url")) {
			t.Errorf("%s: %v, want refused=%v", base, err, refused)
		}
	}
}

// D-446 review: a profile saved at localhost before D-446 still loads (Validate does not judge Vedette itself) and its call is
// refused at the dialer as ErrOwnAddress, before any packet.
func TestD446_StoredLocalhostProfileLoadsAndIsRefusedAtCall(t *testing.T) {
	t.Parallel()
	p := Profile{ID: "old", Name: "Old local", Kind: "openai-compatible", BaseURL: "http://localhost:11434/v1", Model: "qwen3:8b", Location: LocationInternal, DailyCap: 10_000}
	if err := p.Validate(); err != nil {
		t.Fatalf("a stored profile at localhost no longer loads: %v", err)
	}
	cl, err := p.provider(provider.OwnSources{Machine: func() ([]netip.Addr, bool) { return nil, true }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = cl.Complete(ctx, provider.Request{MaxTokens: 1, Messages: []provider.Message{{Role: provider.RoleUser, Text: "hi"}}})
	if !errors.Is(err, provider.ErrOwnAddress) {
		t.Errorf("call of a stored localhost profile: %v", err)
	}
}
