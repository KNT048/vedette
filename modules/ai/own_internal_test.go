package ai

import (
	"errors"
	"net/netip"
	"testing"
)

// D-446 (walk 4): a model server on the machine that runs Vedette, at the machine's LAN address and its own port, is accepted;
// Vedette's own ports there, loopback and localhost are refused with the one sentence for Vedette itself.
func TestD446_ProfileOnTheMachine(t *testing.T) {
	t.Parallel()
	machine := func() ([]netip.Addr, bool) { return []netip.Addr{netip.MustParseAddr("10.77.0.9")}, true }
	for base, refused := range map[string]bool{
		"http://10.77.0.9:18080/v1": false, "http://10.77.0.9:11434/v1": false, "https://10.77.0.9/v1": false, "http://ollama.lan:11434/v1": false,
		"https://10.77.0.9:8443/v1": true, "http://10.77.0.9:8765/v1": true, "http://127.0.0.1:11434/v1": true, "http://localhost:11434/v1": true,
		"http://ollama.localhost/v1": true,
	} {
		p := Profile{ID: "x", Name: "Local", Kind: "openai-compatible", BaseURL: base, Model: "qwen3:8b", Location: LocationInternal, DailyCap: 10_000}
		err := p.checkOwn(machine)
		var pe *ProfileError
		if got := err != nil; got != refused || (refused && (!errors.As(err, &pe) || pe.Code != "invalid_base_url")) {
			t.Errorf("%s: %v, want refused=%v", base, err, refused)
		}
	}
}
