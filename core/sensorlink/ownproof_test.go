package sensorlink

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// proven_at rides on an external nmap job and an own_ip nuclei job as an RFC 3339 time and comes back as the same instant; a job
// without a proof has no proven_at key at all, so a worker that does not know the field still decodes it.
func TestProvenAtRoundTripsOnTheWire(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 10, 1, 3, 53, 0, 0, time.UTC)
	nmap := Job{ID: strings.Repeat("c", 32), Kind: KindNmap, Shape: "external", Rate: 100, Targets: []string{"8.8.8.8"}, TimeoutS: 60, ProvenAt: &at}
	nuc := Job{ID: strings.Repeat("d", 32), Kind: KindNuclei, TimeoutS: 60, Nuclei: &NucleiJob{Templates: []string{"CVE-2024-1"},
		Targets: []NucleiTarget{{Host: "8.8.8.8", Port: 443, Scheme: "https"}}, Rate: 5, MaxHostErrors: 3, Scope: "own_ip", ProvenAt: &at}}
	for _, j := range []Job{nmap, nuc} {
		raw, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `"proven_at":"2026-10-01T03:53:00Z"`) {
			t.Fatalf("wire: %s", raw)
		}
		rep, err := decodeReply(t, string(raw))
		if err != nil {
			t.Fatal(err)
		}
		got := rep.Jobs[0].ProvenAt
		if rep.Jobs[0].Nuclei != nil {
			got = rep.Jobs[0].Nuclei.ProvenAt
		}
		if got == nil || !got.Equal(at) {
			t.Fatalf("decoded proven_at %v from %s", got, raw)
		}
	}
	nmap.ProvenAt, nuc.Nuclei.ProvenAt = nil, nil
	for _, j := range []Job{nmap, nuc} {
		if raw, _ := json.Marshal(j); strings.Contains(string(raw), "proven_at") {
			t.Fatalf("a job without a proof carries the key: %s", raw)
		}
	}
}
