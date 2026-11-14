package sensorlink

import (
	"encoding/json"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
)

// D-591: every refusal of the worker's domain fence is a result core accepts, and a domain_ip job keeps its fence fields on the wire
// (an nmap one and a nuclei one) while every other job keeps the shape an older worker knows.
func TestDomainFenceOnTheWire(t *testing.T) {
	t.Parallel()
	for _, r := range domainfence.Reasons {
		for _, st := range []string{"refused", "stopped"} {
			if _, err := decodeJobResult([]byte(`{"status":"` + st + `","reason":"` + r + `","exit_code":-1,"truncated":false,"xml_b64":""}`)); err != nil {
				t.Errorf("%s %s: %v", st, r, err)
			}
		}
	}
	d := &DomainScope{Domain: "acme.example", Name: "www.acme.example", Token: "0123456789abcdef"}
	for _, j := range []Job{
		{ID: "a", Kind: KindNmap, Shape: "external_full", Rate: 300, Targets: []string{"8.8.8.8"}, TimeoutS: 60, Scope: ScopeDomainIP, Domain: d},
		{ID: "b", Kind: KindNuclei, TimeoutS: 60, Nuclei: &NucleiJob{Scope: ScopeDomainIP, Depth: "full", Domain: d, Targets: []NucleiTarget{{Host: "8.8.8.8", Port: 443}}}},
	} {
		raw, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		var back Job
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		got := back.Domain
		if back.Nuclei != nil {
			got = back.Nuclei.Domain
		}
		if got == nil || *got != *d {
			t.Fatalf("%s: %s", j.ID, raw)
		}
	}
	plain, _ := json.Marshal(Job{ID: "c", Kind: KindNmap, Shape: "external", Rate: 100, Targets: []string{"8.8.8.8"}, TimeoutS: 60})
	if string(plain) != `{"id":"c","kind":"nmap","shape":"external","rate":100,"targets":["8.8.8.8"],"timeout_s":60}` {
		t.Fatalf("a plain nmap job changed shape: %s", plain)
	}
}
