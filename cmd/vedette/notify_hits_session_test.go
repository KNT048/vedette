package main

import (
	"testing"
)

// The session reader keeps the hits of one source, without test hits, from the JSON lines the honeypot export writes, also when a
// line is cut across two writes.
func TestNotifySessionHitsKeepOneSourceWithoutTests(t *testing.T) {
	w := &sourceRows{src: "192.0.2.7", limit: 500}
	lines := `{"id":"hit-1","ts":"2026-11-25T09:28:52.734Z","kind":"token","service":null,"label":"URL token Router admin","src_ip":"192.0.2.7","is_test":0}
{"id":"hit-2","ts":"2026-11-25T09:28:52.765Z","kind":"service","service":"ssh","label":"SSH","src_ip":"192.0.2.8","is_test":0}
{"id":"hit-3","ts":"2026-11-25T09:28:53Z","kind":"service","service":"smb","label":"SMB","src_ip":"192.0.2.7","is_test":1}
{"id":"hit-4","ts":"2026-11-25T09:28:55.811Z","kind":"service","service":"smb","label":"SMB","src_ip":"192.0.2.7","is_test":0}
`
	for _, part := range []string{lines[:70], lines[70:]} {
		if _, err := w.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if len(w.out) != 2 || w.out[0].ID != "hit-1" || w.out[0].Label != "URL token Router admin" || w.out[0].Service != "" ||
		w.out[1].ID != "hit-4" || w.out[1].Service != "smb" || w.out[1].At.Second() != 55 {
		t.Fatalf("%+v", w.out)
	}
}
