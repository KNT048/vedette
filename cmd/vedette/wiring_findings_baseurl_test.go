package main

import (
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/findings"
)

// feat-inventory:8, feat-module-wiring-2:6: a device's findings_count is the number of its findings (every status: deleting the
// device deletes them all), through cmd/vedette's late-bound adapter, in the list and on the device page.
func TestWiringInventoryFindingsCount(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	s.setModule("inventory", true)
	s.setModule("findings", true)
	s.kev("CVE-2024-21762", "Fortinet", "FortiOS")
	id := s.addFortiGate()
	if _, err := s.d.Findings.ConfirmFromScan(t.Context(), id, "CVE-2024-21762", findings.Evidence{Summary: "x", Template: "CVE-2024-21762", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	recs, err := s.d.Findings.List(t.Context(), id)
	if err != nil || len(recs) == 0 {
		t.Fatalf("findings = %v, %v", recs, err)
	}
	if _, err := s.d.Findings.SetStatus(t.Context(), recs[0].ID, findings.ActionMitigated, "done", "admin@acme.example"); err != nil {
		t.Fatal(err)
	}
	want := float64(len(recs))
	c, v := s.do("GET", "/inventory/devices/"+id, "viewer", "")
	if c != 200 || v["findings_count"] != want {
		t.Fatalf("device page findings_count = %v (%d), want %v", v["findings_count"], c, want)
	}
	c, v = s.do("GET", "/inventory/devices", "viewer", "")
	found := false
	items, _ := v["items"].([]any)
	for _, it := range items {
		if m, _ := it.(map[string]any); m["id"] == id {
			found = m["findings_count"] == want
		}
	}
	if c != 200 || !found {
		t.Fatalf("list findings_count of %s is not %v: %v", id, want, v)
	}
	s.setModule("findings", false) // off: deleting the device would not delete them (no subscriber), so the dialog promises nothing
	if c, v := s.do("GET", "/inventory/devices/"+id, "viewer", ""); c != 200 || v["findings_count"] != float64(0) {
		t.Fatalf("findings off: %v (%d), want 0", v["findings_count"], c)
	}
}

// feat-e2e-real-response-chains:6: the block list address a firewall pulls is the box's full address when the box has a name.
func TestWiringResponseBlocklistURLIsAbsolute(t *testing.T) {
	t.Parallel()
	s := newStackWith(t, func(d *deps) { d.BaseURL = "https://vedette.acme.example:8443" })
	s.setModule("inventory", true)
	s.setModule("response", true)
	c, v := s.do("GET", "/response/blocklist", "admin", "")
	url, _ := v["url"].(string)
	if c != 200 || !strings.HasPrefix(url, "https://vedette.acme.example:8443/api/v1/response/blocklist/") || !strings.HasSuffix(url, ".txt") {
		t.Fatalf("blocklist url = %q (%d)", url, c)
	}
}
