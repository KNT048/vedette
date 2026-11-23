package findings

import (
	"strings"
	"testing"
)

// The class: a finding's fix and its confirmation told in words by the readers outside the finding page (the assistant's context and
// tools, the MCP tools). Over the fixture's findings stored by the match pass: how many carry a fixed release in the words of the view
// that is not the stored fix, how many say "no fixed release" while the stored fix names one, and, after a person confirms nine of
// them, how many of those do not read "confirmed by <person>" (or say "not confirmed"). The older reader of the fix (the finding page's
// FixedInFor, which the assistant's context was built from) is counted beside them: it names no release for the ESXi finding that
// VMware's per-train builds give one for.
func TestFixCount_TheWordsOfAViewNameTheStoredFixAndWhoConfirmed(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.inv.mu.Lock()
	e.inv.assets, e.inv.match = map[string]AssetView{}, map[string]Asset{}
	devices := fixDevices(t)
	for _, d := range devices {
		e.inv.match[d.a.ID] = d.a
		e.inv.assets[d.a.ID] = AssetView{ID: d.a.ID, Name: d.a.Name + "-" + d.a.ID, IP: NoIP, Kind: "server", Approved: true}
	}
	e.inv.mu.Unlock()
	older := map[string]string{} // the older reader's release per device, CVE and line
	for _, d := range devices {
		if _, err := e.svc.UpsertFromMatch(ctx, d.a, d.vulns); err != nil {
			t.Fatal(err)
		}
		for k, p := range pathsOf(d.a, d.vulns) {
			older[d.a.ID+"|"+k] = p.page
		}
	}
	vs, err := e.svc.Views(ctx, ViewFilter{OpenOnly: true})
	if err != nil || len(vs) == 0 {
		t.Fatalf("views: %d %v", len(vs), err)
	}
	var named, notStored, saysNone, olderNone int
	var unconfirmed []View
	for _, v := range vs {
		stored, text := v.Finding.Fix.Version, v.FixText()
		if v.Finding.Verified == VerifiedNo {
			unconfirmed = append(unconfirmed, v)
		}
		if stored == "" {
			continue
		}
		named++
		if !strings.Contains(text, stored) {
			notStored++
			t.Errorf("%s on %s: the words %q do not carry the stored fix %q", v.Finding.CVE, v.Finding.AssetID, text, stored)
		}
		if strings.Contains(text, "No fixed release") || strings.Contains(text, "not known for this device") {
			saysNone++
		}
		if old, ok := older[v.Finding.AssetID+"|"+v.Finding.CVE+"|"+v.Finding.SoftwareID]; ok && old == "" {
			olderNone++
		}
	}
	if len(unconfirmed) < 9 {
		t.Fatalf("%d unconfirmed findings, want 9 to confirm", len(unconfirmed))
	}
	notConfirmed := 0
	for _, v := range unconfirmed[:9] {
		if _, err := e.svc.Verify(ctx, v.Finding.ID, "I checked the version on the device.", "it@example.com"); err != nil {
			t.Fatal(err)
		}
		c, err := e.svc.View(ctx, v.Finding.ID)
		if err != nil {
			t.Fatal(err)
		}
		text := c.ConfirmText()
		if !strings.HasPrefix(text, "Confirmed by a person on this box on ") || strings.Contains(text, "example.com") || strings.Contains(text, "@") || strings.Contains(text, "Not confirmed") {
			notConfirmed++
			t.Errorf("%s: %q", v.Finding.CVE, text)
		}
	}
	t.Logf("open findings %d, %d with a stored release; words not carrying it: %d; saying no fixed release: %d; the finding page's own reader names none for: %d; person-confirmed not read as confirmed: %d of 9",
		len(vs), named, notStored, saysNone, olderNone, notConfirmed)
	if notStored+saysNone+notConfirmed != 0 {
		t.Fatal("the words of a view disagree with the page")
	}
	if olderNone != 1 {
		t.Errorf("the older reader names no release for %d findings the stored fix names one for, want only the ESXi one", olderNone)
	}
}
