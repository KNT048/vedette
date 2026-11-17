package inventory_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// INV-41 (6) (J3, kien G15): a person says the OpenSSH row a scan reported is not installed. It is a correction of that row that
// replaces it with nothing: matching reads neither, MatchInput names the row for findings, a rescan at the same version keeps it, a
// rescan at another version is a new install that matches (the correction rests and says so), Set again moves it onto the new reading,
// a version edit makes it an ordinary correction, and Clear brings the row back. Audited; a row a person added is removed instead.
func TestINV41_NotInstalledReplacesTheReportedRowWithNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"openbsd|openssh": {"CVE-2026-123158"}}}))
	hint := observe.AssetHint{IP: netip.MustParseAddr("192.168.18.1")}
	scan := func(version string) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, []observe.Software{
			{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: version, CPE: "cpe:/a:openbsd:openssh:" + version, KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9},
		}); err != nil {
			t.Fatal(err)
		}
	}
	scan("10.2")
	dev := deviceAt(t, e, hint.IP)
	scanned, _ := swViews(t, e, dev)
	notInstalled := func(sid string) {
		t.Helper()
		if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, sid, inventory.SoftwareEdit{NotInstalled: true}); err != nil {
			t.Fatal(err)
		}
	}

	wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{NotInstalled: true, Version: ptr("10.2")}), 400, "bad_edit")
	e.ev.reset()
	notInstalled(scanned.ID)
	if len(e.ev.named(inventory.EventSoftwareChanged)) != 1 {
		t.Fatal("Not installed must match the device again (inventory.software.changed)")
	}
	m, _, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Software) != 0 {
		t.Fatalf("matching must read neither the row nor the correction: %+v", m.Software)
	}
	if len(m.NotInstalled) != 1 || m.NotInstalled[0].ID != scanned.ID || m.NotInstalled[0].Version != "10.2" || m.NotInstalled[0].Source != "nmap" ||
		!slices.Equal(m.NotInstalled[0].KevKeys, []string{"openbsd|openssh"}) ||
		!strings.HasPrefix(m.NotInstalled[0].Correction, "op@example.com said OpenSSH 10.2 (nmap) is not installed on ") {
		t.Fatalf("findings must get the row the person said is not installed, with the person's words: %+v", m.NotInstalled)
	}
	sc, mine := swViews(t, e, dev)
	if c := mine.Correction; c == nil || !c.NotInstalled || !c.Active || c.Disagrees || c.Detected == nil || c.Detected.ID != scanned.ID || c.SetBy != "op@example.com" ||
		len(mine.KevCVEs) != 0 || sc.CorrectedBy == nil || *sc.CorrectedBy != mine.ID {
		t.Fatalf("detail: scanned %+v, correction %+v %+v", sc, mine, mine.Correction)
	}
	notInstalled(scanned.ID) // the same again writes nothing
	if n := countOf(e.auditActions(), "inventory.mark_not_installed"); n != 1 {
		t.Fatalf("audit: %d mark_not_installed", n)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.mark_not_installed' AND user = 'op@example.com' AND detail = 'OpenSSH 10.2 (nmap) → not installed'`) != 1 {
		t.Fatal("the audit row must say what the scan read and that the person said it is not installed")
	}

	// A rescan at the same version keeps it.
	scan("10.2")
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); len(m.Software) != 0 || len(m.NotInstalled) != 1 {
		t.Fatalf("the next scan at the same version must keep it: %+v", m)
	}
	// A rescan at another version is a new install: it matches and names the resting correction; the device shows it not in use.
	scan("10.3")
	m, _, _ = e.svc.MatchInput(e.ctx(), dev)
	if len(m.Software) != 1 || m.Software[0].Version != "10.3" || len(m.NotInstalled) != 0 ||
		!strings.Contains(m.Software[0].Superseded, "op@example.com said OpenSSH 10.2 (nmap) is not installed on ") ||
		!strings.HasSuffix(m.Software[0].Superseded, "; nmap now reads OpenSSH 10.3, so Vedette uses that until the correction is set again") {
		t.Fatalf("a new install must match and name the resting correction: %+v", m)
	}
	sc, mine = swViews(t, e, dev)
	if c := mine.Correction; c == nil || !c.NotInstalled || c.Active || !c.Disagrees || c.Detected == nil || deref(c.Detected.Version) != "10.3" {
		t.Fatalf("the correction must show as not in use, the scan reading 10.3: %+v", mine.Correction)
	}
	// Set again on what the scan reads now: the 10.3 row is the one the person says is not there.
	notInstalled(sc.ID)
	m, _, _ = e.svc.MatchInput(e.ctx(), dev)
	if len(m.Software) != 0 || len(m.NotInstalled) != 1 || m.NotInstalled[0].Version != "10.3" {
		t.Fatalf("set again on 10.3: %+v", m)
	}
	if _, again := swViews(t, e, dev); again.ID != mine.ID || deref(again.Version) != "10.3" || !again.Correction.Active {
		t.Fatalf("set again moves the same correction: %+v", again)
	}
	// A version edit makes it an ordinary correction: the person now says what is installed.
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, mine.ID, inventory.SoftwareEdit{Version: ptr("10.3p1")}); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); len(m.Software) != 1 || m.Software[0].Source != "manual" || m.Software[0].Version != "10.3p1" || len(m.NotInstalled) != 0 {
		t.Fatalf("an ordinary correction again: %+v", m)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_software' AND detail = 'not installed → OpenSSH 10.3p1'`) != 1 {
		t.Fatal("the audit row must say it was not installed before")
	}
	// Mark it again, then Clear: the scanned row matches again.
	notInstalled(mine.ID)
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); len(m.Software) != 0 || len(m.NotInstalled) != 1 {
		t.Fatalf("not installed from the correction itself: %+v", m)
	}
	if err := e.svc.RemoveSoftware(e.ctx(), "op@example.com", dev, mine.ID); err != nil {
		t.Fatal(err)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); len(m.Software) != 1 || m.Software[0].Source != "nmap" || len(m.NotInstalled) != 0 {
		t.Fatalf("cleared: the scanned row is back: %+v", m)
	}
	if a := e.auditActions(); countOf(a, "inventory.mark_not_installed") != 3 || countOf(a, "inventory.clear_software_correction") != 1 {
		t.Fatalf("audit %v", a)
	}

	// A row a person added is removed instead (DELETE), never marked.
	if _, err := e.svc.AddSoftware(e.ctx(), "op@example.com", dev, inventory.AddInput{CatalogID: "openvpn-access-server"}); err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Detail(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Asset.Software {
		if s.Source == "manual" {
			wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, s.ID, inventory.SoftwareEdit{NotInstalled: true}), 400, "bad_edit")
		}
	}
}
