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

// nmap's fingerprint guesses "Android 9 - 10 (Linux 4.9 - 4.14)"; the device's SNMP answer (net-snmp's uname layout) says
// Alpine Linux and wins over the guess (INV-1); a person's correction wins over both, drives matching, survives later reads, says when
// the sources disagree, and can be cleared (INV-41).
func TestINV41_CorrectedOSWinsDrivesMatchingAndClears(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.18.1")
	rec := func(v string, src observe.Source) {
		t.Helper()
		e.tick(time.Minute)
		if err := e.svc.Record(e.ctx(), []observe.Observation{{AssetHint: observe.AssetHint{IP: ip}, Field: observe.OS, Value: v, Source: src, Confidence: 0.9}}); err != nil {
			t.Fatal(err)
		}
	}
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Alpine Linux", observe.SNMP)
	id := e.count(`SELECT count(*) FROM inv_asset`) // one device
	if id != 1 {
		t.Fatalf("%d devices", id)
	}
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	dev := addrs[ip.String()]
	detail := func() inventory.Detail {
		t.Helper()
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := detail(); d.Asset.OS == nil || d.Asset.OS.Value != "Alpine Linux" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("SNMP's OS must beat nmap's guess: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}

	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine <b>")}), 400, "bad_os")
	e.ev.reset()
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("  Alpine Linux 3.23 ")}); err != nil {
		t.Fatal(err)
	}
	if ev := e.ev.named(inventory.EventAssetUpdated); len(ev) != 1 || !ev[0].Data.(inventory.AssetEvent).Match {
		t.Fatalf("a corrected OS must match the device again: %+v", ev)
	}
	d := detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" || d.Asset.OS.Source != "manual" {
		t.Fatalf("the correction must win: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || c.Value != "Alpine Linux 3.23" || c.Detected == nil || c.Detected.Value != "Alpine Linux" || c.Detected.Source != "snmp" || c.Disagrees {
		t.Fatalf("correction %+v (SNMP's Alpine Linux does not contradict Alpine Linux 3.23)", c)
	}
	m, ok, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil || !ok || m.OS != "Alpine Linux 3.23" || m.SNMPOS != "Alpine Linux 3.23" || m.StatedOS != "Alpine Linux 3.23" || m.AgentOS != "" || m.ManualOS != "Alpine Linux 3.23" ||
		!strings.HasPrefix(m.OSCorrection, "op@example.com set the OS to Alpine Linux 3.23 on ") {
		t.Fatalf("matching must read the person's OS: %+v %v %v", m, ok, err)
	}

	// The next reads change nothing shown; one that reads another OS makes the device say so.
	rec("Android 9 - 10 (Linux 4.9 - 4.14)", observe.Nmap)
	rec("Ubuntu", observe.SNMP)
	d = detail()
	if d.Asset.OS.Value != "Alpine Linux 3.23" {
		t.Fatalf("the correction must survive the next scan: %+v", d.Asset.OS)
	}
	if c := d.Asset.OSCorrection; c == nil || !c.Disagrees || c.Detected.Value != "Ubuntu" {
		t.Fatalf("the device must say the last read disagrees: %+v", c)
	}

	// The same value again writes nothing; clearing brings back what the sources read.
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine Linux 3.23")}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("")}); err != nil {
		t.Fatal(err)
	}
	if d := detail(); d.Asset.OS.Value != "Ubuntu" || d.Asset.OS.Source != "snmp" || d.Asset.OSCorrection != nil {
		t.Fatalf("cleared: %+v %+v", d.Asset.OS, d.Asset.OSCorrection)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); m.SNMPOS != "Ubuntu" || m.ManualOS != "" {
		t.Fatalf("cleared: matching reads the sources again: %+v", m)
	}
	a := e.auditActions()
	if n := countOf(a, "inventory.correct_os"); n != 1 || countOf(a, "inventory.clear_os") != 1 {
		t.Fatalf("audit %v", a)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_os' AND user = 'op@example.com' AND detail = 'Alpine Linux → Alpine Linux 3.23'`) != 1 {
		t.Fatal("the audit row must say who changed what to what")
	}
}

// INV-41: a person corrects the OpenSSH row a scan reported (package release 10.2_p1-r1). The correction replaces exactly that
// row for matching, and its re-reports; a later scan that reads another version is another row, which matches and makes the device
// say the scan disagrees. The correction can change the product (the wrong row's CVEs stop matching); clearing it brings the scanned
// row back.
func TestINV41_CorrectedSoftwareReplacesTheScannedRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withKEV(fakeKEV{cves: map[string][]string{"openbsd|openssh": {"CVE-2026-123158"}, "matt johnston|dropbear ssh": {"CVE-2026-0002"}}}))
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

	wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{}), 400, "bad_edit")
	wantAPIError(t, e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{PkgVersion: ptr("10.2 <x>")}), 400, "bad_pkg_version")
	e.ev.reset()
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, scanned.ID, inventory.SoftwareEdit{Version: ptr("10.2p1"), PkgVersion: ptr("10.2_p1-r1")}); err != nil {
		t.Fatal(err)
	}
	if len(e.ev.named(inventory.EventSoftwareChanged)) != 1 {
		t.Fatal("a correction must match the device again (inventory.software.changed)")
	}
	sw := matchRows(t, e, dev)
	if len(sw) != 1 || sw[0].Source != "manual" || sw[0].ReportedSource != "nmap" || sw[0].Version != "10.2p1" || sw[0].PkgVersion != "10.2_p1-r1" ||
		sw[0].CPE != "cpe:/a:openbsd:openssh:10.2" || !slices.Equal(sw[0].KevKeys, []string{"openbsd|openssh"}) {
		t.Fatalf("matching must read only the correction, with what the person kept: %+v", sw)
	}
	if !strings.HasPrefix(sw[0].Correction, "op@example.com corrected OpenSSH 10.2 (nmap) to OpenSSH 10.2p1 (package 10.2_p1-r1) on ") {
		t.Fatalf("the correction names the person for the findings history: %q", sw[0].Correction)
	}
	scanned, mine := swViews(t, e, dev)
	if mine.Correction == nil || mine.Correction.Detected == nil || mine.Correction.Detected.ID != scanned.ID || !mine.Correction.Disagrees || mine.Correction.SetBy != "op@example.com" ||
		mine.PkgVersion == nil || *mine.PkgVersion != "10.2_p1-r1" || scanned.CorrectedBy == nil || *scanned.CorrectedBy != mine.ID {
		t.Fatalf("detail: scanned %+v, correction %+v", scanned, mine)
	}

	// A re-report of the same row is replaced too; a scan that reads another version is another row: it matches, and the device says so.
	scan("10.2")
	if sw := matchRows(t, e, dev); len(sw) != 1 || sw[0].Source != "manual" {
		t.Fatalf("the correction must survive the next scan: %+v", sw)
	}
	// The source now reads another version: the person's entry stays in use (INV-50) and the 10.1 reading matches too; the device
	// says what the scan reads now.
	scan("10.1")
	if rows := matchRows(t, e, dev); len(rows) != 2 {
		t.Fatalf("matching reads the entry and the 10.1 reading (another release): %+v", rows)
	}
	if m, _, _ := e.svc.MatchInput(e.ctx(), dev); len(m.StaleCorrections) != 0 {
		t.Fatalf("stale corrections %v", m.StaleCorrections)
	}
	if _, mine := swViews(t, e, dev); mine.Correction == nil || !mine.Correction.Active || mine.Correction.Detected == nil || *mine.Correction.Detected.Version != "10.1" || !mine.Correction.Disagrees {
		t.Fatalf("the device shows the entry in use and the scan reading 10.1: %+v", mine.Correction)
	}
	// Setting it again (here on the correction itself) puts it on what the scan reads now; a version change without a package release
	// drops the old release (review r1 L3).
	_, mine = swViews(t, e, dev)
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, mine.ID, inventory.SoftwareEdit{Version: ptr("10.1")}); err != nil {
		t.Fatal(err)
	}
	if sc, again := swViews(t, e, dev); again.ID != mine.ID || *again.Version != "10.1" || again.PkgVersion != nil || !again.Correction.Active || again.Correction.Disagrees ||
		sc.CorrectedBy == nil || *sc.CorrectedBy != mine.ID {
		t.Fatalf("set again: %+v / %+v", again, sc)
	}

	// Another product: the wrong row's CVEs stop matching on this row (the 10.1 row the scan reads now still matches OpenSSH).
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, mine.ID, inventory.SoftwareEdit{Vendor: "Matt Johnston", Product: "Dropbear SSH", Version: ptr("2024.86")}); err != nil {
		t.Fatal(err)
	}
	var mineNow inventory.MatchSoftware
	for _, r := range matchRows(t, e, dev) {
		if r.Source == "manual" {
			mineNow = r
		}
	}
	if !slices.Equal(mineNow.KevKeys, []string{"matt johnston|dropbear ssh"}) || mineNow.ReportedSource != "" || mineNow.CPE != "" {
		t.Fatalf("matching must read the corrected product, with nothing of the old one: %+v", mineNow)
	}

	// Clearing: the scanned row matches again.
	_, mine = swViews(t, e, dev)
	if err := e.svc.RemoveSoftware(e.ctx(), "op@example.com", dev, mine.ID); err != nil {
		t.Fatal(err)
	}
	if sw := matchRows(t, e, dev); len(sw) != 1 || sw[0].Source != "nmap" || sw[0].Version != "10.1" {
		t.Fatalf("cleared: the scanned row is back: %+v", sw)
	}
	a := e.auditActions()
	if countOf(a, "inventory.correct_software") != 3 || countOf(a, "inventory.clear_software_correction") != 1 {
		t.Fatalf("audit %v", a)
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.correct_software' AND user = 'op@example.com' AND detail = 'OpenSSH 10.2 (nmap) → OpenSSH 10.2p1 (package 10.2_p1-r1)'`) != 1 {
		t.Fatal("the first audit row must say what the scan read and what the person set")
	}
}

// Review r1 H1 of #950: a correction replaces exactly the row the person corrected. Another source's row of the product (.181: the
// nmap row corrected while the agent's packaged row stands), another version from the same agent (a Debian box with two kernels) and
// another version from the same scan (OpenSSH on two ports) keep matching.
func TestINV41_ACorrectionReplacesOnlyItsRow(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := netip.MustParseAddr("192.168.18.181")
	hint := observe.AssetHint{IP: at}
	if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Nmap, []observe.Software{
		{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2p1 Ubuntu 2ubuntu3.8", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9},
		{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.9p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9}, // a container on 2222/tcp
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Agent, []observe.Software{
		{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2p1", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.95,
			Packaged: true, PkgVersion: "1:10.2p1-2ubuntu3.8", PkgSource: "openssh"},
		{Display: "Linux kernel", Vendor: "Linux", Product: "Linux kernel", Version: "6.12.116", KevKeys: []string{"linux|kernel"}, Confidence: 0.95,
			Packaged: true, PkgVersion: "6.12.116-1", PkgSource: "linux"},
		{Display: "Linux kernel", Vendor: "Linux", Product: "Linux kernel", Version: "6.12.117", KevKeys: []string{"linux|kernel"}, Confidence: 0.95,
			Packaged: true, PkgVersion: "6.12.117-1", PkgSource: "linux"},
	}); err != nil {
		t.Fatal(err)
	}
	dev := deviceAt(t, e, at)
	idOf := func(source, version string) string {
		t.Helper()
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range d.Asset.Software {
			if r.Source == source && r.Version != nil && *r.Version == version {
				return r.ID
			}
		}
		t.Fatalf("no %s row %s", source, version)
		return ""
	}
	for _, c := range []struct{ source, version, to string }{
		{"nmap", "10.2p1 Ubuntu 2ubuntu3.8", "10.2p1"},
		{"agent", "6.12.116", "6.12.116"},
	} {
		if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, idOf(c.source, c.version), inventory.SoftwareEdit{Version: ptr(c.to), PkgVersion: ptr("9.9-1")}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, r := range matchRows(t, e, dev) {
		got = append(got, r.Source+" "+r.Version)
	}
	slices.Sort(got)
	want := []string{"agent 6.12.117", "manual 10.2p1", "manual 6.12.116", "nmap 8.9p1"}
	if !slices.Equal(got, want) {
		t.Fatalf("rows matched %v, want %v (the two corrected rows go, and the agent's own 10.2p1 is the release the correction says)", got, want)
	}
	// .181 (review r2 M-A): with the nmap row corrected to 10.2p1, the agent's own 10.2p1 row is corrected too (its package release).
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, idOf("agent", "10.2p1"), inventory.SoftwareEdit{PkgVersion: ptr("1:10.2p1-2ubuntu3.9")}); err != nil {
		t.Fatalf("the second source's row must be correctable: %v", err)
	}
	got = nil // the entry that corrects the agent's row ranks with the agent rows: the container's 8.9p1 next to it still matches (INV-50)
	for _, r := range matchRows(t, e, dev) {
		if r.Source == "manual" && r.Version == "10.2p1" {
			got = append(got, "manual 10.2p1") // two corrections of one release: one of them is the line, the other is listed under it
			continue
		}
		got = append(got, r.Source+" "+r.Version+" "+r.ReportedSource+" "+r.PkgVersion)
	}
	slices.Sort(got)
	want = []string{"agent 6.12.117  6.12.117-1", "manual 10.2p1", "manual 6.12.116 agent 9.9-1", "nmap 8.9p1  "}
	if !slices.Equal(got, want) {
		t.Fatalf("rows matched %q, want %q", got, want)
	}
}

// Review r2 M-A of #950: nmap and the agent both read OpenSSH 7.4; both rows are corrected to 9.6 (the same release), and neither
// original matches. Corrections never collide with each other, with the rows they correct, or with a declared row.
func TestINV41_TwoSourcesCorrectedToTheSameVersion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := netip.MustParseAddr("192.168.18.60")
	ssh := []observe.Software{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "7.4", KevKeys: []string{"openbsd|openssh"}, Confidence: 0.9}}
	for _, src := range []observe.Source{observe.Nmap, observe.Agent} {
		if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: at}, src, ssh); err != nil {
			t.Fatal(err)
		}
	}
	dev := deviceAt(t, e, at)
	detail, err := e.svc.Detail(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range detail.Asset.Software {
		if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, r.ID, inventory.SoftwareEdit{Version: ptr("9.6"), PkgVersion: ptr("1:9.6p1-3ubuntu13.14")}); err != nil {
			t.Fatalf("%s: %v", r.Source, err)
		}
	}
	sw := matchRows(t, e, dev)
	if len(sw) != 1 || sw[0].Source != "manual" || sw[0].Version != "9.6" { // the newest correction is the one effective row (INV-50, INV-52)
		t.Fatalf("one effective row, no original matches: %+v", sw)
	}
	if e.count(`SELECT count(*) FROM inv_software WHERE corrects IS NOT NULL`) != 2 {
		t.Fatal("one correction per reported row")
	}
}

// Review r2 M-B of #950: the agent stops reporting the package (removed, or its row expired): the correction rests and stops matching,
// the device says so, and the findings history can name it.
func TestINV41_TheAgentStopsReportingTheCorrectedPackage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := netip.MustParseAddr("192.168.18.61")
	hint := observe.AssetHint{IP: at}
	report := func(items ...observe.Software) {
		t.Helper()
		if err := e.svc.ReplaceSoftware(e.ctx(), hint, observe.Agent, items); err != nil {
			t.Fatal(err)
		}
	}
	curl := observe.Software{Display: "curl", Vendor: "haxx", Product: "curl", Version: "8.5.0", KevKeys: []string{"haxx|curl"}, Confidence: 0.95}
	vim := observe.Software{Display: "vim", Vendor: "vim", Product: "vim", Version: "9.1", Confidence: 0.95}
	report(curl, vim)
	dev := deviceAt(t, e, at)
	var curlID string
	for _, r := range matchRows(t, e, dev) {
		if r.Product == "curl" {
			curlID = r.ID
		}
	}
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, curlID, inventory.SoftwareEdit{Version: ptr("8.5.1")}); err != nil {
		t.Fatal(err)
	}
	report(vim)
	m, _, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Software) != 1 || m.Software[0].Product != "vim" {
		t.Fatalf("a correction of a package the agent no longer reports must not match: %+v", m.Software)
	}
	if len(m.StaleCorrections) != 1 || !strings.HasSuffix(m.StaleCorrections[0], "; agent reports it no more, so Vedette does not use the correction") {
		t.Fatalf("stale %q", m.StaleCorrections)
	}
	if _, mine := swViews(t, e, dev); mine.Correction == nil || mine.Correction.Active || mine.Correction.Detected != nil || !mine.Correction.Disagrees {
		t.Fatalf("the device shows the correction not in use: %+v", mine.Correction)
	}
}

// Review r1 M1 of #950: a version-only correction of an agent's packaged row keeps the row's distribution semantics: matching reads it
// as built by the agent's packages (ReportedSource agent, Packaged, the source package, the CPE); the package release of the old
// version is dropped, so no distribution fix is read against it; a package-only correction keeps the version.
func TestINV41_ACorrectionKeepsWhatThePersonDidNotChange(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	at := netip.MustParseAddr("192.168.18.50")
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{IP: at}, observe.Agent, []observe.Software{
		{Display: "OpenSSL", Vendor: "OpenSSL", Product: "OpenSSL", Version: "3.0.13", CPE: "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*", KevKeys: []string{"openssl|openssl"},
			Confidence: 0.95, Packaged: true, PkgVersion: "3.0.13-0ubuntu3.5", PkgSource: "openssl"},
	}); err != nil {
		t.Fatal(err)
	}
	dev := deviceAt(t, e, at)
	row := matchRows(t, e, dev)[0]
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, row.ID, inventory.SoftwareEdit{Version: ptr("3.0.14")}); err != nil {
		t.Fatal(err)
	}
	sw := matchRows(t, e, dev)
	if len(sw) != 1 || sw[0].Source != "manual" || sw[0].ReportedSource != "agent" || !sw[0].Packaged || sw[0].PkgSource != "openssl" ||
		sw[0].PkgVersion != "" || sw[0].CPE != row.CPE || sw[0].Version != "3.0.14" {
		t.Fatalf("version-only correction: %+v", sw)
	}
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", dev, sw[0].ID, inventory.SoftwareEdit{PkgVersion: ptr("3.0.14-0ubuntu1")}); err != nil {
		t.Fatal(err)
	}
	if sw := matchRows(t, e, dev); sw[0].Version != "3.0.14" || sw[0].PkgVersion != "3.0.14-0ubuntu1" || sw[0].PkgSource != "openssl" || !sw[0].Packaged {
		t.Fatalf("package-only correction: %+v", sw)
	}
}

func deviceAt(t *testing.T, e *env, ip netip.Addr) string {
	t.Helper()
	addrs, err := e.svc.AddressMap(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	return addrs[ip.String()]
}

func matchRows(t *testing.T, e *env, dev string) []inventory.MatchSoftware {
	t.Helper()
	m, ok, err := e.svc.MatchInput(e.ctx(), dev)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	return m.Software
}

// swViews is the device detail's reported row and the person's correction (the last of each).
func swViews(t *testing.T, e *env, dev string) (scanned, mine inventory.SoftwareView) {
	t.Helper()
	d, err := e.svc.Detail(e.ctx(), dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Asset.Software {
		if s.Source == "manual" {
			mine = s
		} else {
			scanned = s
		}
	}
	return scanned, mine
}

func countOf(list []string, v string) int {
	n := 0
	for _, x := range list {
		if x == v {
			n++
		}
	}
	return n
}
