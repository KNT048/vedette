package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// correct sets the version of the one row of the product that source reported.
func (c *softwareCase) correct(source, version, pkg string) {
	c.t.Helper()
	c.e.tick(time.Minute)
	for _, s := range c.e.detail(c.dev).Asset.Software {
		if s.Source == source && s.Correction == nil {
			edit := inventory.SoftwareEdit{Version: &version}
			if pkg != "" {
				edit.PkgVersion = &pkg
			}
			if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev, s.ID, edit); err != nil {
				c.t.Fatal(err)
			}
			return
		}
	}
	c.t.Fatalf("no %s row", source)
}

func (c *softwareCase) sshLine() inventory.EffectiveSoftware {
	c.t.Helper()
	for _, l := range c.lines() {
		if l.Product == "OpenSSH" {
			return l
		}
	}
	c.t.Fatal("no line of OpenSSH")
	return inventory.EffectiveSoftware{}
}

// A person's version holds against an older reading, the same release written another way, and the old version a source keeps
// repeating; a newer reading from any source ends it, and the history says so (INV-52).
func TestINV52_CorrectionLapsesOnANewerReadingFromAnySource(t *testing.T) {
	t.Parallel()
	for _, src := range []observe.Source{observe.Agent, observe.SNMP, observe.Nmap, observe.Passive} {
		t.Run(string(src), func(t *testing.T) {
			t.Parallel()
			c := newSoftwareCase(t)
			c.report(src, "OpenSSH", "10.0", "")
			c.correct(string(src), "10.2", "")
			l := c.oneLine("manual", 1)
			if !l.Corrected || l.CorrectedFrom == nil || l.CorrectedFrom.Version != "10.0" || !l.CanCorrect {
				t.Fatalf("the correction is the line: %+v", l)
			}
			c.report(src, "OpenSSH", "10.0", "")   // the old version again: the correction is the one it replaced
			c.report(src, "OpenSSH", "10.2p1", "") // the same release as the person's, written with a patch level
			// the same release keeps the person's version; the agent reading it with its patch level is that version with more detail
			if l := c.sshLine(); src != observe.Agent && (l.Source != "manual" || l.Version != "10.2") || src == observe.Agent && (l.Source != "agent" || l.Version != "10.2p1") {
				t.Fatalf("same release keeps the person's version: %+v", l)
			}
			c.report(src, "OpenSSH", "10.1", "") // older
			if l := c.sshLine(); l.Source != "manual" || l.Version != "10.2" {
				t.Fatalf("an older reading keeps the person's version: %+v", l)
			}
			c.report(src, "OpenSSH", "banner-unknown", "") // cannot be compared
			if l := c.sshLine(); l.Source != "manual" || l.Version != "10.2" {
				t.Fatalf("an unparseable reading keeps the person's version: %+v", l)
			}
			if countOf(c.e.auditActions(), "inventory.software_correction_lapsed") != 0 {
				t.Fatal("nothing lapsed yet")
			}
			c.report(src, "OpenSSH", "10.3", "")
			l = c.sshLine()
			if l.Source != string(src) || l.Version != "10.3" || l.Corrected {
				t.Fatalf("a newer reading ends the correction: %+v", l)
			}
			if countOf(c.e.auditActions(), "inventory.software_correction_lapsed") != 1 {
				t.Fatalf("history: %v", c.e.auditActions())
			}
			var detail string
			if err := c.e.db.Reader().QueryRowContext(c.e.ctx(), `SELECT detail FROM core_audit WHERE action = 'inventory.software_correction_lapsed'`).Scan(&detail); err != nil {
				t.Fatal(err)
			}
			if want := "OpenSSH 10.2 → OpenSSH 10.3 (" + string(src) + ")"; detail != want {
				t.Fatalf("history says %q, want %q", detail, want)
			}
		})
	}
}

// A person who corrects a newer reading down is not undone when that source repeats it: it was read before the correction.
func TestINV52_ADownwardCorrectionSurvivesTheSameReading(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.5", "")
	c.correct("nmap", "10.2", "")
	c.report(observe.Nmap, "OpenSSH", "10.5", "")
	c.report(observe.Agent, "OpenSSH", "10.2p1", "")
	if l := c.oneLine("agent", 2); l.Version != "10.2p1" { // the agent confirms the person's release: its reading is the line
		t.Fatalf("%+v", l)
	}
}

// The corrected OS follows the same rule: a newer version of the same OS read after it ends it; older, the same, another OS or a
// range a scan only guesses keep it.
func TestINV52_CorrectedOSLapsesOnANewerReading(t *testing.T) {
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
	rec("Alpine Linux 3.15", observe.SNMP)
	dev := deviceAt(t, e, ip)
	e.tick(time.Minute)
	if err := e.svc.PatchDevice(e.ctx(), "op@example.com", dev, inventory.Patch{OS: ptr("Alpine Linux 3.20")}); err != nil {
		t.Fatal(err)
	}
	osNow := func() (string, bool) {
		d, err := e.svc.Detail(e.ctx(), dev)
		if err != nil {
			t.Fatal(err)
		}
		return d.Asset.OS.Value, d.Asset.OSCorrection != nil
	}
	for _, keep := range []struct {
		v   string
		src observe.Source
	}{{"Alpine Linux 3.15", observe.SNMP}, {"Alpine Linux 3.18", observe.Agent}, {"Alpine Linux 3.20", observe.SNMP}, {"Debian GNU/Linux 12", observe.Agent},
		{"Linux 4.15 - 5.19", observe.Nmap}, {"Alpine Linux", observe.Passive}} {
		rec(keep.v, keep.src)
		if v, corrected := osNow(); v != "Alpine Linux 3.20" || !corrected {
			t.Fatalf("%q from %s must keep the person's OS, the device says %q", keep.v, keep.src, v)
		}
	}
	rec("Alpine Linux 3.22", observe.Nmap) // a scan's guess never ends it
	if v, corrected := osNow(); v != "Alpine Linux 3.20" || !corrected {
		t.Fatalf("a scan guess must keep the person's OS, the device says %q", v)
	}
	rec("Alpine Linux 3.23", observe.Agent)
	if v, corrected := osNow(); v != "Alpine Linux 3.23" || corrected {
		t.Fatalf("a newer version ends the correction: %q %v", v, corrected)
	}
	if countOf(e.auditActions(), "inventory.os_correction_lapsed") != 1 {
		t.Fatalf("history: %v", e.auditActions())
	}
}

// Two installs a source reads at other releases (two ports, two kernels) are one line, the newest release; the other is listed under
// it with the differs note and still matches (INV-52).
func TestINV52_TwoInstallsOfOneSourceAreOneLine(t *testing.T) {
	t.Parallel()
	for _, src := range []observe.Source{observe.Agent, observe.Nmap} {
		t.Run(string(src), func(t *testing.T) {
			t.Parallel()
			c := newSoftwareCase(t)
			c.e.tick(time.Minute)
			items := []observe.Software{
				{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "8.9p1", Confidence: 0.9},
				{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "10.2p1", Confidence: 0.9},
			}
			if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, src, items); err != nil {
				t.Fatal(err)
			}
			c.dev = deviceAt(t, c.e, c.hint.IP)
			l := c.oneLine(string(src), 1)
			if l.Version != "10.2p1" || !l.Differs || l.AlsoSeen[0].Version != "8.9p1" || l.AlsoSeen[0].SameRelease || !l.CanCorrect {
				t.Fatalf("%+v", l)
			}
			m, _, err := c.e.svc.MatchInput(c.e.ctx(), c.dev)
			if err != nil {
				t.Fatal(err)
			}
			if len(m.Software) != 2 {
				t.Fatalf("both installs still match: %+v", m.Software)
			}
		})
	}
}

// A person who corrects a reading down is not undone when the source drops that reading and reads it again later (INV-52): only a
// release newer than both the person's and the one they overrode is an update.
func TestINV52_AReadingReadAgainIsNotAnUpdate(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.3", "")
	c.correct("nmap", "10.1", "")
	c.report(observe.Nmap, "Dropbear", "2024.86", "") // the scan misses OpenSSH once: its row goes
	c.report(observe.Nmap, "OpenSSH", "10.3", "")     // and reads the same wrong banner again
	if l := c.sshLine(); l.Source != "manual" || l.Version != "10.1" {
		t.Fatalf("the reading the person overrode, read again, keeps their version: %+v", l)
	}
	c.report(observe.Nmap, "OpenSSH", "10.4", "")
	if l := c.sshLine(); l.Source != "nmap" || l.Version != "10.4" {
		t.Fatalf("a newer release than both ends it: %+v", l)
	}
}

// A distribution's security update of the same upstream version is a newer release (INV-52): Debian and Alpine package revisions.
func TestINV52_APackageRevisionUpdateEndsACorrection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ upstream, old, person, newer string }{
		{"9.2p1", "1:9.2p1-2+deb12u1", "1:9.2p1-2+deb12u2", "1:9.2p1-2+deb12u4"},
		{"10.2p1", "10.2_p1-r0", "10.2_p1-r1", "10.2_p1-r3"},
	} {
		c := newSoftwareCase(t)
		pkg := func(release string) { // the agent's package database row (the package source is the distribution's lower-case name)
			t.Helper()
			c.e.tick(time.Minute)
			it := observe.Software{Display: "OpenSSH", Vendor: "Vendor OpenSSH", Product: "OpenSSH", Version: tc.upstream, Confidence: 0.9,
				Packaged: true, PkgVersion: release, PkgSource: "openssh"}
			if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, observe.Agent, []observe.Software{it}); err != nil {
				t.Fatal(err)
			}
			c.dev = deviceAt(t, c.e, c.hint.IP)
		}
		pkg(tc.old)
		c.correct("agent", tc.upstream, tc.person)
		pkg(tc.old) // the old package again: kept
		if l := c.sshLine(); l.Source != "manual" || l.PkgVersion != tc.person {
			t.Fatalf("%s: %+v", tc.person, l)
		}
		pkg(tc.newer)
		if l := c.sshLine(); l.Source != "agent" || l.PkgVersion != tc.newer || l.Corrected {
			t.Fatalf("%s: the update ends the correction: %+v", tc.newer, l)
		}
	}
}
