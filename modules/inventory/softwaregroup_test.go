package inventory_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// softwareCase is one device whose software sources are driven by the test.
type softwareCase struct {
	t    *testing.T
	e    *env
	hint observe.AssetHint
	dev  string
}

func newSoftwareCase(t *testing.T) *softwareCase {
	t.Helper()
	e := newEnv(t)
	return &softwareCase{t: t, e: e, hint: observe.AssetHint{IP: netip.MustParseAddr("192.168.30.1")}}
}

func (c *softwareCase) report(src observe.Source, product, version, pkg string) {
	c.t.Helper()
	c.e.tick(time.Minute)
	it := observe.Software{Display: product, Vendor: "Vendor " + product, Product: product, Version: version, Confidence: 0.9}
	if pkg != "" {
		it.Packaged, it.PkgVersion, it.PkgSource = true, pkg, product
	}
	if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, src, []observe.Software{it}); err != nil {
		c.t.Fatal(err)
	}
	c.dev = deviceAt(c.t, c.e, c.hint.IP)
}

// enter is a person's entry on the row the scan reported.
func (c *softwareCase) enter() {
	c.t.Helper()
	c.e.tick(time.Minute)
	d := c.e.detail(c.dev)
	for _, s := range d.Asset.Software {
		if s.Source == "nmap" {
			version, pkg := "10.2", "10.2_p1-r1"
			edit := inventory.SoftwareEdit{Version: &version, PkgVersion: &pkg}
			if err := c.e.svc.EditSoftware(c.e.ctx(), "op@example.com", c.dev, s.ID, edit); err != nil {
				c.t.Fatal(err)
			}
			return
		}
	}
	c.t.Fatal("no nmap row")
}

func (c *softwareCase) lines() []inventory.EffectiveSoftware {
	c.t.Helper()
	l, err := c.e.svc.EffectiveSoftware(c.e.ctx(), c.dev)
	if err != nil {
		c.t.Fatal(err)
	}
	return l
}

func (c *softwareCase) oneLine(wantSource string, wantListed int) inventory.EffectiveSoftware {
	c.t.Helper()
	l := c.lines()
	if len(l) != 1 || l[0].Source != wantSource || len(l[0].AlsoSeen) != wantListed {
		c.t.Fatalf("want one %s line with %d other sources, got %+v", wantSource, wantListed, l)
	}
	return l[0]
}

// A device whose agent, the person's entry and a scan banner all read OpenSSH: one line, the agent's reading, the others listed, no notice.
func TestINV50_ThreeSourcesOneLine(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.2", "")
	c.enter()
	c.report(observe.Agent, "OpenSSH", "10.2p1", "10.2_p1-r1")
	l := c.oneLine("agent", 2)
	if l.Differs {
		t.Fatalf("the same release read three ways is not a disagreement: %+v", l)
	}
	m, ok, err := c.e.svc.MatchInput(c.e.ctx(), c.dev)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	shadowed := map[string]string{}
	for _, sw := range m.Software {
		shadowed[sw.Source] = sw.ShadowedBy
	}
	if len(m.Software) != 2 || shadowed["agent"] != "" || shadowed["manual"] != l.ID {
		t.Fatalf("matching rows: %+v", m.Software)
	}
	for _, s := range l.AlsoSeen {
		if !s.SameRelease || s.Source == "agent" {
			t.Fatalf("source %+v", s)
		}
	}
	if l.AlsoSeen[0].Source != "manual" || l.AlsoSeen[1].Source != "nmap" {
		t.Fatalf("sources strongest first: %+v", l.AlsoSeen)
	}
}

// The person's entry and the banner only: the entry is shown; a banner of the same release gives no notice.
func TestINV50_EnteredAndBannerSameRelease(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.2", "")
	c.enter()
	c.report(observe.Nmap, "OpenSSH", "10.2", "") // the next scan
	l := c.oneLine("manual", 1)
	if l.Differs || l.Version != "10.2" || l.PkgVersion != "10.2_p1-r1" || !l.AlsoSeen[0].SameRelease {
		t.Fatalf("%+v", l)
	}
}

// A weaker source that reads another release, newer than the entry, is the one notice; the same release is not.
func TestINV50_RealDifferenceIsNoticed(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.2", "")
	c.enter()
	c.report(observe.SNMP, "OpenSSH", "9.8", "")
	l := c.oneLine("manual", 2)
	if !l.Differs || l.AlsoSeen[0].Source != "snmp" || l.AlsoSeen[0].Version != "9.8" || l.AlsoSeen[0].SameRelease || !l.AlsoSeen[1].SameRelease {
		t.Fatalf("snmp reads another release: %+v", l)
	}
}

// The person's entry stays the effective row when its scan later reads another version (INV-50): the banner is listed as another
// release and differs is set; matching follows the same row.
func TestINV50_EntryStaysWhenTheBannerChanges(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.2", "")
	c.enter()
	c.report(observe.Nmap, "OpenSSH", "10.3", "")
	l := c.oneLine("manual", 1)
	if !l.Differs || l.Version != "10.2" || l.AlsoSeen[0].Version != "10.3" || l.AlsoSeen[0].SameRelease {
		t.Fatalf("%+v", l)
	}
	m, _, err := c.e.svc.MatchInput(c.e.ctx(), c.dev)
	if err != nil {
		t.Fatal(err)
	}
	for _, sw := range m.Software {
		if (sw.Source == "manual") != (sw.ShadowedBy == "") || sw.Source == "nmap" && sw.ShadowedBy != l.ID {
			t.Fatalf("matching rows follow the effective row: %+v", m.Software)
		}
	}
}

// Software of one CPE application is one software, whatever the vendor and product names say.
func TestINV50_SameCPEIsOneSoftware(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.e.tick(time.Minute)
	if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, observe.Nmap, []observe.Software{{Display: "OpenSSH 10.2", Vendor: "openbsd", Product: "openssh", Version: "10.2", CPE: "cpe:/a:openbsd:openssh:10.2", Confidence: 0.8}}); err != nil {
		t.Fatal(err)
	}
	c.e.tick(time.Minute)
	if err := c.e.svc.ReplaceSoftware(c.e.ctx(), c.hint, observe.Agent, []observe.Software{{Display: "OpenSSH server", Vendor: "OpenBSD Project", Product: "OpenSSH Server", Version: "10.2p1", CPE: "cpe:/a:openbsd:openssh:10.2p1", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	c.dev = deviceAt(t, c.e, c.hint.IP)
	l := c.oneLine("agent", 1)
	if l.Differs || !l.AlsoSeen[0].SameRelease {
		t.Fatalf("%+v", l)
	}
}

// The strongest reading that disagrees decides; a weaker newer one does not replace it.
func TestINV50_StrongestDisagreeingSourceDecides(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.SNMP, "OpenSSH", "9.8", "")
	c.report(observe.Nmap, "OpenSSH", "10.3", "")
	c.report(observe.Agent, "OpenSSH", "10.2p1", "10.2_p1-r1")
	// the agent is the shown row and is the newest, so no weaker reading is newer: no notice
	if l := c.oneLine("agent", 2); l.Differs {
		t.Fatalf("%+v", l)
	}
	c.report(observe.SNMP, "OpenSSH", "9.8", "") // snmp reads again, now newer than the agent
	l := c.oneLine("agent", 2)
	if !l.Differs || l.AlsoSeen[0].Source != "snmp" {
		t.Fatalf("the strongest disagreeing source is snmp: %+v", l.Differs)
	}
}

// Debian and RPM package releases are the same release as their upstream version.
func TestINV50_DistributionReleaseForms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ banner, upstream, pkg string }{
		{"9.2", "9.2p1", "1:9.2p1-2+deb12u3"},
		{"8.7", "8.7p1", "8.7p1-38.el9"},
		{"9.6p1 Ubuntu 3ubuntu13.14", "9.6p1", "1:9.6p1-3ubuntu13.14"},
	} {
		c := newSoftwareCase(t)
		c.report(observe.Nmap, "OpenSSH", tc.banner, "")
		c.report(observe.Agent, "OpenSSH", tc.upstream, tc.pkg)
		l := c.oneLine("agent", 1)
		if l.Differs || !l.AlsoSeen[0].SameRelease {
			t.Fatalf("%s vs %s: %+v", tc.banner, tc.pkg, l)
		}
		c.report(observe.Nmap, "OpenSSH", "8.0", "")
		if l := c.oneLine("agent", 1); l.AlsoSeen[0].SameRelease || !l.Differs {
			t.Fatalf("8.0 is not %s: %+v", tc.pkg, l)
		}
	}
}

// Two products are never one software.
func TestINV50_TwoProductsStayTwoLines(t *testing.T) {
	t.Parallel()
	c := newSoftwareCase(t)
	c.report(observe.Nmap, "OpenSSH", "10.2", "")
	c.report(observe.Agent, "Dropbear", "2024.86", "")
	if l := c.lines(); len(l) != 2 || len(l[0].AlsoSeen) != 0 || len(l[1].AlsoSeen) != 0 {
		t.Fatalf("%+v", l)
	}
}
