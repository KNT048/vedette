package sensoractive

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/versionscheme"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

func hostOf(t *testing.T, name string) host {
	t.Helper()
	hosts, err := parseNmapXML(fixture(t, name))
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%s: %v %d hosts", name, err, len(hosts))
	}
	return hosts[0]
}

func osOf(h host) string {
	for _, o := range deviceObservations(h, nmapargv.Normal) {
		if o.Field == observe.OS {
			return o.Value
		}
	}
	return ""
}

// What a device states about its firmware without a login becomes its OS line and a software row with the CPE NVD names the
// product by: an iLO's /xmldata, an ESXi's service content (the build names the update), and nothing when the device says nothing,
// something that is not a version, or is not an ESXi host.
func TestStatedFirmwareOfDevices(t *testing.T) {
	t.Parallel()
	type want struct {
		os, display, vendor, product, version, cpe string
		guess                                      bool
	}
	for _, c := range []struct {
		fixture string
		want    *want
	}{
		{"ilo.xml", &want{os: "HPE iLO 4 firmware 2.77", display: "HPE iLO 4 firmware 2.77", vendor: "hp", product: "integrated lights-out 4 firmware", version: "2.77", cpe: "cpe:2.3:o:hp:integrated_lights-out_4_firmware:2.77:*:*:*:*:*:*:*"}},
		{"esxi.xml", &want{os: "VMware ESXi 8.0 Update 3 (build 24022510)", display: "VMware ESXi 8.0 Update 3 (build 24022510)", vendor: "vmware", product: "esxi", version: "8.0", cpe: "cpe:2.3:o:vmware:esxi:8.0:update_3:*:*:*:*:*:*"}},
		// a build the table does not list is shown with the version the host stated and is never matched: no CPE, a guess row
		{"esxi_unlisted_build.xml", &want{os: "VMware ESXi 8.0.3 (build 99999999)", display: "VMware ESXi 8.0.3 (build 99999999)", vendor: "vmware", product: "esxi", version: "8.0.3", guess: true}},
		{"ilo_junk.xml", nil},
		{"esxi_nobuild.xml", nil}, // no build: the line could not be told from a fingerprint name
		{"vcenter.xml", nil},
		{"noversion.xml", nil}, // a device that answers nothing useful
	} {
		h := hostOf(t, c.fixture)
		sw := softwareOf(h)
		if c.want == nil {
			if osOf(h) != "" && strings.Contains(osOf(h), "firmware") || len(h.statedFirmware()) != 0 {
				t.Errorf("%s: stated %+v", c.fixture, h.statedFirmware())
			}
			continue
		}
		if got := osOf(h); got != c.want.os {
			t.Errorf("%s: OS %q, want %q", c.fixture, got, c.want.os)
		}
		if observe.SelfStatedBasis(c.want.os) != observe.BasisStatedWeb {
			t.Errorf("%s: %q is not recognised as a self-statement", c.fixture, c.want.os)
		}
		i := slices.IndexFunc(sw, func(s observe.Software) bool { return s.Display == c.want.display })
		if i < 0 {
			t.Fatalf("%s: no software row %q in %+v", c.fixture, c.want.display, sw)
		}
		s := sw[i]
		if s.Vendor != c.want.vendor || s.Product != c.want.product || s.Version != c.want.version || s.CPE != c.want.cpe || s.Guess != c.want.guess {
			t.Errorf("%s: row %+v, want %+v", c.fixture, s, *c.want)
		}
		// the ESXi service's own OS CPE ("esxi:8.0.3") must not add a second, less exact row of the same product
		if n := len(slices.DeleteFunc(slices.Clone(sw), func(s observe.Software) bool { return s.Product != c.want.product })); n != 1 {
			t.Errorf("%s: %d rows of %s: %+v", c.fixture, n, c.want.product, sw)
		}
		if f, _ := identified([]host{h}, h.addr, nmapargv.Normal); !slices.Contains(f, "Operating system: "+c.want.os) {
			t.Errorf("%s: the check does not say what it found: %v", c.fixture, f)
		}
	}
}

// A gentle look with titles records the statement (it is the only thing such a scan says about software); the plain gentle shape
// runs no script, so a fragile device is never asked.
func TestGentleShapeRunsNoFirmwareScript(t *testing.T) {
	t.Parallel()
	args, err := nmapargv.Build(nmapargv.Gentle, 1, []netip.Addr{netip.MustParseAddr("192.168.10.20")})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(args, "--script") || slices.Contains(args, "-sV") || slices.Contains(args, "-sU") {
		t.Fatalf("the gentle shape of a fragile device: %v", args)
	}
	// every fragile device (and one of known type that is fragile) gets that shape; only an unclassified one nobody made fragile
	// gets the titles and the firmware scripts
	for name, dec := range map[string]Decision{
		"fragile": {Fragile: true}, "fragile and unclassified": {Fragile: true, Unclassified: true}, "known type": {},
	} {
		if k := gentleShape(dec); k != nmapargv.Gentle {
			t.Errorf("%s: shape %v, want the plain gentle shape", name, k)
		}
	}
	if k := gentleShape(Decision{Unclassified: true}); k != nmapargv.GentleTitles {
		t.Errorf("unclassified, not fragile: %v", k)
	}
}

// The ESXi build table (core/versionscheme): every row names a release by version and an update NVD writes, and the build of the
// customer's host is in it.
func TestESXiBuildsData(t *testing.T) {
	t.Parallel()
	builds := versionscheme.ESXiBuilds()
	for b, r := range builds {
		if !esxiBuildRE.MatchString(b) || (r.Version != "8.0" && r.Version != "7.0") || r.Update == "" || !strings.HasPrefix(r.Name, "ESXi "+r.Version) {
			t.Errorf("build %s: %+v", b, r)
		}
	}
	if builds["24022510"] != (versionscheme.ESXiRelease{Version: "8.0", Update: "update_3", Name: "ESXi 8.0 Update 3"}) {
		t.Errorf("8.0 U3: %+v", builds["24022510"])
	}
}

// Every release of Broadcom KB 316595 (7.0 and 8.0) has a row, with the update NVD names it by; the three withdrawn 7.0 Update 3 builds
// the KB no longer lists are in too (from the 7.0 Update 3c release notes).
func TestESXiBuildsCoverTheKB(t *testing.T) {
	t.Parallel()
	for _, l := range strings.Split(strings.TrimSpace(string(fixture(t, "esxi-kb-316595.txt"))), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		i := strings.LastIndexByte(l, ' ')
		name, build := l[:i], l[i+1:]
		if b, ok := versionscheme.ESXiBuild(build); !ok || b.Name != name {
			t.Errorf("build %s (%s): %+v", build, name, b)
		}
	}
	for b, name := range map[string]string{"18644231": "ESXi 7.0 Update 3", "18825058": "ESXi 7.0 Update 3a", "18905247": "ESXi 7.0 Update 3b"} {
		if r, _ := versionscheme.ESXiBuild(b); r.Name != name {
			t.Errorf("build %s: %+v", b, r)
		}
	}
}

// An OS value of nmap's fingerprint that starts like a statement is a guess, never the device's own words.
func TestFingerprintNamesAreNotSelfStatements(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"VMware ESXi 5.5 - 6.7", "VMware ESXi 6.x", "VMware ESXi 8.0.3", "HPE iLO 4", "Grandstream GXP1610 VoIP phone"} {
		if b := observe.SelfStatedBasis(v); b != "" {
			t.Errorf("%q is read as a statement (%s)", v, b)
		}
	}
	if observe.SelfStatedBasis("VMware ESXi 8.0 Update 3 (build 24022510)") != observe.BasisStatedWeb {
		t.Error("the written statement is not recognised")
	}
}
