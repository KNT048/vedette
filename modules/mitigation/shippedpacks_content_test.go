package mitigation

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/findings"
)

// Content checks of the shipped packs that count a whole class of gap, so a new pack cannot bring one back: a placeholder the
// customer must fill without an example of what to type, a host firewall for one operating system only, a patch link that is
// not the vendor's advisory, a sign on the device without the command that shows it.

// netPlaceholder is a placeholder that stands for a network the customer types: <MGMT-NET>, <ALLOWED-NET-ADDRESS>,
// <ADMIN-NET-MASK>, <LOG-SENDERS-WILDCARD>.
var netPlaceholder = regexp.MustCompile(`<[A-Z]+(?:-[A-Z]+)*-(?:NET|SENDERS)(-ADDRESS|-MASK|-WILDCARD)?>`)

var (
	exampleMask     = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3} 255\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	exampleWildcard = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3} 0\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	examplePrefix   = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b`)
)

func guideText(g findings.FirewallGuide) (code, notes string) {
	var c, n []string
	n = append(n, g.Intro)
	n = append(n, g.Plain...)
	for _, list := range [][]findings.CodeStep{g.Steps, g.Verify, g.Undo} {
		for _, s := range list {
			c = append(c, s.Code)
			n = append(n, s.Note)
		}
	}
	if g.Alternative != nil {
		for _, s := range g.Alternative.Steps {
			c = append(c, s.Code)
			n = append(n, s.Note)
		}
	}
	return strings.Join(c, "\n"), strings.Join(n, "\n")
}

// Every network placeholder in a firewall block is explained next to it with a real value in the form the command takes: an
// address and a mask (10.0.10.0 255.255.255.0), an address and a wildcard (10.0.10.0 0.0.0.255) or address/prefix
// (10.0.10.0/24). "for example a management network" leaves the customer guessing what to type.
func TestShippedPacks_NetworkPlaceholdersCarryAnExampleValue(t *testing.T) {
	t.Parallel()
	var missing []string
	for cve, p := range shippedPacks(t) {
		for _, g := range p.Firewall {
			code, notes := guideText(g)
			seen := map[string]bool{}
			for _, m := range netPlaceholder.FindAllStringSubmatch(code, -1) {
				if seen[m[0]] {
					continue
				}
				seen[m[0]] = true
				var ok bool
				switch m[1] {
				case "-ADDRESS", "-MASK":
					ok = exampleMask.MatchString(notes)
				case "-WILDCARD":
					ok = exampleWildcard.MatchString(notes)
				default:
					ok = examplePrefix.MatchString(notes)
				}
				if !ok {
					missing = append(missing, fmt.Sprintf("%s %s %s", cve, g.Vendor, m[0]))
				}
			}
		}
	}
	sort.Strings(missing)
	t.Logf("network placeholders without an example value: %d", len(missing))
	for _, m := range missing {
		t.Errorf("%s: no example value of the form the command takes", m)
	}
}

// A pack for software that runs on a general-purpose server (nginx, Java) and limits the port on the server's own firewall gives
// that block for each system it may run on, not for Windows only: Ubuntu's ufw and the firewalld of Red Hat, Fedora and SUSE.
func TestShippedPacks_HostFirewallForEachServerSystem(t *testing.T) {
	t.Parallel()
	var missing []string
	for cve, p := range shippedPacks(t) {
		for _, g := range p.Firewall {
			var windows, ufw, firewalld bool
			for _, s := range g.Steps {
				windows = windows || strings.Contains(s.Title, "Windows Firewall")
				ufw = ufw || strings.Contains(s.Code, "ufw ")
				firewalld = firewalld || strings.Contains(s.Code, "firewall-cmd ")
			}
			if windows && !ufw {
				missing = append(missing, cve+": a Windows Firewall block and no ufw block")
			}
			if windows && !firewalld {
				missing = append(missing, cve+": a Windows Firewall block and no firewalld block")
			}
		}
	}
	sort.Strings(missing)
	t.Logf("server packs missing a Linux host firewall: %d", len(missing))
	for _, m := range missing {
		t.Error(m)
	}
}

// The patch link opens under "Open the vendor advisory", so it is the vendor's own page; a CERT, NVD or a researcher's write-up
// stays in the sources.
func TestShippedPacks_PatchLinkIsTheVendorAdvisory(t *testing.T) {
	t.Parallel()
	thirdParty := []string{"cert.europa.eu", "nvd.nist.gov", "cisa.gov", "rapid7.com", "cve.org", "xint.io"}
	n := 0
	for cve, p := range shippedPacks(t) {
		u, err := url.Parse(p.Patch.URL)
		if err != nil {
			t.Fatalf("%s: %v", cve, err)
		}
		for _, h := range thirdParty {
			if u.Host == h || strings.HasSuffix(u.Host, "."+h) {
				n++
				t.Errorf("%s: the patch link %s is not the vendor's advisory", cve, p.Patch.URL)
			}
		}
	}
	t.Logf("patch links that are not the vendor's advisory: %d", n)
}

// The "Have I been hit?" signs on a device the customer can open a shell on carry the command that shows them: the ransomware
// files on a Synology NAS (over SSH) and the root password change on a Junos device (its commit history).
func TestShippedPacks_DeviceSignsCarryTheirCommand(t *testing.T) {
	t.Parallel()
	packs := shippedPacks(t)
	without := 0
	for _, p := range packs {
		if p.Compromise == nil {
			continue
		}
		for _, in := range p.Compromise.Indicators {
			if len(in.Commands) == 0 {
				without++
			}
		}
	}
	t.Logf("signs without a command (all packs): %d", without)
	want := map[string]string{
		"CVE-2024-10441": ".L0CK3D", "CVE-2026-13639": ".L0CK3D", "CVE-2026-13684": ".L0CK3D",
		"CVE-2023-36844": "Root password", "CVE-2023-36845": "Root password", "CVE-2023-36847": "Root password",
	}
	for cve, title := range want {
		p, ok := packs[cve]
		if !ok || p.Compromise == nil {
			t.Errorf("%s: no signs", cve)
			continue
		}
		found := false
		for _, in := range p.Compromise.Indicators {
			if strings.Contains(in.Title, title) {
				found = true
				if len(in.Commands) == 0 {
					t.Errorf("%s %q: no command to check it", cve, in.Title)
				}
			}
		}
		if !found {
			t.Errorf("%s: no sign titled %q", cve, title)
		}
	}
}
