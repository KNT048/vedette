package findings

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Microsoft Edge Legacy (D-619, customer walk 3 N53-1 and n57). Two different browsers have been called "Microsoft Edge": the EdgeHTML
// one built into Windows 10 (version 20 to 44, NVD product microsoft:edge) and the Chromium-based one Microsoft released on
// 15 January 2020 (version 79 and later, NVD product microsoft:edge_chromium). CISA's "Microsoft | Edge" entries from before that day
// (CVE-2016-7200, CVE-2016-7201: Chakra, Edge Legacy's script engine) are about the first; NVD lists them as microsoft:edge with no
// version ("-"). An agent reports the browser installed today as "Microsoft Edge 157.0.4341.46", a Chromium version, and the matcher
// could only say it cannot compare. Such an entry is proved not to apply to a Chromium Edge row when all of this holds:
//   - the row's version is a Chromium Edge build: four numbers, the first 79 or more (EdgeHTML's app versions are 20 to 44);
//   - NVD lists the CVE for microsoft:edge, and every Microsoft Edge entry of the list is Edge Legacy: no version, or a version or
//     range end before 79 (an edge_chromium entry, a "*" with no range, or a bound Vedette cannot read keeps the finding);
//   - the CVE came out before Chromium Edge did: NVD published it before 15 January 2020 (or, when the day is unknown, its id is from
//     2018 or earlier), so its list cannot be lagging behind a Chromium Edge fix;
//   - Edge Legacy is not left unpatched beside it (review r1 #1 of #807): Microsoft removed Edge Legacy only with April 2021's update
//     and only from Windows 10 1803 and later, so an older Windows 10 keeps it next to Chromium Edge. The device runs a system that never
//     shipped it (Windows Server, Windows 11, another OS: edgeHost.other), or every Windows 10 client release row of it carries a monthly
//     update of a month after the one NVD published the CVE in (Edge Legacy was fixed by Windows' own cumulative update, D-618's
//     build month). A Windows 10 client whose month is not known, or a device whose system is not known, keeps the finding.
// Anything else keeps the finding as before: hiding a real exploited CVE is the worse mistake.

// chromiumEdgeGA is the day Microsoft released the Chromium-based Edge (version 79) to everyone.
var chromiumEdgeGA = time.Date(2020, time.January, 15, 0, 0, 0, 0, time.UTC)

// chromiumEdgeFirst is the first Chromium Edge version; every EdgeHTML Edge version is below it.
const chromiumEdgeFirst = 79

var chromiumVersion = regexp.MustCompile(`^(\d{2,4})\.\d+\.\d+\.\d+$`)

// edgeChromium is NVD's Chromium-based Edge (microsoft:edge_chromium).
var edgeChromium = identity{vendor: "microsoft", product: "edgechromium"}

// edgeIDs is the NVD product a Microsoft Edge row also is (#910): microsoft:edge_chromium when its version is a Chromium Edge build
// (four numbers, the first 79 or more), so NVD's Chromium Edge ranges are read for it. An EdgeHTML version (20 to 44) or none is
// only microsoft:edge: Chromium Edge's ranges would put every Edge Legacy version inside.
func edgeIDs(vendor, product, ver string) []identity {
	m := chromiumVersion.FindStringSubmatch(strings.TrimSpace(ver))
	if m == nil || norm(vendor) != "microsoft" || norm(product) != "edge" {
		return nil
	}
	if major, _ := strconv.Atoi(m[1]); major < chromiumEdgeFirst {
		return nil
	}
	return []identity{edgeChromium}
}

// edgeMajor is the first number of a version ("157.0.4341.46" → 157, "44" → 44); false when it does not start with one.
func edgeMajor(v string) (int, bool) {
	head, _, _ := strings.Cut(strings.TrimSpace(v), ".")
	n, err := strconv.Atoi(head)
	return n, err == nil && n >= 0
}

// edgeLegacyOnly says whether the CVE is about Edge Legacy only and the row is a Chromium Edge build (D-619). why names the proof for
// the page.
func edgeLegacyOnly(s Software, in swInfo, v Vuln) (why string, out bool) {
	if KevKey(v.Vendor, v.Product) != "microsoft|edge" {
		return "", false
	}
	m := chromiumVersion.FindStringSubmatch(strings.TrimSpace(in.ver))
	if m == nil {
		return "", false
	}
	if major, _ := strconv.Atoi(m[1]); major < chromiumEdgeFirst {
		return "", false
	}
	if !v.Published.IsZero() && !v.Published.Before(chromiumEdgeGA) || v.Published.IsZero() && (cveYear(v.CVE) == 0 || cveYear(v.CVE) > 2018) {
		return "", false
	}
	legacy := 0
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			return "", false // an entry Vedette cannot read might be the Chromium one
		}
		vendor, _ := c.Vendor.Literal()
		product, _ := c.Product.Literal()
		if norm(vendor) != "microsoft" || !strings.HasPrefix(norm(product), "edge") {
			continue // another product of the list (Windows, ChakraCore): not a Microsoft Edge entry
		}
		if norm(product) != "edge" || !edgeLegacyEntry(c, af.Range) {
			return "", false
		}
		legacy++
	}
	if legacy == 0 {
		return "", false
	}
	h := in.edgeHost
	after := ""
	switch {
	case len(h.win10) > 0:
		if v.Published.IsZero() {
			return "", false // no month to compare the Windows 10 build with
		}
		for _, w := range h.win10 {
			if w.month == 0 || w.month <= monthKeyOf(v.Published) {
				return "", false
			}
		}
		after = fmt.Sprintf(" Its %s build carries Microsoft's monthly update of %s, after the CVE, which fixed Edge Legacy on Windows 10.", h.win10[0].display, h.win10[0].month)
	case !h.other:
		return "", false // the device's system is not known: Edge Legacy may still be on it
	}
	return fmt.Sprintf("NVD lists %s only for Microsoft Edge Legacy, the EdgeHTML browser built into Windows 10 (NVD microsoft:edge, versions before 79), and the CVE was published before Microsoft released the Chromium-based Edge in January 2020; this device's %s %s is the Chromium-based Edge, which does not contain that code.%s",
		v.CVE, clean(s.Display), clean(in.ver), after), true
}

// edgeHost is what the device's own system says about Edge Legacy (D-619): other when it runs one that never shipped it (a Windows
// Server or Windows 11 release row, or an OS name of Windows 11, Windows Server, macOS, Linux, a phone or Junos, with no Windows 10
// client); win10 the Windows 10 client release rows with the monthly update each carries (month 0: not known), or one entry of unknown
// month when only the OS name says Windows 10.
type edgeHost struct {
	other bool
	win10 []edgeWin10
}

type edgeWin10 struct {
	display string
	month   monthKey
}

// win11First is the first Windows 11 build; every Windows client release below it is Windows 10.
const win11First = 22000

var (
	win10OS        = regexp.MustCompile(`(?i)\bwindows 10\b`)
	noEdgeLegacyOS = regexp.MustCompile(`(?i)\bwindows 11\b|\bwindows server\b|\bmac ?os\b|\bos x\b|\blinux\b|\bubuntu\b|\bdebian\b|\bandroid\b|\bios\b|\bipados\b|\bjunos\b`)
)

func edgeHostOf(a Asset, infos []swInfo) edgeHost {
	var h edgeHost
	for _, in := range infos {
		d, ok := winDevice(in)
		switch {
		case !ok:
		case !d.rel.Server && d.rel.Build < win11First:
			h.win10 = append(h.win10, edgeWin10{display: d.rel.Display, month: in.winBuild.month})
		default:
			h.other = true
		}
	}
	os := a.AgentOS
	if os == "" {
		os = a.OS
	}
	switch {
	case len(h.win10) > 0:
		h.other = false
	case h.other:
	case win10OS.MatchString(os) && !noEdgeLegacyOS.MatchString(os):
		h.win10 = []edgeWin10{{display: "Windows 10"}}
	case noEdgeLegacyOS.MatchString(os):
		h.other = true
	}
	return h
}

// edgeLegacyEntry says whether one microsoft:edge entry is Edge Legacy for sure: version NA ("-"), a literal version before 79, or a
// range whose end is before 79 (with a start, if any, before it too). "*" with no range could be any Edge.
func edgeLegacyEntry(c CPE, r VersionRange) bool {
	switch c.Version.Kind {
	case NA:
		return r.IsZero()
	case Value:
		lit, ok := c.Version.Literal()
		if !ok {
			return false
		}
		n, ok := edgeMajor(lit)
		return ok && n < chromiumEdgeFirst && r.IsZero()
	}
	end := r.EndExcl
	if end == "" {
		end = r.EndIncl
	}
	n, ok := edgeMajor(end)
	if !ok || n >= chromiumEdgeFirst {
		return false
	}
	for _, start := range []string{r.StartIncl, r.StartExcl} {
		if start == "" {
			continue
		}
		if n, ok := edgeMajor(start); !ok || n >= chromiumEdgeFirst {
			return false
		}
	}
	return true
}
