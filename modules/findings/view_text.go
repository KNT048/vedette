package findings

import (
	"cmp"
	"strings"
	"time"
	"unicode"
)

// The words a finding is told in outside the finding page: the fix of the device and who confirmed that it is affected. The assistant's
// context and tools, the MCP tools and the device updates all say them with these functions, so a person reads the same release and the
// same confirmation in all of them as on the page.

// oneLine is a text of the box's data as one short line: control and invisible format characters gone, blanks collapsed, at most n characters.
func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r), unicode.In(r, unicode.Zl, unicode.Zp):
			return ' '
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, ""))), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// FixWords says a fix in words: what to do, with the release. "" for a fix that names no release to install (none yet, not known).
func FixWords(kind FixKind, product, installed, version, ref string) string {
	product, installed, version = oneLine(cmp.Or(product, "the software"), 100), oneLine(installed, 60), oneLine(version, 100)
	switch kind {
	case FixUpdate:
		if version == "" {
			return ""
		}
		if installed != "" {
			return "update " + product + " from " + installed + " to " + version
		}
		return "update " + product + " to " + version
	case FixDistroUpdate:
		if version != "" {
			return "install the security update of the distribution's " + product + " package, version " + version + " (the distribution carries the fix under its own numbers)"
		}
		return "install the distribution's security updates of " + product + " (it has not published a fixed package yet; they arrive with its updates)"
	case FixOSUpdate:
		s := "install the Windows update that brings the build to " + version
		if kb := oneLine(ref, 20); kb != "" {
			s += " (" + kb + ")"
		}
		return s
	case FixFeatureUpdate:
		return "move " + product + " to " + cmp.Or(version, "a later release") + " (this release no longer gets the fix)"
	}
	return ""
}

// FixText is the fix of the finding in one sentence: the stored fix, the one the finding page shows. A fix with no release says so as a
// fact, never by naming a release of an affected range.
func (v View) FixText() string {
	fx := v.Finding.Fix
	if w := FixWords(fx.Kind, v.FixProduct(), "", fx.Version, fx.Ref); w != "" {
		r := []rune(w)
		return strings.ToUpper(string(r[0])) + string(r[1:]) + "."
	}
	if fx.Kind == FixNoneYet {
		return "No fixed release exists yet: the vendor's affected versions have no end."
	}
	return "The fixed release is not known for this device's version."
}

// ConfirmText says who or what confirmed the finding, or that nobody has. named false leaves out the person ("a person"), for a reader
// that is not given the people of the box (the MCP tools).
func (v View) ConfirmText(named bool) string {
	cf := v.Confirmation()
	day := ""
	if !cf.At.IsZero() {
		day = " on " + cf.At.UTC().Format(time.DateOnly)
	}
	switch cf.Verified {
	case VerifiedPerson:
		who := "a person"
		if named {
			who = cmp.Or(oneLine(cf.By, 100), who)
		}
		return "Confirmed by " + who + day + " on their own word."
	case VerifiedScan:
		return "Confirmed by a safe check Vedette ran" + day + "."
	case VerifiedDevice:
		return "Confirmed by the device itself: its own report of the installed version is inside the affected versions" + day + "."
	}
	return "Not confirmed yet: " + basisWords(cf.Basis) + "."
}

// basisWords says how an unconfirmed finding was detected.
func basisWords(b DetectionBasis) string {
	switch b {
	case DetectScan:
		return "found by a scan"
	case DetectBannerVersion:
		return "the version was read from a service banner or a fingerprint"
	}
	return "matched from what the device shows"
}
