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

// FixWords says fix fx in words: what to do, with the release. "" for a fix that names no release to install (none yet, not known). A
// Windows update without a build names its KB, or the latest cumulative update when the data names neither (as the finding page does).
// A fix only a subscription carries says so, and what a person without it can do.
func FixWords(fx Fix, product, installed string) string {
	w := fixWords(fx.Kind, product, installed, fx.Version, fx.Ref)
	switch {
	case w == "":
	case fx.Chan() == ChannelUbuntuPro:
		w += "; only Ubuntu Pro (ESM) has this fixed package: attach Ubuntu Pro (free for personal use on a few machines; sudo pro attach) and install the updates, otherwise accept the risk or remove the package"
	case fx.Chan() == ChannelESU:
		w += "; it comes only with Extended Security Updates (an ESU subscription), otherwise move to a release Microsoft still updates"
	}
	return w
}

func fixWords(kind FixKind, product, installed, version, ref string) string {
	named := oneLine(product, 100) // "" when the device's product is not known
	product, installed, version = cmp.Or(named, "the software"), oneLine(installed, 60), oneLine(version, 100)
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
		kb := oneLine(ref, 20)
		switch {
		case version == "" && kb != "":
			return "install the Windows update " + kb
		case version == "" && named != "": // the data names neither the build nor the KB: the newest monthly update has the fix
			return "install the latest Windows cumulative update on " + named
		case version == "":
			return "install the latest Windows cumulative update"
		}
		s := "install the Windows update that brings the build to " + version
		if kb != "" {
			s += " (" + kb + ")"
		}
		return s
	case FixFeatureUpdate:
		return "move " + product + " to " + cmp.Or(version, "a later release") + " (this release no longer gets the fix)"
	case FixRestart:
		return "restart the device so it runs the installed " + product + " " + cmp.Or(version, "update") + " (the fixed kernel is installed; the device still runs an older one)"
	}
	return ""
}

// FixText is the fix of the finding in one sentence: the stored fix, the one the finding page shows. A fix with no release says so as a
// fact, never by naming a release of an affected range.
func (v View) FixText() string {
	fx := v.Finding.Fix
	if w := FixWords(fx, v.FixProduct(), ""); w != "" {
		r := []rune(w)
		return strings.ToUpper(string(r[0])) + string(r[1:]) + "."
	}
	if fx.Kind == FixNoneYet {
		return "No fixed release exists yet: the vendor's affected versions have no end."
	}
	return "The fixed release is not known for this device's version."
}

// ConfirmText says what confirmed the finding, or that nothing has. It never names the person who confirmed it: the words go to an AI
// provider and to MCP clients, and a user's name or address is personal data; the finding page shows the person.
func (v View) ConfirmText() string {
	cf := v.Confirmation()
	day := ""
	if !cf.At.IsZero() {
		day = " on " + cf.At.UTC().Format(time.DateOnly)
	}
	switch cf.Verified {
	case VerifiedPerson:
		return "Confirmed by a person on this box" + day + " on their own word."
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
