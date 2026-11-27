package findings

import (
	"slices"
	"strconv"

	"github.com/knt048/vedette/core/versionscheme"
	"github.com/knt048/vedette/core/winrel"
)

// FixOf is the one fix resolver: what fixes CVE v on software line s of device a, read from the same data the matcher compares
// (the CVE's affected ranges as their origin states them, the distribution's word on its own package, Microsoft's release data for a
// Windows release). The match pass stores its answer on the finding (fnd_finding.fix_*, fix_key); every reader shows the stored fix,
// never a fix of its own.
//
//   - a product whose vendor states its fixes per release train in its own notation (Vuln.Schemed: ESXi's builds): the vendor's
//     fixed release of the device's train (versionscheme.Judge), when the device's version and build place it in a train;
//   - a Windows release row: the monthly update whose build the range ends at (os_update, the build, its KB when Microsoft's release
//     data lists it; channel esu when only Extended Security Updates bring it), or the later release that has the fix when the device's release no longer gets one (feature_update);
//   - a distribution's package: the distribution's fixed package release (distro_update; "" when its data names none yet; channel
//     ubuntu_pro when only Ubuntu Pro's archive has it and no public fix exists), or, on a
//     distribution kernel whose fixed release is installed and not running yet, a restart into the installed kernel (restart, its
//     package release: installedKernel);
//   - otherwise the nearest release outside every range of the CVE that applies to the line (update);
//   - no range that applies has an end: no fix yet (none_yet);
//   - anything else (the ranges do not say, the version cannot be read): unknown.
//
// It never guesses: a range's end that is itself listed affected (Junos' release-by-release lists) is no fix.
func FixOf(a Asset, s Software, v Vuln) Fix {
	if f, ok := schemeFix(a, s, v); ok {
		return f
	}
	in := swInfoOn(s, a)
	if f, ok := windowsFixedIn(in, v); ok {
		return winFixOf(in, f)
	}
	var key []identity
	if keyedTo(s, v) {
		key = keyIDs(v)
	}
	if f := fixedInSoftware(in, v, key); f != nil {
		switch f.Kind {
		case "fixed":
			return Fix{Kind: FixUpdate, Version: f.Fixed}
		case "distro":
			if k, ok := restartInto(a, s, f.DistroFixed); ok { // the fixed kernel is installed: the device runs it after a restart
				return Fix{Kind: FixRestart, Version: k}
			}
			fx := Fix{Kind: FixDistroUpdate, Version: f.DistroFixed}
			if f.DistroPro && f.DistroFixed != "" { // only Ubuntu Pro's archive has the fixed package
				fx.Channel = ChannelUbuntuPro
			}
			return fx
		}
		return Fix{Kind: FixUnknown}
	}
	if d, ok := distroVerdict(in, v); ok {
		if d.kind == distroNeeded { // the distribution's word "affected, no fix yet": no fixed package to install
			return Fix{Kind: FixNoneYet}
		}
		return Fix{Kind: FixUnknown} // the distribution says it is fixed or not affected here: nothing to install
	}
	if noEnd(in, v, key) {
		return Fix{Kind: FixNoneYet}
	}
	return Fix{Kind: FixUnknown}
}

// winFixOf is FixOf of a Windows release row, from windowsFixedIn's answer.
func winFixOf(in swInfo, f *FixedIn) Fix {
	if f == nil {
		return Fix{Kind: FixUnknown}
	}
	switch f.Kind {
	case "fixed":
		return Fix{Kind: FixOSUpdate, Version: f.Fixed, Ref: winKB(in, f.Fixed)}
	case "esu": // the build comes only with Extended Security Updates
		return Fix{Kind: FixOSUpdate, Version: f.Fixed, Ref: winKB(in, f.Fixed), Channel: ChannelESU}
	case "feature_update":
		if len(f.Branches) > 0 && f.Branches[0].Branch != "" {
			return Fix{Kind: FixFeatureUpdate, Version: f.Branches[0].Branch}
		}
		return Fix{Kind: FixFeatureUpdate, Version: f.Fixed}
	}
	return Fix{Kind: FixUnknown}
}

// winKB is the KB number of the monthly update that brings a Windows release to build ("10.0.26100.4061"), "" when Microsoft's release
// data does not list that build.
func winKB(in swInfo, build string) string {
	d, ok := winDevice(in)
	m := winBoundRE.FindStringSubmatch(build)
	if !ok || m == nil {
		return ""
	}
	b, _ := strconv.Atoi(m[1])
	rev, _ := strconv.Atoi(m[2])
	us := winrel.Updates(b, d.rel.Server)
	if i := slices.IndexFunc(us, func(u winrel.Update) bool { return u.Rev == rev }); i >= 0 {
		return us[i].KB
	}
	return ""
}

// noEnd says the CVE's ranges that apply to the line all lack an end (affected from a release on, with no release that fixes it):
// the vendor has no fix yet. False when no range applies.
func noEnd(in swInfo, v Vuln, key []identity) bool {
	p := fixedPartsOf(in, v, key)
	if len(p.usable) == 0 {
		return false
	}
	for _, e := range p.usable {
		if e.r.EndExcl != "" || e.r.EndIncl != "" {
			return false
		}
	}
	return true
}

// schemeFix is FixOf from the ranges a vendor states in its notation for the line's product: the fixed release of the device's train,
// as the matcher reads them (schemeJudge). ok is false when none names the product, the device's version does not place it in a train
// of a line the rows name, or the vendor states no fix for it.
func schemeFix(a Asset, s Software, v Vuln) (Fix, bool) {
	r, ok := schemeJudge(a, s, swInfoOn(s, a), v)
	if !ok || r.verdict.State != versionscheme.Affected || r.verdict.Fix == nil {
		return Fix{}, false
	}
	return Fix{Kind: FixUpdate, Version: releaseName(*r.verdict.Fix)}, true
}
