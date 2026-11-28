package findings

import (
	"cmp"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// Distribution package findings, end to end through the match pass and the stored lifecycle: what an agent reads from a Debian or
// Ubuntu package database (ordinary packages and the running kernel), what the distribution's security data says (a public fix, a
// fix only Ubuntu Pro carries, no word yet), and what a person does in between. Each row is one evidence sequence; the row states
// what a person must see at the end: the finding open or not, how it was closed, the stored fix, and what the page says about the
// version the match compared.

const matrixOS = "Ubuntu 26.04.1 LTS (Resolute Raccoon)"

// mxDeb is an agent's package row: the binary package name, the upstream version the package database gives, the full package
// release and the source package.
func mxDeb(name, upstream, full, src string) Software {
	return Software{ID: "s-" + name, Display: name, Vendor: name, Product: name, Version: upstream, Source: "agent", Packaged: true,
		PkgVersion: full, PkgSource: src}
}

// mxKernel is the Kernel row of the running kernel at package release full.
func mxKernel(full string) Software {
	return Software{ID: "s-kernel", Display: "Kernel", Vendor: "Linux", Product: "Kernel", Version: "7.0.0", Source: "agent", Packaged: true,
		PkgVersion: full, PkgSource: "linux-signed", KevKeys: []string{"linux|kernel"}}
}

// mxImage is an installed kernel image the device does not run.
func mxImage(abi, full string) Software {
	return mxDeb("linux-image-"+abi+"-generic", "7.0.0", full, "linux-signed")
}

// mxUbuntu is Ubuntu 26.04's fix of source package pkg in release fixed; pro: only Ubuntu Pro (ESM) carries it.
func mxUbuntu(pkg, fixed string, pro bool) DistroFix {
	return DistroFix{Distro: "ubuntu", Release: "26.04", Package: pkg, Status: "fixed", Fixed: fixed, Pro: pro}
}

// mxVuln is a CVE nobody lists as exploited, known to the box through the distribution's data (fixes).
func mxVuln(cve string, fixes ...DistroFix) Vuln {
	return Vuln{CVE: cve, NVDAnswered: true, Distro: fixes}
}

// mxKernelKEV is an exploited kernel CVE whose NVD rows give upstream kernel ranges (6.19 up to before 7.0.10), with the
// distribution's word in fixes (none: Ubuntu has published nothing yet).
func mxKernelKEV(fixes ...DistroFix) Vuln {
	return Vuln{CVE: mxCVEKEV, Vendor: "Linux", Product: "Kernel", Source: "cisa-kev", NVDAnswered: true, Distro: fixes, DistroOn: mxDistroOn,
		Affected: []Affected{{CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", Range: VersionRange{StartIncl: "6.19", EndExcl: "7.0.10"}}}}
}

// mxCVEKEV is the exploited CVE of the matrix's exploited rows.
const mxCVEKEV = "CVE-2026-91003"

// mxDistroOn: the box's Ubuntu and Debian security feeds are on.
var mxDistroOn = map[string]bool{"ubuntu": true, "debian": true}

// mxChromeKEV is an exploited Chrome CVE whose NVD rows give an upstream range: a vendor's own .deb on Ubuntu is judged by it.
func mxChromeKEV() Vuln {
	return Vuln{CVE: mxCVEKEV, Vendor: "Google", Product: "Chromium V8", Source: "cisa-kev", NVDAnswered: true, DistroOn: mxDistroOn,
		Affected: []Affected{{CPE: "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "132.0.6834.83"}}}}
}

// mxStep is one thing that happens to the device: an agent report (software, with the catalogue the pass reads), or a person's act on
// the row's finding.
type mxStep struct {
	read   []Software // an agent report: the device's package rows now
	vulns  []Vuln     // the catalogue of this pass; nil keeps the previous one
	person string     // "patched" (a person marks it patched) or "reopen" (a person opens it again)
}

func mxRead(vulns []Vuln, sw ...Software) mxStep { return mxStep{read: sw, vulns: vulns} }

var (
	mxPatched = mxStep{person: "patched"}
	mxReopen  = mxStep{person: "reopen"}
)

// mxWant is what a person must find at the end of the sequence. Empty fields are not checked.
type mxWant struct {
	open     *bool      // the finding is open (true) or handled (false)
	none     bool       // no finding exists for the CVE
	via      Via        // how it was handled
	fix      FixKind    // the stored fix kind
	fixVer   string     // the stored fix version
	channel  FixChannel // the stored fix's channel (where it is published), part of its By fix group
	words    string     // the stored fix said in words (FixWords: report, mail, AI context) contains this
	known    string     // the version the finding page says the device has (knownVersion of the matched line)
	detected bool       // the invariant: an open finding is one the latest match of the device detects
	verified Verified   // the stored verification (VerifiedNo: not confirmed, only suspected)
	evidence string     // the stored evidence sentence contains this
	fixText  string     // the fix in one sentence (View.FixText: notices, AI context) contains this
	reopen   string     // the newest reopened event's note contains this
}

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

// TestDistroPackageFindingScenarios is the scenario matrix of distribution package findings: evidence sequence × package kind
// (ordinary package, binary named otherwise than its source, the running kernel) × fix kind (distribution update, restart into an
// installed kernel) × where the fix is (public, Ubuntu Pro only).
func TestDistroPackageFindingScenarios(t *testing.T) {
	t.Parallel()
	const (
		cvePkg    = "CVE-2026-91001"
		cveKernel = "CVE-2026-91002"
		cveKEV    = mxCVEKEV
	)
	pipOld := mxDeb("python3-pip", "25.1.1+dfsg", "25.1.1+dfsg-1ubuntu2", "python-pip")
	pipESM := mxDeb("python3-pip", "25.1.1+dfsg", "25.1.1+dfsg-1ubuntu2+esm3", "python-pip")
	pipPublic := mxDeb("python3-pip", "25.1.1+dfsg", "25.1.1+dfsg-1ubuntu2.1", "python-pip")
	nltk := mxDeb("python3-nltk", "3.9.2", "3.9.2-1", "nltk") // a package Ubuntu took from Debian unchanged: a plain revision
	nltkESM := mxDeb("python3-nltk", "3.9.2", "3.9.2-1ubuntu0.1~esm1", "nltk")
	sshOld := mxDeb("openssh-server", "9.6p1", "1:9.6p1-3ubuntu13.4", "openssh")
	sshNew := mxDeb("openssh-server", "9.6p1", "1:9.6p1-3ubuntu13.5", "openssh")

	pipPro := []Vuln{mxVuln(cvePkg, mxUbuntu("python-pip", "25.1.1+dfsg-1ubuntu2+esm3", true))}
	pipBoth := []Vuln{mxVuln(cvePkg, mxUbuntu("python-pip", "25.1.1+dfsg-1ubuntu2+esm3", true), mxUbuntu("python-pip", "25.1.1+dfsg-1ubuntu2.1", false))}
	nltkPro := []Vuln{mxVuln(cvePkg, mxUbuntu("nltk", "3.9.2-1ubuntu0.1~esm1", true))}
	nltkProNVD := slices.Clone(nltkPro) // NVD also names the upstream product, with an upstream range the package is inside
	nltkProNVD[0].Affected = []Affected{{CPE: "cpe:2.3:a:nltk:nltk:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "3.9.3"}}}
	utilDeb := mxDeb("util-linux", "2.41", "2.41-5", "util-linux")
	utilDebFixed := mxDeb("util-linux", "2.41", "2.41-5+deb13u1", "util-linux")
	utilDebian := []Vuln{mxVuln(cvePkg, DistroFix{Distro: "debian", Release: "13", Package: "util-linux", Status: "fixed", Fixed: "2.41-5+deb13u1"})}
	sshPub := []Vuln{mxVuln(cvePkg, mxUbuntu("openssh", "1:9.6p1-3ubuntu13.5", false))}
	kern := []Vuln{mxVuln(cveKernel, mxUbuntu("linux", "7.0.0-44.44", false))}
	kevNoWord := []Vuln{mxKernelKEV()}
	kevFixed := []Vuln{mxKernelKEV(mxUbuntu("linux", "7.0.0-22.22", false))}
	kevOpen := []Vuln{mxKernelKEV(DistroFix{Distro: "ubuntu", Release: "26.04", Package: "linux", Status: "open"})}
	kevDebOpen := []Vuln{mxKernelKEV(DistroFix{Distro: "debian", Release: "13", Package: "linux", Status: "open", Reason: "postponed"})}
	kevFeedsOff := []Vuln{mxKernelKEV()}
	kevFeedsOff[0].DistroOn = nil
	chrome := Software{ID: "s-chrome", Display: "Google Chrome", Vendor: "Google", Product: "Chrome", Version: "131.0.6778.85", Source: "agent",
		Packaged: true, PkgVersion: "131.0.6778.85-1", PkgSource: "google-chrome-stable", KevKeys: []string{"google|chromium v8"}}
	chromeKEV := []Vuln{mxChromeKEV()}
	// an exploited OpenSSH CVE on a package whose release has an epoch ("1:9.6p1-3ubuntu13.4"): the upstream range raises it while
	// Ubuntu is silent, and Ubuntu's word that the installed release is fixed closes it as a data correction, never as an update the
	// device made (the upstream "9.6p1" compared with the package release "1:9.6p1-3ubuntu13.4")
	sshKEV := sshOld
	sshKEV.KevKeys = []string{"openbsd|openssh"}
	sshKEVVuln := func(fixes ...DistroFix) []Vuln {
		return []Vuln{{CVE: mxCVEKEV, Vendor: "OpenBSD", Product: "OpenSSH", Source: "cisa-kev", NVDAnswered: true, Distro: fixes, DistroOn: mxDistroOn,
			Affected: []Affected{{CPE: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", Range: VersionRange{EndExcl: "9.8p1"}}}}}
	}

	// the distribution's own build of an earlier upstream release than its fix, on the same release: below the stated fixed build, so
	// affected (the distribution's records state "introduced 0, fixed F" for the release); a product in no audit, and a Ruby one
	widgetOld := mxDeb("acme-widget", "2.1.0", "2.1.0-1", "acme-widget")
	widgetFixed := mxDeb("acme-widget", "2.3.4", "2.3.4-1~deb13u1", "acme-widget")
	widgetVendor := mxDeb("acme-widget", "2.1.0", "2.1.0-1~trixie", "acme-widget") // a vendor repository's build of the same source name
	widgetDebian := []Vuln{mxVuln(cvePkg, DistroFix{Distro: "debian", Release: "13", Package: "acme-widget", Status: "fixed", Fixed: "2.3.4-1~deb13u1"})}
	widgetEpoch := []Vuln{mxVuln(cvePkg, DistroFix{Distro: "debian", Release: "13", Package: "acme-widget", Status: "fixed", Fixed: "1:2.3.4-1~deb13u1"})}
	widgetOtherRelease := []Vuln{mxVuln(cvePkg, DistroFix{Distro: "debian", Release: "12", Package: "acme-widget", Status: "fixed", Fixed: "2.3.4-1~deb12u1"})}
	rubyOld := mxDeb("libruby3.3", "3.3.8", "3.3.8-2", "ruby3.3")
	rubyDebian := []Vuln{mxVuln(cvePkg, DistroFix{Distro: "debian", Release: "13", Package: "ruby3.3", Status: "fixed", Fixed: "3.3.14-0+deb13u1"})}
	gadgetOld := mxDeb("acme-gadget", "1.2.0", "1.2.0-1ubuntu1", "acme-gadget")
	gadgetUbuntu := []Vuln{mxVuln(cvePkg, mxUbuntu("acme-gadget", "1.4.0-0ubuntu0.26.04.1", false))}
	kernOlderSeries := mxKernel("6.8.0-40.40") // a kernel of an earlier series than the fix's: another kernel, never compared
	// a build marked for another release, left on a box upgraded from it: its own release's fix may be in it, so the device release's
	// fix of a later upstream release is not compared with it; a build marked for the device's own release still is
	widgetOwnMark := mxDeb("acme-widget", "2.1.0", "2.1.0-1+deb13u1", "acme-widget")
	widgetLeftover := mxDeb("acme-widget", "2.1.0", "2.1.0-1~deb12u3", "acme-widget")
	gadgetOwnMark := mxDeb("acme-gadget", "1.2.0", "1.2.0-0ubuntu0.26.04.1", "acme-gadget")
	gadgetLeftover := mxDeb("acme-gadget", "1.2.0", "1.2.0-0ubuntu0.24.04.1", "acme-gadget")
	gadgetLeftoverTilde := mxDeb("acme-gadget", "1.2.0", "1.2.0-1ubuntu0.1~24.04.1", "acme-gadget")
	// Debian 12's kernel left running on a box upgraded to Debian 13: another series than Debian 13's fix
	debKernelOld := Software{ID: "s-kernel", Display: "Kernel", Vendor: "Linux", Product: "Kernel", Version: "6.1.128", Source: "agent", Packaged: true,
		PkgVersion: "6.1.128-1", PkgSource: "linux-signed-amd64", KevKeys: []string{"linux|kernel"}}
	debKern := []Vuln{mxVuln(cveKernel, DistroFix{Distro: "debian", Release: "13", Package: "linux", Status: "fixed", Fixed: "6.12.60-1"})}

	k43, k44 := mxKernel("7.0.0-43.43"), mxKernel("7.0.0-44.44")
	img44, img43 := mxImage("7.0.0-44", "7.0.0-44.44"), mxImage("7.0.0-43", "7.0.0-43.43")

	rows := []struct {
		name  string
		os    string // the device's OS; "" is Ubuntu 26.04.1
		cve   string
		line  string // the software id the finding is on
		steps []mxStep
		want  mxWant
	}{
		// ordinary package, public fix
		{"package/public/below fix", "", cvePkg, sshOld.ID, []mxStep{mxRead(sshPub, sshOld)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "1:9.6p1-3ubuntu13.5", channel: ChannelPublic, known: "1:9.6p1-3ubuntu13.4"}},
		{"package/public/below fix, then updated", "", cvePkg, sshOld.ID, []mxStep{mxRead(sshPub, sshOld), mxRead(nil, sshNew)},
			mxWant{open: no(), via: ViaVersionMoved}},
		{"package/public/at fix from the start", "", cvePkg, sshNew.ID, []mxStep{mxRead(sshPub, sshNew)}, mxWant{none: true}},
		{"package/public/marked patched, a newer report still below", "", cvePkg, sshOld.ID, []mxStep{mxRead(sshPub, sshOld), mxPatched, mxRead(nil, sshOld)},
			mxWant{open: yes(), fix: FixDistroUpdate}},

		// Debian: a stable update appends to the revision ("2.41-5" -> "2.41-5+deb13u1")
		{"package/debian/below fix", "Debian GNU/Linux 13 (trixie)", cvePkg, utilDeb.ID, []mxStep{mxRead(utilDebian, utilDeb)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "2.41-5+deb13u1"}},
		{"package/debian/stable update installed", "Debian GNU/Linux 13 (trixie)", cvePkg, utilDeb.ID, []mxStep{mxRead(utilDebian, utilDeb), mxRead(nil, utilDebFixed)},
			mxWant{open: no(), via: ViaVersionMoved}},

		// the distribution's own build below its fix, of an earlier upstream release: affected, with the distribution's fix
		{"package/debian/own build of an earlier upstream than the fix: affected with the fix", "Debian GNU/Linux 13 (trixie)", cvePkg, widgetOld.ID,
			[]mxStep{mxRead(widgetDebian, widgetOld)}, mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "2.3.4-1~deb13u1", known: "2.1.0-1"}},
		{"package/debian/own build of an earlier upstream, then the fixed build installed", "Debian GNU/Linux 13 (trixie)", cvePkg, widgetOld.ID,
			[]mxStep{mxRead(widgetDebian, widgetOld), mxRead(nil, widgetFixed)}, mxWant{open: no(), via: ViaVersionMoved}},
		{"package/debian/own build of an earlier upstream, binary named otherwise than its source", "Debian GNU/Linux 13 (trixie)", cvePkg, rubyOld.ID,
			[]mxStep{mxRead(rubyDebian, rubyOld)}, mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "3.3.14-0+deb13u1"}},
		{"package/ubuntu/own build of an earlier upstream than the fix: affected with the fix", "", cvePkg, gadgetOld.ID,
			[]mxStep{mxRead(gadgetUbuntu, gadgetOld)}, mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "1.4.0-0ubuntu0.26.04.1", channel: ChannelPublic}},
		{"package/debian/a vendor's build of the same source name below the fix: never compared", "Debian GNU/Linux 13 (trixie)", cvePkg, widgetVendor.ID,
			[]mxStep{mxRead(widgetDebian, widgetVendor)}, mxWant{none: true}},
		{"package/debian/own build of another epoch than the fix: another numbering, no word", "Debian GNU/Linux 13 (trixie)", cvePkg, widgetOld.ID,
			[]mxStep{mxRead(widgetEpoch, widgetOld)}, mxWant{none: true}},
		{"package/debian/own build, the fix stated for another release only: no word", "Debian GNU/Linux 13 (trixie)", cvePkg, widgetOld.ID,
			[]mxStep{mxRead(widgetOtherRelease, widgetOld)}, mxWant{none: true}},
		{"package/debian/own build marked for the device's release, of an earlier upstream: affected with the fix", "Debian GNU/Linux 13 (trixie)", cvePkg,
			widgetOwnMark.ID, []mxStep{mxRead(widgetDebian, widgetOwnMark)}, mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "2.3.4-1~deb13u1"}},
		{"package/debian/a build marked for the release before, left after the upgrade: not compared", "Debian GNU/Linux 13 (trixie)", cvePkg,
			widgetLeftover.ID, []mxStep{mxRead(widgetDebian, widgetLeftover)}, mxWant{none: true}},
		{"package/ubuntu/own build marked for the device's release, of an earlier upstream: affected with the fix", "", cvePkg, gadgetOwnMark.ID,
			[]mxStep{mxRead(gadgetUbuntu, gadgetOwnMark)}, mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "1.4.0-0ubuntu0.26.04.1"}},
		{"package/ubuntu/a build marked for the release before, left after the upgrade: not compared", "", cvePkg, gadgetLeftover.ID,
			[]mxStep{mxRead(gadgetUbuntu, gadgetLeftover)}, mxWant{none: true}},
		{"package/ubuntu/a build marked for the release before after a tilde, left after the upgrade: not compared", "", cvePkg, gadgetLeftoverTilde.ID,
			[]mxStep{mxRead(gadgetUbuntu, gadgetLeftoverTilde)}, mxWant{none: true}},
		{"kernel/debian/the release before's kernel still running after the upgrade: another series, no finding", "Debian GNU/Linux 13 (trixie)", cveKernel,
			debKernelOld.ID, []mxStep{mxRead(debKern, debKernelOld)}, mxWant{none: true}},
		{"kernel/a kernel of an earlier series than the fix: another kernel, no finding", "", cveKernel, kernOlderSeries.ID,
			[]mxStep{mxRead(kern, kernOlderSeries)}, mxWant{none: true}},

		// ordinary package, binary named otherwise than its source (python3-pip from python-pip), fix only in Ubuntu Pro
		{"package/pro/below fix: the fix says Ubuntu Pro", "", cvePkg, pipOld.ID, []mxStep{mxRead(pipPro, pipOld)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "25.1.1+dfsg-1ubuntu2+esm3", channel: ChannelUbuntuPro, words: "Ubuntu Pro"}},
		{"package/pro/the page names the package release compared", "", cvePkg, pipOld.ID, []mxStep{mxRead(pipPro, pipOld)},
			mxWant{open: yes(), known: "25.1.1+dfsg-1ubuntu2"}},
		{"package/pro/marked patched three times without Pro: still open, still says Pro", "", cvePkg, pipOld.ID,
			[]mxStep{mxRead(pipPro, pipOld), mxPatched, mxRead(nil, pipOld), mxPatched, mxRead(nil, pipOld), mxPatched, mxRead(nil, pipOld)},
			mxWant{open: yes(), words: "Ubuntu Pro", reopen: "Only Ubuntu Pro (ESM) has the fixed package"}},
		{"package/pro/Pro attached, esm release installed", "", cvePkg, pipOld.ID, []mxStep{mxRead(pipPro, pipOld), mxRead(nil, pipESM)},
			mxWant{open: no(), via: ViaVersionMoved}},
		{"package/pro and public/public fix preferred", "", cvePkg, pipOld.ID, []mxStep{mxRead(pipBoth, pipOld)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "25.1.1+dfsg-1ubuntu2.1", channel: ChannelPublic}},
		{"package/pro and public/public fix installed", "", cvePkg, pipOld.ID, []mxStep{mxRead(pipBoth, pipOld), mxRead(nil, pipPublic)},
			mxWant{open: no(), via: ViaVersionMoved}},
		{"package/pro/plain Debian revision below an esm fix", "", cvePkg, nltk.ID, []mxStep{mxRead(nltkPro, nltk)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "3.9.2-1ubuntu0.1~esm1", words: "Ubuntu Pro"}},
		{"package/pro/plain Debian revision below an esm fix, NVD names the upstream product", "", cvePkg, nltk.ID, []mxStep{mxRead(nltkProNVD, nltk)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "3.9.2-1ubuntu0.1~esm1"}},
		{"package/pro/plain Debian revision, then the esm release", "", cvePkg, nltk.ID, []mxStep{mxRead(nltkPro, nltk), mxRead(nil, nltkESM)},
			mxWant{open: no(), via: ViaVersionMoved}},

		// the running kernel, fix installed and not running yet, then a restart
		{"kernel/restart/fixed image installed, not running", "", cveKernel, k43.ID, []mxStep{mxRead(kern, k43, img44)},
			mxWant{open: yes(), fix: FixRestart, fixVer: "7.0.0-44.44", known: "7.0.0-43.43"}},
		{"kernel/restart/restarted into the fixed kernel", "", cveKernel, k43.ID, []mxStep{mxRead(kern, k43, img44), mxRead(nil, k44, img43)},
			mxWant{open: no(), via: ViaVersionMoved}},
		{"kernel/install/fixed kernel not installed", "", cveKernel, k43.ID, []mxStep{mxRead(kern, k43)},
			mxWant{open: yes(), fix: FixDistroUpdate, fixVer: "7.0.0-44.44"}},
		{"kernel/restart/marked patched before the restart report", "", cveKernel, k43.ID, []mxStep{mxRead(kern, k43, img44), mxPatched, mxRead(nil, k44, img43)},
			mxWant{open: no()}},
		{"kernel/restart/marked patched, restarted, then undone: not open on the fixed kernel", "", cveKernel, k43.ID,
			[]mxStep{mxRead(kern, k43, img44), mxPatched, mxRead(nil, k44, img43), mxReopen},
			mxWant{open: no(), detected: true}},
		{"kernel/restart/undone, then the next report: closed by the evidence", "", cveKernel, k43.ID,
			[]mxStep{mxRead(kern, k43, img44), mxPatched, mxRead(nil, k44, img43), mxReopen, mxRead(nil, k44, img43)},
			mxWant{open: no(), via: ViaVersionMoved}},
		{"kernel/restart/booted back into the old kernel", "", cveKernel, k43.ID, []mxStep{mxRead(kern, k43, img44), mxRead(nil, k44, img43), mxRead(nil, k43, img44)},
			mxWant{open: yes(), fix: FixRestart, fixVer: "7.0.0-44.44"}},

		// an exploited kernel CVE whose NVD rows give upstream ranges; the distribution's word decides the backported kernel
		{"kernel/exploited/Ubuntu fixed it in an older kernel", "", cveKEV, k44.ID, []mxStep{mxRead(kevFixed, k44)}, mxWant{none: true}},
		{"kernel/exploited/no word from Ubuntu yet: NVD's range raises it, not confirmed, saying why", "", cveKEV, k44.ID, []mxStep{mxRead(kevNoWord, k44)},
			mxWant{open: yes(), verified: VerifiedNo, evidence: "Ubuntu has not published its answer yet; based on the upstream version ranges"}},
		{"kernel/exploited/no word yet, then Ubuntu fixed it in an older kernel: closed", "", cveKEV, k44.ID,
			[]mxStep{mxRead(kevNoWord, k44), mxRead(kevFixed, k44)}, mxWant{open: no()}},
		{"kernel/exploited/no word yet, then Ubuntu says affected with no fix: confirmed", "", cveKEV, k44.ID,
			[]mxStep{mxRead(kevNoWord, k44), mxRead(kevOpen, k44)}, mxWant{open: yes(), verified: VerifiedDevice, fix: FixNoneYet}},
		{"kernel/exploited/upstream-range finding (feeds off), then Ubuntu's fix arrives", "", cveKEV, k44.ID,
			[]mxStep{mxRead(kevFeedsOff, k44), mxRead(kevFixed, k44)}, mxWant{open: no()}},
		{"kernel/exploited/upstream-range finding (feeds off), feeds on and Ubuntu still silent: open, no longer confirmed", "", cveKEV, k44.ID,
			[]mxStep{mxRead(kevFeedsOff, k44), mxRead(kevNoWord, k44)}, mxWant{open: yes(), verified: VerifiedNo}},
		{"kernel/exploited/Ubuntu says affected, no fix yet: open, no fixed package yet", "", cveKEV, k44.ID, []mxStep{mxRead(kevOpen, k44)},
			mxWant{open: yes(), fix: FixNoneYet, fixText: "No fixed package yet: watch for the distribution's update or accept the risk"}},
		{"kernel/exploited/Debian says affected, fixed only in a later point release: open with the reason", "Debian GNU/Linux 13 (trixie)", cveKEV, k44.ID,
			[]mxStep{mxRead(kevDebOpen, k44)}, mxWant{open: yes(), fix: FixNoneYet, evidence: "a later point release"}},
		{"kernel/exploited/Ubuntu's feeds off: NVD's range decides", "", cveKEV, k44.ID, []mxStep{mxRead(kevFeedsOff, k44)},
			mxWant{open: yes()}},
		{"package/exploited/epoch release, no word yet: NVD's range raises it, not confirmed", "", cveKEV, sshKEV.ID,
			[]mxStep{mxRead(sshKEVVuln(), sshKEV)}, mxWant{open: yes(), verified: VerifiedNo}},
		{"package/exploited/epoch release, no word yet, then Ubuntu says the installed release is fixed: closed by the data, not as an update", "", cveKEV,
			sshKEV.ID, []mxStep{mxRead(sshKEVVuln(), sshKEV), mxRead(sshKEVVuln(mxUbuntu("openssh", "1:9.6p1-3ubuntu13.4", false)), sshKEV)},
			mxWant{open: no(), via: ViaDataCorrected}},
		{"package/exploited/a vendor's own .deb (plain revision): NVD's range decides", "", cveKEV, chrome.ID, []mxStep{mxRead(chromeKEV, chrome)},
			mxWant{open: yes(), known: "131.0.6778.85-1"}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			var vulns []Vuln
			var a Asset
			for i, st := range row.steps {
				e.advance(time.Hour)
				switch st.person {
				case "patched", "reopen":
					f, ok := mxFinding(t, e, row.cve, row.line)
					if !ok {
						t.Fatalf("step %d (%s): no finding to act on", i, st.person)
					}
					var err error
					if st.person == "patched" {
						_, _, err = e.svc.HandleConfirmed(t.Context(), []string{f.ID}, ResolutionPatched, "", time.Time{}, "pat@example.com")
					} else {
						_, err = e.svc.Reopen(t.Context(), f.ID, "", "pat@example.com")
					}
					if err != nil {
						t.Logf("step %d (%s): %v", i, st.person, err)
					}
					continue
				}
				if st.vulns != nil {
					vulns = st.vulns
				}
				sw := slices.Clone(st.read)
				for j := range sw {
					sw[j].SeenAt = *e.clock
				}
				osName := cmp.Or(row.os, matrixOS)
				a = Asset{ID: "a-1", Name: "host-a", OS: osName, AgentOS: osName, Software: sw}
				e.inv.mu.Lock()
				e.inv.match[a.ID] = a
				e.inv.mu.Unlock()
				if _, err := e.svc.UpsertFromMatch(t.Context(), a, vulns); err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
			}
			f, ok := mxFinding(t, e, row.cve, row.line)
			gaps := mxGaps(row.want, f, ok, a)
			if row.want.reopen != "" && ok {
				evs, err := eventsOf(t.Context(), e.db.Reader(), `f.id = ?`, f.ID)
				if err != nil {
					t.Fatal(err)
				}
				note := ""
				for _, ev := range evs[f.ID] {
					if ev.Kind == EvReopened {
						note = ev.Detail.Note
					}
				}
				if !strings.Contains(note, row.want.reopen) {
					gaps = append(gaps, fmt.Sprintf("want the reopen to say %q, it says %q", row.want.reopen, note))
				}
			}
			if len(gaps) > 0 {
				t.Errorf("%s\n  got: %s", strings.Join(gaps, "\n  "), mxDescribe(f, ok))
			}
		})
	}
}

// mxFinding is the finding of cve on line, or of cve on any line when the line holds none.
func mxFinding(t *testing.T, e *env, cve, line string) (Finding, bool) {
	t.Helper()
	fs, err := e.svc.Findings(t.Context(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.CVE == cve && f.SoftwareID == line {
			return f, true
		}
	}
	for _, f := range fs {
		if f.CVE == cve {
			return f, true
		}
	}
	return Finding{}, false
}

func mxDescribe(f Finding, ok bool) string {
	if !ok {
		return "no finding"
	}
	return fmt.Sprintf("verified=%s state=%s detected=%v resolution=%s via=%s fix=%s %q matched=%q", f.Verified, f.State, f.Detected, f.Resolution, f.Via, f.Fix.Kind, f.Fix.Version, f.MatchedVersion)
}

// mxGaps lists how the finding differs from what a person must see.
func mxGaps(w mxWant, f Finding, ok bool, a Asset) []string {
	var gaps []string
	if w.none {
		if ok {
			gaps = append(gaps, "want no finding")
		}
		return gaps
	}
	if !ok {
		return append(gaps, "want a finding, got none")
	}
	if w.open != nil && (f.State == StateOpen) != *w.open {
		gaps = append(gaps, fmt.Sprintf("want open=%v", *w.open))
	}
	if w.detected && f.State == StateOpen && !f.Detected {
		gaps = append(gaps, "an open finding the latest match no longer detects (the device runs the fix; the advice is stale)")
	}
	if w.via != "" && f.Via != w.via {
		gaps = append(gaps, fmt.Sprintf("want handled via %s", w.via))
	}
	if w.fix != "" && f.Fix.Kind != w.fix {
		gaps = append(gaps, fmt.Sprintf("want fix kind %s", w.fix))
	}
	if w.fixVer != "" && f.Fix.Version != w.fixVer {
		gaps = append(gaps, fmt.Sprintf("want fix version %s", w.fixVer))
	}
	if w.channel != "" && (f.Fix.Chan() != w.channel || !strings.HasSuffix(f.FixKey, "|"+f.Fix.Version+map[bool]string{true: "|" + string(w.channel)}[w.channel != ChannelPublic])) {
		gaps = append(gaps, fmt.Sprintf("want fix channel %s in the fix and its group (key %q)", w.channel, f.FixKey))
	}
	if w.words != "" {
		product := ""
		if i := slices.IndexFunc(a.Software, func(s Software) bool { return s.ID == f.SoftwareID }); i >= 0 {
			product = a.Software[i].Display
		}
		if s := FixWords(f.Fix, product, ""); !strings.Contains(s, w.words) {
			gaps = append(gaps, fmt.Sprintf("want the stored fix to say %q, it says %q", w.words, s))
		}
	}
	if w.verified != "" && f.Verified != w.verified {
		gaps = append(gaps, fmt.Sprintf("want verified %s", w.verified))
	}
	if w.evidence != "" && (f.Evidence == nil || !strings.Contains(f.Evidence.Summary, w.evidence)) {
		gaps = append(gaps, fmt.Sprintf("want the evidence to say %q", w.evidence))
	}
	if w.fixText != "" {
		if s := (View{Finding: f}).FixText(); !strings.Contains(s, w.fixText) {
			gaps = append(gaps, fmt.Sprintf("want the fix sentence to say %q, it says %q", w.fixText, s))
		}
	}
	if w.known != "" {
		var got string
		for _, s := range a.Software {
			if s.ID == f.SoftwareID {
				if k := knownVersion(a, s); k != nil {
					got = k.Version
				}
			}
		}
		if got != w.known {
			gaps = append(gaps, fmt.Sprintf("want the page to say the device has %q (the release the match compared), it says %q", w.known, got))
		}
	}
	return gaps
}

// A finding left open and not detected by an older build (a person's Undo on a kernel the device had already moved past) closes at the
// next match on the device's own evidence: the release it runs now, with patch credit; it never shows the stale restart advice again.
func TestDistroOpenUndetectedClosesAtTheNextMatch(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	const cve = "CVE-2026-91002"
	kern := []Vuln{mxVuln(cve, mxUbuntu("linux", "7.0.0-44.44", false))}
	read := func(sw ...Software) {
		t.Helper()
		e.advance(time.Hour)
		for i := range sw {
			sw[i].SeenAt = *e.clock
		}
		a := Asset{ID: "a-1", Name: "host-a", OS: matrixOS, AgentOS: matrixOS, Software: sw}
		e.inv.mu.Lock()
		e.inv.match[a.ID] = a
		e.inv.mu.Unlock()
		if _, err := e.svc.UpsertFromMatch(t.Context(), a, kern); err != nil {
			t.Fatal(err)
		}
	}
	read(mxKernel("7.0.0-43.43"), mxImage("7.0.0-44", "7.0.0-44.44"))
	f, ok := mxFinding(t, e, cve, "s-kernel")
	if !ok || f.State != StateOpen {
		t.Fatalf("setup: %s", mxDescribe(f, ok))
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error { // the row an older build left: open, not detected
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET detected = 0 WHERE id = ?`, f.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	read(mxKernel("7.0.0-44.44"), mxImage("7.0.0-43", "7.0.0-43.43"))
	f, ok = mxFinding(t, e, cve, "s-kernel")
	if !ok || f.State != StateHandled || f.Via != ViaVersionMoved || f.FromVersion != "7.0.0-43.43" || f.ToVersion != "7.0.0-44.44" {
		t.Fatalf("after the next match: %s", mxDescribe(f, ok))
	}
	// such a row whose CVE the pass no longer reads (it left the catalogue) closes too: open means detected, whatever the pass judges
	read(mxKernel("7.0.0-43.43"), mxImage("7.0.0-44", "7.0.0-44.44"))
	if f, ok = mxFinding(t, e, cve, "s-kernel"); !ok || f.State != StateOpen {
		t.Fatalf("reopened by the older kernel: %s", mxDescribe(f, ok))
	}
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE fnd_finding SET detected = 0 WHERE id = ?`, f.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	kern = nil
	read(mxKernel("7.0.0-44.44"), mxImage("7.0.0-43", "7.0.0-43.43"))
	if f, ok = mxFinding(t, e, cve, "s-kernel"); !ok || f.State != StateHandled {
		t.Fatalf("a row of a CVE the pass no longer reads: %s", mxDescribe(f, ok))
	}
}
