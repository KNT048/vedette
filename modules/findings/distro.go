package findings

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/pkgrel"
	"github.com/knt048/vedette/core/productid"
)

// linuxDistro is the Linux distribution an OS name names, as a platform id ("alpine", "ubuntu", "debian", "rhel", "suse"), "" for
// none (Windows, a network OS, an unknown OS).
func linuxDistro(osName string) string { return pkgrel.Distro(osName) }

var (
	debPkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
)

// personDeb says a package release a person gave is a full Debian version with a revision ("1:10.2p1-2ubuntu3.8", "9.2p1-2+deb12u3").
func personDeb(p string) bool {
	p = strings.TrimSpace(p)
	if _, t := apkRelease(p); t != "" {
		return false
	}
	return debver.Valid(p) && debver.Revision(p) != ""
}

// debPkg is the full Debian version and source package of a row the Ubuntu or Debian data can decide: an agent's deb row
// (both read from the package database), or a Debian release a person gave (Needs your input, a correction), which the
// distribution's word decides like an agent's row: its source package is the row's when inventory kept one, else the product's own
// name as Debian and Ubuntu name many sources ("openssh"; guessed true). A guessed name is only a key to ask the feeds for: many
// sources are named otherwise (postgresql-16, bind9, exim4, php8.3), so the feeds are asked for such a row's data only by that
// name, and a name they hold no rows under leaves the row to NVD's ranges.
func debPkg(s Software) (version, source string, guessed, ok bool) {
	switch {
	case s.Packaged && s.builtBy() == "agent" && s.PkgVersion != "" && s.PkgSource != "":
		return s.PkgVersion, s.PkgSource, false, true
	case s.Source == "manual" && personDeb(s.PkgVersion):
		if src := strings.TrimSpace(s.PkgSource); src != "" {
			return strings.TrimSpace(s.PkgVersion), src, false, true
		}
		if src := debSourceName(s.Product); src != "" {
			return strings.TrimSpace(s.PkgVersion), src, true, true
		}
	}
	return "", "", false, false
}

// debSourceName is a product's name as Debian names its source package ("OpenSSH" -> "openssh"), "" when it is not one.
func debSourceName(product string) string {
	if n := strings.ToLower(strings.TrimSpace(product)); debPkgName.MatchString(n) {
		return n
	}
	return ""
}

// pkgReleaseText says a text is a distribution's package release: Alpine's apk ("10.2_p1-r1"), a release with a distribution's mark
// ("2ubuntu3.8", "+deb12u3", ".el9"), or a Debian version with an epoch ("1:9.2p1-2"). A plain "7.2.13" or "v7.2.13" is not.
func pkgReleaseText(p string) bool { return pkgrel.Release(p) }

// Distribution backports. Ubuntu and Debian fix a package without changing its upstream version, so NVD's
// upstream ranges cannot tell a patched OpenSSH 9.6p1 from a vulnerable one. For a row an agent read from the device's
// package database, with its full Debian version and source package, on a device whose OS names the release, the
// distribution's word decides:
//   - installed version at or above the version the distribution fixed it in, or the distribution says the package is
//     not affected: proved not affected (no new finding; an open suspected one closes as not_relevant);
//   - installed below the fixed version: affected, basis version, and "Fixed in <distro version> for <release>";
//   - no word (no row for the release and package, still open, needs triage, deferred, ignored): NVD decides, as before.
//
// A fixed version beats "not affected" (feeds keep both kinds for Ubuntu from two files): the comparison is the stronger
// evidence, and it keeps a finding open rather than closing one.

type distroKind int

const (
	distroFixedHere   distroKind = iota + 1 // installed >= fixed
	distroNotAffected                       // the distribution says its package is not affected
	distroNeeded                            // installed < fixed
)

// distroAnswer is the distribution's word on one software row for one CVE.
type distroAnswer struct {
	kind    distroKind
	pkg     string // the source package the distribution's data names ("linux" for a linux-signed kernel)
	name    string // "Ubuntu", "Debian"
	release string // the device's release ("24.04", "12", "3.23"), else the release of the row that decided
	from    string // the release of the row that decided when it is another than the device's (an Alpine fix of a later branch), else ""
	fixed   string // the fixed version (fixed here, needed)
	pro     bool   // the fix is in Ubuntu Pro (ESM) only
	reason  string // affected with no fix (open, fixed ""): why the distribution publishes no security update (Debian), "" otherwise
}

// DistroSource names where a distribution's word comes from, for the evidence line and FixedIn.Source.
func DistroSource(name string) string {
	switch name {
	case "Debian":
		return "Debian Security Tracker"
	case "Alpine Linux":
		return "Alpine Linux security database"
	}
	return "Ubuntu security data"
}

// distroOf is the distribution and release of the device's OS as the feeds name them ("ubuntu", "24.04"; "debian", "12").
func distroOf(in swInfo) (string, string) {
	switch in.os.vendor {
	case "canonical":
		return "ubuntu", in.osVer
	case "debian":
		major, _, _ := strings.Cut(in.osVer, ".")
		return "debian", major
	}
	return "", ""
}

// DevicePackages is the distribution whose own security data the feeds supply ("ubuntu", "debian", "alpine") when it can say something
// about this device: its OS is that distribution and it has at least one package row that data names (distroRows); "" otherwise (the
// feeds module pulls a distribution's files only while some device needs them). With it come the release as the distribution's data
// is asked for it ("24.04", "12"; "" for a distribution
// whose rows of every release are read, Alpine: the branch is chosen per row, distroData.anyRelease) and the source packages of the
// device's package rows as the security data names them (securitySource: "linux" for linux-signed), sorted, each once (the
// distribution feeds keep their rows for these packages only). A kernel counts by its Kernel row alone
// (distroRows). "" and nil when no distribution's data can say something about the device.
func DevicePackages(a Asset) (distro, release string, pkgs []string) {
	d, rel, rows := distroRows(a)
	if d == nil || len(rows) == 0 {
		return "", "", nil
	}
	for _, r := range rows {
		pkgs = append(pkgs, r.pkg)
	}
	slices.Sort(pkgs)
	if d.anyRelease {
		rel = ""
	}
	return d.id, rel, slices.Compact(pkgs)
}

// distroPkgRow is a row the distribution's word may decide: its swInfo, its package release and its source package as the
// security data names it.
type distroPkgRow struct {
	s   Software
	in  swInfo
	ver string // the package release ("1:9.6p1-3ubuntu13.14", "10.2_p1-r1")
	pkg string
}

// distroRows are the device's package rows compared with their distribution's data (distroData.pkgOf: an agent's package row
// with its release and source package, or a package release a person gave), with that distribution and the device's release ("" when
// the OS names none: no row, unless the distribution's rows of every release are read, Alpine). A kernel's packages other than its
// Kernel row (kernelPart) are never compared: the Kernel row stands for the running kernel, which is the source package the data lists.
func distroRows(a Asset) (d *distroData, release string, rows []distroPkgRow) {
	d = distroOfDevice(a)
	if d == nil {
		return nil, "", nil
	}
	osName := d.os(a)
	release = d.rel(osName)
	if release == "" && !d.anyRelease {
		return d, "", nil
	}
	for _, s := range a.Software {
		ver, src, ok := d.pkgOf(s, osName)
		if !ok || d.kernelRule && kernelPart(s) {
			continue
		}
		in := newSWInfo(s, osName)
		in.install = installOf(s, a)
		in.pkgVer, in.pkgSrc, in.pkgDistro, in.pkgRel = ver, src, d, release
		rows = append(rows, distroPkgRow{s: s, in: in, ver: ver, pkg: d.source(src)})
	}
	return d, release, rows
}

// Distribution kernels. Ubuntu and Debian name a kernel's packages after its ABI (linux-image-7.0.0-43-generic,
// linux-modules-7.0.0-43-generic, linux-headers-6.12.48+deb13-amd64), so apt keeps the previous kernel's packages installed next to
// the new kernel's, under names of their own, and a kernel update installs a new image that runs only after a restart. Their security
// data lists every kernel CVE under the kernel's source package ("linux"), which builds the image, its modules, headers and tools,
// linux-libc-dev and the kernel's userspace tools. A flaw in the kernel is the running kernel's: the device has it once, on its Kernel
// row (intake makes it of the running kernel's image alone), whatever kernel packages are installed. So, on those distributions:
//   - a package of a kernel's source other than the Kernel row (kernelPart: the headers, modules and tools of any kernel, an image that
//     does not run, a metapackage) is never matched: it is a part of a kernel, not the exposure, and its fix can never be a newer
//     release of its own name (linux-headers-7.0.0-43-generic never gets a 7.0.0-44 release);
//   - an installed image the device does not run yet, of the same source, at or above the release the distribution fixed a CVE in
//     (installedKernel) makes the Kernel row's fix a restart into it (FixRestart), not an update to install.
//
// Ubuntu's own OVAL checks of kernel CVEs compare the running kernel (uname), not the installed packages; listing a CVE once per ABI
// package multiplies one flaw by every package of every installed kernel.

// isKernelRow says the row is the Linux kernel itself (the catalogue's Kernel product, NVD's linux_kernel).
func isKernelRow(s Software) bool {
	p := productid.Norm(s.Product)
	return productid.Norm(s.Vendor) == "linux" && (p == "kernel" || p == "linuxkernel")
}

// kernelPart says an agent's package row is built from a Linux kernel's source package and is not the Kernel row: a part of a kernel
// (headers, modules, tools, an image that does not run, a metapackage, linux-libc-dev), never matched on its own.
func kernelPart(s Software) bool {
	return s.Packaged && s.builtBy() == "agent" && !isKernelRow(s) && kernelSource(strings.ToLower(strings.TrimSpace(s.PkgSource)))
}

// withoutKernelParts is rows without the kernel parts (kernelPart) on a device whose distribution keeps several kernels' packages
// installed (distroData.kernelRule); rows itself when there is none to leave out.
func withoutKernelParts(a Asset, rows []Software) []Software {
	if !slices.ContainsFunc(rows, kernelPart) {
		return rows
	}
	if d := distroOfDevice(a); d == nil || !d.kernelRule {
		return rows
	}
	out := make([]Software, 0, len(rows))
	for _, s := range rows {
		if !kernelPart(s) {
			out = append(out, s)
		}
	}
	return out
}

// kernelImageRE is the name of a kernel image package of Ubuntu or Debian (intake's own rule): linux-image-7.0.0-44-generic,
// linux-image-unsigned-…, linux-image-6.12.57+deb13-amd64; linux-image-generic and linux-image-amd64 are metapackages.
var kernelImageRE = regexp.MustCompile(`^linux-image-(unsigned-)?[0-9]`)

// installedKernel is the newest kernel image installed on the device that is not its Kernel row (an image intake lists under its own
// name: one the device does not run), of the same source package as the Kernel row k as the security data names it, built by the
// distribution itself, and newer than the running one. ok is false when there is none.
func installedKernel(a Asset, k Software) (string, bool) {
	if !isKernelRow(k) || k.PkgVersion == "" || k.PkgSource == "" {
		return "", false
	}
	in := swInfoOn(k, a)
	d, _ := distroOf(in)
	if d == "" {
		return "", false
	}
	src := securitySource(d, strings.ToLower(k.PkgSource))
	best := k.PkgVersion
	for _, s := range a.Software {
		name := strings.ToLower(strings.TrimSpace(s.Product))
		if !kernelPart(s) || !kernelImageRE.MatchString(name) || securitySource(d, strings.ToLower(s.PkgSource)) != src || !ownBuild(d, src, s.PkgVersion, false) {
			continue
		}
		if c, err := debver.Compare(s.PkgVersion, best); err == nil && c > 0 {
			best = s.PkgVersion
		}
	}
	return best, best != k.PkgVersion
}

// restartInto is the kernel release the device runs after a restart when that alone fixes a CVE the distribution fixed in fixed on
// its Kernel row k: an installed kernel it does not run yet at or above fixed (installedKernel). ok is false otherwise (the fix is to
// install updates).
func restartInto(a Asset, k Software, fixed string) (string, bool) {
	kv, ok := installedKernel(a, k)
	if !ok || fixed == "" {
		return "", false
	}
	c, err := debver.Compare(kv, fixed)
	return kv, err == nil && c >= 0
}

// notKernel are the linux-* source packages that build no kernel, kernel modules, headers or tools.
var notKernel = map[string]bool{"linux-atm": true, "linux-base": true, "linux-sound-base": true, "linux-ftpd": true, "linux-ftpd-ssl": true,
	"linux-igd": true, "linux-minidisc": true, "linux-show-player": true, "linux-apfs-rw": true, "linux-gpib": true, "linux-wlan-ng": true,
	"linux-user-chroot": true}

// kernelSource says whether a source package (as the security data names it, or a signing source of one) builds a Linux kernel or its
// modules, headers and tools: "linux", "linux-signed", "linux-hwe-6.8", "linux-aws", "linux-meta", "linux-restricted-modules". The
// firmware sources (linux-firmware, linux-firmware-raspi) build none.
func kernelSource(pkg string) bool {
	return pkg == "linux" || strings.HasPrefix(pkg, "linux-") && !notKernel[pkg] && !strings.HasPrefix(pkg, "linux-firmware")
}

// securitySource is the source package under which the distribution's security data lists a device's source package.
// Kernel images are built by a signing source package whose binaries carry the kernel's own version, while Ubuntu's and
// Debian's data list the kernel's source: Ubuntu linux-signed → linux, linux-signed-hwe-7.0 → linux-hwe-7.0; Debian
// linux-signed-amd64 (and -arm64, -i386) → linux, and a long-term-support kernel series a Debian release ships as a source of its
// own (Debian 11's linux-6.1, signed by linux-signed-6.1-amd64) → that source. Every other package is listed under its own source name.
func securitySource(distro, src string) string {
	rest, ok := strings.CutPrefix(src, "linux-signed")
	switch {
	case !ok:
		return src
	case distro == "debian":
		series := strings.TrimPrefix(rest, "-")
		if i := strings.LastIndexByte(series, '-'); i >= 0 && debianArch[series[i+1:]] {
			series = series[:i]
		} else if debianArch[series] {
			series = ""
		}
		if series == "" {
			return "linux"
		}
		return "linux-" + series
	}
	return "linux" + rest
}

// debianArch are the architectures Debian names its signed kernel sources after (linux-signed-amd64, linux-signed-6.1-arm64).
var debianArch = map[string]bool{"amd64": true, "arm64": true, "i386": true, "armhf": true, "armel": true, "ppc64el": true, "s390x": true,
	"riscv64": true, "mips64el": true, "loong64": true}

// The distribution's word is about the distribution's own package (review H2 of #732). A package from a PPA or a vendor's
// repository can share the source name and compare higher ("2.4.62-1+ubuntu24.04.1+deb.sury.org+1" against Ubuntu's fix
// "2.4.58-1ubuntu8.8") while being another build, so the word applies only to a revision the distribution itself builds,
// and anything else is left to NVD:
//   - Ubuntu: a revision with Ubuntu's own mark ("3ubuntu13.14", "0ubuntu0.24.04.1", "1ubuntu0.1~22.04.1", "2build1",
//     "+esm6"), or a plain Debian revision ("43.43" of a kernel, "2" of a package Ubuntu took from Debian unchanged) for a fix;
//   - Debian: a plain revision, optionally a stable update ("+deb12u3", "~deb12u1") and a binNMU ("+b1").
//
// A PPA (~ppa, ondrej's +deb.sury.org), a backport (~bpo12+1), a vendor suffix (~noble, ~ubuntu.24.04, ~bookworm) or a
// native version with no revision does not match. "Not affected" has no version to compare, so on Ubuntu it needs
// Ubuntu's own mark (a plain revision may be a vendor's own .deb).
var (
	ubuntuOwnRE = regexp.MustCompile(`^[0-9][0-9.]*((build|ubuntu)[0-9][0-9.]*)+(\+esm[0-9]+)?(~[0-9][0-9.]*)*$`)
	debianOwnRE = regexp.MustCompile(`^[0-9][0-9.]*([+~]deb[0-9]+u[0-9]+)?(\+b[0-9]+)?$`)
)

// ubuntuKernelRE is the revision of an Ubuntu kernel built for an older release or a cloud: "45.45~22.04.1" (HWE),
// "1015.16~22.04.1" (a cloud kernel), the plain ABI.upload revision with the release it was backported to (review round 2 of
// #732). Digits only after "~", so "45.45~ppa1" and "~bpo" do not match.
var ubuntuKernelRE = regexp.MustCompile(`^[0-9][0-9.]*(~[0-9][0-9.]*)*$`)

// ownBuild says whether the installed revision is the distribution's own build of the source package pkg (as the security data
// names it); strict is the rule for "not affected".
func ownBuild(distro, pkg, version string, strict bool) bool {
	rev := debver.Revision(version)
	if distro == "debian" {
		return debianOwnRE.MatchString(rev)
	}
	if !strict && (pkg == "linux" || strings.HasPrefix(pkg, "linux-")) && ubuntuKernelRE.MatchString(rev) {
		return true
	}
	return ubuntuOwnRE.MatchString(rev) || !strict && debianOwnRE.MatchString(rev) && !strings.Contains(rev, "deb")
}

// distroDecides says only the distribution's own data judges row in for v: a package an agent read from an Ubuntu or Debian package
// database whose release is the distribution's own build (its revision carries the distribution's mark, "1ubuntu2", "+deb13u1", or it
// is a kernel the distribution built), on a box where that distribution's security feeds are on (Vuln.DistroOn). NVD's upstream ranges
// do not see the fixes a distribution backports, so they never raise a finding on such a package (an exploited kernel CVE whose NVD
// range names the upstream 7.0.0 on Ubuntu's 7.0.0-44.44): its finding waits for the distribution's word, fixed or "affected, no fix
// yet" (status open). A vendor's own .deb (a plain revision, "131.0.6778.85-1") and a distribution whose feeds are off keep NVD.
func distroDecides(in swInfo, v Vuln) bool {
	if !in.packaged || in.pkgVer == "" || in.pkgSrc == "" {
		return false
	}
	d, rel := distroOf(in)
	if d == "" || rel == "" || !v.DistroOn[d] {
		return false
	}
	pkg := securitySource(d, in.pkgSrc)
	if pkg == "linux" || strings.HasPrefix(pkg, "linux-") {
		return ownBuild(d, pkg, in.pkgVer, false)
	}
	rev := debver.Revision(in.pkgVer)
	if d == "debian" {
		return strings.Contains(rev, "deb") && debianOwnRE.MatchString(rev)
	}
	return ubuntuOwnRE.MatchString(rev)
}

// distroVerdict reads v.Distro for the software row through its distribution's adapter (distroData), the same way for every
// distribution the feeds supply; ok is false when the distribution has no word on it (no row of the package for the release, a fixed
// release about another build, a build that is not the distribution's own).
func distroVerdict(in swInfo, v Vuln) (distroAnswer, bool) {
	d := in.pkgDistro
	if d == nil || in.pkgVer == "" || in.pkgSrc == "" || len(v.Distro) == 0 || in.pkgRel == "" && !d.anyRelease {
		return distroAnswer{}, false
	}
	ver := d.release(in.pkgVer)
	if ver == "" {
		return distroAnswer{}, false
	}
	pkg := d.source(in.pkgSrc)
	var rows []DistroFix
	for _, f := range v.Distro {
		if f.Distro == d.id && f.Package == pkg {
			rows = append(rows, f)
		}
	}
	f, ok := d.choose(rows, in.pkgRel, ver)
	if !ok {
		return distroAnswer{}, false
	}
	a := distroAnswer{pkg: pkg, name: d.name, release: cmp.Or(in.pkgRel, f.Release)}
	if f.Release != a.release {
		a.from = f.Release
	}
	switch f.Status {
	case "fixed":
		if !d.applies(pkg, ver, f.Fixed) {
			return distroAnswer{}, false
		}
		c, ok := d.compare(ver, f.Fixed)
		if !ok {
			return distroAnswer{}, false // a version Vedette cannot compare: NVD decides
		}
		a.fixed, a.pro, a.kind = f.Fixed, f.Pro, distroNeeded
		if c >= 0 {
			a.kind = distroFixedHere
		}
	case "not_affected": // no version to compare: the strict rule, or a kernel the distribution signed itself
		if !d.own(pkg, ver, true) && (!d.kernelRule || !signedKernel(in.pkgSrc) || !d.own(pkg, ver, false)) {
			return distroAnswer{}, false
		}
		a.kind = distroNotAffected
	case "open": // affected, no fix yet: the device has the flaw until the distribution publishes a fixed package
		// Of a CVE on no exploited list it raises nothing: such a finding asks for an update (StartUrgency) that does not exist, so it
		// waits for the distribution's fix or an exploited list (DistroNoFixYet names why it is undecided meanwhile).
		if !v.listed() || !d.own(pkg, ver, false) {
			return distroAnswer{}, false
		}
		a.kind, a.reason = distroNeeded, f.Reason
	default:
		return distroAnswer{}, false
	}
	return a, true
}

// signedKernel says a source package is a signing source of a kernel ("linux-signed", "linux-signed-hwe-7.0", "linux-signed-amd64"): the
// distribution signs its own kernel images, so the image's plain ABI revision ("44.44") is the distribution's build, and the
// distribution's "not affected" for the kernel's source applies to it (a mainline or vendor kernel is not built by a signing source).
func signedKernel(src string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(src)), "linux-signed")
}

// upstreamJudges says NVD's upstream ranges judge a package the distribution built for v: the distribution's data lists fixed
// releases only (distroData.fixedOnly, Alpine's secdb) and has no word on the package, and its feed is not loading (with its first
// pull still to come, the matcher waits for it rather than read the upstream ranges). A package of such a distribution is its upstream
// release unless the data names a fix of its own (Grype's apk matcher: an NVD match stands unless secdb has a fix for it).
func upstreamJudges(in swInfo, v Vuln) bool {
	d := in.pkgDistro
	if d == nil || !d.fixedOnly || !in.packaged || v.DistroLoading[d.id] {
		return false
	}
	_, ok := distroVerdict(in, v)
	return !ok
}

// debianKernelMoves says the package is Debian's kernel (source linux, its signed images included: securitySource), whose stable
// updates bring newer upstream point releases, so an installed build of another upstream release than the fix still compares with it,
// as long as both are of one kernel series ("6.1" of 6.1.119-1 and 6.1.128-1): a stable release keeps its kernel series, so a kernel of
// another series (a later release's kernel installed by hand) is not the build the fix is about.
// A long-term-support series a release ships as a source of its own (linux-6.1 on Debian 11) moves the same way inside its series.
func debianKernelMoves(distro, pkg, installed, fixed string) bool {
	series, own := strings.CutPrefix(pkg, "linux-")
	if distro != "debian" || pkg != "linux" && !own {
		return false
	}
	si, ok1 := kernelSeries(installed)
	sf, ok2 := kernelSeries(fixed)
	return ok1 && ok2 && si == sf && (pkg == "linux" || series == si)
}

// kernelSeries is the kernel series of a Debian kernel package version, its first two upstream numbers ("6.1" of "6.1.119-1",
// "6.12" of "6.12.57-1"); ok is false for a version with an epoch or without two leading numbers.
func kernelSeries(v string) (string, bool) {
	if strings.Contains(v, ":") {
		return "", false
	}
	nums, ok := leadingRelease(v)
	if !ok || len(nums) < 2 {
		return "", false
	}
	return fmt.Sprintf("%d.%d", nums[0], nums[1]), true
}

// noUpdateWords says why Debian publishes no security update for an entry it lists as affected (DistroFix.Reason), "" for none.
func noUpdateWords(reason string) string {
	switch reason {
	case "postponed":
		return "will fix it in a later point release, not in a security update"
	case "ignored":
		return "has decided not to fix it in this release"
	case "minor":
		return "rates it a minor issue, fixed in a later point release rather than a security update"
	case "unimportant":
		return "rates it unimportant for its packages"
	case "end_of_life":
		return "no longer gives this release security support for the package"
	}
	return ""
}

// distroMatch is matchOne's result for a row the distribution has a word on.
func distroMatch(a Asset, s Software, in swInfo, v Vuln, d distroAnswer, now time.Time) (Match, outcome) {
	src := DistroSource(d.name)
	if d.kind != distroNeeded {
		note := fmt.Sprintf("Not affected: %s %s fixed %s in %s %s, and this device has %s (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
			d.name, d.release, v.CVE, clean(d.pkg), clean(d.fixed), clean(in.pkgVer), src)
		provedOn := strings.TrimSpace(in.pkgVer)
		if d.kind == distroNotAffected { // the distribution's word on the package, no version compared
			provedOn = ""
			note = fmt.Sprintf("Not affected: %s says its %s package of %s %s is not affected by %s (%s). Vedette closed this by itself and reopens it if a later match says the device is affected.",
				d.name, clean(d.pkg), d.name, d.release, v.CVE, src)
		}
		return Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Evidence: Evidence{Summary: note, CheckedAt: now}, provedOn: provedOn}, outNotAffected
	}
	m := Match{CVE: v.CVE, SoftwareID: s.ID, SoftwareDisplay: clean(s.Display), Basis: BasisVersion, Confidence: ConfVersion, Severity: SeverityHigh, bounded: true}
	if v.Ransomware || v.EPSS >= 0.5 {
		m.Severity = SeverityCritical
	}
	pro := ""
	if d.pro {
		pro = " (Ubuntu Pro)"
	}
	if d.from != "" { // the fix of another branch decides (alpineFixBranch): say which
		pro += fmt.Sprintf(" for its %s branch", d.from)
	}
	said := fmt.Sprintf("%s fixed %s in %s %s%s (%s)", d.name, v.CVE, clean(d.pkg), clean(d.fixed), pro, src)
	until := fmt.Sprintf("so this device has the flaw until it installs %s's security updates.", d.name)
	if d.fixed == "" { // the distribution's word "affected, no fix yet"
		said = fmt.Sprintf("%s lists its %s package as affected by %s, with no fixed release yet (%s)", d.name, clean(d.pkg), v.CVE, src)
		until = fmt.Sprintf("so this device has the flaw until %s publishes a fixed package and the device installs it.", d.name)
		if w := noUpdateWords(d.reason); w != "" {
			said = fmt.Sprintf("%s lists its %s package as affected by %s and %s (%s)", d.name, clean(d.pkg), v.CVE, w, src)
			until = "so this device has the flaw until a fixed package comes; watch for it or accept the risk."
		}
	}
	m.Evidence = Evidence{CheckedAt: now, Summary: fmt.Sprintf("%s runs %s %s from %s %s's packages. %s"+suspectedClause,
		clean(a.Name), softwareName(s.Display, in.pkgVer), clean(in.pkgVer), d.name, d.release, said)}
	if k, ok := restartInto(a, s, d.fixed); ok { // the fixed kernel is installed and not running yet
		until = fmt.Sprintf("and the fixed kernel %s is already installed, so this device has the flaw until it restarts into it.", clean(k))
		m.Evidence.Summary += fmt.Sprintf(" The fixed kernel %s is already installed: a restart into it fixes this.", clean(k))
	}
	if s.Source == "agent" { // The agent read the installed package; a detection
		m.Evidence.Agent = true
		if deviceSays(a) { // a person's OS correction is not the device's word
			m.Evidence.Source = SourceAgent
		}
		m.Evidence.Summary = fmt.Sprintf("The agent on %s reports %s %s installed from %s %s's packages. %s, %s",
			clean(a.Name), softwareName(s.Display, in.pkgVer), clean(in.pkgVer), d.name, d.release, said, until)
	}
	return m, outMatch
}

// Why a distribution's package stays undecided for a CVE (distroSilence): the package is judged by its distribution's word alone and
// the distribution's data the box keeps has no word it may decide by. A closed list.
const (
	// DistroOutsideWindow: a CVE on no exploited list published before the catalogue's last 12 months. The box tracks the exploited
	// CVEs and those of the last 12 months (product scope), so the distribution feeds keep no row of it.
	DistroOutsideWindow = "outside_window"
	// DistroNoFixYet: the distribution lists its package as affected with no fixed release yet, and the CVE is on no exploited list:
	// it becomes a finding when the distribution publishes the fix or the CVE is exploited. Not a cause of an undecided pair: the
	// distribution decided it, and the coverage counts it decided affected (CoverageDistroNoFix).
	DistroNoFixYet = "distro_no_fix_yet"
	// DistroOtherPackages: the distribution lists the CVE for other packages only (another kernel flavour of the release, such as
	// linux-aws or linux-azure, or the package in no release the box keeps).
	DistroOtherPackages = "distro_other_packages"
	// DistroOtherReleases: the distribution lists the CVE for this package in other releases only (most often a CVE fixed before the
	// device's release came out, which the distribution never lists for it).
	DistroOtherReleases = "distro_other_releases"
	// DistroOtherBuild: the distribution's row for the package is about another build than the installed one (a PPA or a vendor's
	// package of the same source, an earlier upstream release than its fix).
	DistroOtherBuild = "distro_other_build"
	// DistroNotListed: the distribution's data has no row of the CVE at all (not triaged yet, or its feed holds no row of it yet).
	DistroNotListed = "distro_not_listed"
	// DistroNoData: Vedette has no security data of the device's distribution (Red Hat, SUSE and the other RPM distributions).
	DistroNoData = "distro_no_data"
)

// DistroSilences lists every cause of distroSilence: the causes of a pair no question asks about, beside PossibleCauses (the causes of
// a question); an agent's package row without its release or source takes PossibleCause's CauseVersionNeeded.
var DistroSilences = []string{DistroOutsideWindow, DistroOtherPackages, DistroOtherReleases, DistroOtherBuild, DistroNotListed,
	DistroNoData, CauseVersionNeeded}

// catalogueDays is the catalogue's window of CVEs on no exploited list (feeds' recentDays): the distribution feeds keep their rows of
// those CVEs and of the exploited ones only.
const catalogueDays = 365

// distroSilence is why the distribution's data decides nothing (or DistroNoFixYet: it decided "affected, no fix yet" and no finding is
// raised) for a package it built (distroVerdict has no word and NVD's upstream
// ranges may not judge it: upstreamJudges), one of DistroSilences; "" when its data or the upstream ranges decide, or the row is not an
// agent's package row. now is the time of the match pass.
func distroSilence(in swInfo, v Vuln, now time.Time) string {
	d := in.pkgDistro
	switch {
	case !in.packaged:
		return "" // a release a person gave: the matcher does not read it against the distribution's data
	case d == nil:
		return DistroNoData
	case in.pkgVer == "" || in.pkgSrc == "":
		return CauseVersionNeeded
	}
	if _, ok := distroVerdict(in, v); ok || upstreamJudges(in, v) {
		return ""
	}
	pkg := d.source(in.pkgSrc)
	release := func(f DistroFix) bool { return d.anyRelease || f.Release == in.pkgRel }
	var mine, sameRelease, samePkg, listed bool
	open := false
	for _, f := range v.Distro {
		if f.Distro != d.id {
			continue
		}
		listed = true
		switch {
		case f.Package == pkg && release(f):
			mine = true
			open = open || f.Status == "open"
		case release(f):
			sameRelease = true
		case f.Package == pkg:
			samePkg = true
		}
	}
	switch {
	case open && !v.listed():
		return DistroNoFixYet
	case mine:
		return DistroOtherBuild
	case !v.listed() && !v.Published.IsZero() && v.Published.Before(now.AddDate(0, 0, -catalogueDays)):
		return DistroOutsideWindow
	case sameRelease:
		return DistroOtherPackages
	case samePkg:
		return DistroOtherReleases
	case listed:
		return DistroOtherPackages
	}
	return DistroNotListed
}
