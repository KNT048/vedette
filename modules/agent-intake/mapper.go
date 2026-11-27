package agentintake

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/winrel"
)

// Package and program names → products. osquery gives package names, not vendors, and the inventory matches the exploited lists by
// lower(vendor)|lower(product): core/productid's catalogue (content/catalog/products) is the explicit table from deb/rpm/apk package or
// source names and Windows display names (and name patterns) to the product, its exploited-list keys and the release a name states.
// It is never guessed. A package the catalogue does not name keeps its own name for vendor and product (the Windows publisher when
// there is one) and so matches nothing.

// linuxProduct is the product of a package: its own name first, then its source package's.
func linuxProduct(names ...string) (productid.Product, bool) {
	for _, n := range names {
		if n == "" {
			continue
		}
		if p, ok := productid.Resolve(productid.Linux, n, "", ""); ok {
			return p, true
		}
	}
	return productid.Product{}, false
}

const maxKeyBytes = 400 // inventory: a match key is at most 400 bytes

// softwareConfidence is the confidence of a package an agent listed (INV-7; the mock uses the same).
const softwareConfidence = 0.95

// debUpstream is the upstream version of a Debian version: no epoch ("1:") and no Debian revision (from the last "-").
func debUpstream(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return v
}

// mapPackages turns the package snapshots of one request into the software list of the device. Rows whose name or version does not fit
// the inventory's limits are dropped, and the count is returned. One list per device: the deb, rpm and programs rows are joined (a
// host has one of them), the same product and version once. deb and rpm rows are Packaged (the distribution's package database),
// programs rows are not, nor a vendor's own package the catalogue marks upstream (google-chrome-stable: its version is Chrome's). At most limit rows are kept; the rows past it are dropped and counted.
//
// A deb row also carries its full Debian version and source package. Binaries of one source that map to the same
// product and upstream version are one row; when they differ in the full version (openssh-client upgraded,
// openssh-server not) the row keeps the lowest, so a binary that was not updated keeps its finding. Kernel images: a machine
// keeps older kernels installed and runs one of them, so when the rows say which kernel runs (the "kernel" column the caller puts on
// every deb row: osquery's kernel_info query stored on the node, Wazuh's uname, the box's own kernel; "7.0.0-43-generic") and an installed image is that kernel (linux-image-7.0.0-43-generic),
// only that image is the Kernel row (review H1 of #732: the newest installed one may not run yet); every other image is listed
// under its own package name with its full version (runningImage), as the kernel's headers, modules and tools are. Otherwise
// every image is the Kernel row and the lowest gives it its version, as for every package. A metapackage (linux-image-generic,
// source linux-meta) is never the Kernel row.
// A row whose Source names another epoch or upstream version than the binary's ("foo (2:1.0-1)" for "1:3.0-1", a package
// built from another source release) gives no full version either, so NVD decides it (review L1); the signed kernel
// sources (linux-signed*) are the exception, their binaries carry the kernel's own version.
//
// A "windows_os" row (withWindows: the node's Windows release with its update revision) gives the operating system's own row
// (windowsRow), first in the list so a list cut at limit keeps it.
func mapPackages(snaps map[string][]row, limit int) (items []observe.Software, dropped int) {
	seen := map[string]int{} // key -> index in items
	add := func(display, vendor, product, version string, kev []string, packaged bool, pkgVersion, pkgSource string, conf float64) {
		if !debver.Valid(pkgVersion) && !apkver.Valid(pkgVersion) || pkgSource == "" {
			pkgVersion, pkgSource = "", ""
		}
		// The key vendor|product must stay within the inventory's 400 bytes, or it refuses the whole list.
		if !fits(display) || !fits(vendor) || !fits(product) || len(vendor)+len(product)+1 > maxKeyBytes || utf8.RuneCountInString(version) > maxVersion || len(items) >= limit {
			dropped++
			return
		}
		k := strings.ToLower(vendor) + "\x00" + strings.ToLower(product) + "\x00" + version
		if i, ok := seen[k]; ok {
			items[i].Confidence = max(items[i].Confidence, conf) // a version the machine stated outranks one from its components
			if pkgVersion == "" {
				return
			}
			if lower, ok := lowerRelease(pkgVersion, items[i].PkgVersion); ok {
				if lower {
					items[i].PkgVersion, items[i].PkgSource = pkgVersion, pkgSource
				}
				return
			}
			c, err := debver.Compare(pkgVersion, items[i].PkgVersion) // an empty stored version is ErrInvalid: the new one is taken
			if err != nil || c < 0 {
				items[i].PkgVersion, items[i].PkgSource = pkgVersion, pkgSource
			}
			return
		}
		seen[k] = len(items)
		s := observe.Software{Display: display, Vendor: vendor, Product: product, Version: version, Confidence: conf, Packaged: packaged,
			PkgVersion: pkgVersion, PkgSource: pkgSource}
		if len(kev) > 0 {
			s.KevKeys = slices.Clone(kev)
		}
		items = append(items, s)
	}
	for _, r := range snaps["windows_os"] {
		if s, ok := windowsRow(winOS{name: r["name"], version: r["version"], target: r["target"]}); ok && len(items) < limit {
			items = append(items, s)
		}
	}
	running := runningImages(snaps["deb_packages"])
	for _, r := range snaps["deb_packages"] {
		name := r["name"]
		p, ok := linuxProduct(name, sourceName(r["source"]))
		version := debUpstream(r["version"])
		src := strings.ToLower(cmp.Or(sourceName(r["source"]), name)) // dpkg leaves Source out when it equals the package name
		full := r["version"]
		if lname := strings.ToLower(name); ok && strings.HasPrefix(lname, "linux-image-") && !runningImage(lname, running) {
			ok = false // a kernel metapackage, or an installed kernel that does not run: listed under its own name, never the Kernel row
		}
		if !strings.HasPrefix(src, "linux-signed") && !sameSourceRelease(r["source"], full) {
			full = "" // built from another source release: NVD decides (review L1)
		}
		switch {
		case ok && p.Upstream:
			add(p.Product, p.Vendor, p.Product, version, p.KEV, false, "", "", softwareConfidence)
		case ok:
			add(p.Product, p.Vendor, p.Product, version, p.KEV, true, full, src, softwareConfidence)
		default:
			add(name, name, name, version, nil, true, full, src, softwareConfidence)
		}
	}
	for _, r := range snaps["rpm_packages"] {
		name := r["name"]
		p, ok := linuxProduct(name)
		if ok {
			add(p.Product, p.Vendor, p.Product, r["version"], p.KEV, !p.Upstream, "", "", softwareConfidence)
		} else {
			add(name, name, name, r["version"], nil, true, "", "", softwareConfidence)
		}
	}
	for _, r := range snaps["apk_packages"] {
		if !apkNameRE.MatchString(r["name"]) || !apkver.Valid(r["version"]) {
			dropped++ // not an Alpine package: never guessed
			continue
		}
		name, origin, upstream := r["name"], cmp.Or(r["origin"], r["name"]), apkNVDVersion(r["version"])
		if !apkNameRE.MatchString(origin) {
			origin = name
		}
		p, ok := linuxProduct(name, origin)
		switch {
		case ok && p.Upstream:
			add(p.Product, p.Vendor, p.Product, upstream, p.KEV, false, "", "", softwareConfidence)
		case ok:
			add(p.Product, p.Vendor, p.Product, upstream, p.KEV, true, r["version"], origin, softwareConfidence)
		default:
			add(name, name, name, upstream, nil, true, r["version"], origin, softwareConfidence)
		}
	}
	for _, r := range snaps["pacman_packages"] {
		// Arch's rolling release carries the upstream version unpatched; no distribution data feed covers it, so the row is not Packaged
		// and findings reads NVD's ranges against the version ("1:2.43.0-1" is epoch 1, upstream 2.43.0, Arch release 1).
		name, version := r["name"], pacmanUpstream(r["version"])
		if !apkNameRE.MatchString(strings.ToLower(name)) || version == "" {
			dropped++
			continue
		}
		if p, ok := linuxProduct(name); ok {
			add(p.Product, p.Vendor, p.Product, version, p.KEV, false, "", "", softwareConfidence)
		} else {
			add(name, name, name, version, nil, false, "", "", softwareConfidence)
		}
	}
	sql := sqlServerVersions(snaps["programs"])
	fx := dotnetFrameworks(snaps["programs"])
	for _, f := range fx.rows {
		add(f.display, f.p.Vendor, f.p.Product, f.version, f.p.KEV, false, "", "", softwareConfidence)
	}
	for _, r := range sqlUmbrellaFirst(snaps["programs"]) {
		if r["reg_key"] != "" {
			continue // a registry value the programs query reads with the list (SQL Server's PatchLevel, a .NET framework's version), not a program
		}
		name, version, conf := r["name"], r["version"], softwareConfidence
		rel, umbrella := sqlUmbrella(name)
		if v, ok := sql[rel]; ok && umbrella && (version == "" || v.registry) {
			version, conf = v.version, v.confidence // the instance's build, not the one the release was installed with
		}
		p, ok := productid.Resolve(productid.Windows, name, r["publisher"], "")
		if ok && !umbrella && sql.authoritative(name, p) {
			ok = false // a component of a release whose own version the setup registry gave: its version is not the release's
		}
		switch {
		case ok:
			version = p.OwnVersion(version) // without a vendor's word before the release ("ad 9.7.6": 9.7.6)
			if p.Version != "" || p.VersionNotOwn {
				version = p.Version // the release the name states ("Eclipse Temurin JDK with Hotspot 21.0.7+6": 21.0.7, not 21.0.7.6)
			}
			add(name, p.Vendor, p.Product, version, p.KEV, false, "", "", conf)
		case r["publisher"] != "":
			add(name, r["publisher"], name, version, nil, false, "", "", conf)
		default:
			add(name, name, name, version, nil, false, "", "", conf)
		}
	}
	return items, dropped
}

// apkNameRE is the name of an Alpine (or Arch) package.
var apkNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]{0,99}$`)

// lowerRelease compares two apk releases; ok is false when either is not one (the caller then compares as Debian versions).
func lowerRelease(a, b string) (lower, ok bool) {
	va, okA := apkver.Parse(a)
	vb, okB := apkver.Parse(b)
	if !okA || !okB || strings.ContainsAny(a+b, ":") {
		return false, false
	}
	return apkver.Compare(va, vb) < 0, true
}

// apkNVDVersion is the upstream version of an apk release in the form NVD writes it (apkver.NVDVersion).
func apkNVDVersion(rel string) string { return apkver.NVDVersion(rel) }

// pacmanVersionRE is the shape pacman prints (the reporter reads the same one): an optional epoch, the upstream version, "-", the release.
var pacmanVersionRE = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9._+~]+-[A-Za-z0-9._+]+$`)

// pacmanUpstream is the upstream version of a pacman version "[epoch:]version-pkgrel"; "" when it has no release part.
func pacmanUpstream(v string) string {
	if !pacmanVersionRE.MatchString(v) {
		return ""
	}
	if i := strings.IndexByte(v, ':'); i > 0 && strings.Trim(v[:i], "0123456789") == "" {
		v = v[i+1:]
	}
	i := strings.LastIndexByte(v, '-')
	if i <= 0 {
		return ""
	}
	return v[:i]
}

// kernelImageRE is a kernel image package of Ubuntu or Debian: linux-image-7.0.0-43-generic, linux-image-unsigned-…,
// linux-image-6.1.0-18-amd64 (a release number after the prefix; linux-image-generic and linux-image-amd64 are metapackages).
var kernelImageRE = regexp.MustCompile(`^linux-image-(unsigned-)?[0-9]`)

// kernelReleaseRE is a running kernel release as uname -r gives it ("7.0.0-43-generic", "6.1.0-18-amd64").
var kernelReleaseRE = regexp.MustCompile(`^[0-9][a-z0-9.+_-]{0,99}$`)

// runningImage says whether a linux-image-* package is the image of the kernel the machine runs, and so gives the Kernel row: the
// running kernel's image when the rows say which kernel runs and it is installed (running, runningImages), else any kernel image
// (the lowest then gives the row its version, as for every package). A metapackage (linux-image-generic, linux-image-amd64) names no
// kernel and never is. Every other image stays an installed package under its own name: a kernel installed by an update and not
// booted yet (its release says a restart brings the fix) or an older one kept for a fallback, neither of which the machine runs.
func runningImage(lname string, running map[string]bool) bool {
	if !kernelImageRE.MatchString(lname) {
		return false
	}
	return running == nil || running[lname]
}

// runningImages is the set of kernel image package names of the running kernel ("linux-image-7.0.0-43-generic" and its
// -unsigned- twin) when the rows say which kernel runs (column "kernel") and one of them is installed; nil when not known,
// and the Kernel row then takes the lowest installed image, as every package does.
func runningImages(rows []row) map[string]bool {
	var rel string
	for _, r := range rows {
		if k := strings.ToLower(r["kernel"]); k != "" {
			rel = k
			break
		}
	}
	if !kernelReleaseRE.MatchString(rel) {
		return nil
	}
	set := map[string]bool{"linux-image-" + rel: true, "linux-image-unsigned-" + rel: true}
	for _, r := range rows {
		if set[strings.ToLower(r["name"])] {
			return set
		}
	}
	return nil
}

// sameSourceRelease reports whether a deb row's Source column, "name" or "name (version)", is the release the binary was
// built from: no version given (dpkg leaves it out when it equals the binary's), or one with the same epoch and upstream
// (a binNMU "1.2-3+b1" of source "1.2-3" is the same release).
func sameSourceRelease(source, binary string) bool {
	_, rest, found := strings.Cut(source, " (")
	if !found {
		return true
	}
	return debver.SameUpstream(strings.TrimSuffix(rest, ")"), binary)
}

// DebPackage is one installed Debian package: name, full Debian version and source package ("" when it has none). Kernel is the
// running kernel release ("7.0.0-43-generic", the same on every package; "" when not known), so the Kernel row takes the
// running kernel's image.
type DebPackage struct{ Name, Version, Source, Kernel string }

// MapDebPackages turns a dpkg list into software the way an osquery deb_packages snapshot is turned (same table, same upstream
// version, same limits), so the box's own list (vedette-host) and an osquery agent on the same machine give the same rows.
// It is a pure function: it reads no table and works with the module off. dropped counts rows whose fields are outside the
// inventory's limits. Unlike an agent's snapshot the list is never cut at maxRows: the caller stores it whole or not at all
// (the inventory refuses a list over its 5 000 items, so the box keeps its last list instead of a part of the box).
func MapDebPackages(pkgs []DebPackage) (items []observe.Software, dropped int) {
	rows := make([]row, 0, len(pkgs))
	for _, p := range pkgs {
		rows = append(rows, row{"name": p.Name, "version": p.Version, "source": p.Source, "kernel": p.Kernel})
	}
	return mapPackages(map[string][]row{"deb_packages": rows}, len(rows))
}

// fits reports whether s is 1..maxName runes (the rows are already clean text).
func fits(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= maxName
}

// sourceName is the source package of a deb_packages row: its "source" column is "name" or "name (version)".
func sourceName(s string) string {
	name, _, _ := strings.Cut(s, " ")
	return name
}

// kindOf is the device kind of an os_version row (core/observe AgentKind), within the inventory's kind list; "" gives no kind
// observation (the device keeps what it has). It goes in with the agent's rank, so a person's choice still wins and a passive guess never
// overrides it.
func kindOf(r row) string { return observe.AgentKind(r["platform"], r["name"]) }

// observations makes the device observations of one request from os_version and system_info, for the device the node is bound to.
func observations(hint observe.AssetHint, snaps map[string][]row, mac string) []observe.Observation {
	var out []observe.Observation
	add := func(f observe.Field, v string) {
		if fits(v) {
			out = append(out, observe.Observation{AssetHint: hint, Field: f, Value: v, Source: observe.Agent, Confidence: softwareConfidence})
		}
	}
	if rows := snaps["os_version"]; len(rows) > 0 {
		r := rows[0]
		v := strings.TrimSpace(r["name"] + " " + r["version"])
		if r["build"] != "" && r["platform"] == "windows" {
			v += " build " + r["build"]
		}
		add(observe.OS, v)
		if k := kindOf(r); k != "" {
			add(observe.Kind, k)
		}
	}
	if rows := snaps["system_info"]; len(rows) > 0 {
		r := rows[0]
		add(observe.Hostname, r["hostname"])
		add(observe.Vendor, r["hardware_vendor"])
		add(observe.Model, r["hardware_model"])
	}
	if mac != "" && len(out) > 0 { // the card's MAC, once per request that records something (hintConfidence in the inventory)
		out = append(out, observe.Observation{AssetHint: hint, Field: observe.MAC, Value: mac, Source: observe.Agent, Confidence: 0.9})
	}
	return out
}

// ---- Windows release and update revision ----

// winOS is a Windows machine's release with its monthly update revision, as the os_revision query gives it, stored on the node
// because osquery's splay may send it in another request than os_version (Wazuh: its os version and arch). version is
// "10.0.22631.4460"; target is the NVD target_hw of the machine ("x64", "x86", "arm64", "" when not known).
type winOS struct{ name, version, target string }

// winBuildRE is the version of Windows 10, 11 and Server 2016 and later as osquery gives it ("10.0.22631"); winFullRE the same with
// the update revision (Wazuh, the stored value). Older releases (6.x) are named by NVD without build ranges, so they are left out.
var (
	winBuildRE = regexp.MustCompile(`^10\.0\.[1-9][0-9]{4}$`)
	winFullRE  = regexp.MustCompile(`^10\.0\.[1-9][0-9]{4}\.[1-9][0-9]{0,5}$`)
)

// parseWinOS reads the os_revision row: a Windows 10/11/Server version and a revision 1..999999 written as osquery writes an
// integer (no sign, no leading zero, no space). Anything else is not taken (the agent's data is untrusted, INV-7): a revision 0
// or a missing one would place the machine at the release's first build.
func parseWinOS(rows []row) (winOS, bool) {
	if len(rows) == 0 {
		return winOS{}, false
	}
	r := rows[0]
	rev, err := strconv.Atoi(r["revision"])
	if err != nil || rev < 1 || rev > 999999 || strconv.Itoa(rev) != r["revision"] || !winBuildRE.MatchString(r["version"]) || !fits(r["name"]) {
		return winOS{}, false
	}
	return winOS{name: r["name"], version: r["version"] + "." + r["revision"], target: winTarget(r["arch"])}, true
}

// winTarget is the NVD target_hw of the architecture osquery reads from WMI (Win32_OperatingSystem.OSArchitecture: "64-bit",
// translated on some systems, "64 bits", "64-Bit"; "ARM 64-bit Processor" on ARM) or Wazuh gives ("x86_64", "i686", "aarch64",
// "ARM64"); "" when it names none of them.
func winTarget(arch string) string {
	a := strings.ToLower(arch)
	switch {
	case strings.Contains(a, "arm") || strings.Contains(a, "aarch64"):
		return "arm64"
	case strings.Contains(a, "64"):
		return "x64"
	case strings.Contains(a, "32") || a == "x86" || a == "i386" || a == "i686":
		return "x86"
	}
	return ""
}

// windowsRow is the operating system's own software row: vendor microsoft, the release as product ("Windows 11 23H2"),
// the full version with its update revision, the KEV key of CISA's "Microsoft | Windows" entries and a CPE that names the release
// as NVD does with the machine's target_hw ("cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*"), so findings
// reads NVD's ranges of the release ("< 10.0.22631.5189") against the patched build. Client or server by the name ("Microsoft
// Windows Server 2022 Datacenter"). A build core/winrel does not list (a release newer than the table) or Azure Local / Azure Stack
// HCI (a server OS whose name says neither, on builds clients share) still gets a row, shown by the machine's name ("Windows 11 Pro"),
// product "Windows (build 28000)", with the key and no release CPE: findings then gives each Windows entry an honest "not checked" instead of nothing (review r1 M3).
// false only when the version is not 10.0.<build>.<revision>.
func windowsRow(w winOS) (observe.Software, bool) {
	if !winFullRE.MatchString(w.version) {
		return observe.Software{}, false
	}
	build, err := strconv.Atoi(strings.Split(w.version, ".")[2])
	if err != nil {
		return observe.Software{}, false
	}
	name := strings.ToLower(w.name)
	rel, ok := winrel.ByBuild(build, strings.Contains(name, "server"))
	if !ok || strings.Contains(name, "azure stack hci") || strings.Contains(name, "azure local") {
		// The product is fixed ("Windows (build 28000)"), never the machine's name: a caption of just "Microsoft Windows" would be NVD's
		// family product o:microsoft:windows and could match its rows as the software's own (review r2 LOW-2).
		display := cmp.Or(strings.TrimSpace(strings.TrimPrefix(w.name, "Microsoft ")), "Windows")
		return observe.Software{Display: display, Vendor: "microsoft", Product: "Windows (build " + strconv.Itoa(build) + ")", Version: w.version,
			KevKeys: []string{"microsoft|windows"}, Confidence: softwareConfidence}, true
	}
	return observe.Software{Display: rel.Display, Vendor: "microsoft", Product: rel.Display, Version: w.version,
		CPE:     "cpe:2.3:o:microsoft:" + rel.Product + ":" + w.version + ":*:*:*:*:*:" + cmp.Or(w.target, "*") + ":*",
		KevKeys: []string{"microsoft|windows"}, Confidence: softwareConfidence}, true
}

// KnownSoftware is every software row the mapper gives a KEV key (#910, findings' KEV reachability audit): one per product of the catalogue an agent's
// package or program name maps to, as mapPackages makes a mapped row (no version, not Packaged: the audit reads the product, not a
// distribution's build), and the operating-system row windowsRow makes for every release core/winrel lists (at update revision 1).
func KnownSoftware() []observe.Software {
	var out []observe.Software
	for _, p := range productid.AgentProducts() {
		out = append(out, observe.Software{Display: p.Product, Vendor: p.Vendor, Product: p.Product, KevKeys: slices.Clone(p.KEV), Confidence: softwareConfidence})
	}
	for _, r := range winrel.Releases() {
		name := "Microsoft " + r.Display
		if s, ok := windowsRow(winOS{name: name, version: "10.0." + strconv.Itoa(r.Build) + ".1", target: "x64"}); ok {
			out = append(out, s)
		}
	}
	return out
}

// sameWinBuild says whether the request's os_version row, when it has a Windows one, is of the build of w ("10.0.22631" and
// "10.0.22631.4460"). A request without one says nothing against w.
func sameWinBuild(snaps map[string][]row, w winOS) bool {
	rows := snaps["os_version"]
	return len(rows) == 0 || rows[0]["platform"] != "windows" || strings.HasPrefix(w.version, rows[0]["version"]+".")
}

// withWindows puts the node's Windows release on a copy of the snapshots. With a Windows package list (programs) it adds a
// "windows_os" row, which the package mapper turns into the operating system's software row, unless the request's
// os_version row is of another build (a feature update whose revision is not reported yet: the stored release is stale, review
// M2). It puts the full version on the os_version row, so the device's OS reads "Microsoft Windows 11 Pro 10.0.22631.4460": on
// this request's os_version row when its build is the stored one (a machine whose feature update is not reported yet keeps
// "… build 26100"), or, when the request carries a usable os_revision row and no os_version row, on an os_version row made from
// it (the revision's own report shows the OS at once, in the first report). A zero w leaves the snapshots as they are.
func withWindows(snaps map[string][]row, w winOS) map[string][]row {
	if w.version == "" {
		return snaps
	}
	out := make(map[string][]row, len(snaps)+1)
	for k, v := range snaps {
		out[k] = v
	}
	same := sameWinBuild(snaps, w)
	if len(snaps["programs"]) > 0 && same {
		out["windows_os"] = []row{{"name": w.name, "version": w.version, "target": w.target}}
	}
	var r row
	if rows := snaps["os_version"]; len(rows) > 0 {
		if rows[0]["platform"] != "windows" || !same {
			return out
		}
		r = make(row, len(rows[0]))
		for k, v := range rows[0] {
			r[k] = v
		}
	} else if fresh, ok := parseWinOS(snaps["os_revision"]); ok && fresh == w {
		r = row{"name": w.name, "platform": "windows"}
	} else {
		return out
	}
	r["version"], r["build"] = w.version, ""
	out["os_version"] = []row{r}
	return out
}
