package agentintake

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/observe"
)

// Package names → KEV keys (D-169 (11)). osquery gives package names, not vendors, and the inventory matches KEV by
// lower(vendor)|lower(product): pkgmap.json is the explicit table from deb/rpm package or source names and Windows display names to the
// vendor and product the catalog knows. It is never guessed; a test checks every pair against the catalog. A package not in the table
// keeps its own name for vendor and product (the Windows publisher when there is one) and so matches nothing.
// ponytail: about 100 entries, grown by test; upgrade path: a bigger table.

//go:embed pkgmap.json
var pkgmapJSON []byte

type pkgPair struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type pkgPrefix struct {
	Prefix  string `json:"prefix"`
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
}

type pkgTable struct {
	Exact  map[string]pkgPair `json:"exact"`
	Prefix []pkgPrefix        `json:"prefix"`
}

type pkgMap struct {
	Linux   pkgTable `json:"linux"`
	Windows pkgTable `json:"windows"`
}

var pkgmap = mustPkgmap(pkgmapJSON)

func mustPkgmap(b []byte) pkgMap {
	var m pkgMap
	if err := json.Unmarshal(b, &m); err != nil {
		panic("agentintake: pkgmap.json: " + err.Error()) // embedded; a test loads it too
	}
	return m
}

// lookup finds the pair of a lower-case name: exact first, then the longest listed prefix.
func (t pkgTable) lookup(name string) (pkgPair, bool) {
	if p, ok := t.Exact[name]; ok {
		return p, true
	}
	best, bestLen := pkgPair{}, 0
	for _, p := range t.Prefix {
		if len(p.Prefix) > bestLen && strings.HasPrefix(name, p.Prefix) {
			best, bestLen = pkgPair{Vendor: p.Vendor, Product: p.Product}, len(p.Prefix)
		}
	}
	return best, bestLen > 0
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
// host has one of them), the same product and version once. deb and rpm rows are Packaged (the distribution's package database,
// D-474), programs rows are not. At most limit rows are kept; the rows past it are dropped and counted.
//
// A deb row also carries its full Debian version and source package (D-516). Binaries of one source that map to the same
// product and upstream version are one row; when they differ in the full version (openssh-client upgraded,
// openssh-server not) the row keeps the lowest, so a binary that was not updated keeps its finding. Kernel images: a machine
// keeps older kernels installed and runs one of them, so when the rows say which kernel runs (the "kernel" column the caller puts on
// every deb row: osquery's kernel_info query stored on the node, Wazuh's uname, the box's own kernel; "7.0.0-43-generic") and an installed image is that kernel (linux-image-7.0.0-43-generic),
// only that image gives the Kernel row its version (review H1 of #732: the newest installed one may not run yet). Otherwise
// the lowest, as for every package. A metapackage (linux-image-generic, source linux-meta) never gives the row its version.
// A row whose Source names another epoch or upstream version than the binary's ("foo (2:1.0-1)" for "1:3.0-1", a package
// built from another source release) gives no full version either, so NVD decides it (review L1); the signed kernel
// sources (linux-signed*) are the exception, their binaries carry the kernel's own version.
func mapPackages(snaps map[string][]row, limit int) (items []observe.Software, dropped int) {
	seen := map[string]int{} // key -> index in items
	add := func(display, vendor, product, version string, mapped, packaged bool, pkgVersion, pkgSource string) {
		if !debver.Valid(pkgVersion) || pkgSource == "" {
			pkgVersion, pkgSource = "", ""
		}
		// The key vendor|product must stay within the inventory's 400 bytes, or it refuses the whole list.
		if !fits(display) || !fits(vendor) || !fits(product) || len(vendor)+len(product)+1 > maxKeyBytes || utf8.RuneCountInString(version) > maxVersion || len(items) >= limit {
			dropped++
			return
		}
		k := strings.ToLower(vendor) + "\x00" + strings.ToLower(product) + "\x00" + version
		if i, ok := seen[k]; ok {
			if pkgVersion == "" {
				return
			}
			c, err := debver.Compare(pkgVersion, items[i].PkgVersion) // an empty stored version is ErrInvalid: the new one is taken
			if err != nil || c < 0 {
				items[i].PkgVersion, items[i].PkgSource = pkgVersion, pkgSource
			}
			return
		}
		seen[k] = len(items)
		s := observe.Software{Display: display, Vendor: vendor, Product: product, Version: version, Confidence: softwareConfidence, Packaged: packaged,
			PkgVersion: pkgVersion, PkgSource: pkgSource}
		if mapped {
			s.KevKeys = []string{strings.ToLower(vendor) + "|" + strings.ToLower(product)}
		}
		items = append(items, s)
	}
	running := runningImages(snaps["deb_packages"])
	for _, r := range snaps["deb_packages"] {
		name := r["name"]
		p, ok := pkgmap.Linux.lookup(strings.ToLower(name))
		if !ok {
			p, ok = pkgmap.Linux.lookup(strings.ToLower(sourceName(r["source"])))
		}
		version := debUpstream(r["version"])
		src := strings.ToLower(cmp.Or(sourceName(r["source"]), name)) // dpkg leaves Source out when it equals the package name
		full := r["version"]
		switch lname := strings.ToLower(name); {
		case strings.HasPrefix(lname, "linux-image-") && !kernelImageRE.MatchString(lname):
			full = "" // a kernel metapackage: it names no kernel the machine runs
		case kernelImageRE.MatchString(lname) && running != nil && !running[lname]:
			full = "" // an installed kernel that does not run (the running one is listed)
		case !strings.HasPrefix(src, "linux-signed") && !sameSourceRelease(r["source"], full):
			full = "" // built from another source release: NVD decides (review L1)
		}
		if ok {
			add(p.Product, p.Vendor, p.Product, version, true, true, full, src)
		} else {
			add(name, name, name, version, false, true, full, src)
		}
	}
	for _, r := range snaps["rpm_packages"] {
		name := r["name"]
		p, ok := pkgmap.Linux.lookup(strings.ToLower(name))
		if ok {
			add(p.Product, p.Vendor, p.Product, r["version"], true, true, "", "")
		} else {
			add(name, name, name, r["version"], false, true, "", "")
		}
	}
	for _, r := range snaps["programs"] {
		name := r["name"]
		p, ok := pkgmap.Windows.lookup(strings.ToLower(name))
		switch {
		case ok:
			add(name, p.Vendor, p.Product, r["version"], true, false, "", "")
		case r["publisher"] != "":
			add(name, r["publisher"], name, r["version"], false, false, "", "")
		default:
			add(name, name, name, r["version"], false, false, "", "")
		}
	}
	return items, dropped
}

// kernelImageRE is a kernel image package of Ubuntu or Debian: linux-image-7.0.0-43-generic, linux-image-unsigned-…,
// linux-image-6.1.0-18-amd64 (a release number after the prefix; linux-image-generic and linux-image-amd64 are metapackages).
var kernelImageRE = regexp.MustCompile(`^linux-image-(unsigned-)?[0-9]`)

// kernelReleaseRE is a running kernel release as uname -r gives it ("7.0.0-43-generic", "6.1.0-18-amd64").
var kernelReleaseRE = regexp.MustCompile(`^[0-9][a-z0-9.+_-]{0,99}$`)

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
// running kernel's image (D-516).
type DebPackage struct{ Name, Version, Source, Kernel string }

// MapDebPackages turns a dpkg list into software the way an osquery deb_packages snapshot is turned (same table, same upstream
// version, same limits), so the box's own list (vedette-host, D-470) and an osquery agent on the same machine give the same rows.
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

// kindOf is the device kind of an os_version row (D-503, core/observe AgentKind), within the inventory's kind list; "" gives no kind
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
