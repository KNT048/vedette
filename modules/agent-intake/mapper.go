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
// openssh-server not) the row keeps the lowest, so a binary that was not updated keeps its finding. Kernel images are the
// exception: Ubuntu and Debian keep the previous kernel installed as a boot fallback after an update, and the machine boots
// the newest one, so the Kernel row keeps the HIGHEST version of the kernel images (linux-image-7.0.0-43-generic over
// -30-generic); a metapackage (linux-image-generic, source linux-meta) never gives the row its version or source.
func mapPackages(snaps map[string][]row, limit int) (items []observe.Software, dropped int) {
	seen := map[string]int{} // key -> index in items
	add := func(display, vendor, product, version string, mapped, packaged bool, pkgVersion, pkgSource string, kernel bool) {
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
			if err != nil || kernel && c > 0 || !kernel && c < 0 {
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
	for _, r := range snaps["deb_packages"] {
		name := r["name"]
		p, ok := pkgmap.Linux.lookup(strings.ToLower(name))
		if !ok {
			p, ok = pkgmap.Linux.lookup(strings.ToLower(sourceName(r["source"])))
		}
		version := debUpstream(r["version"])
		src := strings.ToLower(cmp.Or(sourceName(r["source"]), name)) // dpkg leaves Source out when it equals the package name
		full, kernel := r["version"], kernelImageRE.MatchString(name)
		if strings.HasPrefix(strings.ToLower(name), "linux-image-") && !kernel {
			full, src = "", "" // a kernel metapackage: it names no kernel the machine runs
		}
		if ok {
			add(p.Product, p.Vendor, p.Product, version, true, true, full, src, kernel)
		} else {
			add(name, name, name, version, false, true, full, src, kernel)
		}
	}
	for _, r := range snaps["rpm_packages"] {
		name := r["name"]
		p, ok := pkgmap.Linux.lookup(strings.ToLower(name))
		if ok {
			add(p.Product, p.Vendor, p.Product, r["version"], true, true, "", "", false)
		} else {
			add(name, name, name, r["version"], false, true, "", "", false)
		}
	}
	for _, r := range snaps["programs"] {
		name := r["name"]
		p, ok := pkgmap.Windows.lookup(strings.ToLower(name))
		switch {
		case ok:
			add(name, p.Vendor, p.Product, r["version"], true, false, "", "", false)
		case r["publisher"] != "":
			add(name, r["publisher"], name, r["version"], false, false, "", "", false)
		default:
			add(name, name, name, r["version"], false, false, "", "", false)
		}
	}
	return items, dropped
}

// kernelImageRE is a kernel image package of Ubuntu or Debian: linux-image-7.0.0-43-generic, linux-image-unsigned-…,
// linux-image-6.1.0-18-amd64 (a release number after the prefix; linux-image-generic and linux-image-amd64 are metapackages).
var kernelImageRE = regexp.MustCompile(`^linux-image-(unsigned-)?[0-9]`)

// DebPackage is one installed Debian package: name, full Debian version and source package ("" when it has none).
type DebPackage struct{ Name, Version, Source string }

// MapDebPackages turns a dpkg list into software the way an osquery deb_packages snapshot is turned (same table, same upstream
// version, same limits), so the box's own list (vedette-host, D-470) and an osquery agent on the same machine give the same rows.
// It is a pure function: it reads no table and works with the module off. dropped counts rows whose fields are outside the
// inventory's limits. Unlike an agent's snapshot the list is never cut at maxRows: the caller stores it whole or not at all
// (the inventory refuses a list over its 5 000 items, so the box keeps its last list instead of a part of the box).
func MapDebPackages(pkgs []DebPackage) (items []observe.Software, dropped int) {
	rows := make([]row, 0, len(pkgs))
	for _, p := range pkgs {
		rows = append(rows, row{"name": p.Name, "version": p.Version, "source": p.Source})
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
