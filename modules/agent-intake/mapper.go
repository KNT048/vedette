package agentintake

import (
	_ "embed"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"

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
// host has one of them), the same product and version once.
func mapPackages(snaps map[string][]row) (items []observe.Software, dropped int) {
	seen := map[string]bool{}
	add := func(display, vendor, product, version string, mapped bool) {
		// The key vendor|product must stay within the inventory's 400 bytes, or it refuses the whole list.
		if !fits(display) || !fits(vendor) || !fits(product) || len(vendor)+len(product)+1 > maxKeyBytes || utf8.RuneCountInString(version) > maxVersion || len(items) >= maxRows {
			dropped++
			return
		}
		k := strings.ToLower(vendor) + "\x00" + strings.ToLower(product) + "\x00" + version
		if seen[k] {
			return
		}
		seen[k] = true
		s := observe.Software{Display: display, Vendor: vendor, Product: product, Version: version, Confidence: softwareConfidence}
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
		if ok {
			add(p.Product, p.Vendor, p.Product, version, true)
		} else {
			add(name, name, name, version, false)
		}
	}
	for _, r := range snaps["rpm_packages"] {
		name := r["name"]
		p, ok := pkgmap.Linux.lookup(strings.ToLower(name))
		if ok {
			add(p.Product, p.Vendor, p.Product, r["version"], true)
		} else {
			add(name, name, name, r["version"], false)
		}
	}
	for _, r := range snaps["programs"] {
		name := r["name"]
		p, ok := pkgmap.Windows.lookup(strings.ToLower(name))
		switch {
		case ok:
			add(name, p.Vendor, p.Product, r["version"], true)
		case r["publisher"] != "":
			add(name, r["publisher"], name, r["version"], false)
		default:
			add(name, name, name, r["version"], false)
		}
	}
	return items, dropped
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

// linuxServer is the os_version platform of the Linux distributions the agent supports (INV-2) and their close kin; all are run here as
// servers (the install is for servers only, D-34). Another Linux (a desktop distribution) gives no kind.
var linuxServer = []string{"ubuntu", "debian", "rhel", "centos", "rocky", "almalinux", "ol", "amzn", "sles"}

// kindOf is the device kind of an os_version row (D-503), within the inventory's kind list: Windows Server is a server and another
// Windows a pc, a supported Linux a server, macOS a pc; anything else "" (no kind observation, the device keeps what it has). It goes in
// with the agent's rank, so a person's choice still wins and a passive guess never overrides it.
func kindOf(r row) string {
	switch p := strings.ToLower(r["platform"]); {
	case p == "windows":
		if strings.Contains(strings.ToLower(r["name"]), "server") {
			return "server"
		}
		return "pc"
	case p == "darwin":
		return "pc"
	case slices.Contains(linuxServer, p):
		return "server"
	}
	return ""
}

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
