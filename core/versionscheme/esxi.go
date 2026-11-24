package versionscheme

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// ESXi. A host reports its version and build ("8.0.3", "24022510"); VMware's advisories and CVE records state a fixed release per
// train as "ESXi80U3d-24585383" (8.0 Update 3d, build 24585383), "ESXi70U3s-24585291", "ESXi80b-21203435" (a patch of the first
// 8.0 release) and, from 9.0 on, "ESXi-9.0.2.0100-25595025". A train is an update of a line (8.0 Update 3, 8.0 Update 2): the
// updates of one line are maintained side by side, so a build is compared only with builds of its own update. A range's lower bound
// "8.0" or "9.0.x.x" is the start of the line. Builds and releases: content/catalog/esxi-builds.json (Broadcom KB 316595).

// ESXiRelease is one ESXi release of esxi-builds.json: its version and update as NVD names them ("8.0", "update_3"; "-" for the
// first release) and its name ("ESXi 8.0 Update 3").
type ESXiRelease struct {
	Version string `json:"version"`
	Update  string `json:"update"`
	Name    string `json:"name"`
}

var esxiBuilds = func() map[string]ESXiRelease {
	var f struct {
		Builds map[string]ESXiRelease `json:"builds"`
	}
	if err := json.Unmarshal(catalogdata.ESXiBuilds, &f); err != nil {
		panic(fmt.Sprintf("versionscheme: esxi-builds.json: %v", err)) // embedded data, checked by TestESXiBuildsData
	}
	return f.Builds
}()

// ESXiBuild is the release of an ESXi build number; ok is false for a build esxi-builds.json does not list.
func ESXiBuild(build string) (ESXiRelease, bool) {
	r, ok := esxiBuilds[strings.TrimSpace(build)]
	return r, ok
}

// ESXiBuilds is every build esxi-builds.json lists, with its release.
func ESXiBuilds() map[string]ESXiRelease {
	out := make(map[string]ESXiRelease, len(esxiBuilds))
	for b, r := range esxiBuilds {
		out[b] = r
	}
	return out
}

var (
	// esxiNotation is VMware's "ESXi80U3d-24585383", "ESXi70U3s-24585291", "ESXi80b-21203435", "ESXi80-20513097", and a security-only
	// image of a patch, two letters ("ESXi70U3si-20841705": the security fixes of 7.0 Update 3i, an earlier build of the same train).
	esxiNotation = regexp.MustCompile(`^(?i:esxi)([6-9])([0-9])(?:U([1-9]))?([a-z]{1,2})?-([0-9]{5,9})$`)
	// esxi9Notation is VMware's "ESXi-9.0.2.0100-25595025": the release's version, then its build.
	esxi9Notation = regexp.MustCompile(`^(?i:esxi)-([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}(?:\.[0-9]{1,6})?)-([0-9]{5,9})$`)
	// esxiLine is a range's lower bound: a line ("8.0") or every release of it ("9.0.x.x", "8.0.x").
	esxiLine = regexp.MustCompile(`^([6-9])\.([0-9])(?:\.[xX])*$`)
	// esxiUpdate is esxi-builds.json's update ("update_3d", "b", "-").
	esxiUpdate = regexp.MustCompile(`^(?:update_([1-9])([a-z])?|([a-z])|-)$`)
)

// VMwareESXi is the ESXi scheme.
var VMwareESXi = register(&Scheme{
	Name:      "vmware-esxi",
	About:     "VMware ESXi: line 8.0, train = the update (8.0 U3), place = the build; VMware's ESXi80U3d-24585383 and ESXi-9.0.2.0100-25595025",
	parse:     esxiParse,
	installed: esxiInstalled,
	stated:    esxiStated,
})

var (
	// esxiTyped is a release as a host, a scan or a person writes it: "8.0.3 build 24022510", "8.0.3-24022510", "8.0 U3e", "8.0 Update 3
	// (build 24022510)", "VMware ESXi 8.0b", "8.0" (a line alone, placed only by a build the name states).
	esxiTyped = regexp.MustCompile(`^(?i:vmware\s+)?(?i:esxi\s+)?([6-8])\.([0-9])(?:\.([0-9]))?(?:\s*(?i:u|update)\s*([1-9]))?([a-z])?(?:\s+(?i:ga))?` +
		`(?:[\s,;]*\(?\s*(?i:build)?[\s-]*([0-9]{5,9})\s*\)?)?$`)
	// esxiNamedBuild is the build a name states ("VMware ESXi 8.0 Update 3 (build 24022510)").
	esxiNamedBuild = regexp.MustCompile(`\(build ([0-9]{5,9})\)`)
)

// esxiStated writes an ESXi 6.x to 8.x release as the host states it to the matcher: version "<line>.<update>" ("8.0.3", "8.0.0" for
// the first release and its patches) and the name with its build ("VMware ESXi 8.0 Update 3 (build 24022510)"), the build placing the
// release inside its update. The build is the one the text gives, else the one the name already states when it is of the release the
// text says (a device's own statement is the more precise), else the build of the release the text names exactly ("8.0 U3" is the release ESXi 8.0 Update 3, build 24022510; "8.0 U3e" is Update 3e) in esxi-builds.json. A
// text that names no update or build ("8.0"), a build of another line or update than the text says, or a release the table does not
// list without its build is not written (ok false): it is kept as given.
func esxiStated(version, display string) (string, string, bool) {
	m := esxiTyped.FindStringSubmatch(version)
	if m == nil {
		return "", "", false
	}
	line := m[1] + "." + m[2]
	update, letter, build := -1, m[5], m[6]
	if m[3] != "" {
		update = atoi(m[3])
	}
	if m[4] != "" {
		if update >= 0 && update != atoi(m[4]) {
			return "", "", false // "8.0.2 U3": two updates
		}
		update = atoi(m[4])
	}
	named := build == "" && update < 0 && letter == "" // the text is a line alone: the name's build says the release
	if build == "" {
		if b := esxiNamedBuild.FindStringSubmatch(display); b != nil {
			rel, ok := esxiBuilds[b[1]]
			switch {
			case ok && rel.Version == line && (named || sameUpdate(rel, max(update, 0), letter)):
				build = b[1]
			case !ok && letter == "":
				// a build the table does not list yet (a host patched after the table was written) is the device's own word: it is
				// kept when the name states it for the update the text says, never replaced by an older build the table lists
				if u, ok := esxiNamedUpdate(display, line, b[1]); ok && (named || u == update) {
					build, update = b[1], u
				}
			}
		}
	}
	if build == "" {
		if named {
			return "", "", false
		}
		want := "-"
		switch {
		case update > 0:
			want = "update_" + strconv.Itoa(update) + letter
		case letter != "":
			want = letter
		}
		for b, rel := range esxiBuilds {
			if rel.Version == line && rel.Update == want && (build == "" || b < build) {
				build = b
			}
		}
		if build == "" {
			return "", "", false
		}
	}
	rel, known := esxiBuilds[build]
	if !known {
		if update < 0 {
			return "", "", false // a build the table does not list says no update by itself
		}
		name := "ESXi " + line
		if update > 0 {
			name += " Update " + strconv.Itoa(update)
		}
		return line + "." + strconv.Itoa(update), "VMware " + name + letter + " (build " + build + ")", true
	}
	u, l := esxiUpdateOf(rel)
	if rel.Version != line || u < 0 || update >= 0 && u != update || letter != "" && l != letter {
		return "", "", false // the build belongs to another release than the text says
	}
	return line + "." + strconv.Itoa(u), "VMware " + rel.Name + " (build " + build + ")", true
}

// esxiNamedUpdate is the update a name states for its build ("VMware ESXi 8.0.3 (build N)" and "VMware ESXi 8.0 Update 3 (build N)"
// are update 3, "VMware ESXi 8.0.0 (build N)" is 0); ok is false when the name is of another line or build, or states no update.
func esxiNamedUpdate(display, line, build string) (int, bool) {
	m := esxiTyped.FindStringSubmatch(display)
	if m == nil || m[1]+"."+m[2] != line || m[6] != build || m[5] != "" {
		return 0, false
	}
	switch {
	case m[3] != "" && m[4] != "" && m[3] != m[4]:
		return 0, false
	case m[4] != "":
		return atoi(m[4]), true
	case m[3] != "":
		return atoi(m[3]), true
	}
	return 0, false
}

// esxiUpdateOf is a release's update number and patch letter ("update_3e" is 3, "e"; "b" is 0, "b"; "-" is 0, ""); -1 when unreadable.
func esxiUpdateOf(rel ESXiRelease) (int, string) {
	m := esxiUpdate.FindStringSubmatch(rel.Update)
	switch {
	case m == nil:
		return -1, ""
	case m[1] != "":
		return atoi(m[1]), m[2]
	}
	return 0, m[3]
}

// sameUpdate says rel is a release of this update with this patch letter, or of any letter when the text gives none ("8.0.3" is what a
// host at 8.0 Update 3e reports).
func sameUpdate(rel ESXiRelease, update int, letter string) bool {
	u, l := esxiUpdateOf(rel)
	return u == update && (letter == "" || l == letter)
}

func esxiParse(s string) (Version, bool) {
	if m := esxiLine.FindStringSubmatch(s); m != nil {
		line := []int{atoi(m[1]), atoi(m[2])}
		return Version{Line: line, LineStart: true, Train: lineName(line), Label: s, Display: s}, true
	}
	if m := esxiNotation.FindStringSubmatch(s); m != nil {
		line := []int{atoi(m[1]), atoi(m[2])}
		rank := 0
		if m[3] != "" {
			rank = atoi(m[3])
		}
		return esxiVersion(line, rank, m[4], atoi(m[5])), true
	}
	if m := esxi9Notation.FindStringSubmatch(s); m != nil {
		n, ok := nums(m[1])
		if !ok || n[0] < 9 {
			return Version{}, false
		}
		return esxi9Version(n, m[1], atoi(m[2])), true
	}
	return Version{}, false
}

// esxiVersion is a release of the 6.x to 8.x lines: line, update (0 for the first release), the patch letter, the build.
func esxiVersion(line []int, rank int, letter string, build int) Version {
	train := lineName(line)
	label := train
	if rank > 0 {
		train += " U" + strconv.Itoa(rank)
		label = train
	}
	label += letter
	return Version{Line: line, Rank: rank, Build: []int{build}, Train: train, Label: label, Display: label + " (build " + strconv.Itoa(build) + ")"}
}

// esxi9Version is a release of 9.0 on: the line is the first two numbers, the train the third ("9.0.2"), the place the build.
func esxi9Version(n []int, text string, build int) Version {
	line := n[:2]
	rank := 0
	if len(n) > 2 {
		rank = n[2]
	}
	return Version{Line: line, Rank: rank, Build: []int{build}, Train: lineName(line) + "." + strconv.Itoa(rank), Label: text,
		Display: text + " (build " + strconv.Itoa(build) + ")"}
}

// esxiInstalled reads a host's version ("8.0.3", "7.0.3", "9.0.2.0") and build ("24022510"): the version's third number is the
// update (8.0.3 is 8.0 Update 3). A build esxi-builds.json lists must name the same line and update (its name gives the patch
// letter); a build it does not list is placed by the version alone. Without a build nothing is placed.
func esxiInstalled(version, build string) (Version, bool) {
	n, ok := nums(version)
	if !ok || len(n) < 2 || len(n) > 4 || n[0] < 6 || n[0] > 9 || len(build) < 5 || len(build) > 9 || strings.TrimLeft(build, "0123456789") != "" {
		return Version{}, false
	}
	b := atoi(build)
	rank := 0
	if len(n) > 2 {
		rank = n[2]
	}
	if n[0] >= 9 {
		return esxi9Version(n, version, b), true
	}
	rel, known := esxiBuilds[build]
	if !known {
		return esxiVersion(n[:2], rank, "", b), true
	}
	m := esxiUpdate.FindStringSubmatch(rel.Update)
	if m == nil || rel.Version != lineName(n[:2]) {
		return Version{}, false
	}
	relRank, letter := 0, m[3]
	if m[1] != "" {
		relRank, letter = atoi(m[1]), m[2]
	}
	if len(n) > 2 && relRank != rank {
		return Version{}, false // the build belongs to another update than the version says
	}
	return esxiVersion(n[:2], relRank, letter, b), true
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
