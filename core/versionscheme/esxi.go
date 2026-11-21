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
	// esxiNotation is VMware's "ESXi80U3d-24585383", "ESXi70U3s-24585291", "ESXi80b-21203435", "ESXi80-20513097".
	esxiNotation = regexp.MustCompile(`^(?i:esxi)([6-9])([0-9])(?:U([1-9]))?([a-z])?-([0-9]{5,9})$`)
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
})

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
