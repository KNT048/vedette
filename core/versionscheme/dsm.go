package versionscheme

import (
	"regexp"
	"strconv"
)

// Synology DiskStation Manager. A release is "<line>-<build>" and its updates "<line>-<build>-<update>": DSM's Info Center says
// "DSM 7.2.1-69057 Update 5", Synology's advisories and NVD write "7.2.1-69057-5". A line (7.2, 7.2.1, 7.2.2, 7.3.1) is maintained
// on its own build with numbered updates, so a release is compared only with releases of its line: 7.2.1-69057-5 is before
// 7.2.1-69057-6 and has nothing to do with 7.2-64570-4. A range's lower bound "7.2.1" is the start of that line. NVD writes DSM's
// bounds in this notation too (NVDNotation): "from 7.2.1-69057 before 7.2.1-69057-6".
var (
	dsmRelease = regexp.MustCompile(`^(?i:dsm\s+)?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,2}))?-([0-9]{4,6})(?:(?:-|\s*(?i:update)\s*)([0-9]{1,3}))?$`)
	dsmLine    = regexp.MustCompile(`^(?i:dsm\s+)?([0-9]{1,2})\.([0-9]{1,2})(?:\.([0-9]{1,2}))?(?:\.[xX])*$`)
)

// SynologyDSM is the DSM scheme.
var SynologyDSM = register(&Scheme{
	Name:        "synology-dsm",
	About:       "Synology DSM: line = train (7.2.1), place = the build and its update (69057 Update 5); Synology's and NVD's 7.2.1-69057-5",
	NVDNotation: true,
	Described:   true,
	parse:       dsmParse,
	stated: func(version, _ string) (string, string, bool) {
		v, ok := dsmParse(version)
		if !ok || v.LineStart {
			return "", "", false
		}
		out := lineName(v.Line) + "-" + strconv.Itoa(v.Build[0])
		if v.Build[1] > 0 {
			out += "-" + strconv.Itoa(v.Build[1])
		}
		return out, "", true
	},
})

func dsmParse(s string) (Version, bool) {
	if m := dsmLine.FindStringSubmatch(s); m != nil {
		line := dsmLineOf(m[1], m[2], m[3])
		return Version{Line: line, LineStart: true, Train: lineName(line), Label: lineName(line), Display: lineName(line)}, true
	}
	m := dsmRelease.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	line, build, update := dsmLineOf(m[1], m[2], m[3]), atoi(m[4]), 0
	if m[5] != "" {
		update = atoi(m[5])
	}
	label := lineName(line) + "-" + m[4]
	if update > 0 {
		label += " Update " + strconv.Itoa(update)
	}
	return Version{Line: line, Build: []int{build, update}, Train: lineName(line), Label: label, Display: label}, true
}

func dsmLineOf(major, minor, patch string) []int {
	line := []int{atoi(major), atoi(minor)}
	if patch != "" {
		line = append(line, atoi(patch))
	}
	return line
}
