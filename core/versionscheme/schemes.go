package versionscheme

import (
	"regexp"
	"strconv"
	"strings"
)

// NetScaler (Citrix ADC and Gateway). A release is "<line>-<build>" ("14.1-73.37", also written "14.1.73.37" or "NS14.1: Build
// 73.37.nc"); the FIPS and NDcPP builds share a line of their own ("13.1-37.247 FIPS", "13.1.37.279 FIPS and NDcPP"). Citrix's
// bulletins and CVE records state the fixed build of each line ("0 lessThan 14.1-73.37", "0 lessThan 13.1-64.23", or the line as the
// start and the build alone as the end: "14.1" lessThan "72.61"): a build is compared only with builds of its line. A range's lower
// bound "14.1" is the start of that line.
var (
	netscalerRelease = regexp.MustCompile(`^(?i:ns)?([0-9]{1,2})\.([0-9]{1,2})(?:[-.]|\s*:?\s*(?i:build)\s*)([0-9]{1,3})\.([0-9]{1,4})(?i:\.nc)?` + netscalerVariantRE + `$`)
	netscalerLine    = regexp.MustCompile(`^([0-9]{1,2})\.([0-9]{1,2})(?:\.[xX])*` + netscalerVariantRE + `$`)
	netscalerBuild   = regexp.MustCompile(`^([0-9]{1,3})\.([0-9]{1,4})$`)
)

// netscalerVariantRE is the FIPS and NDcPP line's words after a release: "FIPS", "NDcPP", "FIPS and NDcPP", "(FIPS)".
const netscalerVariantRE = `(?:\s*\(?\s*((?i:fips)(?:\s+(?i:and)\s+(?i:ndcpp))?|(?i:ndcpp))\s*\)?)?`

// NetScaler is the NetScaler scheme.
var NetScaler = register(&Scheme{
	Name:  "citrix-netscaler",
	About: "NetScaler ADC and Gateway: line = train (14.1; 13.1 FIPS and NDcPP apart), place = the build (73.37)",
	endInLine: func(start Version, s string) (Version, bool) {
		m := netscalerBuild.FindStringSubmatch(s)
		if m == nil {
			return Version{}, false
		}
		label := lineName(start.Line) + "-" + m[1] + "." + m[2]
		if start.Variant != "" {
			label += " " + start.Variant
		}
		return Version{Line: start.Line, Variant: start.Variant, Build: []int{atoi(m[1]), atoi(m[2])}, Train: start.Train, Label: label, Display: label}, true
	},
	parse: func(s string) (Version, bool) {
		if m := netscalerLine.FindStringSubmatch(s); m != nil {
			line, variant := []int{atoi(m[1]), atoi(m[2])}, netscalerVariant(m[3])
			return Version{Line: line, Variant: variant, LineStart: true, Train: trainOf(line, variant), Label: s, Display: s}, true
		}
		m := netscalerRelease.FindStringSubmatch(s)
		if m == nil {
			return Version{}, false
		}
		line, variant := []int{atoi(m[1]), atoi(m[2])}, netscalerVariant(m[5])
		label := lineName(line) + "-" + m[3] + "." + m[4]
		if variant != "" {
			label += " " + variant
		}
		return Version{Line: line, Variant: variant, Build: []int{atoi(m[3]), atoi(m[4])}, Train: trainOf(line, variant), Label: label, Display: label}, true
	},
})

// netscalerVariant names the FIPS and NDcPP line, one line for both (their builds share numbers: 13.1-37.x).
func netscalerVariant(s string) string {
	if s == "" {
		return ""
	}
	return "FIPS and NDcPP"
}

func trainOf(line []int, variant string) string {
	if variant != "" {
		return lineName(line) + " " + variant
	}
	return lineName(line)
}

// Linux kernel. The kernel's CVE records state the first release of each stable branch that has the fix ("6.1.149", "6.6.30") and
// the mainline release ("6.17"); a branch is a train (6.1), its stable releases the places inside it. A distribution's kernel
// ("6.8.0-45-generic") carries the distribution's own fixes and is never read here: only an upstream release of numbers and dots.
// Lines before 3.0 have three numbers (2.6.32, its stable releases 2.6.32.71).
var linuxRelease = regexp.MustCompile(`^[0-9]{1,2}(?:\.[0-9]{1,4}){1,3}$`)

// LinuxKernel is the Linux kernel scheme.
var LinuxKernel = register(&Scheme{
	Name:  "linux-kernel",
	About: "Linux kernel: train = the stable branch (6.1), place = the stable release (6.1.149); upstream releases only",
	parse: func(s string) (Version, bool) {
		if !linuxRelease.MatchString(s) {
			return Version{}, false
		}
		n, ok := nums(s)
		if !ok {
			return Version{}, false
		}
		width := 2
		if n[0] < 3 {
			width = 3
		}
		if len(n) < width {
			return Version{}, false
		}
		line, build := n[:width], n[width:]
		if len(build) == 0 {
			build = []int{0}
		}
		return Version{Line: line, Build: build, Train: lineName(line), Label: s, Display: s}, true
	},
})

// Java SE. Java 8 and earlier write "1.8.0_491" (or "8u491"), Java 9 on "17.0.10" (with "+7" for the build); a feature release is a
// train (8, 17), its updates the places inside it.
var (
	javaOld = regexp.MustCompile(`^1\.([1-8])\.0(?:_([0-9]{1,4}))?(?:-b([0-9]{1,3}))?$`)
	javaU   = regexp.MustCompile(`^([1-8])u([0-9]{1,4})(?:-?b([0-9]{1,3}))?$`)
	javaNew = regexp.MustCompile(`^([0-9]{1,3})((?:\.[0-9]{1,4}){0,3})(?:\+[0-9]{1,4})?$`)
)

// Java is the Java SE scheme.
var Java = register(&Scheme{
	Name:  "java",
	About: "Java SE: train = the feature release (8, 17), place = the update (1.8.0_491, 8u491, 17.0.10)",
	parse: func(s string) (Version, bool) {
		mk := func(feature int, place []int) (Version, bool) {
			line := []int{feature}
			return Version{Line: line, Build: place, Train: strconv.Itoa(feature), Label: s, Display: s}, true
		}
		if len(s) == 1 && s[0] >= '1' && s[0] <= '8' { // "8": the line, as a range's lower bound
			line := []int{atoi(s)}
			return Version{Line: line, LineStart: true, Train: s, Label: s, Display: s}, true
		}
		withPatch := func(v Version, ok bool, b string) (Version, bool) { // the build after the update ("-b33"): a patch build
			if b != "" {
				v.Patch = atoi(b)
			}
			return v, ok
		}
		if m := javaOld.FindStringSubmatch(s); m != nil {
			v, ok := mk(atoi(m[1]), []int{0, atoi(m[2])})
			return withPatch(v, ok, m[3])
		}
		if m := javaU.FindStringSubmatch(s); m != nil {
			v, ok := mk(atoi(m[1]), []int{0, atoi(m[2])})
			return withPatch(v, ok, m[3])
		}
		if m := javaNew.FindStringSubmatch(s); m != nil && atoi(m[1]) >= 9 {
			place := []int{0, 0}
			if m[2] != "" {
				n, ok := nums(strings.TrimPrefix(m[2], "."))
				if !ok {
					return Version{}, false
				}
				place = n
			}
			return mk(atoi(m[1]), place)
		}
		return Version{}, false
	},
})

// Junos OS. A release is "<line>R<n>" with an optional service release "-S<m>" and respin ".<k>" ("21.4R3-S5.4", "15.1R7.9"), or a
// special release of a line "<line>X<n>-D<m>" ("15.1X49-D200"); Junos OS Evolved writes "-EVO" after it. Juniper's advisories and CVE
// records state the fixed release of each line ("21.4 lessThan 21.4R3-S7", "0 lessThan 21.2R3-S8"): a line (21.4) is a train, its
// releases the places inside it (R1 < R1-S1 < R2 < R3 < R3-S7, a respin after its release); the X releases of a line and Junos OS
// Evolved (and the F releases of 15.1) are lines of their own. A range's lower bound "21.4" is the start of that line.
var (
	junosRelease = regexp.MustCompile(`^([0-9]{1,2})\.([0-9]{1,2})(?:([RrFf])([0-9]{1,3})(?:\.([0-9]{1,3}))?(?:-[Ss]([0-9]{1,3})(?:\.([0-9]{1,3}))?)?|[Xx]([0-9]{1,3})-[Dd]([0-9]{1,4})(?:\.([0-9]{1,3}))?)(-(?i:evo))?$`)
	junosLine    = regexp.MustCompile(`^([0-9]{1,2})\.([0-9]{1,2})(?:[Xx]([0-9]{1,3}))?(-(?i:evo))?$`)
)

// Junos is the Junos OS scheme.
var Junos = register(&Scheme{
	Name:  "juniper-junos",
	About: "Juniper Junos OS: train = the release line (21.4; its X releases and Junos OS Evolved apart), place = R3-S5.4",
	parse: func(s string) (Version, bool) {
		if m := junosLine.FindStringSubmatch(s); m != nil {
			x := ""
			if m[3] != "" {
				x = "X" + m[3]
			}
			line, variant := []int{atoi(m[1]), atoi(m[2])}, junosVariant(x, m[4])
			return Version{Line: line, Variant: variant, LineStart: true, Train: trainOf(line, variant), Label: s, Display: s}, true
		}
		m := junosRelease.FindStringSubmatch(s)
		if m == nil {
			return Version{}, false
		}
		line := []int{atoi(m[1]), atoi(m[2])}
		var build []int
		variant := junosVariant("", m[11])
		if m[8] != "" { // X<n>-D<m>.<k>
			variant = junosVariant("X"+m[8], m[11])
			build = []int{atoi(m[9]), atoi(m[10])}
		} else { // R<n>[.<k>][-S<m>[.<k>]]: the respin of the release or of its service release; F releases are a line of their own
			if strings.EqualFold(m[3], "F") {
				variant = junosVariant("F", m[11])
			}
			respin := atoi(m[5])
			if m[6] != "" {
				respin = atoi(m[7])
			}
			build = []int{atoi(m[4]), atoi(m[6]), respin}
		}
		return Version{Line: line, Variant: variant, Build: build, Train: trainOf(line, variant), Label: s, Display: s}, true
	},
})

// junosVariant names a Junos line apart from the plain one: an X release line ("X49"), Junos OS Evolved ("EVO"), or both.
func junosVariant(x, evo string) string {
	switch {
	case x != "" && evo != "":
		return x + " EVO"
	case evo != "":
		return "EVO"
	}
	return x
}
