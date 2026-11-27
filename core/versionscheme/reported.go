package versionscheme

import (
	"regexp"
	"strings"
)

// A program often reports its version with a token beside the release that no comparison reads: a word of the vendor's before it
// ("zx 5.4.2"), the "v" of a release tag ("v2.3.1"), or its build in parentheses after it ("4.2.9 (31207)", as Windows'
// DisplayVersion carries it). Vulnerability data states the release alone ("before 4.3.0"), and scanners that read such a program
// compare the release it states. Reported reads that release by these general forms only; the build adds nothing to the release's
// place among the vendor's releases, and the source's own text stays with its reading.
var (
	// reportedWord is a word of letters before the release, then a space, or the "v" of a tag right before it.
	reportedWord = regexp.MustCompile(`^(?:([A-Za-z]{1,16})\s+|[vV])([0-9].*)$`)
	// reportedBuild is a build number in parentheses after the release.
	reportedBuild = regexp.MustCompile(`^(.*?)\s*\([0-9]{1,12}\)$`)
	// reportedRelease is what must be left: dotted numbers, with a tag's pre-release or build part ("2.4.0-rc.1").
	reportedRelease = regexp.MustCompile(`^[0-9]{1,9}(?:\.[0-9]{1,9})+(?:[-+~][0-9A-Za-z.+~-]{1,40})?$`)
)

// qualifierWords are words that, before a number, say what the number is (a pre-release, an update, a build): never a vendor's word
// to drop, since the number after it is not the release.
var qualifierWords = map[string]bool{
	"alpha": true, "beta": true, "rc": true, "pre": true, "preview": true, "dev": true, "nightly": true, "snapshot": true,
	"insider": true, "canary": true, "build": true, "update": true, "patch": true, "sp": true, "hotfix": true, "hf": true, "rev": true,
	"revision": true, "r": true, "u": true, "p": true, "pl": true, "fp": true, "fixpack": true, "cu": true,
}

// Reported is the release a program's reported version states when a token beside it is a word before the release, a tag's "v" or
// a build in parentheses after it ("zx 5.4.2", "v2.3.1", "4.2.9 (31207)": 5.4.2, 2.3.1, 4.2.9). ok is false, and the version is
// returned as given, when it has no such token or what is left is not a release of dotted numbers: nothing is guessed.
func Reported(version string) (string, bool) {
	s := strings.TrimSpace(version)
	if s == "" || len(s) > 100 {
		return version, false
	}
	stripped := false
	if m := reportedBuild.FindStringSubmatch(s); m != nil {
		s, stripped = strings.TrimSpace(m[1]), true
	}
	if m := reportedWord.FindStringSubmatch(s); m != nil {
		if qualifierWords[strings.ToLower(m[1])] {
			return version, false
		}
		s, stripped = m[2], true
	}
	if !stripped || !reportedRelease.MatchString(s) {
		return version, false
	}
	return s, true
}
