package findings

import (
	"regexp"

	"github.com/knt048/vedette/core/apkver"
)

// Alpine package releases: core/apkver, shared with the feeds module's Alpine parser.
type apkVer = apkver.Version

func parseAPK(s string) (apkVer, bool) { return apkver.Parse(s) }

func compareAPK(a, b apkVer) int { return apkver.Compare(a, b) }

func apkUpstream(s string) string { return apkver.Upstream(s) }

// upstreamOrder orders two releases by their upstream version only (the -rN revision left out).
func upstreamOrder(a, b apkVer) int { return apkver.CompareUpstream(a, b) }

// apkLineRE reads the release line of an upstream version: its first two numbers ("3.12" of "3.12.16", "10.2" of "10.2_p1"), or its
// one number ("259" of "259").
var apkLineRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?`)

// apkLine is the upstream release line of a version or an apk release ("3.12" of "3.12.16-r0"); "" when it starts with no number.
func apkLine(s string) string { return apkLineRE.FindString(apkUpstream(s)) }
