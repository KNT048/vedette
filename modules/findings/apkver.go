package findings

import "github.com/knt048/vedette/core/apkver"

// Alpine package releases: core/apkver, shared with the feeds module's Alpine parser.
type apkVer = apkver.Version

func parseAPK(s string) (apkVer, bool) { return apkver.Parse(s) }

func compareAPK(a, b apkVer) int { return apkver.Compare(a, b) }

func apkUpstream(s string) string { return apkver.Upstream(s) }

// upstreamOrder orders two releases by their upstream version only (the -rN revision left out).
func upstreamOrder(a, b apkVer) int { return apkver.CompareUpstream(a, b) }
