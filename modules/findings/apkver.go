package findings

import "github.com/knt048/vedette/core/apkver"

// Alpine package releases (D-604): core/apkver, shared with the feeds module's Alpine parser (D-605).
type apkVer = apkver.Version

func parseAPK(s string) (apkVer, bool) { return apkver.Parse(s) }

func compareAPK(a, b apkVer) int { return apkver.Compare(a, b) }

func apkUpstream(s string) string { return apkver.Upstream(s) }
