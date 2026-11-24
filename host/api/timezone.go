package api

import (
	"regexp"
	"strings"
)

// The box's time zone (spec 6.15): one zone for the pages, the mails, the logs and the operating system. Core keeps the organization's
// zone and asks the host to set the operating system's to the same name.

// CmdOSTimezoneSet is os.timezone.set.
const CmdOSTimezoneSet = "os.timezone.set"

// Refusal and failure codes of os.timezone.set.
const (
	// CodeZoneUnknown (412) is a well-formed name the operating system has no zone file for (an old alias its tzdata package left
	// out, a zone that does not exist).
	CodeZoneUnknown = "zone_unknown"
	// CodeTimezoneNotSet is a timedatectl that exited non-zero.
	CodeTimezoneNotSet = "timezone_not_set"
)

// MaxZoneName is the longest zone name either side passes on (the longest IANA name is 32 bytes).
const MaxZoneName = 64

// zoneNameRE is the shape of an IANA zone name: one to three parts of letters, digits, "_", "+" and "-", each starting with a letter
// (Etc/GMT+7, America/Argentina/Buenos_Aires, America/Port-au-Prince, UTC). No dot anywhere, so no "." or ".." part and no file of
// the database that is not a zone (zone.tab, tzdata.zi); no leading "/", so never an absolute path.
var zoneNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z][A-Za-z0-9_+-]*){0,2}$`)

// notZones are names in the zone database directory that are not zones a box may use: the posix/ and right/ trees (right/ counts
// leap seconds, which would put the clock off by 27 s), the database's default rules, its own link to /etc/localtime, and the
// placeholder zone.
var notZones = []string{"posix", "right", "posixrules", "localtime", "Factory"}

// ValidZoneName reports whether s has the shape of a zone name the box may set (see zoneNameRE and notZones). It says nothing of
// whether the zone exists: core checks its own database, the host the operating system's.
func ValidZoneName(s string) bool {
	if len(s) == 0 || len(s) > MaxZoneName || !zoneNameRE.MatchString(s) {
		return false
	}
	first, _, _ := strings.Cut(s, "/")
	for _, n := range notZones {
		if strings.EqualFold(first, n) {
			return false
		}
	}
	return true
}

// ZoneOfLink is the zone name a /etc/localtime link points at: the part after the last "zoneinfo/" of the target
// ("/usr/share/zoneinfo/Asia/Ho_Chi_Minh", "../usr/share/zoneinfo/Etc/UTC"); "" when the target is not in a zone database or the
// rest is not a valid name.
func ZoneOfLink(target string) string {
	i := strings.LastIndex(target, "zoneinfo/")
	if i < 0 {
		return ""
	}
	if z := target[i+len("zoneinfo/"):]; ValidZoneName(z) {
		return z
	}
	return ""
}

// OSTimezoneArgs are the args of os.timezone.set.
type OSTimezoneArgs struct {
	Zone string `json:"zone"`
}

// OSTimezoneResult is the result of os.timezone.set: the zone the operating system uses now (read back), and whether the run
// changed it (false: it already was).
type OSTimezoneResult struct {
	Zone    string `json:"zone"`
	Changed bool   `json:"changed"`
}

// TimeState is the body of GET /v1/state/time: the operating system's time zone, read from the /etc/localtime link ("" when it is
// not a link into a zone database: a copied file, no file, a name that is not valid).
type TimeState struct {
	Timezone string `json:"timezone"`
}
