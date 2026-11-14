package findings

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

// Platform limits (D-547, KF-4, KF-5). Some exploited CVEs affect a product only on some platforms: CVE-2026-123158 is
// OpenSSH built with musl libc and without PAM (Alpine), not Ubuntu's or Debian's glibc+PAM build of the same upstream version.
// No feed Vedette reads says so in a form a program can use (KEV: "on Linux"; CVE.org: platform "Linux"; NVD: the product
// only), so content/catalog/platform-limits.json holds a short reviewed list. For a CVE on it:
//   - the device's OS, the software's own version or banner text, or an agent's deb/rpm package database names another
//     platform, and nothing names one it affects → proved not affected (no finding; an open one closes, D-530 path);
//   - otherwise (platform not known, or one it affects) → the finding as before, with "It affects only …; check …".

type platformLimit struct {
	Only    []string `json:"only"`
	Affects string   `json:"affects"`
	Check   string   `json:"check"`
	Source  string   `json:"source"`
}

var platformLimits, platformLimitErr = loadPlatformLimits(catalogdata.PlatformLimits)

func loadPlatformLimits(data []byte) (map[string]platformLimit, error) {
	var rows map[string]json.RawMessage
	out := map[string]platformLimit{}
	if err := json.Unmarshal(data, &rows); err != nil {
		return out, err // TestPlatformLimits_DataIsValid fails on it; the matcher only loses the limits
	}
	for k, raw := range rows {
		if k == "_about" {
			continue
		}
		var l platformLimit
		if err := json.Unmarshal(raw, &l); err != nil {
			return out, fmt.Errorf("%s: %w", k, err)
		}
		if !ValidCVE(k) || len(l.Only) == 0 || l.Affects == "" || l.Check == "" || !strings.HasPrefix(l.Source, "https://") {
			return out, fmt.Errorf("%s: needs a CVE id, only, affects, check and an https source", k)
		}
		for _, p := range l.Only {
			if platformName(p) == "" {
				return out, fmt.Errorf("%s: unknown platform %q", k, p)
			}
		}
		out[k] = l
	}
	return out, nil
}

// platformWords are the platforms Vedette recognises in an OS name ("Ubuntu 26.04.1 LTS") or in the version and banner a service
// sends ("9.6p1 Ubuntu 3ubuntu13.20", "Ubuntu Linux; protocol 2.0", "7.4p1 Debian 10+deb9u7"): whole words, any case.
var platformWords = []struct {
	id, name string
	re       *regexp.Regexp
}{
	{"alpine", "Alpine Linux", regexp.MustCompile(`(?i)\balpine\b`)},
	{"ubuntu", "Ubuntu", regexp.MustCompile(`(?i)\bubuntu\b`)},
	{"debian", "Debian", regexp.MustCompile(`(?i)\b(debian|raspbian)\b`)},
	{"rhel", "Red Hat Enterprise Linux or a rebuild of it", regexp.MustCompile(`(?i)\b(red ?hat|rhel|centos|rocky|almalinux|oracle linux|fedora|amazon linux)\b`)},
	{"suse", "SUSE", regexp.MustCompile(`(?i)\b(open)?suse\b|\bsles\b`)},
	{"windows", "Windows", regexp.MustCompile(`(?i)\bwindows\b`)},
	{"macos", "macOS", regexp.MustCompile(`(?i)\b(mac ?os|os x)\b`)},
	{"bsd", "a BSD", regexp.MustCompile(`(?i)\b(freebsd|openbsd|netbsd)\b`)},
}

func platformName(id string) string {
	for _, w := range platformWords {
		if w.id == id {
			return w.name
		}
	}
	return ""
}

// platformEvidence names what says which platform the software runs on, as a clause ("this device runs Ubuntu 26.04.1 LTS"),
// with the platform ids it names. Only evidence of a recognised platform counts; "Linux 5.4 - 5.15" says none.
type platformEvidence struct {
	ids  []string
	says []string
}

func (e *platformEvidence) add(ids []string, clause string) {
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if !slices.Contains(e.ids, id) {
			e.ids = append(e.ids, id)
		}
	}
	e.says = append(e.says, clause)
}

func platformsIn(text string) []string {
	var ids []string
	for _, w := range platformWords {
		if w.re.MatchString(text) {
			ids = append(ids, w.id)
		}
	}
	return ids
}

func evidenceOf(in swInfo) platformEvidence {
	var e platformEvidence
	// The device's OS says nothing about a service a scan saw on one of its ports: a Ubuntu host may forward the port to an
	// Alpine container (CVE-2026-123158's references are about such containers), so only the service's own text decides there.
	if t := strings.TrimSpace(in.osName); t != "" && !in.netSeen {
		e.add(platformsIn(t), "this device runs "+clean(t))
	}
	if t := strings.TrimSpace(in.ver + " " + in.banner); t != "" {
		e.add(platformsIn(t), "the software reports "+clean(t))
	}
	if in.packaged { // an agent read it from a deb or rpm database: a Debian, Ubuntu, Red Hat or SUSE family build, never Alpine's apk
		kind := "rpm"
		if in.pkgVer != "" {
			kind = "deb"
		}
		e.add([]string{"deb-rpm"}, "an agent read it from the device's "+kind+" package database")
	}
	return e
}

// platformRuledOut says whether the evidence rules v out for the software: v is on the list, something names a platform,
// and nothing it names is one v affects. why is the sentence for the page ("CVE-… affects only …; this device runs Ubuntu 26.04.").
func platformRuledOut(in swInfo, cve string) (why string, out bool) {
	l, ok := platformLimits[cve]
	if !ok {
		return "", false
	}
	e := evidenceOf(in)
	if len(e.ids) == 0 || slices.ContainsFunc(e.ids, func(id string) bool { return slices.Contains(l.Only, id) }) {
		return "", false
	}
	return fmt.Sprintf("%s affects only %s; %s.", cve, l.Affects, strings.Join(e.says, ", and ")), true
}

// platformCondition is the sentence a finding of a platform-limited CVE carries when the platform is not ruled out (KF-5):
// "It affects only …: check …". "" for a CVE not on the list.
func platformCondition(cve string) string {
	l, ok := platformLimits[cve]
	if !ok {
		return ""
	}
	return fmt.Sprintf(" It affects only %s: %s (%s).", l.Affects, l.Check, l.Source)
}
