package inventory

import (
	"regexp"
	"strings"
)

// sourceRank orders the sources (DATA_MODEL 5.1 (2)): manual > agent > snmp > nmap = scan > passive.
// An unknown source ranks lowest; the database refuses one anyway.
func sourceRank(s string) int {
	switch s {
	case "manual":
		return 5
	case "agent":
		return 4
	case "snmp":
		return 3
	case "nmap", "scan":
		return 2
	case "passive":
		return 1
	}
	return 0
}

// obs is a stored observation, as the merge sees it.
type obs struct {
	id         string
	field      string
	value      string
	source     string
	confidence float64
	seenAt     string // fixed-width UTC ISO-8601: lexical order is time order
}

// uuidName is a host name that is only an identifier: a UUID (a Mac's mDNS service name
// "fbaf5191-cc17-4626-a85b-812bc3d7b83b") or 32 hex digits. A person cannot tell the device from it.
var uuidName = regexp.MustCompile(`^(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$`)

// better reports whether a wins over b: source rank, then higher confidence, then newer seen_at, then the
// smaller id, so the result is deterministic (DATA_MODEL 5.1 (2)). One exception before all that (M5-186, walk 1
// W1-10): of two host names a readable one beats a UUID-looking one from any source but a person's.
func better(a, b obs) bool {
	if a.field == "hostname" && a.source != "manual" && b.source != "manual" {
		if ua, ub := uuidName.MatchString(a.value), uuidName.MatchString(b.value); ua != ub {
			return ub
		}
	}
	if ra, rb := sourceRank(a.source), sourceRank(b.source); ra != rb {
		return ra > rb
	}
	if a.confidence != b.confidence {
		return a.confidence > b.confidence
	}
	if a.seenAt != b.seenAt {
		return a.seenAt > b.seenAt
	}
	return a.id < b.id
}

// winners picks the current observation of each field.
func winners(list []obs) map[string]obs {
	best := map[string]obs{}
	for _, o := range list {
		if b, ok := best[o.field]; !ok || better(o, b) {
			best[o.field] = o
		}
	}
	return best
}

// fold lower-cases, strips accents (Vietnamese included) and turns every other character into one space:
// "Tường lửa FortiGate-60F" -> "tuong lua fortigate 60f". The web catalog (catalog.ts) folds the same way;
// the golden search file keeps both in step.
func fold(s string) string {
	var b strings.Builder
	space := true
	for _, r := range strings.ToLower(s) {
		if base, ok := accentBase[r]; ok {
			r = base
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			space = false
		} else if !space {
			b.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSuffix(b.String(), " ")
}

var accentBase = func() map[rune]rune {
	m := map[rune]rune{'đ': 'd'}
	for base, group := range map[rune]string{
		'a': "àáạảãâầấậẩẫăằắặẳẵäåāą", 'e': "èéẹẻẽêềếệểễëēę", 'i': "ìíịỉĩïī", 'o': "òóọỏõôồốộổỗơờớợởỡöō",
		'u': "ùúụủũưừứựửữüū", 'y': "ỳýỵỷỹÿ", 'c': "çćč", 'n': "ñń", 's': "śš", 'z': "źżž",
	} {
		for _, r := range group {
			m[r] = base
		}
	}
	return m
}()
