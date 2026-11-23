package inventory

import (
	"regexp"
	"strings"
	"unicode"
)

// sourceRank orders the sources (DATA_MODEL 5.1 (2)): manual = declared > agent > snmp > nmap = scan > passive. A declared OS (the
// stored decision of a declared software line) is only ever written when no person typed an OS, so it never competes with a manual one.
// An unknown source ranks lowest; the database refuses one anyway.
func sourceRank(s string) int {
	switch s {
	case "manual", "declared":
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

// rank is the observation's place in the ranking: its source's, except that an OS the device states over LLDP (obs.stated,
// INV-44) ranks between SNMP and nmap: above nmap's fingerprint guess, below the device's own SNMP answer.
func (o obs) rank() int {
	if o.stated {
		return 2*sourceRank("snmp") - 1
	}
	return 2 * sourceRank(o.source)
}

// obs is a stored observation, as the merge sees it.
type obs struct {
	id         string
	field      string
	value      string
	source     string
	confidence float64
	seenAt     string // fixed-width UTC ISO-8601: lexical order is time order
	// stated: an OS the device states in its LLDP description, which its own network card vouches for (markStated, INV-44).
	stated bool
}

// uuidName is a host name that is only an identifier: a UUID (a Mac's mDNS service name
// "fbaf5191-cc17-4626-a85b-812bc3d7b83b") or 32 hex digits. A person cannot tell the device from it.
var uuidName = regexp.MustCompile(`^(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$`)

// better reports whether a wins over b: source rank (obs.rank), then (two nmap OS readings) the newer scan, then higher confidence, then newer seen_at, then the
// smaller id, so the result is deterministic (DATA_MODEL 5.1 (2)). Two exceptions before all that, both unless a person
// stated the value: of two host names a readable one beats a UUID-looking one (M5-186); of two MACs the
// one seen last wins, whoever saw it: a MAC is not more true for a stronger source, it is where the
// device answers now. A private Wi-Fi address that rotates would otherwise stay behind a scan's MAC of days ago, and
// the next sighting of the new address, found by MAC, would make a second device.
func better(a, b obs) bool {
	if a.field == "hostname" && a.source != "manual" && b.source != "manual" {
		if ua, ub := uuidName.MatchString(a.value), uuidName.MatchString(b.value); ua != ub {
			return ub
		}
	}
	if a.field == "mac" && a.source != "manual" && b.source != "manual" && a.seenAt != b.seenAt {
		return a.seenAt > b.seenAt
	}
	if ra, rb := a.rank(), b.rank(); ra != rb {
		return ra > rb
	}
	// Of two nmap OS readings the newer scan wins, whatever its accuracy: a fingerprint is replaced by the next one, as its
	// software rows are (ReplaceSoftware), so the device's OS and its guess row never name two different scans' guesses.
	if a.field == "os" && a.source == "nmap" && b.source == "nmap" && a.seenAt != b.seenAt {
		return a.seenAt > b.seenAt
	}
	if a.confidence != b.confidence {
		return a.confidence > b.confidence
	}
	if a.seenAt != b.seenAt {
		return a.seenAt > b.seenAt
	}
	return a.id < b.id
}

// winners picks the current observation of each field, after marking the OS the device states over LLDP (markStated: it
// outranks nmap's guess, INV-44). A passive model without a letter ("0,1,2" from an mDNS TXT record,
// n69) names nothing and never wins; the passive sensor no longer sends one (sensor-passive capture.UsefulValue), older rows
// may still hold one. A model of digits that SNMP, an agent or a person states is a part number and stays.
func winners(list []obs) map[string]obs {
	markStated(list)
	best := map[string]obs{}
	for _, o := range list {
		if o.field == "model" && o.source == "passive" && !strings.ContainsFunc(o.value, unicode.IsLetter) {
			continue
		}
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
