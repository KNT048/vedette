package feeds

import "strings"

// Verdict is the decision for an IOC (INV-12).
type Verdict string

// Verdicts.
const (
	VerdictNone  Verdict = ""      // not judged: unknown value or whitelisted domain
	VerdictAlert Verdict = "alert" // one source
	VerdictBlock Verdict = "block" // two independent sources, or one DROP/CC0-class source
)

// Sighting says one source listed the IOC. Source is the feed id (independence
// is by distinct id); BlockClass marks a DROP/CC0-class source (Source.BlockClass).
type Sighting struct {
	Source     string
	BlockClass bool
}

// IOCKey is the canonical identity of an IOC value: an IP is its exact
// address (never widened to a /24 or any range), a domain is lower-case
// without a trailing dot. ok is false for a value that is neither.
func IOCKey(kind, value string) (string, bool) {
	v := jsTrim(value)
	switch kind {
	case "ip":
		return canonicalIP(v)
	case "domain":
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		return v, validDomain(v)
	}
	return "", false
}

// whitelisted reports whether domain is, or sits under, an entry of allow.
// The whitelist is by domain only: an IP is never excused because it belongs
// to a CDN or cloud range.
func whitelisted(domain string, allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSuffix(jsTrim(a), "."))
		if a != "" && (domain == a || strings.HasSuffix(domain, "."+a)) {
			return true
		}
	}
	return false
}

// Judge applies INV-12 (DATA_PIPELINE §3) to one IOC: whitelisted domains and
// values that are not an IP or domain get no verdict; otherwise `block` for two
// or more distinct sources or any block-class source, `alert` for one.
func Judge(kind, value string, sightings []Sighting, allowDomains []string) Verdict {
	key, ok := IOCKey(kind, value)
	if !ok || (kind == "domain" && whitelisted(key, allowDomains)) {
		return VerdictNone
	}
	sources := map[string]bool{}
	block := false
	for _, s := range sightings {
		if s.Source == "" {
			continue
		}
		sources[s.Source] = true
		block = block || s.BlockClass
	}
	switch {
	case len(sources) == 0:
		return VerdictNone
	case len(sources) >= 2 || block:
		return VerdictBlock
	}
	return VerdictAlert
}
