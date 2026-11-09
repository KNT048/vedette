package feeds

import (
	"net/netip"
	"strings"
)

// Verdict is the decision for an IOC (INV-12).
type Verdict string

// Verdicts.
const (
	VerdictNone  Verdict = ""      // not judged: unknown value, special address, local name, whitelisted domain
	VerdictAlert Verdict = "alert" // one independent source, or only aggregate or informational sources
	VerdictBlock Verdict = "block" // two independent sources, or one DROP/CC0-class source
)

// Sighting says one source listed the IOC. Source is the feed id (compared
// trimmed and lower-case). The flags describe the source; for a built-in feed
// Judge takes them from the registry whatever the caller says (SightingOf
// fills them in).
type Sighting struct {
	Source        string
	BlockClass    bool     // DROP/CC0-class list: one such source is enough to block
	Aggregate     bool     // the list is a merge of other lists: never block alone
	Informational bool     // describes the address, not malice (Tor exit): never counts toward block
	Upstreams     []string // ids of the sources an aggregate includes
}

// SightingOf describes a sighting by a built-in source.
func SightingOf(s Source) Sighting {
	return Sighting{Source: s.ID, BlockClass: s.BlockClass(), Aggregate: s.Aggregate, Informational: s.Informational, Upstreams: s.Upstreams}
}

// Whitelist is a validated set of domains that never get a verdict.
type Whitelist struct{ domains []string }

// NewWhitelist normalises entries ("Google.com.", "*.google.com" and
// ".google.com" all mean google.com and everything under it) and refuses any
// entry that is not a registrable domain, instead of ignoring it silently.
func NewWhitelist(entries []string) (Whitelist, error) {
	var w Whitelist
	for _, e := range entries {
		d := strings.ToLower(jsTrim(e))
		d = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(d, "*"), "."), ".")
		if hasControl(d) || !validDomain(d) || localName(d) {
			return Whitelist{}, fail(ErrInvalidWhitelist, "%s is not a domain that can be whitelisted.", quoteVal(e))
		}
		w.domains = append(w.domains, d)
	}
	return w, nil
}

// has reports whether domain is, or sits under, an entry. The whitelist is by
// domain only: an IP is never excused because it belongs to a CDN or cloud range.
func (w Whitelist) has(domain string) bool {
	for _, d := range w.domains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// IOCKey is the canonical identity of an IOC value: an IP is its exact
// address (never widened to a /24 or any range), a domain is lower-case
// without a trailing dot. ok is false for a value that is neither, and for a
// private, reserved or special-purpose address or a local, reserved or
// public-suffix name, which are never IOCs.
func IOCKey(kind, value string) (string, bool) {
	v := jsTrim(value)
	switch kind {
	case "ip":
		c, ok := canonicalIP(v)
		if !ok {
			return "", false
		}
		a, _ := netip.ParseAddr(c)
		return c, !isSpecialAddr(a)
	case "domain":
		v = strings.ToLower(strings.TrimSuffix(v, "."))
		return v, validDomain(v) && !localName(v)
	}
	return "", false
}

type sightingFlags struct{ block, aggregate, informational bool }

// Judge applies INV-12 (DATA_PIPELINE §3) to one IOC: whitelisted domains and
// values that are not a public IP or domain get no verdict; otherwise `block`
// for two independent sources or any block-class source, `alert` below that.
// Independence: ids are normalised; an informational source (Tor exit) never
// counts toward block; an aggregate (IPsum) never blocks alone, and with one of
// its upstreams present is not a second source; all aggregates together count
// as at most one source.
func Judge(kind, value string, sightings []Sighting, wl Whitelist) Verdict {
	key, ok := IOCKey(kind, value)
	if !ok || (kind == "domain" && wl.has(key)) {
		return VerdictNone
	}
	type src struct {
		sightingFlags
		upstreams []string
	}
	seen := map[string]*src{}
	for _, s := range sightings {
		id := strings.ToLower(jsTrim(s.Source))
		if id == "" {
			continue
		}
		cur := &src{sightingFlags{s.BlockClass, s.Aggregate, s.Informational}, nil}
		for _, u := range s.Upstreams {
			cur.upstreams = append(cur.upstreams, strings.ToLower(jsTrim(u)))
		}
		if b, known := BuiltinByID(id); known {
			cur = &src{sightingFlags{b.BlockClass(), b.Aggregate, b.Informational}, b.Upstreams}
		}
		if prev := seen[id]; prev != nil {
			cur.block = cur.block || prev.block
			cur.aggregate = cur.aggregate || prev.aggregate
			cur.informational = cur.informational || prev.informational
			cur.upstreams = append(cur.upstreams, prev.upstreams...)
		}
		seen[id] = cur
	}
	if len(seen) == 0 {
		return VerdictNone
	}
	independent, block, aggregateCounts := 0, false, false
	for _, s := range seen {
		if !s.aggregate && !s.informational {
			independent++
			block = block || s.block
		}
	}
	for _, s := range seen {
		if !s.aggregate || s.informational {
			continue
		}
		covered := false
		for _, u := range s.upstreams {
			if o := seen[u]; o != nil && !o.aggregate && !o.informational {
				covered = true
			}
		}
		aggregateCounts = aggregateCounts || !covered
	}
	if aggregateCounts {
		independent++
	}
	if independent >= 2 || block {
		return VerdictBlock
	}
	return VerdictAlert
}
