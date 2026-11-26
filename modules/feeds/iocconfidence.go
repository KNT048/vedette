package feeds

import (
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// How sure the feeds are that an indicator is bad (INV-12b). A built-in list gives no confidence per line, so a listing by one weighs
// what the list is (Source.Weight); a custom feed's listing weighs what the feed said for it, or 0.5 when it said nothing. The
// listings of independent feeds add up as independent evidence (1 - the product of (1 - weight)), with the independence rules of
// Judge: an aggregate list that merges a feed that also lists the value adds nothing, and all aggregates together count once. A Tor
// exit relay is not malicious by itself: it counts only when nothing else lists the address, and aggregated blocklists that list a
// Tor exit relay count half (abuse traffic of Tor users leaves through the relay, so such lists pick up exits for that alone).

// levelRE is the last part of an address that names a level of IPsum: levels/N.txt, N from 1 to 99.
var levelRE = regexp.MustCompile(`(?:^|/)levels/([1-9][0-9]?)\.txt$`)

// levelOf reads the level an address names (the path only; a query or fragment is ignored); ok is false when it names none or the
// address cannot be read.
func levelOf(raw string) (int, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, false
	}
	m := levelRE.FindStringSubmatch(u.Path)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// levelWeight is the weight of a listing by a list of addresses found on at least n blocklists: each list counted as 40% evidence
// on its own (level 1 0.4, 2 0.64, 3 0.78, 4 0.87), never above 0.9, as an aggregate is never certain.
func levelWeight(n int) float64 {
	return round2(min(0.9, 1-math.Pow(0.6, float64(n))))
}

// listingWeight is the confidence a listing by the built-in source s carries, with the address the feed is pulled from now.
func (s Source) listingWeight(addr string) float64 {
	if s.LevelInURL {
		if n, ok := levelOf(addr); ok {
			return levelWeight(n)
		}
	}
	return s.Weight
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

// IOCConfidence is how sure the switched-on feeds that list an indicator are, together, that it is bad (0 to 1, two decimals), and
// whether one of them lists it as a botnet command-and-control server. A switched-off feed's listing is stale and does not count.
// The sightings are those of IOCLookup (a built-in list's Confidence is its weight there).
func IOCConfidence(gs []IOCSighting) (conf float64, c2 bool) {
	type src struct {
		w               float64
		aggregate, info bool
		upstreams       []string
	}
	seen := map[string]*src{}
	for _, g := range gs {
		id := strings.ToLower(jsTrim(g.SourceID))
		if !g.Enabled || id == "" {
			continue
		}
		w := g.Confidence
		if w != w { //nolint:gocritic // NaN is the only float that differs from itself
			w = 0
		}
		cur := &src{w: min(1, max(0, w))}
		if b, ok := BuiltinByID(id); ok && g.Builtin {
			cur.aggregate, cur.info, cur.upstreams = b.Aggregate, b.Informational, b.Upstreams
			c2 = c2 || g.C2
		}
		if prev := seen[id]; prev != nil {
			cur.w = max(cur.w, prev.w)
		}
		seen[id] = cur
	}
	miss, independent, tor, info := 1.0, false, false, 0.0
	for _, s := range seen {
		switch {
		case s.info:
			tor, info = true, max(info, s.w)
		case !s.aggregate:
			miss *= 1 - s.w
			independent = true
		}
	}
	agg := 0.0
	for _, s := range seen {
		if !s.aggregate || s.info {
			continue
		}
		covered := false
		for _, u := range s.upstreams {
			if o := seen[u]; o != nil && !o.aggregate && !o.info {
				covered = true
			}
		}
		if !covered {
			agg = max(agg, s.w)
		}
	}
	if agg > 0 && tor && !independent {
		agg /= 2
	}
	if agg > 0 {
		miss *= 1 - agg
		independent = true
	}
	if !independent {
		return round2(info), c2
	}
	return round2(1 - miss), c2
}
