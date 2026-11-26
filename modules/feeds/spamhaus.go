package feeds

import (
	"net/netip"
	"strconv"
	"strings"
)

// Spamhaus DROP ("Don't Route Or Peer") lists netblocks that are hijacked or leased by professional spam or cyber-crime operations
// (since April 2024 it also holds the former EDROP list). The box pulls Spamhaus's own IPv4 file, drop_v4.json: newline-delimited
// JSON, one record per network ({"cidr":"…","sblid":"…","rir":"…"}) and a closing metadata record that counts them
// ({"type":"metadata","timestamp":…,"records":N,…}). Spamhaus recommends the JSON files and marks the older text files (drop.txt:
// one network per line, comments after ';') for deprecation; the parser reads both, so an administrator's mirror of either works.
// The list is off by default; each box fetches it from Spamhaus itself and nothing of it is redistributed by the project.

// dropFeedID is the built-in Spamhaus DROP feed.
const dropFeedID = "spamhaus-drop"

// The networks a DROP list may hold: an IPv4 network of /8 to /32 or an IPv6 network of /16 to /128 (Spamhaus's widest are far
// narrower; a wider row would make most of the internet one indicator). A network of one address is stored as the address.
const (
	dropMinBits4 = 8
	dropMinBits6 = 16
	// dropMaxRows is the most networks a DROP list may hold (the list held 1,737 in November 2026). A longer list is refused whole,
	// never cut: a cut list would silently drop the networks past the cut.
	dropMaxRows = 20_000
	// dropMaxLine is the longest line read as a record; a longer one is rejected without being decoded.
	dropMaxLine = 4096
)

// DROPList is a parsed Spamhaus DROP list: its networks in canonical form ("192.0.2.0/24"; a network of one address as the address),
// each once, in list order, with the accounting of the rows dropped (INV-3).
type DROPList struct {
	Prefixes []string
	Stats
}

// ParseSpamhausDROP reads a Spamhaus DROP list, in the JSON form or the text form, and fails closed: a row that is not a canonical public
// network within the length bounds is rejected and counted by reason, and the whole list is refused when it is larger than
// MaxBodyBytes, holds more than maxRows rows, has no accepted network, or, in the JSON form, does not end with exactly one metadata
// record whose count equals the rows read (a list cut short in transit).
func ParseSpamhausDROP(data []byte, maxRows int) (DROPList, error) {
	if len(data) > MaxBodyBytes {
		return DROPList{}, fail(ErrTooLarge, "The list is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	text := cleanText(data)
	tl := newTally()
	out := DROPList{Prefixes: []string{}}
	seen := map[string]bool{}
	take := func(row int, v string) {
		p, tmpl := dropNetwork(v)
		switch {
		case tmpl != "":
			tl.reject(row, tmpl, v)
		case !seen[p]:
			seen[p] = true
			out.Prefixes = append(out.Prefixes, p)
			tl.Accepted++
		}
	}
	isJSON := strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "{")
	rows, metas, counted := 0, 0, -1
	n := 0
	for rest := text; rest != ""; {
		var line string
		line, rest = nextLine(rest)
		n++
		if !isJSON {
			line, _, _ = strings.Cut(line, ";")
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if metas > 0 {
			return DROPList{}, fail(ErrBadSample, "The list goes on after its closing metadata record.")
		}
		if isJSON {
			if c, ok := dropMetadata(line); ok {
				metas, counted = 1, c
				continue
			}
		}
		if rows++; rows > maxRows {
			return DROPList{}, fail(ErrBadSample, "The list has more than %s networks; Vedette refused it and kept the networks it had.", grouped(maxRows))
		}
		if !isJSON {
			take(n, line)
			continue
		}
		cidr, ok := dropRecord(line)
		if !ok {
			tl.reject(n, "%s is not a DROP record", line)
			continue
		}
		take(n, cidr)
	}
	if isJSON && (metas == 0 || counted != rows) {
		return DROPList{}, fail(ErrBadSample, "The list does not end with a metadata record that counts its %s networks: it may have been cut short. Vedette kept the networks it had.", grouped(rows))
	}
	out.Stats = tl.stats()
	if err := accepted(out.Stats); err != nil {
		return DROPList{}, err
	}
	return out, nil
}

// dropMetadata reads the closing metadata record of the JSON form: its record count, or -1 when it states none that can be read (the
// count check then fails). ok is false for a line that is not a metadata record.
func dropMetadata(line string) (records int, ok bool) {
	if len(line) > dropMaxLine {
		return 0, false
	}
	n, err := decodeJSON(line)
	if err != nil || n.k != jObj {
		return 0, false
	}
	if t, _ := n.get("type"); t == nil || t.k != jStr || t.s != "metadata" {
		return 0, false
	}
	c, _ := n.get("records")
	if c == nil || c.k != jNum {
		return -1, true
	}
	v, err := strconv.Atoi(c.s)
	if err != nil || v < 0 {
		return -1, true
	}
	return v, true
}

// dropRecord reads the network of one record of the JSON form; ok is false for a line that is not a JSON object with a "cidr" string.
func dropRecord(line string) (string, bool) {
	if len(line) > dropMaxLine {
		return "", false
	}
	n, err := decodeJSON(line)
	if err != nil || n.k != jObj {
		return "", false
	}
	if _, typed := n.get("type"); typed {
		return "", false // a record of another kind
	}
	c, _ := n.get("cidr")
	if c == nil || c.k != jStr {
		return "", false
	}
	return c.s, true
}

// dropNetwork checks one network of a DROP list and returns its canonical form, or the reason it is refused (a template with one %s
// for the value).
func dropNetwork(v string) (string, string) {
	if len(v) > 64 {
		return "", "%s is not a network (address/length)"
	}
	p, err := netip.ParsePrefix(v)
	if err != nil || p.Addr().Is4In6() {
		return "", "%s is not a network (address/length)"
	}
	if p.Masked() != p {
		return "", "%s is not the start of its network"
	}
	lo := dropMinBits4
	if p.Addr().Is6() {
		lo = dropMinBits6
	}
	if p.Bits() < lo {
		return "", "%s is wider than Vedette accepts from this list"
	}
	if isSpecialAddr(p.Addr()) {
		return "", "%s is a private, reserved or documentation range"
	}
	for _, sp := range specialPrefixes {
		if sp.Overlaps(p) {
			return "", "%s is a private, reserved or documentation range"
		}
	}
	if p.IsSingleIP() {
		return p.Addr().String(), ""
	}
	return p.String(), ""
}

// networksAround is every network of the lengths a DROP list may hold that contains the address, in the canonical form the list is
// stored in (narrowest last); nil for a value that is not an address. A network of one address is the address itself and is not in it.
func networksAround(value string) []any {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Zone() != "" {
		return nil
	}
	a = a.Unmap()
	lo, hi := dropMinBits4, 31
	if a.Is6() {
		lo, hi = dropMinBits6, 127
	}
	out := make([]any, 0, hi-lo+1)
	for b := lo; b <= hi; b++ {
		if p, err := a.Prefix(b); err == nil {
			out = append(out, p.String())
		}
	}
	return out
}

// CreditName is how a listing is named wherever it is shown (the logs hit and incident, Feeds → Look up, the AI): the feed's name, and
// for a list whose terms ask for the list to be credited with its time (Source.CreditFetch: Spamhaus DROP) the time the box fetched
// the list that holds the listing, in UTC.
func CreditName(g IOCSighting) string {
	if b, ok := BuiltinByID(g.SourceID); ok && g.Builtin && b.CreditFetch && !g.ListedAt.IsZero() {
		return g.SourceName + " (list fetched " + g.ListedAt.UTC().Format("2006-01-02 15:04") + " UTC)"
	}
	return g.SourceName
}
