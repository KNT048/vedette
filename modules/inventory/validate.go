package inventory

import (
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/localnet"
	"github.com/knt048/vedette/core/observe"
)

func badRequest(code, msg string) *apierr.Error { return apierr.New(http.StatusBadRequest, code, msg) }
func conflict(code, msg string) *apierr.Error   { return apierr.New(http.StatusConflict, code, msg) }

var versionRE = regexp.MustCompile(`^[A-Za-z0-9_.\-+() ]{1,40}$`)

// label checks the text a person typed for a name, vendor or product: 1..64 characters, no < > and no
// control characters (INV-4).
func label(s string) bool {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxLabel || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || r == '<' || r == '>' })
}

// cleanText checks untrusted observation text: valid UTF-8, no control characters, 1..maxObsValue characters.
func cleanText(s string) bool {
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxObsValue || !utf8.ValidString(s) {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f || invisible(r) })
}

// invisible is a character that changes how text reads or hides in it (L12, defence in depth): C1 controls, every format
// character (bidi marks and controls, zero-width, the tag block, the soft hyphen) and every Default_Ignorable_Code_Point
// (`observe.Ignorable`, the table the honeypot and account names use). A value that holds one is refused; stripIgnorable has
// already removed the harmless ones (variation selectors and fillers) from sensor text.
func invisible(r rune) bool {
	return (r >= 0x80 && r <= 0x9f) || unicode.Is(unicode.Cf, r) || observe.Ignorable(r)
}

// stripIgnorable removes the default-ignorable characters that are not format characters: variation selectors (the U+FE0F of
// an emoji in a device name), the combining grapheme joiner, the Hangul and Mongolian fillers. They render as nothing, so the
// value reads the same without them, and refusing the value would lose a real device name (WP-31 close-out review). Format
// characters (bidi, zero-width) are left for cleanText to refuse: they change how the text reads.
func stripIgnorable(s string) string {
	if !strings.ContainsFunc(s, ignorableNotFormat) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if ignorableNotFormat(r) {
			return -1
		}
		return r
	}, s)
}

func ignorableNotFormat(r rune) bool { return observe.Ignorable(r) && !unicode.Is(unicode.Cf, r) }

// ipv4 parses an IPv4 address in the plain dotted form.
func ipv4(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a, true
}

// normMAC returns the lower-case aa:bb:cc:dd:ee:ff form of a 6-byte MAC, or false.
func normMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return hw.String(), true
}

// Adjustment says a range was written with host bits and was reduced to its network ("192.168.18.5/24" to
// "192.168.18.0/24"); the response of PUT /inventory/settings lists them (SettingsSaved.adjusted, as the mock does).
type Adjustment struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// checkRanges validates the LAN ranges the way PUT /inventory/settings needs (INV-6, D-32), in the mock's order:
// a range with host bits is first reduced to its network and reported; then duplicates collapse, and at most 16
// remain, each with a prefix (never guessed), a valid IPv4 CIDR, inside a local network only (RFC 1918 or the RFC 6598 shared space 100.64/10,
// localnet.Prefix, D-461), no overlap. The prefix length the
// person typed is kept: only host bits go.
func checkRanges(in []string) ([]string, []Adjustment, *apierr.Error) {
	adjusted := []Adjustment{}
	var ranges []string
	for _, raw := range in {
		r := strings.TrimSpace(raw)
		if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() && p.Masked() != p {
			r = p.Masked().String()
			adjusted = append(adjusted, Adjustment{From: strings.TrimSpace(raw), To: r})
		}
		if !slices.Contains(ranges, r) {
			ranges = append(ranges, r)
		}
	}
	if len(ranges) > MaxLANRanges {
		return nil, nil, badRequest("too_many_ranges", "At most 16 network ranges.")
	}
	// The mock checks each range, in order, against the WHOLE list (so [A, "bogus", B] with A and B overlapping
	// names A, not B). Entries that are not valid CIDRs cannot overlap anything and are skipped for that test.
	parsed := make([]netip.Prefix, len(ranges))
	for i, r := range ranges {
		if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() {
			parsed[i] = p
		}
	}
	for i, r := range ranges {
		if _, ok := ipv4(r); ok {
			return nil, nil, badRequest("no_prefix", `"`+clip(r, 30)+`" has no prefix length. Add it so Vedette scans the right size of network, for example `+r+"/24 or "+r+"/25.")
		}
		p := parsed[i]
		if !p.IsValid() {
			return nil, nil, badRequest("bad_cidr", `"`+clip(r, 30)+`" is not a valid network range. Enter something like 192.168.10.0/24.`)
		}
		if !localnet.Prefix(p) {
			return nil, nil, badRequest("public_range", r+" is not an internal range ("+localnet.Names+"). To scan public addresses, add them under External exposure after verifying ownership.")
		}
		for j, q := range parsed {
			if j != i && q.IsValid() && q.Overlaps(p) {
				return nil, nil, badRequest("overlap_range", "Range "+r+" overlaps "+ranges[j]+". Keep the larger range and drop the smaller one.")
			}
		}
	}
	if ranges == nil {
		ranges = []string{}
	}
	return ranges, adjusted, nil
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

var hhmmRE = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func validKind(k string) bool { return slices.Contains(Kinds, k) }
