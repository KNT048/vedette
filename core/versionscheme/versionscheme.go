// Package versionscheme reads the notations vendors write their releases in, and compares two versions only where the notation says
// they can be compared.
//
// A CVE id is shared, but each vendor states affected and fixed versions in its own notation. VMware states the fixed ESXi build of
// each release train ("8.0 lessThan ESXi80U3d-24585383", "8.0 lessThan ESXi80U2d-24585300"); NetScaler the fixed build of each
// release line ("14.1-73.37", "13.1-37.247 FIPS"); the Linux kernel the fixed release of each stable branch ("6.1.149", "6.6.30").
// Comparing build numbers alone is wrong: ESXi 8.0 has two trains, Update 3 and Update 2, so a patched 8.0 U2d host (build 24585300)
// is below the U3d build (24585383) and would look affected. A scheme turns a version into its release line, its train inside the
// line and its place inside the train, and Judge decides inside a train first, as the vendor's own advisories do.
//
// The scheme of a product is declared in the product catalogue (content/catalog/products, field "scheme"; core/productid). The
// registry is here so that every reader (the CVE brief, the matcher) uses the same rules. Nothing here guesses: a version the scheme
// cannot place (an unknown build, another notation) is not comparable.
package versionscheme

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Version is a version read in a vendor's notation.
type Version struct {
	// Line is the release line, the numbers every train of it shares: ESXi [8 0], NetScaler [14 1], Linux [6 1].
	Line []int
	// Variant is a line built apart from the plain one (NetScaler "FIPS", "NDcPP"); versions of two variants never compare.
	Variant string
	// LineStart marks the start of a line as a range's lower bound ("8.0", "9.0.x.x"): before every release of the line.
	LineStart bool
	// Rank is the train inside the line (ESXi's update: 0 for the first release and its patches, 3 for Update 3).
	Rank int
	// Build is the place inside the train: ESXi [24585383], NetScaler [73 37], Linux [149].
	Build []int
	// Train names the release train ("8.0 U3", "14.1 FIPS", "6.1"); Label the release in the vendor's words ("8.0 U3d",
	// "14.1-73.37"); Display the release with its build when the label does not say it ("8.0 U3d (build 24585383)").
	Train, Label, Display string
}

// sameTrain says a and b are releases of one train.
func sameTrain(a, b Version) bool {
	return !a.LineStart && !b.LineStart && a.Variant == b.Variant && slices.Equal(a.Line, b.Line) && a.Rank == b.Rank
}

// order compares two versions in release order: line, then train, then the place inside the train. ok is false for two variants.
// A line's start is before every release of the line.
func order(a, b Version) (int, bool) {
	if a.Variant != b.Variant {
		return 0, false
	}
	if c := cmpNums(a.Line, b.Line); c != 0 {
		return c, true
	}
	switch {
	case a.LineStart && b.LineStart:
		return 0, true
	case a.LineStart:
		return -1, true
	case b.LineStart:
		return 1, true
	}
	if c := cmp.Compare(a.Rank, b.Rank); c != 0 {
		return c, true
	}
	return cmpNums(a.Build, b.Build), true
}

// cmpNums compares two lists of numbers, a missing number being 0.
func cmpNums(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// Scheme is one vendor notation.
type Scheme struct {
	// Name is the scheme's name in the product catalogue ("vmware-esxi").
	Name string
	// About says what the scheme reads and where its rules come from.
	About string
	// parse reads a version a vendor states (a range bound, a fixed release).
	parse func(s string) (Version, bool)
	// installed reads the version and build a device reports; nil: parse reads the version alone.
	installed func(version, build string) (Version, bool)
	// endInLine reads a range's end written inside the line its start names ("14.1" lessThan "72.61"); nil: no such form.
	endInLine func(start Version, s string) (Version, bool)
}

// Parse reads a version the vendor states, as a range bound or a fixed release ("ESXi80U3d-24585383", "8.0", "14.1-73.37 FIPS").
func (s *Scheme) Parse(text string) (Version, bool) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > 100 {
		return Version{}, false
	}
	return s.parse(text)
}

// Installed reads what a device reports: its version and, for a scheme that needs it (ESXi), its build. A version that does not say
// its train is not read.
func (s *Scheme) Installed(version, build string) (Version, bool) {
	version, build = strings.TrimSpace(version), strings.TrimSpace(build)
	if len(version) > 100 || len(build) > 100 {
		return Version{}, false
	}
	var (
		v  Version
		ok bool
	)
	if s.installed != nil {
		v, ok = s.installed(version, build)
	} else {
		v, ok = s.Parse(version)
	}
	if !ok || v.LineStart {
		return Version{}, false
	}
	return v, true
}

// Span is one affected range in a scheme: from Start (nil: no lower bound) to End (nil: no upper bound), End excluded unless
// EndIncl. End is the fixed release when it is excluded.
type Span struct {
	Start, End *Version
	EndIncl    bool
}

// Span reads a range's bounds as a CVE record or the catalogue writes them: start ("", "0", "*" and "n/a" are no start) and either
// an excluded end (lessThan) or an included one (lessThanOrEqual); "" or "*" is no end. ok is false when a bound does not read.
func (s *Scheme) Span(start, endExcl, endIncl string) (Span, bool) {
	var sp Span
	switch strings.ToLower(strings.TrimSpace(start)) {
	case "", "0", "*", "n/a":
	default:
		v, ok := s.Parse(start)
		if !ok {
			return Span{}, false
		}
		sp.Start = &v
	}
	end := strings.TrimSpace(endExcl)
	if end == "" {
		end, sp.EndIncl = strings.TrimSpace(endIncl), true
	}
	if end != "" && end != "*" {
		var (
			v  Version
			ok bool
		)
		if sp.Start != nil && sp.Start.LineStart && s.endInLine != nil && len(end) <= 100 {
			v, ok = s.endInLine(*sp.Start, end) // a build inside the start's line, before any other reading ("72.61" is no line)
		}
		if !ok {
			v, ok = s.Parse(end)
		}
		if !ok || v.LineStart {
			return Span{}, false
		}
		sp.End = &v
	} else {
		sp.EndIncl = false
	}
	return sp, true
}

// State is what Judge decided.
type State int

// The states of a verdict.
const (
	NotComparable State = iota // a version or a bound could not be placed: say nothing
	Affected
	NotAffected // outside every range the vendor states
)

// Verdict is Judge's answer: the state and, when affected, the release that fixes it (nil when the vendor states none).
type Verdict struct {
	State State
	Fix   *Version
}

// Judge decides whether an installed version is inside the ranges a vendor states for one product, the way the vendor's advisory
// reads (and Tenable's checks for ESXi do): a range whose end is a release of the installed version's train decides alone, by the
// place inside the train (8.0 U2e is past U2d, whatever the U3d build). When no range ends in that train, release order decides: a
// train older than a range's end and not before its start is affected (8.0 U1 under "8.0 lessThan U2d": its fix is in a later
// train), a later one is not. The fix is the end of the deciding range, the nearest when several. A train two ranges end in at
// different releases (Conflicts) is not comparable, and never named as a fix.
func Judge(installed Version, spans []Span) Verdict {
	if installed.LineStart {
		return Verdict{}
	}
	conflicts := Conflicts(spans)
	in := func(sp Span) bool { // another variant's bound does not name the installed line: outside
		if sp.Start != nil {
			if c, ok := order(*sp.Start, installed); !ok || c > 0 {
				return false
			}
		}
		if sp.End == nil {
			return true
		}
		c, ok := order(installed, *sp.End)
		return ok && (c < 0 || c == 0 && sp.EndIncl)
	}
	decide := func(spans []Span) Verdict {
		var fix *Version
		hit := false
		for _, sp := range spans {
			if !in(sp) {
				continue
			}
			hit = true
			if sp.End != nil && !sp.EndIncl && !conflicts[sp.End.Train] {
				if c, _ := order(*sp.End, ptrOr(fix, *sp.End)); fix == nil || c < 0 {
					e := *sp.End
					fix = &e
				}
			}
		}
		if !hit {
			return Verdict{State: NotAffected}
		}
		return Verdict{State: Affected, Fix: fix}
	}
	if conflicts[installed.Train] {
		return Verdict{}
	}
	var same []Span
	for _, sp := range spans {
		if sp.End != nil && sameTrain(*sp.End, installed) {
			same = append(same, sp)
		}
	}
	if len(same) > 0 {
		return decide(same)
	}
	return decide(spans)
}

// Conflicts is the trains (Version.Train) in which two ranges of one product end at two different releases: the notation did not say
// which line each belongs to (NetScaler's FIPS build "13.1-37.282" written without the word, beside "13.1-64.28"), so nothing in that
// train is compared and no fixed release is named for it.
func Conflicts(spans []Span) map[string]bool {
	out := map[string]bool{}
	ends := map[string]Version{}
	for _, sp := range spans {
		if sp.End == nil {
			continue
		}
		e := *sp.End
		if prev, ok := ends[e.Train]; ok && sameTrain(prev, e) {
			if c, _ := order(prev, e); c != 0 {
				out[e.Train] = true
			}
			continue
		}
		ends[e.Train] = e
	}
	return out
}

func ptrOr(p *Version, v Version) Version {
	if p == nil {
		return v
	}
	return *p
}

// registry is every scheme, by name.
var registry = map[string]*Scheme{}

func register(s *Scheme) *Scheme {
	if _, dup := registry[s.Name]; dup || s.Name == "" || s.parse == nil {
		panic("versionscheme: bad or duplicate scheme " + s.Name)
	}
	registry[s.Name] = s
	return s
}

// Lookup is the scheme of this name.
func Lookup(name string) (*Scheme, bool) {
	s, ok := registry[name]
	return s, ok
}

// Names is every scheme's name, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// nums reads dotted numbers ("8.0.3" -> 8, 0, 3); ok is false for anything else, or a number of more than 9 digits.
func nums(s string) ([]int, bool) {
	if s == "" {
		return nil, false
	}
	var out []int
	for p := range strings.SplitSeq(s, ".") {
		if p == "" || len(p) > 9 || strings.TrimLeft(p, "0123456789") != "" {
			return nil, false
		}
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out, true
}

// lineName writes a line's numbers ("8.0").
func lineName(line []int) string {
	parts := make([]string, len(line))
	for i, n := range line {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}
