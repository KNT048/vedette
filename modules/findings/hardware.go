package findings

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/knt048/vedette/core/productid"
)

// Hardware a CVE record limits a row to. A vendor's record of a device's operating system names the hardware an affected range
// holds on (CVE JSON 5 affected[].platforms: "QRX Series", "MZ Series with SPC3", "ZX4100", "ZX4300-MP (Multigigabit)"). The device
// states its model ("ZX4200-48T"). The names are read by their shape only, never from a list of products: a family is letters
// followed by "Series"; a model is letters and a number ("ZX4100"), a numbered series a model number followed by "Series" ("QRX 5000
// Series", "MZ10k Series": k for thousands). A round number alone ("ZX4000") may name a series too, unless the same list names other
// models inside it one by one ("ZX4100", "ZX4400" beside it): then it is one model. A device's model belongs to a family with its
// letters, to a model with its letters and number, to a series with its letters and a number that starts with the series' digits
// before its trailing zeros. Letters one inside the other ("vQRX" and "QRX") are not told apart. Letters are a name's only when they
// hold two capitals at least ("QRX", "vQRX"; not "All Series"). A model word without "Series" whose letters are none of the device's
// ("MPC10E" beside a ZX480) may be a part the device carries (a line card, a module), not other hardware, so it never rules the device
// out, and neither does a part named after the hardware it fits ("ZX2K-MPC11E"). x stands for any digit ("ZX92xx"). A parenthesis or a
// "with" qualifier is read only when it names no hardware outside the platform (remarkOf). A device that states a word of letters and
// digits that is not read ("Q9K-C93180YC", "ZX10K3") has no known model. Anything else ("Linux", "Cloud", "Tablet 17", a name with a blank before its number and no "Series") is not
// read, and a row naming such a platform may be the device's.

// hardwareName is a family or a model as a record or a device names it: letters, and a number ("" for a family).
type hardwareName struct {
	letters, number string
	series          bool // "Series" follows the number: every model whose number starts with its digits
}

var (
	// deviceModelRE is a model word of what a device states ("Acme Networks ZX4200-48T": ZX, 4200). A number written with k
	// ("ZX10K3") is not read.
	deviceModelRE = regexp.MustCompile(`^([A-Za-z]{1,12})-?([0-9]{2,6})(?:[^0-9kK]|$)`)
	familyNameRE  = regexp.MustCompile(`^[A-Za-z]{1,12}$`)
	// modelNameRE is a model or numbered series word: letters, an optional hyphen, a number (k for thousands), the rest of the word.
	modelNameRE = regexp.MustCompile(`^([A-Za-z]{1,12})-?([0-9]{1,6})([kK]?)([A-Za-z0-9-]*)$`)
	// moreModelsRE is another model number after a hyphen in the rest of a model word ("QRX5400-5600-5800"): a list of models, not one
	// model's variant ("-48T", "-128C").
	moreModelsRE = regexp.MustCompile(`-[0-9]{3,}(?:-|$)`)
	// partRE is a part's own name in the rest of a model word ("ZX2K-MPC11E": a line card that fits the ZX2K), not a variant suffix
	// ("-48T", "-40XS", "-MP").
	partRE = regexp.MustCompile(`-[A-Za-z]{2,}[0-9]`)
	// anyDigitRE is x for any digit after a model number ("ZX92xx": the ZX9200 series).
	anyDigitRE = regexp.MustCompile(`^[xX]+(?:-|$)`)
	// spacedSeriesRE is a numbered series written with a blank ("QRX 5000"), read only before "Series".
	spacedSeriesRE = regexp.MustCompile(`^([A-Za-z]{1,12}) ([0-9]{1,6})([kK]?)$`)
	parenRE        = regexp.MustCompile(`\s*\(([^()]{0,80})\)\s*$`)
	capitalsRE     = regexp.MustCompile(`[A-Z].*[A-Z]`)
	// seriesRE is "Series" at the end of a platform, or followed by one "with" qualifier ("with SPC3"): any other text after it may
	// name more hardware ("QRX Series and NX250"), so such a platform is not read.
	seriesRE = regexp.MustCompile(`\s+Series(?:\s+with\s+([A-Za-z0-9-]{1,40}))?$`)
)

// deviceModels are the model words a device states, read as hardware names ("Chassis AB12 ZX4200": AB12 and ZX4200; at most 16):
// any of them may be the device's model. None when it states no word with a number, or a word of letters and digits that is not read
// ("Q9K-C93180YC", "ZX10K3"): that word may be its model.
func deviceModels(model string) []hardwareName {
	var out []hardwareName
	for _, w := range strings.FieldsFunc(model, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		m := deviceModelRE.FindStringSubmatch(w)
		if m == nil {
			if strings.ContainsFunc(w, unicode.IsLetter) && strings.ContainsFunc(w, unicode.IsDigit) {
				return nil
			}
			continue
		}
		out = append(out, hardwareName{letters: strings.ToLower(m[1]), number: strings.TrimLeft(m[2], "0")})
		if len(out) == 16 {
			break
		}
	}
	return out
}

// platformHardware reads one platform of a record row as a family or a model; ok is false for a name of another shape.
func platformHardware(p string) (hardwareName, bool) {
	p = strings.Join(strings.Fields(p), " ")
	var remark string
	if m := parenRE.FindStringSubmatchIndex(p); m != nil {
		remark, p = p[m[2]:m[3]], p[:m[0]]
	}
	h, with, ok := platformShape(p)
	if !ok || !capitalsRE.MatchString(h.letters) || !remarkOf(h, remark, true) || !remarkOf(h, with, false) {
		return hardwareName{}, false
	}
	h.letters = strings.ToLower(h.letters)
	return h, true
}

// remarkOf says a parenthesis or a "with" qualifier of a platform names no hardware outside it ("(Multigigabit)", "(QRX300)" after
// "QRX Series", "with SPC3"): every model word in it is the platform's own ("(also ZX4600)" after "ZX4300" is not). A parenthesis
// (paren) may list more, so in it a word of capitals is a family ("(and NX)", "(SPC3)") that must be the platform's own too, and so
// must "Series"; a "with" qualifier names the part the platform carries ("with SPC3", "with QRX-SPC3").
func remarkOf(h hardwareName, remark string, paren bool) bool {
	if paren && strings.Contains(strings.ToLower(remark), "series") {
		return false
	}
	for _, w := range strings.FieldsFunc(remark, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		if o, _, ok := platformShape(w); ok && o.number != "" {
			inside := h.number == "" || o.number == h.number || h.series && strings.HasPrefix(o.number, strings.TrimRight(h.number, "0"))
			if !strings.EqualFold(o.letters, h.letters) || !inside {
				return false
			}
		} else if paren && capitalsRE.MatchString(w) {
			letters := strings.ToLower(strings.FieldsFunc(w, func(r rune) bool { return !unicode.IsLetter(r) })[0])
			if h.number != "" || !related(hardwareName{letters: letters}, hardwareName{letters: strings.ToLower(h.letters)}) {
				return false
			}
		}
	}
	return true
}

// platformShape reads a platform without its parenthesis as a family or a model, its letters as written, and the word of a "with"
// qualifier after "Series".
func platformShape(p string) (h hardwareName, with string, ok bool) {
	series := false
	if loc := seriesRE.FindStringSubmatchIndex(p); loc != nil {
		if loc[2] >= 0 {
			with = p[loc[2]:loc[3]]
		}
		series, p = true, p[:loc[0]]
	}
	if series && familyNameRE.MatchString(p) {
		return hardwareName{letters: p}, with, true
	}
	m := modelNameRE.FindStringSubmatch(p)
	if m == nil && series {
		m = spacedSeriesRE.FindStringSubmatch(p)
	}
	if m == nil || len(m) > 4 && (moreModelsRE.MatchString(m[4]) || partRE.MatchString(m[4])) {
		return hardwareName{}, "", false
	}
	if len(m) > 4 && anyDigitRE.MatchString(m[4]) {
		series = true
	}
	number := strings.TrimLeft(m[2], "0")
	if m[3] != "" {
		number += "000"
	} else if len(m[2]) < 2 {
		return hardwareName{}, "", false
	}
	if number == "" {
		return hardwareName{}, "", false
	}
	return hardwareName{letters: m[1], number: number, series: series}, with, true
}

// otherHardware says every platform a record row is limited to names hardware the device's model is not: the row is not about the
// device. False when the model is not known, a platform is not read (hardware rules above), or any platform may be the device's.
func otherHardware(model string, platforms []string) bool {
	devs := deviceModels(model)
	if len(devs) == 0 || len(platforms) == 0 {
		return false
	}
	names := make([]hardwareName, 0, len(platforms))
	for _, p := range platforms {
		h, ok := platformHardware(p)
		if !ok || h.number != "" && !h.series && !slices.ContainsFunc(devs, func(dev hardwareName) bool { return related(dev, h) }) {
			return false // not read, or a model word of other letters: it may name a part the device carries
		}
		names = append(names, h)
	}
	return !slices.ContainsFunc(devs, func(dev hardwareName) bool {
		return slices.ContainsFunc(names, func(h hardwareName) bool { return mayBe(dev, h, names) })
	})
}

// related says the letters of the device's model and of hardware h may be one line: equal, or one inside the other.
func related(dev, h hardwareName) bool {
	return strings.Contains(dev.letters, h.letters) || strings.Contains(h.letters, dev.letters)
}

// mayBe says the device's model may be hardware h of the list names.
func mayBe(dev, h hardwareName, names []hardwareName) bool {
	if dev.letters != h.letters {
		return related(dev, h)
	}
	if h.number == "" || dev.number == h.number {
		return true
	}
	digits := strings.TrimRight(h.number, "0")
	if !h.series && (len(digits) == len(h.number) || listsInside(h, digits, names)) {
		return false // one model
	}
	return strings.HasPrefix(dev.number, digits)
}

// listsInside says names lists another model of h's letters whose number starts with digits: h is one model of a list, not a series.
func listsInside(h hardwareName, digits string, names []hardwareName) bool {
	return slices.ContainsFunc(names, func(o hardwareName) bool {
		return o.letters == h.letters && o.number != "" && o.number != h.number && strings.HasPrefix(o.number, digits)
	})
}

// deviceFirmware says a product is an operating system or firmware (an NVD name of part o or h): a record's hardware of its rows is
// the hardware the device itself is, so the device's model can be read against it. An application's platforms say where it is
// installed, never what the device is.
func deviceFirmware(p productid.Product) bool {
	return slices.ContainsFunc(p.CPEs, func(c productid.CPEName) bool { return c.Part == "o" || c.Part == "h" })
}
