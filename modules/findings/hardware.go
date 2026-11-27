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
// before its trailing zeros. Letters one inside the other ("vQRX" and "QRX") are not told apart. Anything else ("Linux", "Cloud",
// "Tablet 17", a name with a blank before its number and no "Series") is not read, and a row naming such a platform may be the device's.

// hardwareName is a family or a model as a record or a device names it: letters, and a number ("" for a family).
type hardwareName struct {
	letters, number string
	series          bool // "Series" follows the number: every model whose number starts with its digits
}

var (
	// deviceModelRE is a model word of what a device states ("Acme Networks ZX4200-48T": ZX, 4200).
	deviceModelRE = regexp.MustCompile(`^([A-Za-z]{1,12})-?([0-9]{2,6})(?:[^0-9]|$)`)
	familyNameRE  = regexp.MustCompile(`^[A-Za-z]{1,12}$`)
	// modelNameRE is a model or numbered series word: letters, an optional hyphen, a number (k for thousands), the rest of the word.
	modelNameRE = regexp.MustCompile(`^([A-Za-z]{1,12})-?([0-9]{1,6})([kK]?)([A-Za-z0-9-]*)$`)
	// moreModelsRE is another model number after a hyphen in the rest of a model word ("QRX5400-5600-5800"): a list of models, not one
	// model's variant ("-48T", "-128C").
	moreModelsRE = regexp.MustCompile(`-[0-9]{3,}(?:-|$)`)
	// spacedSeriesRE is a numbered series written with a blank ("QRX 5000"), read only before "Series".
	spacedSeriesRE = regexp.MustCompile(`^([A-Za-z]{1,12}) ([0-9]{1,6})([kK]?)$`)
	parenRE        = regexp.MustCompile(`\s*\([^()]{0,80}\)\s*$`)
	// seriesRE is "Series" at the end of a platform, or followed by one "with" qualifier ("with SPC3"): any other text after it may
	// name more hardware ("QRX Series and NX250"), so such a platform is not read.
	seriesRE = regexp.MustCompile(`\s+Series(?:\s+with\s+[A-Za-z0-9-]{1,40})?$`)
)

// deviceModels are the model words a device states, read as hardware names ("Chassis AB12 ZX4200": AB12 and ZX4200; at most 16):
// any of them may be the device's model. None when it states no word with a number.
func deviceModels(model string) []hardwareName {
	var out []hardwareName
	for _, w := range strings.FieldsFunc(model, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		if m := deviceModelRE.FindStringSubmatch(w); m != nil {
			out = append(out, hardwareName{letters: strings.ToLower(m[1]), number: strings.TrimLeft(m[2], "0")})
			if len(out) == 16 {
				break
			}
		}
	}
	return out
}

// platformHardware reads one platform of a record row as a family or a model; ok is false for a name of another shape.
func platformHardware(p string) (hardwareName, bool) {
	p = strings.Join(strings.Fields(p), " ")
	p = parenRE.ReplaceAllString(p, "")
	series := false
	if loc := seriesRE.FindStringIndex(p); loc != nil {
		series, p = true, p[:loc[0]]
	}
	if series && familyNameRE.MatchString(p) {
		return hardwareName{letters: strings.ToLower(p)}, true
	}
	m := modelNameRE.FindStringSubmatch(p)
	if m == nil && series {
		m = spacedSeriesRE.FindStringSubmatch(p)
	}
	if m == nil || len(m) > 4 && moreModelsRE.MatchString(m[4]) {
		return hardwareName{}, false
	}
	number := strings.TrimLeft(m[2], "0")
	if m[3] != "" {
		number += "000"
	} else if len(m[2]) < 2 {
		return hardwareName{}, false
	}
	if number == "" {
		return hardwareName{}, false
	}
	return hardwareName{letters: strings.ToLower(m[1]), number: number, series: series}, true
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
		if !ok {
			return false
		}
		names = append(names, h)
	}
	return !slices.ContainsFunc(devs, func(dev hardwareName) bool {
		return slices.ContainsFunc(names, func(h hardwareName) bool { return mayBe(dev, h, names) })
	})
}

// mayBe says the device's model may be hardware h of the list names.
func mayBe(dev, h hardwareName, names []hardwareName) bool {
	if dev.letters != h.letters {
		return strings.Contains(dev.letters, h.letters) || strings.Contains(h.letters, dev.letters)
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
