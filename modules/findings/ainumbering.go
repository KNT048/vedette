package findings

import "slices"

// The AI's identity of a line proves which product the line is, not that the line's version is numbered as the product's releases
// are. A vendor's installer or a component can report a number of its own ("1.0.40.0") for a product whose releases are numbered
// 25.x and 32.x; that number is below a range's end such as "before 25.30.1400.0" without saying anything about the release installed.
// A finding opened through an AI identity therefore needs the version to be of the product's numbering, read from the product's own
// rows: the release lines every CVE on the list names for it.

// Values of ownRow.numbering.
const (
	numberingUnknown int8 = iota
	numberingFits
	numberingOther
)

// aiNumbering says whether row i's version is of the numbering of the product the AI chose for it: its first number is not below the
// lowest first number of any release the product's rows name, in every entry of the list that names the product (range bounds and
// listed releases; a placeholder such as "0" names none). A version that does not read, or a product whose rows name no release, is
// not judged here (true): the comparison decides those.
func (d *devMatch) aiNumbering(i int) bool {
	r := d.own[i]
	if r.numbering != numberingUnknown {
		return r.numbering == numberingFits
	}
	r.numbering = numberingFits
	in := d.infos[i]
	iv, ok := parseVersion(in.ver)
	if !ok {
		return true
	}
	in.ids = slices.DeleteFunc(slices.Clone(in.ids), func(x identity) bool { return !x.ai }) // the chosen product's names alone
	in.hasCPE = false
	lowest, named := uint64(0), false
	for vi := range d.named[i] {
		for _, af := range rowEntries(d.sws[i], in, d.vulns[vi]) {
			bounds := []string{af.Range.StartIncl, af.Range.StartExcl, af.Range.EndIncl, af.Range.EndExcl}
			if c, err := af.cpe(); err == nil && af.Range.IsZero() {
				if lit, ok := c.Version.Literal(); ok {
					bounds = []string{lit}
				}
			}
			for _, b := range bounds {
				if b == "" || isPlaceholder(b) {
					continue
				}
				if bv, ok := parseVersion(b); ok && (!named || bv.rel[0] < lowest) {
					lowest, named = bv.rel[0], true
				}
			}
		}
	}
	if named && iv.rel[0] < lowest {
		r.numbering = numberingOther
	}
	return r.numbering == numberingFits
}
