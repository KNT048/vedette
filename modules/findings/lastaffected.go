package findings

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// After the last affected release of a line. A vendor's list of exact affected releases with no range (NVD CPE matches with a
// version, CVE JSON 5 versions without lessThan or lessThanOrEqual) is read as OSV's last_affected, and as Grype and Tenable read such
// a list: each listed release is the last affected release of its own release line, so a release of the same line strictly later than
// every listed one is not affected. Oracle lists "8u45" for a flaw fixed in 8u51: Java 8 Update 51 and later are not affected.
//
// The reading closes only on what the list states about the installation's own line, and only when the list reads without a guess:
//   - every row of the product the line is identified by (never a name a model chose) is one exact release, and none is a range: a
//     record that also gives ranges says how its rows are meant, and those rows decide as they always did;
//   - every row is the vendor's own word (VendorCNA: the record's assigner is the product's vendor; NVD's rows of such a record are read
//     with it), not a third party's list of the build it tested, which says nothing past that build; no row was lost, none states a fix
//     above it (LineFix) or what every unlisted version is (VendorList: those rows decide by themselves);
//   - every row reads in one form, the same in which the installation states its version: dotted numbers ("2.4.49", read on its first
//     two numbers' line, "2.4"), or a release and its update (a CPE version with an update "update45" or "-", a record's "8u45", a
//     name's "Java 8 Update 491", read on the release's own numbers). A row that only names a line ("2.1", "21.0.0"), an update ANY
//     beside updates, a build or a word the forms do not read ("8u471-b50", "sp4", "1.4.2_25"), or numbers that are not the
//     installation's numbering ("1.8.0" against "8") make the list read nothing for the line;
//   - each format that lists the product (the CVE record, NVD's configuration) lists a release on the installation's line and the
//     installation is strictly later than every one of them: a line no row is on is unlisted (unlistedLine), and a release at or below
//     a listed one stays as it was.
// The proof is scoped to the product, the line and the releases above the newest listed one (ProofAfterLastAffected).

// releaseForm is how a version is written.
type releaseForm uint8

const (
	formPlain  releaseForm = iota + 1 // dotted numbers: "2.4.49"
	formUpdate                        // a release and its update: "8u45", CPE "1.8.0" with "update45"
)

// release is one version read in a form: its numbers and, in formUpdate, its update.
type release struct {
	form releaseForm
	rel  []uint64
	upd  uint64
}

// line is the release line of r in its form: the first two numbers of a dotted version ("2.4"), the numbers of a release with an
// update without trailing zeros ("1.8 update"); "" when r names no release inside a line: a dotted version of fewer than three numbers
// or whose numbers past the line are all zero names the line itself ("2.1", "21.0.0").
func (r release) line() string {
	switch r.form {
	case formPlain:
		if len(r.rel) < 3 || !slices.ContainsFunc(r.rel[2:], func(n uint64) bool { return n != 0 }) {
			return ""
		}
		return fmt.Sprintf("%d.%d", r.rel[0], r.rel[1])
	case formUpdate:
		n := len(r.rel)
		for n > 1 && r.rel[n-1] == 0 {
			n--
		}
		return joinNumbers(r.rel[:n]) + " update"
	}
	return ""
}

// text is r as the generic order compares it: "2.4.49", "8u45".
func (r release) text() string {
	if r.form == formUpdate {
		return joinNumbers(r.rel) + "u" + strconv.FormatUint(r.upd, 10)
	}
	return joinNumbers(r.rel)
}

// compare orders two releases of one form.
func (r release) compare(o release) int {
	if c := (version{rel: r.rel}).compare(version{rel: o.rel}); c != 0 || r.form != formUpdate {
		return c
	}
	return cmp.Compare(r.upd, o.upd)
}

func joinNumbers(ns []uint64) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.FormatUint(n, 10)
	}
	return strings.Join(parts, ".")
}

// plainRelease reads s as dotted numbers and nothing else ("2.4.49"; not "2.4.49-1", "1.4.2_25", "2.0rc1").
func plainRelease(s string) (release, bool) {
	v, ok := parseVersion(s)
	if !ok || v.q != (qual{}) || v.tail != "" || strings.ContainsAny(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "v"), "+-_~ ") {
		return release{}, false
	}
	return release{form: formPlain, rel: v.rel}, true
}

// updateText is a release and its update written as one version: "8u45", "8 update 45", "8update45".
var updateText = regexp.MustCompile(`^(\d{1,9}(?:\.\d{1,9}){0,5})(?:u| ?update ?)(\d{1,9})$`)

// updateAttr is a CPE update component that states an update number: "update45", "update_45", "u45".
var updateAttr = regexp.MustCompile(`^(?:update_?|u)(\d{1,9})$`)

// updateName is a release and its update a name states: "Java 8 Update 491 (64-bit)" (bounded by a non-word character).
var updateName = regexp.MustCompile(`(?i)(?:^|[^\w.])(\d{1,9}(?:\.\d{1,9}){0,5}) update (\d{1,9})(?:$|[^\w.])`)

func numbers(s string) ([]uint64, bool) {
	var out []uint64
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

func updateRelease(rel, upd string) (release, bool) {
	ns, ok := numbers(rel)
	u, err := strconv.ParseUint(upd, 10, 64)
	if !ok || err != nil {
		return release{}, false
	}
	return release{form: formUpdate, rel: ns, upd: u}, true
}

// listedRelease reads one exact row: an NVD CPE version (with its update component: "-" is the release itself, update 0; ANY is the
// version with no update named) or a record's single version. plainOK and updOK say in which forms it reads.
func listedRelease(af Affected) (plain, upd release, plainOK, updOK bool) {
	rel, _, ok := exactRow(af)
	if !ok {
		return
	}
	c, err := af.cpe()
	if err != nil {
		return
	}
	text := strings.ToLower(strings.TrimSpace(rel))
	if m := updateText.FindStringSubmatch(text); m != nil {
		if c.Update.Kind != Any && c.Update.Kind != NA {
			return
		}
		upd, updOK = updateRelease(m[1], m[2])
		return
	}
	p, ok := plainRelease(text)
	if !ok {
		return
	}
	switch c.Update.Kind {
	case NA: // the release itself, no update: update 0 when its list gives updates
		plain, plainOK = p, true
		upd, updOK = release{form: formUpdate, rel: p.rel}, true
	case Any:
		plain, plainOK = p, true
	default:
		lit, okL := c.Update.Literal()
		if m := updateAttr.FindStringSubmatch(strings.ToLower(lit)); okL && m != nil {
			upd, updOK = updateRelease(joinNumbers(p.rel), m[1])
		}
	}
	return
}

// installedReleases is the installation's version in each form it states: its version as dotted numbers, and a release with its
// update from the version itself ("8u491") or from its name ("Java 8 Update 491 (64-bit)", when the name's release is the version's
// first numbers: "8" of "8.0.4910.10"; a name that states two is read as none).
func installedReleases(ver, display string) (plain, upd release, plainOK, updOK bool) {
	text := strings.ToLower(strings.TrimSpace(ver))
	if m := updateText.FindStringSubmatch(text); m != nil {
		upd, updOK = updateRelease(m[1], m[2])
		return
	}
	plain, plainOK = plainRelease(text)
	if !plainOK {
		return
	}
	ms := updateName.FindAllStringSubmatch(display, 2)
	if len(ms) != 1 {
		return
	}
	if u, ok := updateRelease(ms[0][1], ms[0][2]); ok && len(u.rel) <= len(plain.rel) && slices.Equal(u.rel, plain.rel[:len(u.rel)]) {
		upd, updOK = u, true
	}
	return
}

// lastAffected is what afterLastAffected read for one format of the record: the line, the newest release it lists on it and the
// installation's version, both in the form the format lists it.
type lastAffected struct {
	format    Format
	product   ProductRef
	ref       string // the row that lists the newest release
	line      string
	last      string
	installed string
}

// afterLastAffected says the installation is past the last affected release of its line in every format of v that lists the product
// the line is identified by (see the comment at the top of this file), with what each format read; ok is false when any condition
// fails. Only the line's own names count, never one a model chose.
func afterLastAffected(in swInfo, v Vuln, key []identity) ([]lastAffected, bool) {
	if !versionKnown(in.ver) {
		return nil, false
	}
	own := in.own()
	ip, iu, ipOK, iuOK := installedReleases(in.ver, in.display)
	byFormat := map[Format][]listedRow{}
	sib := siblingsOf(&v)
	for _, af := range v.Affected {
		c, err := af.cpe()
		if err != nil {
			continue
		}
		mine, _, _ := entryFor(c, own, key)
		if !mine {
			continue
		}
		if c.Part.Kind == NA || naVersionApart(c, in.ver, v.Affected) || earlierMarker(c, af, v.Affected) {
			continue
		}
		if _, ok := in.install.judge(c, in.cpe, in.hasCPE, sib); !ok { // a row of another edition, system or architecture
			continue
		}
		if af.Lost || af.VendorList || af.LineFix != "" || !af.VendorCNA {
			return nil, false
		}
		p, u, pOK, uOK := listedRelease(af)
		if !pOK && !uOK { // a range, or an exact row neither form reads
			return nil, false
		}
		f := FormatNVDCPE
		if v.fromCVEOrg() || af.AffectedOnly || v.Origin == RangeADP {
			f = FormatCVE5
		}
		vn, _ := c.Vendor.Literal()
		pn, _ := c.Product.Literal()
		byFormat[f] = append(byFormat[f], listedRow{af: af, ref: ProductRef{Vendor: vn, Product: pn}, p: p, u: u, pOK: pOK, uOK: uOK, proof: !af.AffectedOnly})
	}
	if len(byFormat) == 0 {
		return nil, false
	}
	var out []lastAffected
	for _, f := range []Format{FormatCVE5, FormatNVDCPE} {
		rows := byFormat[f]
		if len(rows) == 0 {
			continue
		}
		// the form of the format's list: a release with an update when any row gives one, else dotted numbers; every row must read in it
		form := formPlain
		if slices.ContainsFunc(rows, func(x listedRow) bool { return x.uOK && !x.pOK }) {
			form = formUpdate
		}
		inst, instOK := ip, ipOK
		if form == formUpdate {
			inst, instOK = iu, iuOK
		}
		if !instOK || inst.line() == "" {
			return nil, false // the installation does not state its version in the list's form
		}
		var last *listedRow
		for i := range rows {
			x := &rows[i]
			r, ok := x.p, x.pOK
			if form == formUpdate {
				r, ok = x.u, x.uOK
			}
			if !ok {
				return nil, false
			}
			l := r.line()
			if l == "" { // a row that names a line, not a release in it
				if form == formPlain && len(r.rel) > 0 && len(inst.rel) > 0 && r.rel[0] == inst.rel[0] {
					return nil, false // it may name the installation's line
				}
				continue
			}
			if l != inst.line() {
				continue
			}
			if last == nil || r.compare(last.in(form)) > 0 {
				last = x
			}
		}
		if last == nil {
			return nil, false // the format lists no release of the installation's line: unlisted, as before
		}
		lr := last.in(form)
		if inst.compare(lr) <= 0 {
			return nil, false // at or below the last affected release
		}
		if !slices.ContainsFunc(rows, func(x listedRow) bool { return x.proof }) {
			continue // the record's rows beside NVD's only ever say affected: they agree, NVD's rows prove
		}
		out = append(out, lastAffected{format: f, product: last.ref, ref: last.af.CPE, line: inst.line(), last: lr.text(), installed: inst.text()})
	}
	return out, len(out) > 0
}

// listedRow is one exact row of the product as afterLastAffected reads it.
type listedRow struct {
	af       Affected
	ref      ProductRef
	p, u     release
	pOK, uOK bool
	proof    bool // the row may prove: not a record row only read for "affected" beside NVD's
}

// in is the row's release in form.
func (x listedRow) in(form releaseForm) release {
	if form == formUpdate {
		return x.u
	}
	return x.p
}
