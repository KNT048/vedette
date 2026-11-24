package feeds

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// VMware's CVE records before 2024 state ESXi's affected versions as words in one version string, not as ranges: "7.0 before
// ESXi70U1c-17325551", "VMware ESXi (8.0 prior to ESXi80a-20842819, 7.0 prior to ESXi70U3si-20841705, VMware Workstation Pro / Player
// (16.x prior to 16.2.5), …)", "ESXi 6.7 prior to patch release ESXi670-201912001". The generic rules refuse them (words, not
// versions), so a host only had NVD's list of exact releases, which says nothing about a later update: a question per host.
//
// esxiTextRows reads those words with a strict grammar. Each clause "<line> prior to|before|without <fixed release>" of ESXi is one
// row of the ESXi product in VMware's notation, from the start of the line to the fixed release (RecordTextType): "8.0" before
// "ESXi80a-20842819". The fixed release is read as VMware writes a build (ESXi80a-20842819, ESXi70U3si-20841705,
// ESXi_7.0.1-0.0.16850804) or names an update ("8.0 Update 1": its first build in esxi-builds.json). Nothing is guessed:
//   - a clause of another product of the same string (Workstation, Fusion, Cloud Foundation, Horizon) is not read;
//   - a line whose fix is a patch bulletin with no build ("ESXi670-202102401-SG"), is not a release of that line, or that any clause
//     of the container states in another form ("8.0 fix pending") gets no row at all: findings then reads NVD's rows for it;
//   - words inside ESXi's list that are no clause ("Update 1 fix pending", "8.x"), or a version before any product is named, make the
//     container's ESXi words unread.
//
// The fixed release says only the line's own releases before it are affected; a later update of the line is read by esxiLaterTrains.

// RecordTextType is the version_type of a row read from a CVE record's words (esxiTextRows), and of a row a reader adds from it
// (esxiLaterTrains): kept in the vendor's notation, read only by the product's version scheme.
const RecordTextType = VendorNotation + "record-text"

var (
	// esxiTextSplit separates the clauses of one version string.
	esxiTextSplit = regexp.MustCompile(`\s*(?:[,;]|\s\band\b)\s*`)
	// esxiTextOpen opens ESXi's own list ("VMware ESXi (8.0 prior to …"); otherOpen another product's ("VMware Fusion Pro / Fusion (12.x").
	esxiTextOpen  = regexp.MustCompile(`^(?i:(?:vmware\s+)?esxi)\s*\(\s*(.*)$`)
	esxiOtherOpen = regexp.MustCompile(`^[A-Za-z][^()]*\(\s*(.*)$`)
	// esxiTextNamed is a clause that names ESXi itself ("ESXi 6.7 prior to …").
	esxiTextNamed = regexp.MustCompile(`^(?i:(?:vmware\s+)?esxi)\s+[0-9]`)
	// esxiTextLine is the line a clause starts with; esxiTextClause the whole clause.
	esxiTextLine   = regexp.MustCompile(`^(?i:(?:vmware\s+)?esxi\s+)?([0-9])\.([0-9])\b`)
	esxiTextClause = regexp.MustCompile(`^(?i:(?:vmware\s+)?esxi\s+)?([0-9])\.([0-9])(?:\.0)?(?:\s*(?i:u|update)\s*([1-9]))?\s+(?i:prior\s+to|before|without)\s+(?i:patch\s+(?:release\s+)?)?(\S+(?:\s+\S+){0,4})$`)
	// esxiTextBuild is VMware's "ESXi80a-20842819"; esxiTextUnderscore its older "ESXi_7.0.1-0.0.16850804" (version, then build).
	esxiTextBuild      = regexp.MustCompile(`^(?i:esxi)[0-9]{2}(?:U[1-9])?[a-z]{0,2}-[0-9]{5,9}$`)
	esxiTextUnderscore = regexp.MustCompile(`^(?i:esxi)_([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})-[0-9]+(?:\.[0-9]+)*\.([0-9]{5,9})$`)
	// esxiTextBulletin is a patch bulletin ("ESXi670-202102401-SG", "ESXi650-201912001"): a known form that states no build.
	esxiTextBulletin = regexp.MustCompile(`^(?i:esxi)[0-9]{3}-[0-9]{9}(?:-[A-Z]{1,3})?$`)
	esxiTextBuildOf  = regexp.MustCompile(`\(build ([0-9]{5,9})\)$`)
)

// esxiProduct is the ESXi product's record key, as RecordProductKey writes VMware's "ESXi".
var esxiProduct = RecordProductKey("VMware", "ESXi")

// esxiTextRows reads the ESXi words of one container's affected list (fallback: the record's assigner, for an entry whose vendor is
// "n/a"). rows are the rows read, keyed as esxiProduct with CVE and origin left to the caller; used marks the version strings (entry
// index, version index) the rows say all of, which the generic rules need not keep as words.
func esxiTextRows(list []cnaAffected, fallback string) (rows []Range, used map[[2]int]bool) {
	type clause struct {
		at   [2]int
		line string
		row  Range
		ok   bool
	}
	var clauses []clause
	whole := map[[2]int]bool{} // the version strings every clause of which is ESXi's
	for i, a := range list {
		v := productid.NormVendor(a.Vendor)
		if noVendor[v] {
			v = productid.NormVendor(fallback)
		}
		if v != esxiProduct.Vendor || !strings.Contains(strings.ToLower(a.Product), "esxi") || len(a.Versions) > recordMaxVersions {
			continue
		}
		onlyESXi := RecordProductKey("VMware", a.Product) == esxiProduct
		for j, ver := range a.Versions {
			text := strings.Join(strings.Fields(ver.Version), " ")
			if !strings.EqualFold(strings.TrimSpace(ver.Status), "affected") || ver.LessThan != nil || ver.LessThanOrEqual != nil || len(ver.Changes) > 0 ||
				!strings.Contains(text, " ") || len(text) > 1000 || !printableASCII(text) {
				continue // a structured version: the generic rules and statedRows read it
			}
			ctx := "" // the product the clauses name: "esxi", "other", or "" before any is named
			if onlyESXi {
				ctx = "esxi"
			}
			all := true
			for _, piece := range esxiTextSplit.Split(text, -1) {
				piece = strings.TrimSpace(piece)
				opened := false // the piece opens another product's list
				if m := esxiTextOpen.FindStringSubmatch(piece); m != nil {
					ctx, piece = "esxi", m[1]
				} else if m := esxiOtherOpen.FindStringSubmatch(piece); m != nil && !esxiTextNamed.MatchString(piece) {
					ctx, piece, all, opened = "other", m[1], false, true
				}
				piece = strings.TrimSpace(strings.TrimRight(piece, ").; "))
				if piece == "" {
					continue
				}
				switch first := piece[0]; {
				case esxiTextNamed.MatchString(piece):
					ctx = "esxi"
				case (first < '0' || first > '9') && ctx == "esxi" && !opened:
					return nil, nil // words inside ESXi's list that are no clause ("Update 1 fix pending"): nothing of these words is read
				case first < '0' || first > '9':
					ctx, all = "other", false // another product named without parentheses ("Horizon DaaS 8.x prior to …")
				}
				switch ctx {
				case "other":
					all = false
					continue
				case "":
					return nil, nil // a version before any product is named: whose it is, the words do not say
				}
				m := esxiTextLine.FindStringSubmatch(piece)
				if m == nil {
					return nil, nil // an ESXi clause that names no line ("8.x", "all"): nothing of these words is read
				}
				c := clause{at: [2]int{i, j}, line: m[1] + "." + m[2]}
				c.row, c.ok = esxiClause(piece)
				if !c.ok {
					all = false
				}
				clauses = append(clauses, c)
			}
			if all {
				whole[[2]int{i, j}] = true
			}
		}
	}
	bad := map[string]bool{} // a line one clause states in a form not read: no row for it at all
	for _, c := range clauses {
		if !c.ok {
			bad[c.line] = true
		}
	}
	used = map[[2]int]bool{}
	for _, c := range clauses {
		if bad[c.line] {
			delete(whole, c.at)
			continue
		}
		if !slices.ContainsFunc(rows, func(r Range) bool { return sameSpan(r, c.row) }) {
			rows = append(rows, c.row)
		}
	}
	for at := range whole {
		used[at] = true
	}
	return rows, used
}

// esxiClause reads one ESXi clause ("8.0 prior to ESXi80a-20842819") as its row; ok is false when its fixed release is not a build of
// the clause's line (and train, when the clause names an update) in a form read.
func esxiClause(piece string) (Range, bool) {
	m := esxiTextClause.FindStringSubmatch(piece)
	if m == nil {
		return Range{}, false
	}
	line := m[1] + "." + m[2]
	fix, ok := esxiFixRelease(strings.TrimRight(m[4], ").; "))
	if !ok || lineName(fix.Line) != line || m[3] != "" && strconv.Itoa(fix.Rank) != m[3] {
		return Range{}, false
	}
	n, ok := esxiNotationOf(fix)
	if !ok {
		return Range{}, false
	}
	return Range{StartIncl: line, EndExcl: n, Fixed: n, VersionType: RecordTextType, DefaultStatus: DefaultUnknown,
		Vendor: esxiProduct.Vendor, Product: esxiProduct.Product}, true
}

// esxiFixRelease reads a fixed release as a VMware record writes it: a build in VMware's notation ("ESXi80a-20842819"), the older
// "ESXi_7.0.1-0.0.16850804", or an update named in words ("8.0 Update 1", "ESXi 8.0 U3e": its first build in esxi-builds.json). A patch
// bulletin ("ESXi670-202102401-SG") states no build: not read.
func esxiFixRelease(s string) (versionscheme.Version, bool) {
	es := versionscheme.VMwareESXi
	switch {
	case esxiTextBulletin.MatchString(s):
		return versionscheme.Version{}, false
	case esxiTextBuild.MatchString(s):
		v, ok := es.Parse(s)
		return v, ok && !v.LineStart
	}
	if m := esxiTextUnderscore.FindStringSubmatch(s); m != nil {
		return es.Installed(m[1], m[2])
	}
	ver, display, ok := es.Stated(s, "")
	if !ok {
		return versionscheme.Version{}, false
	}
	b := esxiTextBuildOf.FindStringSubmatch(display)
	if b == nil {
		return versionscheme.Version{}, false
	}
	return es.Installed(ver, b[1])
}

// esxiNotationOf writes a release of the 6.x to 8.x lines in VMware's notation ("ESXi80U3d-24585383", "ESXi80a-20842819"), checked by
// reading it back.
func esxiNotationOf(v versionscheme.Version) (string, bool) {
	if v.LineStart || len(v.Line) != 2 || len(v.Build) != 1 || v.Line[0] < 6 || v.Line[0] > 8 {
		return "", false
	}
	n := "ESXi" + strconv.Itoa(v.Line[0]) + strconv.Itoa(v.Line[1])
	if v.Rank > 0 {
		n += "U" + strconv.Itoa(v.Rank)
	}
	n += strings.TrimPrefix(v.Label, v.Train) + "-" + strconv.Itoa(v.Build[0])
	back, ok := versionscheme.VMwareESXi.Parse(n)
	if !ok {
		return "", false
	}
	if c, ok := versionscheme.Compare(back, v); !ok || c != 0 || back.Train != v.Train {
		return "", false
	}
	return n, true
}

// lineName writes a line's numbers ("8.0").
func lineName(line []int) string {
	parts := make([]string, len(line))
	for i, n := range line {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

// esxiTrain is one update of an ESXi line in esxi-builds.json: its rank (0 for the first release and its patches) and its first release.
type esxiTrain struct {
	rank  int
	first versionscheme.Version
}

var esxiUpdateWord = regexp.MustCompile(`^(?:update_([1-9])[a-z]{0,2}|[a-z]{1,2}|-)$`)

// esxiTrains is the trains of line ("8.0") esxi-builds.json lists, each with its first release, by rank.
func esxiTrains(line string) []esxiTrain {
	first := map[int]int{}
	for b, rel := range versionscheme.ESXiBuilds() {
		m := esxiUpdateWord.FindStringSubmatch(rel.Update)
		n, err := strconv.Atoi(b)
		if rel.Version != line || m == nil || err != nil {
			continue
		}
		rank := 0
		if m[1] != "" {
			rank, _ = strconv.Atoi(m[1])
		}
		if f, ok := first[rank]; !ok || n < f {
			first[rank] = n
		}
	}
	var out []esxiTrain
	for rank, b := range first {
		rel, _ := versionscheme.ESXiBuild(strconv.Itoa(b))
		v, ok := esxiTableRelease(line, rel.Update, strconv.Itoa(b))
		if !ok || v.Rank != rank {
			continue
		}
		out = append(out, esxiTrain{rank: rank, first: v})
	}
	slices.SortFunc(out, func(a, b esxiTrain) int { return a.rank - b.rank })
	return out
}

// esxiTableRelease is the release of a build esxi-builds.json lists, read in the ESXi scheme.
func esxiTableRelease(line, update, build string) (versionscheme.Version, bool) {
	m := esxiUpdateWord.FindStringSubmatch(update)
	if m == nil {
		return versionscheme.Version{}, false
	}
	ver := line + ".0"
	if m[1] != "" {
		ver = line + "." + m[1]
	}
	return versionscheme.VMwareESXi.Installed(ver, build)
}

// esxiLineRows is what a reader adds to and takes from the ESXi rows of one CVE read from its record's words (esxiTextRows), for each
// line they name: rows are every scheme row of the CVE (the record's words and VMware's own rows), named the generic rows of the CVE that
// name ESXi (NVD's, CISA's). It returns the rows to add (esxiLaterTrains) and the lines whose words are dropped (esxiDisagrees).
func esxiLineRows(rows, named []Range) (add []Range, drop map[string]bool) {
	drop = map[string]bool{}
	es := versionscheme.VMwareESXi
	type lineRows struct {
		text  Range // one row read from the words, the model of the rows added
		spans []versionscheme.Span
	}
	lines := map[string]*lineRows{}
	var order []string
	for _, r := range rows {
		if r.VersionType == RecordTextType && esxiRow(r) {
			if _, ok := lines[r.StartIncl]; !ok {
				lines[r.StartIncl] = &lineRows{text: r}
				order = append(order, r.StartIncl)
			}
		}
	}
	for _, r := range rows {
		if !esxiRow(r) {
			continue
		}
		s, sp, _, ok := RangeScheme(r)
		if !ok || s != es || sp.End == nil || sp.End.LineStart {
			continue
		}
		if l := lines[lineName(sp.End.Line)]; l != nil {
			l.spans = append(l.spans, sp)
		}
	}
	for _, line := range order {
		l := lines[line]
		later := esxiLaterTrains(line, l.spans)
		spans := slices.Clone(l.spans)
		for i := range later {
			r := &later[i]
			r.CVE, r.Origin, r.Part, r.Vendor, r.Product, r.CPE = l.text.CVE, l.text.Origin, l.text.Part, l.text.Vendor, l.text.Product, l.text.CPE
			if _, sp, _, ok := RangeScheme(*r); ok {
				spans = append(spans, sp)
			}
		}
		if esxiDisagrees(line, spans, named) {
			drop[line] = true
			continue
		}
		add = append(add, later...)
	}
	return add, drop
}

// esxiRow says r names ESXi (its catalogue product reads it in the ESXi scheme).
func esxiRow(r Range) bool {
	p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
	return ok && p.Scheme == versionscheme.VMwareESXi.Name
}

// esxiLaterTrains are the rows of the updates of line that began after every fixed release the CVE's rows state on it: an update
// whose first build (esxi-builds.json) is later than each of those fixes and whose rank is higher was built from the line with the fix
// in it, so its releases are not affected (a row from the line's start to its first release, as VMware itself writes "8.0 before
// ESXi80U3-24022510"). VMware fixed CVE-2022-31705 in 8.0a (build 20842819): 8.0 Update 1, 2 and 3 began later and are not affected.
// An update that began before a fix (8.0 Update 3, build 24022510, before 8.0 Update 2d's fix 24585300) gets no row: a fix on
// another update says nothing about it.
func esxiLaterTrains(line string, spans []versionscheme.Span) []Range {
	if len(spans) == 0 {
		return nil
	}
	maxRank, maxBuild := -1, -1
	ends := map[string]bool{}
	for _, sp := range spans {
		e := sp.End
		if e == nil || len(e.Build) != 1 {
			return nil // an end that is not a build: nothing to order the updates by
		}
		maxRank, maxBuild = max(maxRank, e.Rank), max(maxBuild, e.Build[0])
		ends[e.Train] = true
	}
	var out []Range
	for _, t := range esxiTrains(line) {
		if t.rank <= maxRank || t.first.Build[0] <= maxBuild || ends[t.first.Train] {
			continue
		}
		n, ok := esxiNotationOf(t.first)
		if !ok {
			continue
		}
		out = append(out, Range{StartIncl: line, EndExcl: n, VersionType: RecordTextType, DefaultStatus: DefaultUnknown})
	}
	return out
}

// esxiDisagrees says a generic row of the CVE (NVD's, CISA's) states a release of line affected that the line's rows read from the
// words (and the later updates' rows) say is not, or states it in a way that cannot be placed: the affected side wins, so the line's
// words are dropped and the generic rows decide (a question, or a finding). An exact release NVD lists is placed by esxi-builds.json
// ("8.0:-" is 8.0 GA, build 20513097; "7.0:update_3g" is 7.0 Update 3g); a pre-release ("beta") is before every fix; a range that
// reaches the line, every version ("*"), or an update the table does not list disagrees.
func esxiDisagrees(line string, spans []versionscheme.Span, named []Range) bool {
	lineNums, _ := leadNums(line)
	for _, g := range named {
		if g.StartIncl != "" || g.StartExcl != "" || g.EndIncl != "" || g.EndExcl != "" {
			if reachesLine(g, lineNums) {
				return true
			}
			continue
		}
		f := cpeFields(g.CPE)
		if len(f) < 7 {
			return true
		}
		ver, update := f[5], f[6]
		switch ver {
		case "-":
			continue // the product with no version: NVD says nothing about any release
		case "*", "":
			return true // every version
		}
		n, ok := leadNums(ver)
		if !ok || len(n) > 3 || len(n) == 3 && n[2] != 0 || ver != strings.TrimRight(lineName(n), ".") {
			if ok && len(n) >= 2 && n[0] == lineNums[0] && n[1] == lineNums[1] {
				return true // a version of the line written in a form not placed
			}
			if !ok {
				return true
			}
			continue
		}
		if n[0] != lineNums[0] || n[1] != lineNums[1] {
			continue // another line
		}
		if strings.HasPrefix(update, "beta") {
			continue // a pre-release: before every fix
		}
		rel, ok := nvdESXiRelease(line, update)
		if !ok {
			return true
		}
		if versionscheme.Judge(rel, spans).State != versionscheme.Affected {
			return true
		}
	}
	return false
}

// nvdESXiRelease places an exact release NVD names by its update ("-", "update_3g", "b", or one ending in a build such as
// "1.20.16321839") in esxi-builds.json: the first build of that update.
func nvdESXiRelease(line, update string) (versionscheme.Version, bool) {
	if i := strings.LastIndexByte(update, '.'); i >= 0 {
		if b := update[i+1:]; len(b) >= 5 && len(b) <= 9 && strings.Trim(b, "0123456789") == "" {
			rel, ok := versionscheme.ESXiBuild(b)
			if !ok || rel.Version != line {
				return versionscheme.Version{}, false
			}
			return esxiTableRelease(line, rel.Update, b)
		}
	}
	best := -1
	for b, rel := range versionscheme.ESXiBuilds() {
		n, err := strconv.Atoi(b)
		if rel.Version == line && rel.Update == update && err == nil && (best < 0 || n < best) {
			best = n
		}
	}
	if best < 0 {
		return versionscheme.Version{}, false
	}
	return esxiTableRelease(line, update, strconv.Itoa(best))
}

// reachesLine says a generic range may hold a release of the line (major and minor numbers): a bound that cannot be read reaches it.
func reachesLine(g Range, line []int) bool {
	cmpLine := func(s string) (int, bool) {
		n, ok := leadNums(s)
		if !ok {
			return 0, false
		}
		for i := range 2 {
			x := 0
			if i < len(n) {
				x = n[i]
			}
			if x != line[i] {
				if x < line[i] {
					return -1, true
				}
				return 1, true
			}
		}
		return 0, true
	}
	for _, s := range []string{g.StartIncl, g.StartExcl} {
		if s == "" {
			continue
		}
		if c, ok := cmpLine(s); ok && c > 0 {
			return false // starts on a later line
		}
	}
	end := g.EndExcl
	if end == "" {
		end = g.EndIncl
	}
	if end == "" {
		return true
	}
	c, ok := cmpLine(end)
	switch {
	case !ok:
		return true
	case c < 0:
		return false
	case c == 0 && g.EndExcl != "":
		n, _ := leadNums(end)
		return slices.ContainsFunc(n[min(2, len(n)):], func(x int) bool { return x != 0 }) // "before 8.0" ends before the line
	}
	return true
}
