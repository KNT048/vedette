package feeds

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// Oracle's Critical Patch Updates, Critical Security Patch Updates and Security Alerts, as CSAF 2.0 documents its RSS feed lists. Each
// document states, per product release it assessed (its product tree), which CVEs affect it: Oracle lists the newest release of each
// supported line it assessed ("Oracle Java SE 8u491", "21.0.11"), every earlier release of that line being affected too, and a line
// it assessed and does not list is not affected (line-sources.json: listed last_affected, absent unaffected_if_assessed). Only the
// catalogue's products are kept (line-sources.json names, per product, the CPE or the product tree branch of its releases), and of
// them only facts: CVE id, release line, newest affected release, the document's date and page. No text of a document is kept.
//
// Which documents: every one the feed lists (33 on 27 Nov 2026, the oldest of April 2022), each asked with the Last-Modified and ETag
// it last gave, so an unchanged one answers 304 and is not read again while the box runs (oracleMemory; after a restart each is read
// once more). A document is up to 5.6 MB (the July 2026 update), more than the 5 MB of a usual pull: it has its own cap and is read as
// a stream, its other products skipped token by token.

const (
	oracleLineFeedID = "oracle-cpu-csaf"

	// DecoderOracleCSAF is the decoder of Oracle's CSAF line source (buildOracleLines).
	DecoderOracleCSAF Decoder = "oracle-cpu-csaf"

	oracleNotice = "Oracle Critical Patch Update, Critical Security Patch Update and Security Alert CSAF documents (TLP:WHITE), Oracle Terms of Use. Facts only: CVE ids, release lines and the newest affected release; no text is kept."

	// ListedLastAffected says a row is the newest affected release of a line, every earlier release of the line affected too.
	ListedLastAffected = "last_affected"
	// AbsentUnaffectedIfAssessed says a line the document assessed (has a release of in its product tree) and does not list is not affected.
	AbsentUnaffectedIfAssessed = "unaffected_if_assessed"

	// oracleDocMaxBytes bounds one document after decoding (the largest, July 2026, is 5.6 MB): the source's own cap (INV-2).
	oracleDocMaxBytes = 16 << 20
	// Bounds of one document: its vulnerabilities (1,460 in July 2026), its products, and the product ids its statuses name together.
	oracleMaxVulns    = 20_000
	oracleMaxProducts = 100_000
	oracleMaxStatusID = 500_000
	oracleMaxDocs     = 500
)

// oracleDocPath is the path of a CSAF document on Oracle's host as the feed links it (both layouts in use).
var oracleDocPath = regexp.MustCompile(`^/(?:a/tech/docs|docs/tech)/security-alerts/[a-z0-9-]{1,100}csaf\.json$`)

// releaseRE is a release as a line row keeps it: numbers joined by '.' or '_' ("1.8.0_491", "11.0.33.0.3").
var releaseRE = regexp.MustCompile(`^[0-9]{1,6}(?:[._][0-9]{1,6}){0,7}$`)

// CSAFSelector says how a CSAF document names a catalogue product (line-sources.json csaf).
type CSAFSelector struct {
	CPE    []string `json:"cpe"`    // NVD part:vendor:product of its releases ("a:oracle:java_se")
	Branch string   `json:"branch"` // the product tree branch its releases are under when they carry no CPE ("Oracle Java SE")
	// Other are texts that mark another edition of the product in a release's name or CPE ("-perf", Java SE's Enterprise Performance
	// Pack, which runs a newer JVM): such a release is not the product's, so a CVE listed only for it does not make the line affected.
	Other []string `json:"other"`
}

// csafRawProduct is one product of a document's tree: its id, name, CPE and the product it is a version of (the name of the nearest
// branch above it of category product_name, else product_family).
type csafRawProduct struct {
	ID, Name, CPE string
	Product       string
	family        string // the nearest product_family above it, while the tree is read
}

// csafRawDoc is what buildOracleLines reads of a document before it picks the catalogue's products.
type csafRawDoc struct {
	ID, Initial string
	Refs        []string // reference URLs other than the document itself
	Products    []csafRawProduct
	Rels        [][2]string // relationships: the product a new id is built from, the new id
	Vulns       []csafRawVuln
}

type csafRawVuln struct {
	CVE    string
	Status map[string][]string // product_status category -> product ids
}

// parseCSAFLines reads one CSAF document as a stream: its tracking id and first release, its reference URLs, every product of its tree
// (id, name, CPE, the branch names above it) and of every vulnerability the CVE and the product ids of each status. Everything else (notes,
// scores, remediations) is skipped token by token. Every count is bounded while reading.
func parseCSAFLines(r io.Reader) (csafRawDoc, error) {
	j := newJSONStream(r, "The advisory document")
	var (
		d                 csafRawDoc
		products, statIDs int
	)
	product := func() (csafRawProduct, error) {
		var p csafRawProduct
		_, err := j.object(func(k string) (err error) {
			switch k {
			case "name":
				p.Name, err = j.str(500)
			case "product_id":
				p.ID, err = j.str(500)
			case "product_identification_helper":
				_, err = j.object(func(k string) (err error) {
					if k == "cpe" {
						p.CPE, err = j.str(500)
						return err
					}
					return j.skip()
				})
			default:
				err = j.skip()
			}
			return err
		})
		if err == nil {
			if products++; products > oracleMaxProducts {
				err = fail(ErrBadSample, "The advisory document has more than %s products.", grouped(oracleMaxProducts))
			}
		}
		return p, err
	}
	// branches reads a list of branches: the products under them, each with the names of the branches above it (a branch's name may
	// come after its sub-branches, so the name is put in front once the branch is read)
	var branches func() ([]csafRawProduct, error)
	branches = func() ([]csafRawProduct, error) {
		var all []csafRawProduct
		err := j.array(oracleMaxProducts, &products, "branches", func() error {
			var (
				name, category string
				mine           []csafRawProduct
			)
			_, err := j.object(func(k string) error {
				switch k {
				case "name":
					var err error
					name, err = j.str(500)
					return err
				case "category":
					var err error
					category, err = j.str(64)
					return err
				case "branches":
					sub, err := branches()
					mine = append(mine, sub...)
					return err
				case "product":
					p, err := product()
					if p.ID != "" {
						mine = append(mine, p)
					}
					return err
				}
				return j.skip()
			})
			for i := range mine { // the nearest product_name (else product_family) above a product names what it is a version of
				switch {
				case category == "product_name" && mine[i].Product == "":
					mine[i].Product = name
				case category == "product_family" && mine[i].family == "":
					mine[i].family = name
				}
			}
			all = append(all, mine...)
			return err
		})
		return all, err
	}
	tree := func(k string) error {
		switch k {
		case "branches":
			ps, err := branches()
			for _, p := range ps {
				p.Product = cmp.Or(p.Product, p.family)
				d.Products = append(d.Products, p)
			}
			return err
		case "full_product_names":
			return j.array(oracleMaxProducts, &products, "products", func() error {
				p, err := product()
				if p.ID != "" {
					d.Products = append(d.Products, p)
				}
				return err
			})
		case "relationships":
			return j.array(oracleMaxProducts, &products, "relationships", func() error {
				var ref, id string
				_, err := j.object(func(k string) (err error) {
					switch k {
					case "product_reference":
						ref, err = j.str(500)
					case "full_product_name":
						_, err = j.object(func(k string) (err error) {
							if k == "product_id" {
								id, err = j.str(500)
								return err
							}
							return j.skip()
						})
					default:
						err = j.skip()
					}
					return err
				})
				if ref != "" && id != "" {
					d.Rels = append(d.Rels, [2]string{ref, id})
				}
				return err
			})
		}
		return j.skip()
	}
	vuln := func() error {
		v := csafRawVuln{Status: map[string][]string{}}
		_, err := j.object(func(k string) (err error) {
			switch k {
			case "cve":
				v.CVE, err = j.str(64)
			case "product_status":
				_, err = j.object(func(cat string) error {
					return j.array(oracleMaxStatusID, &statIDs, "product statuses", func() error {
						id, err := j.str(500)
						if id != "" {
							v.Status[cat] = append(v.Status[cat], id)
						}
						return err
					})
				})
			default:
				err = j.skip()
			}
			return err
		})
		d.Vulns = append(d.Vulns, v)
		return err
	}
	ok, err := j.object(func(k string) error {
		switch k {
		case "document":
			_, err := j.object(func(k string) error {
				switch k {
				case "tracking":
					_, err := j.object(func(k string) (err error) {
						switch k {
						case "id":
							d.ID, err = j.str(200)
						case "initial_release_date":
							d.Initial, err = j.str(64)
						default:
							err = j.skip()
						}
						return err
					})
					return err
				case "references":
					return j.array(csafMaxNotes, nil, "references", func() error {
						var u, cat string
						_, err := j.object(func(k string) (err error) {
							switch k {
							case "url":
								u, err = j.str(600)
							case "category":
								cat, err = j.str(64)
							default:
								err = j.skip()
							}
							return err
						})
						if cat != "self" && u != "" {
							d.Refs = append(d.Refs, u)
						}
						return err
					})
				}
				return j.skip()
			})
			return err
		case "product_tree":
			_, err := j.object(tree)
			return err
		case "vulnerabilities":
			return j.array(oracleMaxVulns, nil, "vulnerabilities", vuln)
		}
		return j.skip()
	})
	if err != nil {
		return csafRawDoc{}, err
	}
	if !ok {
		return csafRawDoc{}, fail(ErrBadSample, "The advisory document is not a JSON object.")
	}
	if err := j.end(); err != nil {
		return csafRawDoc{}, err
	}
	if strings.TrimSpace(d.ID) == "" {
		return csafRawDoc{}, fail(ErrBadSample, "The advisory document has no id.")
	}
	if _, ok := csafTime(d.Initial); !ok {
		return csafRawDoc{}, fail(ErrBadSample, "The advisory document has no first release date.")
	}
	return d, nil
}

// lineState is what one document states about one release line for one CVE.
type lineState uint8

const (
	lineAssessedOnly lineState = iota + 1 // the document has a release of the line and lists none of them for the CVE: convention
	lineNotAffected                       // every release of the line the document has is listed not affected
	lineAffectedTo                        // a release of the line is listed affected (the newest in newest)
)

// oracleLine is a document's statement on one line of one CVE.
type oracleLine struct {
	state       lineState
	newest      string   // lineAffectedTo: the newest affected release
	notAffected []string // the releases listed not affected
}

// oracleDocCVE is what one document states about one CVE for one product: per line, or unread (a release it names cannot be read, or
// a status Vedette does not read names one).
type oracleDocCVE struct {
	lines  map[string]oracleLine
	unread bool
}

// oracleDoc is the facts kept of one document: its day (first release, UTC), the page a person reads, and per catalogue product
// key the CVEs it states.
type oracleDoc struct {
	Day, Ref string
	CVEs     map[string]map[string]oracleDocCVE // product key -> CVE -> statement
}

// oracleProductRelease is a product of the tree read as a release of a catalogue product.
type oracleProductRelease struct {
	line, release string
	unread        bool
}

// cpeVersion is the version field of a CPE 2.3 string ("8u491"), unescaped; "" for another form or a wildcard.
func cpeVersion(cpe string) string {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(cpe)), "cpe:2.3:")
	if !ok {
		return ""
	}
	f := strings.SplitN(rest, ":", 5)
	if len(f) < 4 || f[3] == "*" || f[3] == "-" {
		return ""
	}
	return strings.ReplaceAll(f[3], `\`, "")
}

// cpeBaseOf is "part:vendor:product" of a CPE 2.3 string, lower case.
func cpeBaseOf(cpe string) string {
	rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(cpe)), "cpe:2.3:")
	if !ok {
		return ""
	}
	f := strings.SplitN(rest, ":", 4)
	if len(f) < 3 {
		return ""
	}
	return strings.Join(f[:3], ":")
}

// releaseOf reads a product of the tree as a release of catalogue product p under sel: ok false when it is another product. A product
// with a CPE is the product's when the CPE names it, its release the CPE's version; one without, when its product branch is sel's and it is named
// "<branch> Version <release>" (or "<branch> Version <branch>:<release>"; "<branch> Version <other product>:<release>" is the other
// product's); one that names another edition (sel.Other) is not the product's. The release is read in the vendor's notation through the product's version_map ("8u491" -> "1.8.0_491") and must give a
// line; one that does not is the product's but unread.
func releaseOf(raw csafRawProduct, p productid.Product, sel CSAFSelector) (oracleProductRelease, bool) {
	for _, o := range sel.Other {
		if o != "" && (strings.Contains(strings.ToLower(raw.Name), o) || strings.Contains(strings.ToLower(raw.CPE), o)) {
			return oracleProductRelease{}, false
		}
	}
	var rel string
	switch {
	case raw.CPE != "":
		if !slices.Contains(sel.CPE, cpeBaseOf(raw.CPE)) {
			return oracleProductRelease{}, false
		}
		rel = cpeVersion(raw.CPE)
	case sel.Branch != "" && raw.Product == sel.Branch:
		rest, ok := strings.CutPrefix(strings.TrimSpace(raw.Name), sel.Branch+" Version ")
		if !ok {
			return oracleProductRelease{unread: true}, true
		}
		if before, after, named := strings.Cut(rest, ":"); named {
			if strings.TrimSpace(before) != sel.Branch {
				return oracleProductRelease{}, false // another product listed under the branch
			}
			rest = after
		}
		rel = strings.TrimSpace(rest)
	default:
		return oracleProductRelease{}, false
	}
	c := p.Canonical(rel)
	line := p.Line(c)
	if !releaseRE.MatchString(c) || line == "" {
		return oracleProductRelease{unread: true}, true
	}
	return oracleProductRelease{line: line, release: c}, true
}

// cmpRelease orders two releases of one line by their numbers ("1.8.0_491" < "1.8.0_501", "11.0.33" < "11.0.33.0.3").
func cmpRelease(a, b string) int {
	split := func(s string) []int {
		var out []int
		for f := range strings.FieldsFuncSeq(s, func(r rune) bool { return r == '.' || r == '_' }) {
			n, _ := strconv.Atoi(f)
			out = append(out, n)
		}
		return out
	}
	x, y := split(a), split(b)
	for len(x) < len(y) {
		x = append(x, 0)
	}
	for len(y) < len(x) {
		y = append(y, 0)
	}
	return slices.Compare(x, y)
}

// oracleFacts picks from a document the statements on the catalogue products of sels (product key -> selector): per CVE that names a
// release of the product in a status, its lines. A line the document has a release of and the CVE names none of is "assessed only"; a
// line all of whose releases it lists not affected is "not affected"; a line with an affected release is affected up to the newest. A
// CVE is unread when it names a release of the product that cannot be read, names one in a status other than known_affected and
// known_not_affected, or lists a release not affected below one it lists affected on the same line.
func oracleFacts(d csafRawDoc, sels map[string]CSAFSelector) oracleDoc {
	day, _ := csafTime(d.Initial)
	out := oracleDoc{Day: day.Format(time.DateOnly), CVEs: map[string]map[string]oracleDocCVE{}}
	for _, u := range d.Refs {
		if strings.HasPrefix(u, "https://www.oracle.com/") && len(u) <= 500 && !strings.ContainsAny(u, " \"<>") {
			out.Ref = u
			break
		}
	}
	for key, sel := range sels {
		p, ok := productid.ByKey(key)
		if !ok {
			continue
		}
		ours := map[string]oracleProductRelease{}
		for _, raw := range d.Products {
			if r, ok := releaseOf(raw, p, sel); ok {
				if old, seen := ours[raw.ID]; seen && (old.unread || r.unread || old != r) {
					r = oracleProductRelease{unread: true} // one id named twice, differently
				}
				ours[raw.ID] = r
			}
		}
		for _, rel := range d.Rels { // a product built from one of ours (on a platform) is a release of the same line
			if r, ok := ours[rel[0]]; ok {
				ours[rel[1]] = r
			}
		}
		if len(ours) == 0 {
			continue
		}
		perLine := map[string][]string{} // the readable releases of each line the document has
		for _, r := range ours {
			if !r.unread {
				perLine[r.line] = append(perLine[r.line], r.release)
			}
		}
		cves := map[string]*struct {
			affected    map[string]string
			notAffected map[string][]string
			unread      bool
		}{}
		for _, v := range d.Vulns {
			cve := strings.ToUpper(strings.TrimSpace(v.CVE))
			if len(cve) > 32 || !cveRE.MatchString(cve) {
				continue
			}
			for cat, ids := range v.Status {
				for _, id := range ids {
					r, mine := ours[id]
					if !mine {
						continue
					}
					c := cves[cve]
					if c == nil {
						c = &struct {
							affected    map[string]string
							notAffected map[string][]string
							unread      bool
						}{affected: map[string]string{}, notAffected: map[string][]string{}}
						cves[cve] = c
					}
					switch {
					case r.unread, cat != "known_affected" && cat != "known_not_affected":
						c.unread = true
					case cat == "known_affected":
						if old, ok := c.affected[r.line]; !ok || cmpRelease(r.release, old) > 0 {
							c.affected[r.line] = r.release
						}
					default:
						c.notAffected[r.line] = append(c.notAffected[r.line], r.release)
					}
				}
			}
		}
		if len(cves) == 0 {
			continue
		}
		stated := map[string]oracleDocCVE{}
		for cve, c := range cves {
			st := oracleDocCVE{lines: map[string]oracleLine{}, unread: c.unread}
			for line, rels := range perLine {
				na := slices.Sorted(slices.Values(c.notAffected[line]))
				na = slices.Compact(na)
				switch newest, ok := c.affected[line]; {
				case ok:
					if slices.ContainsFunc(na, func(r string) bool { return cmpRelease(r, newest) <= 0 }) {
						st.unread = true // not affected below a release listed affected: a range Vedette does not read
					}
					st.lines[line] = oracleLine{state: lineAffectedTo, newest: newest, notAffected: na}
				case len(na) > 0 && !slices.ContainsFunc(rels, func(r string) bool { return !slices.Contains(na, r) }):
					st.lines[line] = oracleLine{state: lineNotAffected, notAffected: na}
				default:
					st.lines[line] = oracleLine{state: lineAssessedOnly, notAffected: na}
				}
			}
			stated[cve] = st
		}
		out.CVEs[key] = stated
	}
	return out
}

// combineOracle is the line statements of every document read (in the feed's order): per product and CVE, the rows of all the
// documents that state it. A line affected in any of them is affected up to the newest release any lists (the affected side wins); else
// not affected when one lists every release of the line not affected (explicit); else, when complete, not affected by the convention
// for a line one of them assessed (explicit false). A CVE one document could not read, or that one lists not affected at or below a
// release another lists affected on the same line, is dropped whole: never stored in part. complete is false when a document of the
// feed could not be read: what it states is unknown, so no line is read as not affected by the convention.
func combineOracle(docs []oracleDoc, complete bool) []lineStatement {
	type acc struct {
		lines  map[string]oracleLine
		unread bool
		day    string
		ref    string
	}
	by := map[[2]string]*acc{}
	for _, d := range docs {
		for key, cves := range d.CVEs {
			for cve, st := range cves {
				a := by[[2]string{key, cve}]
				if a == nil {
					a = &acc{lines: map[string]oracleLine{}}
					by[[2]string{key, cve}] = a
				}
				a.unread = a.unread || st.unread
				if d.Day >= a.day {
					a.day, a.ref = d.Day, cmp.Or(d.Ref, a.ref)
				}
				for line, l := range st.lines {
					old, ok := a.lines[line]
					switch {
					case !ok || l.state > old.state:
						l.notAffected = append(l.notAffected, old.notAffected...)
						if old.state == lineAffectedTo {
							l.newest = old.newest
						}
						a.lines[line] = l
					case l.state == old.state && l.state == lineAffectedTo && cmpRelease(l.newest, old.newest) > 0:
						old.newest = l.newest
						old.notAffected = append(old.notAffected, l.notAffected...)
						a.lines[line] = old
					default:
						old.notAffected = append(old.notAffected, l.notAffected...)
						a.lines[line] = old
					}
				}
			}
		}
	}
	var out []lineStatement
	for _, k := range slices.SortedFunc(maps.Keys(by), func(a, b [2]string) int { return cmp.Or(cmp.Compare(a[1], b[1]), cmp.Compare(a[0], b[0])) }) {
		a := by[k]
		if a.unread {
			continue
		}
		st := lineStatement{CVE: k[1], Product: k[0], Ref: a.ref, StatedAt: a.day}
		for _, line := range slices.Sorted(maps.Keys(a.lines)) {
			l := a.lines[line]
			switch l.state {
			case lineAffectedTo:
				if slices.ContainsFunc(l.notAffected, func(r string) bool { return cmpRelease(r, l.newest) <= 0 }) {
					a.unread = true // two documents disagree on the line
				}
				st.Rows = append(st.Rows, lineRow{Line: line, Status: "affected", LastAffected: l.newest, Explicit: true})
			case lineNotAffected:
				st.Rows = append(st.Rows, lineRow{Line: line, Status: "unaffected", Explicit: true})
			case lineAssessedOnly:
				if complete {
					st.Rows = append(st.Rows, lineRow{Line: line, Status: "unaffected"})
				}
			}
		}
		if !a.unread && len(st.Rows) > 0 {
			out = append(out, st)
		}
	}
	return out
}

// oracleMemory is what the box remembers, between two pulls, of the documents the feed lists: each one's validators and the facts read
// from it. It is kept in memory only (after a restart, a new address or the feed turned off and on, each document is read once more).
type oracleMemory struct {
	url  string
	docs map[string]oracleMemDoc // document path -> what was read
}

type oracleMemDoc struct {
	etag, lastModified string
	facts              oracleDoc
}

// recallOracle is a copy of what the box remembers of the feed's documents, empty for another address or a feed without a good pull.
func (s *Service) recallOracle(src sourceRow) *oracleMemory {
	m := &oracleMemory{url: src.URL, docs: map[string]oracleMemDoc{}}
	s.advMu.Lock()
	defer s.advMu.Unlock()
	if old := s.oracle; old != nil && old.url == src.URL && !prevGood(src).IsZero() {
		maps.Copy(m.docs, old.docs)
	}
	return m
}

// keepOracle stores what a pull read, once its statements are written.
func (s *Service) keepOracle(m *oracleMemory) {
	s.advMu.Lock()
	defer s.advMu.Unlock()
	s.oracle = m
}

// buildOracleLines reads Oracle's CSAF feed and each document it lists (conditional on what the box read of it), and states per
// catalogue product and CVE the release lines the documents speak about (combineOracle). A document gone (404, 410), too large or not
// readable is skipped and counted, and then no line is read as not affected by the convention; any other failure fails the pull, so
// nothing is written from half a list.
func (s *Service) buildOracleLines(ctx context.Context, src sourceRow, p pullPlan) (pullPlan, error) {
	cat, err := lineCat()
	if err != nil {
		return p, err
	}
	def := cat.sources[src.ID]
	sels := map[string]CSAFSelector{}
	for i, key := range cat.keys[src.ID] {
		sels[key] = def.CSAF[def.Products[i]]
	}
	base, err := url.Parse(src.URL)
	if err != nil || base.Host == "" {
		return p, fail(ErrBadConfig, "The feed's address is not valid.")
	}
	ctx, cancel := context.WithTimeout(ctx, vendorTimeout)
	defer cancel()
	var (
		items []feedItem
		size  int
	)
	if _, err := s.Fetcher.Fetch(ctx, Request{URL: src.URL, MaxBytes: csafListMaxBytes, Stream: func(r io.Reader) error {
		c := &countReader{r: r}
		var err error
		items, err = parseAdvisoryFeed(c, "Oracle's advisory feed")
		size += c.n
		return err
	}}); err != nil {
		return p, err
	}
	tl := newTally()
	var paths []string
	skipped := 0
	for i, it := range items {
		u, err := url.Parse(it.Link)
		if err != nil || u.Scheme != "https" || u.RawQuery != "" || !oracleDocPath.MatchString(u.Path) {
			tl.reject(i+1, "item: %s has no CSAF document link", it.Link)
			skipped++ // a document Vedette does not ask: what it states is unknown
			continue
		}
		if !slices.Contains(paths, u.Path) {
			paths = append(paths, u.Path)
		}
	}
	if len(paths) > oracleMaxDocs {
		return p, fail(ErrBadSample, "Oracle's advisory feed names more than %s documents.", grouped(oracleMaxDocs))
	}
	mem := s.recallOracle(src)
	var docs []oracleDoc
	for i, path := range paths {
		if i > 0 {
			if err := s.sleep(ctx, vendorPause); err != nil {
				return p, err
			}
		}
		u := *base
		u.Path, u.RawPath, u.RawQuery, u.Fragment = path, "", "", ""
		old, known := mem.docs[path]
		req := Request{URL: u.String(), MaxBytes: oracleDocMaxBytes}
		if known {
			req.ETag, req.LastModified = old.etag, old.lastModified
		}
		var (
			raw     csafRawDoc
			parseOK bool
		)
		req.Stream = func(r io.Reader) error {
			c := &countReader{r: &transportReader{r: r}}
			var err error
			raw, err = parseCSAFLines(c)
			size += c.n
			var te transportErr
			switch {
			case err == nil:
				parseOK = true
				return nil
			case errors.Is(err, ErrTooLarge):
				return err
			case errors.As(err, &te):
				return te.err // the connection failed, not the document: the pull fails and the document is asked again
			}
			return nil // a bad document is counted below, not a failed pull
		}
		resp, err := s.Fetcher.Fetch(ctx, req)
		var se *StatusError
		switch {
		case errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusGone):
			tl.reject(i+1, "%s: the document is gone", lastPart(path))
		case errors.Is(err, ErrTooLarge):
			tl.reject(i+1, "%s: the document is larger than %s MB", lastPart(path), strconv.Itoa(oracleDocMaxBytes>>20))
		case err != nil:
			return p, err
		case resp.NotModified && known:
			tl.Accepted++
			docs = append(docs, old.facts)
			continue
		case resp.NotModified, !parseOK:
			tl.reject(i+1, "%s: the document could not be read", lastPart(path))
		default:
			facts := oracleFacts(raw, sels)
			if facts.Ref == "" {
				facts.Ref = u.String()
			}
			mem.docs[path] = oracleMemDoc{etag: resp.ETag, lastModified: resp.LastModified, facts: facts}
			tl.Accepted++
			docs = append(docs, facts)
			continue
		}
		skipped++
		delete(mem.docs, path)
	}
	maps.DeleteFunc(mem.docs, func(path string, _ oracleMemDoc) bool { return !slices.Contains(paths, path) })
	st := tl.stats()
	if err := accepted(st); err != nil {
		return p, err
	}
	p.lines, p.hasLines, p.lineMem = combineOracle(docs, skipped == 0), true, mem
	p.out = outcome{OK: true, Bytes: size}
	p.out.fill(st, len(p.lines))
	if skipped > 0 {
		p.out.Note = strings.TrimSpace(p.out.Note + fmt.Sprintf(" %s of the feed's documents could not be read: until they are, a release line Oracle does not list is not read as not affected.", grouped(skipped)))
	}
	return p, nil
}
