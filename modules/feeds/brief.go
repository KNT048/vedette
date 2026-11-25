package feeds

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/versionscheme"
)

// Brief is everything the box knows about one CVE, in one read model: the CVE page, the summary card of a finding, the AI context,
// notices and reports all read it, and none assembles CVE data of its own. Every value comes from the stored catalogue and is read
// by one function each (PickCVSS, Severity, rangeOrigin, ReadVector, refGroup); nothing is fetched to answer it.
type Brief struct {
	CVE                string
	Title, Description string // the CNA's title ("" when it gives none); NVD's English description, else the CNA's
	// Display is the product in plain words: the exploited-list entry's when the CVE is on a list, else the first of Products.
	Display string
	// Products is the vendor and product of the ranges that count, "vmware esxi", distinct, sorted, at most briefMaxProducts.
	Products            []string
	Published, Modified *time.Time
	NVDStatus           string     // NVD's vulnStatus ("Analyzed", "Deferred" …); "" until NVD answered
	NVDAt, RecordAt     *time.Time // when NVD answered and when the CVE record was read; nil: never
	CWE                 []Weakness
	CVSS                *BriefCVSS // PickCVSS of Scores; nil when the CVE has no score
	Scores              []Metric   // every stored score, newest CVSS version first, then NVD, the CNA, CISA's ADP
	Lists               []ListEntry
	Signals             []BriefSignal
	// Ranges is every affected-versions row, with Counts set on the rows the matcher reads (rangeOrigin: NVD's when NVD gives any,
	// else the CVE record's); the other origin's rows stay for what they say (a CNA's fixed release beside NVD's exact versions).
	Ranges []BriefRange
	// RangesFrom is the origin of the rows that count (OriginNVD, OriginCNA, OriginADP; "" when none); RangesComplete says, for the
	// CVE record's rows, whether every product's list says what an unlisted version is.
	RangesFrom     string
	RangesComplete bool
	// Fixes is the fixed release of each release train the ranges state, as the product's version scheme reads them (RangeScheme):
	// VMware's 8.0 U3d (build 24585383) for train 8.0 U3. One per product and train, the vendor's (CNA, ADP) before NVD's; none for a
	// product without a scheme. A row a scheme does not read keeps its fixed release in Ranges.
	Fixes                []BriefFix
	References           []Reference // grouped: ordered by Group (refGroups), then by address
	Solution, Workaround string      // the CNA's text; "" when the record has none
	SSVC                 SSVC
	EPSS                 *BriefEPSS // nil when epss-all holds no score for the CVE
	NVDURL, RecordURL    string     // the CVE's pages at NVD and at the CVE Program
}

// Weakness is one CWE of a CVE with its name in MITRE's CWE List; Name is "" for an id the list does not hold.
type Weakness struct{ ID, Name string }

// BriefCVSS is the picked CVSS score with its band and its vector read into words.
type BriefCVSS struct {
	CVSS
	Severity string         // Severity(Score, Version): "CRITICAL", "HIGH" …
	Reading  *VectorReading // nil when the vector cannot be read
}

// ListEntry is one exploited-list entry of the CVE in the list's own words (feeds_kev), the owner entry first (listRank).
type ListEntry struct {
	List, Source, SourceName       string // "cisa", the feed "cisa-kev", the feed's name "CISA KEV"
	Vendor, Product, Display, Name string
	Description, RequiredAction    string
	Links                          []string
	DateAdded, DueDate             string // days; DueDate "" when the list gives none
	Ransomware                     bool
}

// BriefSignal is one feeds_signal row of the CVE with the name of the feed that wrote it. Kinds and sources are read as stored, so a
// new kind or source appears here without a change.
type BriefSignal struct {
	Signal
	SourceName string // the feed's name ("Metasploit"); the source id when no feed of that id exists
}

// BriefRange is one affected-versions row read for people: Versions says which versions in words ("from 2.0 before 2.4.58",
// "7.0 update_1", "every version"; a row its product's version scheme reads in the scheme's words: "from 8.0 before 8.0 U3d (build
// 24585383)"). Train is the release train the row's end belongs to ("8.0 U3") and FixedRelease its fixed release ("8.0 U3d (build
// 24585383)"), as the scheme reads them; "" when no scheme reads the row.
type BriefRange struct {
	Range
	Counts              bool
	Versions            string
	Train, FixedRelease string
}

// Reference is one reference of the CVE: its address, its tags in the CVE record's words, who gave it (nvd, cna, adp) and the one
// group it is shown under (refGroup).
type Reference struct {
	URL    string
	Tags   []string
	Source string
	Group  string
}

// BriefEPSS is FIRST's EPSS score of the CVE: today's, the day FIRST scored it, the score of a week before and the days the box kept
// (feeds_epss_hist, only for CVEs on a list or with a signal), oldest first.
type BriefEPSS struct {
	Score, Percentile float64
	Day               string // FIRST's score date; "" when the file gave none
	WeekAgo           *float64
	History           []EPSSDay
}

// EPSSDay is one kept day of a CVE's EPSS score.
type EPSSDay struct {
	Day   string
	Score float64
}

// briefMaxProducts caps Brief.Products (a CVE of a shared library names hundreds of products).
const briefMaxProducts = 20

// The groups of references, in the order a brief lists them; a reference is shown under the first group one of its tags names, else
// RefOther. The words are the CVE record's tags (NVD's are read into them: nvdTag).
var refGroups = []string{"vendor-advisory", "patch", "mitigation", "release-notes", "exploit", "government-resource", "third-party-advisory",
	"technical-description", "issue-tracking", "mailing-list", "vdb-entry", "media-coverage"}

// RefOther is the group of a reference with no tag of refGroups.
const RefOther = "other"

// RefGroups is the groups a reference can be shown under, in order, RefOther last.
func RefGroups() []string { return append(slices.Clone(refGroups), RefOther) }

// refGroup is the group a reference with these tags is shown under.
func refGroup(tags []string) string {
	for _, g := range refGroups {
		if slices.Contains(tags, g) {
			return g
		}
	}
	return RefOther
}

// cweNames is MITRE's CWE names (content/catalog/cwe-names.json), read once.
var cweNames = func() map[string]string {
	var f struct {
		Names map[string]string `json:"names"`
	}
	if err := json.Unmarshal(catalogdata.CWENames, &f); err != nil {
		panic(fmt.Sprintf("feeds: content/catalog/cwe-names.json: %v", err)) // embedded at build time; TestCWENames reads it
	}
	return f.Names
}()

// weaknesses names the CWE ids of a CVE.
func weaknesses(ids []string) []Weakness {
	out := make([]Weakness, 0, len(ids))
	for _, id := range ids {
		out = append(out, Weakness{ID: id, Name: cweNames[id]})
	}
	return out
}

// Brief reads the brief of one CVE (upper case); ok is false when the catalogue does not hold it.
func (s *Store) Brief(ctx context.Context, cve string) (Brief, bool, error) {
	db := s.db.Reader()
	b := Brief{CVE: cve, NVDURL: "https://nvd.nist.gov/vuln/detail/" + cve, RecordURL: "https://www.cve.org/CVERecord?id=" + cve}
	var (
		pub, mod, status, nvdAt, recordAt, ssvcE, ssvcA, ssvcI sql.NullString
		cwe                                                    string
	)
	err := db.QueryRowContext(ctx, `SELECT published, modified, nvd_status, nvd_at, record_at, title, description, cwe, solution, workaround,
ssvc_exploitation, ssvc_automatable, ssvc_impact FROM feeds_cve WHERE cve = ?`, cve).Scan(&pub, &mod, &status, &nvdAt, &recordAt, &b.Title,
		&b.Description, &cwe, &b.Solution, &b.Workaround, &ssvcE, &ssvcA, &ssvcI)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Brief{}, false, nil
	case err != nil:
		return Brief{}, false, fmt.Errorf("feeds: brief %s: %w", cve, err)
	}
	b.Workaround = statedWorkaround(b.Workaround)
	b.Published, b.Modified, b.NVDAt, b.RecordAt = optTime(pub), optTime(mod), optTime(nvdAt), optTime(recordAt)
	b.NVDStatus, b.SSVC = status.String, SSVC{Exploitation: ssvcE.String, Automatable: ssvcA.String, Impact: ssvcI.String}
	var ids []string
	if json.Unmarshal([]byte(cwe), &ids) != nil {
		ids = nil
	}
	b.CWE = weaknesses(ids)

	scores, err := s.metricsOf(ctx, []string{cve})
	if err != nil {
		return Brief{}, false, err
	}
	b.Scores = sortedScores(scores[cve])
	if c, ok := PickCVSS(b.Scores); ok {
		b.CVSS = &BriefCVSS{CVSS: c, Severity: Severity(c.Score, c.Version), Reading: ReadVector(c.Vector)}
	}

	if b.Lists, err = listEntries(ctx, db, cve); err != nil {
		return Brief{}, false, err
	}
	names, err := sourceNames(ctx, db)
	if err != nil {
		return Brief{}, false, err
	}
	sigs, err := s.Signals(ctx, []string{cve})
	if err != nil {
		return Brief{}, false, err
	}
	b.Signals = make([]BriefSignal, 0, len(sigs[cve]))
	for _, g := range sigs[cve] {
		b.Signals = append(b.Signals, BriefSignal{Signal: g, SourceName: cmp.Or(names[g.Source], g.Source)})
	}

	rows, err := readRanges(ctx, db, `WHERE r.cve = ?`, cve)
	if err != nil {
		return Brief{}, false, err
	}
	b.Ranges, b.RangesFrom, b.RangesComplete = briefRanges(rows)
	b.Fixes = briefFixes(b.Ranges)
	b.Products = rangeProducts(b.Ranges)
	switch {
	case len(b.Lists) > 0:
		b.Display = b.Lists[0].Display
	case catalogueProduct(b.Ranges) != "":
		b.Display = catalogueProduct(b.Ranges)
	case len(b.Products) > 0:
		b.Display = b.Products[0]
	}

	if b.References, err = references(ctx, db, cve); err != nil {
		return Brief{}, false, err
	}
	if b.EPSS, err = epssOf(ctx, db, cve); err != nil {
		return Brief{}, false, err
	}
	return b, true, nil
}

// sortedScores orders a CVE's scores as PickCVSS prefers them: newest CVSS version first, then NVD, the CNA, CISA's ADP.
func sortedScores(ms []Metric) []Metric {
	out := slices.Clone(ms)
	slices.SortStableFunc(out, func(a, b Metric) int {
		return cmp.Or(cmp.Compare(slices.Index(cvssVersions, a.Version), slices.Index(cvssVersions, b.Version)),
			cmp.Compare(slices.Index(metricSources, a.Source), slices.Index(metricSources, b.Source)))
	})
	if out == nil {
		out = []Metric{}
	}
	return out
}

// listEntries reads the CVE's exploited-list entries, the owner entry first.
func listEntries(ctx context.Context, q queryer, cve string) ([]ListEntry, error) {
	rows, err := q.QueryContext(ctx, `SELECT k2.list, k2.source_id, coalesce(s.name, ''), k2.vendor, k2.product, k2.name, k2.description, k2.required_action,
k2.links, k2.date_added, coalesce(k2.due_date, ''), k2.ransomware
FROM feeds_kev k2 LEFT JOIN feeds_source s ON s.id = k2.source_id WHERE k2.cve = ? ORDER BY `+ownerOrder, cve)
	if err != nil {
		return nil, fmt.Errorf("feeds: brief lists: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []ListEntry{}
	for rows.Next() {
		var (
			e     ListEntry
			links string
		)
		if err := rows.Scan(&e.List, &e.Source, &e.SourceName, &e.Vendor, &e.Product, &e.Name, &e.Description, &e.RequiredAction, &links, &e.DateAdded,
			&e.DueDate, &e.Ransomware); err != nil {
			return nil, fmt.Errorf("feeds: brief lists: %w", err)
		}
		if json.Unmarshal([]byte(links), &e.Links) != nil || e.Links == nil {
			e.Links = []string{}
		}
		e.SourceName = cmp.Or(e.SourceName, e.Source)
		e.Display = DisplayOf(e.Vendor, e.Product)
		out = append(out, e)
	}
	return out, rows.Err()
}

// sourceNames is the name of every feed by id.
func sourceNames(ctx context.Context, q queryer) (map[string]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, name FROM feeds_source`)
	if err != nil {
		return nil, fmt.Errorf("feeds: brief sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("feeds: brief sources: %w", err)
		}
		out[id] = name
	}
	out[appleClaimSource] = appleSourceName // written from the catalogue's CVE records, not by a feed of its own
	return out, rows.Err()
}

// briefRanges marks the rows that count (rangeOrigin) and words each row's versions, in its product's version scheme when one reads
// it. The rows that count come first.
func briefRanges(rows []Range) (out []BriefRange, from string, complete bool) {
	counting := rangeOrigin(slices.Clone(rows))
	if len(counting) > 0 {
		from = counting[0].Origin
	}
	complete = from != "" && from != OriginNVD
	out = make([]BriefRange, 0, len(rows))
	for _, r := range rows {
		if r.Unaffected() { // the versions a vendor states NOT affected are no row of the affected versions (StatementScheme reads them)
			continue
		}
		// rangeOrigin: NVD's rows when there are any, else every row the generic comparison reads
		counts := r.Generic() && (from != OriginNVD || r.Origin == OriginNVD)
		if counts && r.Origin != OriginNVD && r.DefaultStatus != DefaultAffected && r.DefaultStatus != DefaultUnaffected {
			complete = false
		}
		out = append(out, BriefRange{Range: r, Counts: counts, Versions: rangeVersions(r)})
	}
	schemeWords(out)
	slices.SortStableFunc(out, func(a, b BriefRange) int {
		if a.Counts == b.Counts {
			return 0
		}
		if a.Counts {
			return -1
		}
		return 1
	})
	return out, from, complete
}

// schemeWords words the rows their product's version scheme reads (RangeScheme): their versions in the scheme's words, their train and
// fixed release. A train two of a product's rows end in at different releases (versionscheme.Conflicts: NetScaler's FIPS build
// written without the word) is named for none of them: those rows keep their words as written.
func schemeWords(rows []BriefRange) {
	type read struct {
		i     int
		sp    versionscheme.Span
		fixed *versionscheme.Version
	}
	byProduct := map[[3]string][]read{}
	var order [][3]string
	for i, r := range rows {
		if _, sp, fixed, ok := RangeScheme(r.Range); ok {
			k := [3]string{r.Part, r.Vendor, r.Product}
			if _, seen := byProduct[k]; !seen {
				order = append(order, k)
			}
			byProduct[k] = append(byProduct[k], read{i, sp, fixed})
		}
	}
	for _, k := range order {
		reads := byProduct[k]
		spans := make([]versionscheme.Span, len(reads))
		for j, rd := range reads {
			spans[j] = rd.sp
		}
		conflicts := versionscheme.Conflicts(spans)
		for _, rd := range reads {
			if rd.sp.End != nil && conflicts[rd.sp.End.Train] {
				continue
			}
			br := &rows[rd.i]
			br.Versions = schemeVersions(rd.sp, br.Versions)
			if rd.sp.End != nil {
				br.Train = rd.sp.End.Train
			}
			if rd.fixed != nil {
				br.Train, br.FixedRelease = rd.fixed.Train, rd.fixed.Display
			}
		}
	}
}

// schemeVersions words a range its product's scheme reads: its bounds in the scheme's words ("from 8.0 before 8.0 U3d (build
// 24585383)"); words when it has no bound.
func schemeVersions(sp versionscheme.Span, words string) string {
	var parts []string
	if sp.Start != nil {
		parts = append(parts, "from "+sp.Start.Display)
	}
	if sp.End != nil {
		w := "before "
		if sp.EndIncl {
			w = "up to "
		}
		parts = append(parts, w+sp.End.Display)
	}
	if len(parts) == 0 {
		return words
	}
	return strings.Join(parts, " ")
}

// briefFixes is the fixed release of each product and train the rows state (BriefRange.FixedRelease), the vendor's first.
func briefFixes(rows []BriefRange) []BriefFix {
	out := []BriefFix{}
	for _, nvd := range []bool{false, true} {
		for _, r := range rows {
			if r.FixedRelease == "" || (r.Origin == OriginNVD) != nvd {
				continue
			}
			f := BriefFix{Vendor: r.Vendor, Product: r.Product, Origin: r.Origin, Train: r.Train, Release: r.FixedRelease}
			if !slices.ContainsFunc(out, func(g BriefFix) bool { return g.Vendor == f.Vendor && g.Product == f.Product && g.Train == f.Train }) {
				out = append(out, f)
			}
		}
	}
	return out
}

// catalogueProduct names the CVE by the product of the product catalogue (core/productid) that most of the rows the matcher reads name:
// the counted rows and the rows a product's version scheme reads (Train set: VMware's "ESX" rows in its own build notation), so the
// product a device would be matched as ("nginx" for F5's nginx_open_source rows, "Java" for Oracle's jdk, jre and openjdk rows, "VMware
// ESXi" for three ESX rows beside one Workstation row), never the first name in alphabetical order (F5's "dos" module of NGINX, Amazon's
// Corretto build). A scheme row counts only when its assessor is the counted rows' (or, with none counted, the CNA when it gave any):
// another assessor's rows (CISA's ADP rows of Oracle's Java on a WebKit flaw NVD lists for Apple's systems) never outvote the record's
// own. "" when no such row names one.
func catalogueProduct(rs []BriefRange) string {
	from := ""
	for _, r := range rs {
		if r.Counts {
			from = r.Origin
			break
		}
	}
	if from == "" {
		for _, r := range rs {
			if r.Train != "" && (from == "" || r.Origin == OriginCNA) {
				from = r.Origin
			}
		}
	}
	count := map[string]int{}
	var order []string
	for _, r := range rs {
		if !r.Counts && (r.Train == "" || r.Origin != from) {
			continue
		}
		p, ok := productid.ByRangeName(r.Part, r.Vendor, r.Product)
		if !ok || p.Display == "" {
			continue
		}
		if count[p.Display] == 0 {
			order = append(order, p.Display)
		}
		count[p.Display]++
	}
	best := ""
	for _, d := range order {
		if best == "" || count[d] > count[best] {
			best = d
		}
	}
	return best
}

// rangeProducts is the distinct "vendor product" of the rows that count.
func rangeProducts(rs []BriefRange) []string {
	seen := map[string]bool{}
	for _, r := range rs {
		if r.Counts && r.Vendor != "" && r.Product != "" {
			seen[strings.ReplaceAll(r.Vendor+" "+r.Product, "_", " ")] = true
		}
	}
	out := slices.Sorted(mapsKeys(seen))
	if out == nil {
		out = []string{}
	}
	return out[:min(len(out), briefMaxProducts)]
}

// rangeVersions words the versions of one row: its bounds ("from 2.0 before 2.4.58", "up to 3.1"), an exact version ("4.2.1"), the
// version and update of an NVD row that names one release in its CPE ("7.0 update_1"), or "every version".
func rangeVersions(r Range) string {
	if r.StartIncl != "" && r.StartIncl == r.EndIncl && r.StartExcl == "" && r.EndExcl == "" {
		return r.StartIncl
	}
	var parts []string
	for _, b := range []struct{ word, v string }{{"from", r.StartIncl}, {"after", r.StartExcl}, {"before", r.EndExcl}, {"up to", r.EndIncl}} {
		if b.v != "" {
			parts = append(parts, b.word+" "+b.v)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	if f := cpeFields(r.CPE); len(f) > 6 && f[5] != "*" && f[5] != "-" && f[5] != "" {
		if u := f[6]; u != "*" && u != "-" && u != "" {
			return f[5] + " " + u
		}
		return f[5]
	}
	return "every version"
}

// cpeFields splits a CPE 2.3 formatted string at its unescaped colons and removes the escapes ("cpe:2.3:a:x:y:1\.0:…").
func cpeFields(cpe string) []string {
	if !strings.HasPrefix(cpe, "cpe:2.3:") {
		return nil
	}
	var (
		out []string
		cur strings.Builder
	)
	for i := 0; i < len(cpe); i++ {
		switch c := cpe[i]; {
		case c == '\\' && i+1 < len(cpe):
			i++
			cur.WriteByte(cpe[i])
		case c == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}

// references reads the CVE's references, grouped (refGroup) and ordered by group, then by address.
func references(ctx context.Context, q queryer, cve string) ([]Reference, error) {
	rows, err := q.QueryContext(ctx, `SELECT url, tags, source FROM feeds_cve_ref WHERE cve = ? ORDER BY url`, cve)
	if err != nil {
		return nil, fmt.Errorf("feeds: brief references: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []Reference{}
	for rows.Next() {
		var (
			r    Reference
			tags string
		)
		if err := rows.Scan(&r.URL, &tags, &r.Source); err != nil {
			return nil, fmt.Errorf("feeds: brief references: %w", err)
		}
		if json.Unmarshal([]byte(tags), &r.Tags) != nil || r.Tags == nil {
			r.Tags = []string{}
		}
		r.Group = refGroup(r.Tags)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: brief references: %w", err)
	}
	order := RefGroups()
	slices.SortStableFunc(out, func(a, b Reference) int {
		return cmp.Compare(slices.Index(order, a.Group), slices.Index(order, b.Group))
	})
	return out, nil
}

// epssOf reads the CVE's EPSS score, its day, and the kept days.
func epssOf(ctx context.Context, q queryer, cve string) (*BriefEPSS, error) {
	rows, err := q.QueryContext(ctx, `SELECT e.epss, e.percentile, coalesce((SELECT score_date FROM feeds_epss_baseline WHERE id = 1), '') FROM feeds_epss e WHERE e.cve = ?`, cve)
	if err != nil {
		return nil, fmt.Errorf("feeds: brief EPSS: %w", err)
	}
	var out *BriefEPSS
	for rows.Next() {
		out = &BriefEPSS{History: []EPSSDay{}}
		if err := rows.Scan(&out.Score, &out.Percentile, &out.Day); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("feeds: brief EPSS: %w", err)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil || out == nil {
		if err != nil {
			err = fmt.Errorf("feeds: brief EPSS: %w", err)
		}
		return nil, err
	}
	hist, err := q.QueryContext(ctx, `SELECT day, epss FROM feeds_epss_hist WHERE cve = ? ORDER BY day`, cve)
	if err != nil {
		return nil, fmt.Errorf("feeds: brief EPSS: %w", err)
	}
	defer func() { _ = hist.Close() }()
	weekAgo := ""
	if d, err := time.Parse(time.DateOnly, out.Day); err == nil {
		weekAgo = d.AddDate(0, 0, -7).Format(time.DateOnly)
	}
	for hist.Next() {
		var d EPSSDay
		if err := hist.Scan(&d.Day, &d.Score); err != nil {
			return nil, fmt.Errorf("feeds: brief EPSS: %w", err)
		}
		out.History = append(out.History, d)
		if d.Day == weekAgo {
			v := d.Score
			out.WeekAgo = &v
		}
	}
	return out, hist.Err()
}

// ---- the API shape of a brief (GET /feeds/cve/{id}, contract.ts CveBrief)

type briefDTO struct {
	CVE            string          `json:"cve"`
	Title          *string         `json:"title"`
	Description    string          `json:"description"`
	Display        *string         `json:"display"`
	Products       []string        `json:"products"`
	Published      *string         `json:"published"`
	Modified       *string         `json:"modified"`
	NVDStatus      *string         `json:"nvd_status"`
	NVDCheckedAt   *time.Time      `json:"nvd_checked_at"`
	RecordReadAt   *time.Time      `json:"record_read_at"`
	CWE            []weaknessDTO   `json:"cwe"`
	CVSS           *cvssDTO        `json:"cvss"`
	Scores         []scoreDTO      `json:"scores"`
	Lists          []listDTO       `json:"lists"`
	Signals        []signalDTO     `json:"signals"`
	Ranges         []rangeDTO      `json:"ranges"`
	Fixes          []fixDTO        `json:"fixes"`
	RangesFrom     *string         `json:"ranges_from"`
	RangesComplete bool            `json:"ranges_complete"`
	References     []referenceDTO  `json:"references"`
	Solution       *string         `json:"solution"`
	Workaround     *string         `json:"workaround"`
	SSVC           ssvcDTO         `json:"ssvc"`
	EPSS           *epssDTO        `json:"epss"`
	NVDURL         string          `json:"nvd_url"`
	RecordURL      string          `json:"record_url"`
	Matched        *[]MatchedAsset `json:"matched" nullable:"true"`
	NotAffected    int             `json:"not_affected"`
}

type weaknessDTO struct {
	ID   string  `json:"id"`
	Name *string `json:"name"`
}

type scoreDTO struct {
	Source  string  `json:"source"`
	Version string  `json:"version"`
	Score   float64 `json:"score"`
	Vector  string  `json:"vector"`
}

type cvssDTO struct {
	scoreDTO
	Severity string      `json:"severity"`
	Reading  *readingDTO `json:"reading"`
}

type impactDTO struct {
	Confidentiality string `json:"confidentiality"`
	Integrity       string `json:"integrity"`
	Availability    string `json:"availability"`
}

type readingDTO struct {
	AttackVector       string  `json:"attack_vector"`
	AttackComplexity   string  `json:"attack_complexity"`
	AttackRequirements *string `json:"attack_requirements"`
	PrivilegesRequired string  `json:"privileges_required"`
	UserInteraction    *string `json:"user_interaction"`
	Scope              *string `json:"scope"`
	impactDTO
	Subsequent *impactDTO `json:"subsequent"`
	Summary    string     `json:"summary"`
}

type listDTO struct {
	List           string   `json:"list"`
	Source         string   `json:"source"`
	SourceName     string   `json:"source_name"`
	Vendor         string   `json:"vendor"`
	Product        string   `json:"product"`
	Display        string   `json:"display"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RequiredAction string   `json:"required_action"`
	Links          []string `json:"links"`
	DateAdded      string   `json:"date_added"`
	DueDate        *string  `json:"due_date"`
	Ransomware     bool     `json:"ransomware"`
}

type signalDTO struct {
	Kind       string         `json:"kind"`
	Source     string         `json:"source"`
	SourceName string         `json:"source_name"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	Qualifies  bool           `json:"qualifies"`
	URL        *string        `json:"url"`
	Detail     map[string]any `json:"detail" nullable:"true"`
}

type rangeDTO struct {
	Origin        string   `json:"origin"`
	Counts        bool     `json:"counts"`
	Part          string   `json:"part"`
	Vendor        string   `json:"vendor"`
	Product       string   `json:"product"`
	CPE           string   `json:"cpe"`
	StartIncl     string   `json:"start_including"`
	StartExcl     string   `json:"start_excluding"`
	EndIncl       string   `json:"end_including"`
	EndExcl       string   `json:"end_excluding"`
	Fixed         string   `json:"fixed"`
	VersionType   string   `json:"version_type"`
	DefaultStatus string   `json:"default_status"`
	Platforms     []string `json:"platforms"`
	Versions      string   `json:"versions"`
	Train         string   `json:"train"`
	FixedRelease  string   `json:"fixed_release"`
}

type fixDTO struct {
	Vendor  string `json:"vendor"`
	Product string `json:"product"`
	Origin  string `json:"origin"`
	Train   string `json:"train"`
	Release string `json:"release"`
}

type referenceDTO struct {
	URL    string   `json:"url"`
	Tags   []string `json:"tags"`
	Source string   `json:"source"`
	Group  string   `json:"group"`
}

type ssvcDTO struct {
	Exploitation    *string `json:"exploitation"`
	Automatable     *string `json:"automatable"`
	TechnicalImpact *string `json:"technical_impact"`
}

type epssDTO struct {
	Score      float64      `json:"score"`
	Percentile float64      `json:"percentile"`
	Day        *string      `json:"day"`
	WeekAgo    *float64     `json:"week_ago"`
	History    []epssDayDTO `json:"history"`
}

type epssDayDTO struct {
	Day   string  `json:"day"`
	Score float64 `json:"score"`
}

// orNull is s, nil when empty.
func orNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// httpOrNull is an http(s) address, nil for anything else: a page only ever links to one.
func httpOrNull(u string) *string {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil
	}
	return &u
}

// dayOf is the UTC day of t, nil for nil.
func dayOf(t *time.Time) *string {
	if t == nil {
		return nil
	}
	d := t.UTC().Format(time.DateOnly)
	return &d
}

// flatDetail keeps the plain values of a signal's detail (strings, numbers, true/false): the detail is a small object for display,
// and a nested value has no place in the answer.
func flatDetail(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		switch v.(type) {
		case string, float64, bool:
			out[k] = v
		}
	}
	return out
}

func toBriefDTO(b Brief) briefDTO {
	out := briefDTO{CVE: b.CVE, Title: orNull(b.Title), Description: b.Description, Display: orNull(b.Display), Products: b.Products,
		Published: dayOf(b.Published), Modified: dayOf(b.Modified), NVDStatus: orNull(b.NVDStatus), NVDCheckedAt: b.NVDAt, RecordReadAt: b.RecordAt,
		CWE: []weaknessDTO{}, Scores: []scoreDTO{}, Lists: []listDTO{}, Signals: []signalDTO{}, Ranges: []rangeDTO{}, Fixes: []fixDTO{}, RangesFrom: orNull(b.RangesFrom),
		RangesComplete: b.RangesComplete, References: []referenceDTO{}, Solution: orNull(b.Solution), Workaround: orNull(b.Workaround),
		SSVC:   ssvcDTO{Exploitation: orNull(b.SSVC.Exploitation), Automatable: orNull(b.SSVC.Automatable), TechnicalImpact: orNull(b.SSVC.Impact)},
		NVDURL: b.NVDURL, RecordURL: b.RecordURL}
	for _, w := range b.CWE {
		out.CWE = append(out.CWE, weaknessDTO{ID: w.ID, Name: orNull(w.Name)})
	}
	for _, m := range b.Scores {
		out.Scores = append(out.Scores, scoreDTO(m))
	}
	if c := b.CVSS; c != nil {
		out.CVSS = &cvssDTO{scoreDTO: scoreDTO{Source: c.Source, Version: c.Version, Score: c.Score, Vector: c.Vector}, Severity: strings.ToLower(c.Severity)}
		if r := c.Reading; r != nil {
			out.CVSS.Reading = &readingDTO{AttackVector: r.AttackVector, AttackComplexity: r.AttackComplexity, AttackRequirements: orNull(r.AttackRequirements),
				PrivilegesRequired: r.PrivilegesRequired, UserInteraction: orNull(r.UserInteraction), Scope: orNull(r.Scope),
				impactDTO: impactDTO{r.Confidentiality, r.Integrity, r.Availability}, Summary: r.Summary}
			if s := r.Subsequent; s != nil {
				out.CVSS.Reading.Subsequent = &impactDTO{s.Confidentiality, s.Integrity, s.Availability}
			}
		}
	}
	for _, l := range b.Lists {
		out.Lists = append(out.Lists, listDTO{List: l.List, Source: l.Source, SourceName: l.SourceName, Vendor: l.Vendor, Product: l.Product, Display: l.Display,
			Name: l.Name, Description: l.Description, RequiredAction: l.RequiredAction, Links: l.Links, DateAdded: l.DateAdded, DueDate: orNull(l.DueDate),
			Ransomware: l.Ransomware})
	}
	for _, g := range b.Signals {
		out.Signals = append(out.Signals, signalDTO{Kind: g.Kind, Source: g.Source, SourceName: g.SourceName, FirstSeen: g.FirstSeen, LastSeen: g.LastSeen,
			Qualifies: g.Qualifies, URL: httpOrNull(g.URL), Detail: flatDetail(g.Detail)})
	}
	for _, r := range b.Ranges {
		plats := r.Platforms
		if plats == nil {
			plats = []string{}
		}
		out.Ranges = append(out.Ranges, rangeDTO{Origin: r.Origin, Counts: r.Counts, Part: r.Part, Vendor: r.Vendor, Product: r.Product, CPE: r.CPE,
			StartIncl: r.StartIncl, StartExcl: r.StartExcl, EndIncl: r.EndIncl, EndExcl: r.EndExcl, Fixed: r.Fixed, VersionType: r.VersionType,
			DefaultStatus: r.DefaultStatus, Platforms: plats, Versions: r.Versions, Train: r.Train, FixedRelease: r.FixedRelease})
	}
	for _, f := range b.Fixes {
		out.Fixes = append(out.Fixes, fixDTO(f))
	}
	for _, r := range b.References {
		out.References = append(out.References, referenceDTO(r))
	}
	if e := b.EPSS; e != nil {
		out.EPSS = &epssDTO{Score: e.Score, Percentile: e.Percentile, Day: orNull(e.Day), WeekAgo: e.WeekAgo, History: []epssDayDTO{}}
		for _, d := range e.History {
			out.EPSS.History = append(out.EPSS.History, epssDayDTO(d))
		}
	}
	return out
}

// statedWorkaround is a record's workaround text, "" when all it says is that there is none ("None", "No workarounds known.", "There is
// no known mitigation."): the page then says so in its own words instead of printing "None" as if it were the workaround.
func statedWorkaround(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if l := strings.TrimSpace(line); l != "" && !noneStated(l) {
			return text
		}
	}
	return ""
}

// noneStated says a short line only states that no workaround or mitigation exists: "None", or a sentence that starts with "No" or
// "There" and has no other words than those of saying so. "No workaround is needed when the service is off" says more, and is kept.
func noneStated(line string) bool {
	l := strings.ToLower(strings.TrimRight(strings.TrimSpace(line), ".!"))
	switch l {
	case "none", "n/a", "na", "not applicable", "nothing", "-":
		return true
	}
	words := strings.Fields(strings.NewReplacer(",", " ", ";", " ").Replace(l))
	if len(l) > 80 || len(words) < 2 || words[0] != "no" && words[0] != "there" {
		return false
	}
	said := false // the line names a workaround or a mitigation
	for _, w := range words {
		switch {
		case strings.HasPrefix(w, "workaround") || strings.HasPrefix(w, "mitigation"):
			said = true
		case !noneFiller[w]:
			return false
		}
	}
	return said
}

// noneFiller are the other words of a line that says no workaround exists ("There is no known mitigation available for this issue").
var noneFiller = map[string]bool{"no": true, "there": true, "is": true, "are": true, "known": true, "available": true, "currently": true, "exists": true,
	"exist": true, "for": true, "this": true, "these": true, "issue": true, "issues": true, "vulnerability": true, "solution": true,
	"at": true, "the": true, "time": true, "moment": true, "yet": true, "or": true, "and": true, "any": true, "solutions": true}
