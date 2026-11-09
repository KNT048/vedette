package feeds

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Reason counts rejected rows with the same cause (quoted values masked).
type Reason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Reject is one rejected row (row numbers start at 1, after header and comments).
type Reject struct {
	Row    int    `json:"row"`
	Reason string `json:"reason"`
}

// Stats is the accounting shared by every parser (INV-3).
type Stats struct {
	Accepted  int      `json:"accepted"`
	Rejected  int      `json:"rejected"`
	Reasons   []Reason `json:"reasons"`
	Rejects   []Reject `json:"rejects"` // the first MaxRejects
	Truncated bool     `json:"truncated"`
}

// Record is a normalised row: values are string, float64 (confidence) or nil.
type Record map[string]any

// Result is the outcome of ParseFeed. Records holds every accepted record (up
// to MaxRows); Preview gives the shape the SPA shows.
type Result struct {
	Records []Record `json:"records"`
	Stats
}

// Preview returns a copy limited to the first PreviewRows records (parse-test).
func (r Result) Preview() Result {
	if len(r.Records) > PreviewRows {
		r.Records = r.Records[:PreviewRows]
	}
	return r
}

var quotedRE = regexp.MustCompile(`"[^"]*"`)

// tally accumulates accepted/rejected counts the same way for every parser.
type tally struct {
	Stats
	counts map[string]int
	order  []string
}

func newTally() *tally {
	return &tally{Stats: Stats{Reasons: []Reason{}, Rejects: []Reject{}}, counts: map[string]int{}}
}

func (t *tally) reject(row int, reason string) {
	t.Rejected++
	key := quotedRE.ReplaceAllString(reason, `"…"`)
	if _, seen := t.counts[key]; !seen {
		t.order = append(t.order, key)
	}
	t.counts[key]++
	if len(t.Rejects) < MaxRejects {
		t.Rejects = append(t.Rejects, Reject{Row: row, Reason: reason})
	}
}

func (t *tally) stats() Stats {
	s := t.Stats
	s.Reasons = make([]Reason, 0, len(t.order))
	for _, k := range t.order {
		s.Reasons = append(s.Reasons, Reason{k, t.counts[k]})
	}
	sort.SliceStable(s.Reasons, func(i, j int) bool { return s.Reasons[i].Count > s.Reasons[j].Count })
	return s
}

// plan is a validated parser: regexes compiled once, delimiter resolved.
type plan struct {
	kind   Kind
	p      Parser
	delim  rune
	res    map[string]*regexp.Regexp
	active []string // field ids that have a source mapped
}

func (pl *plan) field(id string) (FieldMap, bool) {
	f, ok := pl.p.Fields[id]
	return f, ok
}

// CheckParser validates the rules before a run (parsers.ts checkParser) so a
// bad configuration is a clear error: format fits the kind, only known fields,
// JSONPaths compile, regexes compile (RE2 syntax, at most 200 chars), the
// delimiter is one ordinary character, and the required field is mapped.
func CheckParser(kind Kind, p Parser) error {
	_, err := compilePlan(kind, p)
	return err
}

func compilePlan(kind Kind, p Parser) (*plan, error) {
	if err := CheckKindFormat(kind, p.Format); err != nil {
		var fe *Error
		if errors.As(err, &fe) {
			return nil, fail(ErrBadConfig, "%s", fe.Detail)
		}
		return nil, fail(ErrBadConfig, "The format does not fit the feed kind.")
	}
	pl := &plan{kind: kind, p: p, delim: ',', res: map[string]*regexp.Regexp{}}
	if p.Format == FormatCSV && p.Delimiter != "" {
		d, w := utf8.DecodeRuneInString(p.Delimiter)
		if d == utf8.RuneError || w != len(p.Delimiter) || d == '"' || d == '\n' || d == '\r' {
			return nil, fail(ErrBadConfig, "The delimiter must be one character other than a quote or a line break.")
		}
		pl.delim = d
	}
	if p.Format == FormatJSON {
		path := p.RecordsPath
		if jsTrim(path) == "" {
			path = "$[*]"
		}
		if _, err := compilePath(path); err != nil {
			return nil, err
		}
	}
	known := map[string]bool{}
	for _, f := range fieldSpecs(kind) {
		known[f.id] = true
	}
	for id := range p.Fields {
		if !known[id] {
			return nil, fail(ErrBadConfig, "Unknown field %q.", jsSlice(id, 40))
		}
	}
	for _, spec := range fieldSpecs(kind) {
		f, ok := p.Fields[spec.id]
		if !ok {
			continue
		}
		if f.DateFormat != "" && f.DateFormat != DateAuto && f.DateFormat != DateDMY && f.DateFormat != DateMDY && f.DateFormat != DateEpoch {
			return nil, fail(ErrBadConfig, "Unknown date format for %s.", spec.id)
		}
		src := jsTrim(f.Source)
		if len(src) > MaxPathLen {
			return nil, fail(ErrBadConfig, "The source of %s is longer than %d characters.", spec.id, MaxPathLen)
		}
		if src != "" {
			pl.active = append(pl.active, spec.id)
			if p.Format == FormatJSON {
				if _, err := compilePath(src); err != nil {
					return nil, err
				}
			}
		}
		if f.Regex != "" {
			re, err := regexp.Compile(f.Regex)
			if err != nil || len(f.Regex) > MaxRegexLen {
				return nil, fail(ErrBadConfig, "Invalid regular expression for %s.", spec.id)
			}
			pl.res[spec.id] = re
		}
	}
	if p.Format == FormatJSON || p.Format == FormatCSV || p.Format == FormatRSS {
		need := fieldSpecs(kind)[0]
		if jsTrim(p.Fields[need.id].Source) == "" {
			return nil, fail(ErrBadConfig, "Map the required field %q.", need.id)
		}
	}
	return pl, nil
}

// ParseFeed parses untrusted feed data with a custom parser, fail-closed (INV-2, INV-3):
// input over MaxBodyBytes is ErrTooLarge; rows over MaxRows set Truncated; an
// invalid row is rejected and counted, never half-accepted. Configuration
// problems are ErrBadConfig, undecodable data is ErrBadSample.
func ParseFeed(data []byte, kind Kind, p Parser) (Result, error) {
	if len(data) > MaxBodyBytes {
		return Result{}, fail(ErrTooLarge, "The sample is larger than %d MB; Vedette would skip it.", MaxBodyBytes/1_000_000)
	}
	pl, err := compilePlan(kind, p)
	if err != nil {
		return Result{}, err
	}
	text := cleanText(data)
	var raws []rawRow
	switch p.Format {
	case FormatJSON:
		raws, err = extractJSON(text, p, pl.active)
	case FormatCSV:
		raws = extractCSV(text, p, pl.active, pl.delim)
	case FormatRSS:
		raws, err = extractRSS(text, p, pl.active)
	case FormatSTIX:
		raws, err = extractSTIX(text)
	default:
		raws = extractLines(text)
	}
	if err != nil {
		return Result{}, err
	}
	res := Result{Records: []Record{}}
	t := newTally()
	t.Truncated = len(raws) > MaxRows
	if len(raws) > MaxRows {
		raws = raws[:MaxRows]
	}
	for i, raw := range raws {
		rec, why := pl.build(raw)
		if why != "" {
			t.reject(i+1, why)
			continue
		}
		t.Accepted++
		res.Records = append(res.Records, rec)
	}
	res.Stats = t.stats()
	return res, nil
}

// applyField runs one field's rules: regex, trim, lowercase, date. A nil value
// is "no value"; reject is non-empty when the row must be refused.
func (pl *plan) applyField(id string, c cell, isDate bool) (val any, reject string) {
	if c.reject != "" {
		return nil, id + ": " + c.reject
	}
	if !c.set {
		return nil, ""
	}
	f, has := pl.field(id)
	v := c.s
	if re := pl.res[id]; re != nil {
		loc := re.FindStringSubmatchIndex(v)
		if loc == nil {
			return nil, id + ": regex did not match"
		}
		if len(loc) >= 4 && loc[2] >= 0 {
			v = v[loc[2]:loc[3]]
		} else {
			v = v[loc[0]:loc[1]]
		}
	}
	if !has || f.Trim {
		v = jsTrim(v)
	}
	if has && f.Lowercase {
		v = strings.ToLower(v)
	}
	if v == "" {
		return nil, ""
	}
	if hasControl(v) {
		return nil, id + ": contains control characters"
	}
	if isDate {
		df := DateAuto
		if has && f.DateFormat != "" {
			df = f.DateFormat
		}
		d, ok := normDate(v, df)
		if !ok {
			return nil, id + `: unrecognised date "` + jsSlice(v, 30) + `"`
		}
		return d, ""
	}
	return v, ""
}

func (pl *plan) build(raw rawRow) (Record, string) {
	if raw.reject != "" {
		return nil, raw.reject
	}
	out := Record{}
	for _, spec := range fieldSpecs(pl.kind) {
		v, why := pl.applyField(spec.id, raw.cells[spec.id], spec.date)
		if why != "" {
			return nil, why
		}
		if v == nil && spec.required {
			return nil, spec.id + ": missing"
		}
		out[spec.id] = v
	}
	if pl.kind == KindVulnerabilities {
		return buildVuln(out)
	}
	return buildIOC(out)
}

func buildVuln(out Record) (Record, string) {
	cve := strings.ToUpper(out["cve"].(string))
	if !cveRE.MatchString(cve) {
		return nil, `cve: "` + jsSlice(cve, 30) + `" is not a CVE ID`
	}
	out["cve"] = cve
	if l, ok := out["link"].(string); ok && !validLink(l) {
		return nil, "link: not an http(s) address"
	}
	if d, ok := out["description"].(string); ok {
		out["description"] = jsSlice(d, 500)
	}
	return out, ""
}

func buildIOC(out Record) (Record, string) {
	ind := out["indicator"].(string)
	var given string
	hasKind := false
	if k, ok := out["kind"].(string); ok {
		a, known := kindAlias[strings.ToLower(k)]
		if !known {
			return nil, `kind: unknown value "` + jsSlice(k, 20) + `"`
		}
		given, hasKind = a, true
	}
	value := ind
	if hasKind && given == "ip" && ipPortRE.MatchString(ind) {
		value = portTailRE.ReplaceAllString(ind, "")
	}
	kind := given
	if !hasKind {
		kind = detectKind(value)
	}
	ok := false
	switch kind {
	case "ip":
		value, ok = canonicalIP(value)
	case "domain":
		ok = validDomain(value)
		value = strings.ToLower(value)
	case "url":
		ok = validIndicatorURL(value)
	case "hash":
		ok = hashRE.MatchString(value)
		value = strings.ToLower(value)
	}
	if kind == "" || !ok {
		what := kind
		if what == "" {
			what = "indicator"
		}
		return nil, `indicator: "` + jsSlice(ind, 40) + `" is not a valid ` + what
	}
	out["indicator"], out["kind"] = value, kind
	if cs, ok := out["confidence"].(string); ok {
		c, ok := jsNumber(cs)
		if !ok || c < 0 || c > 100 {
			return nil, `confidence: "` + jsSlice(cs, 20) + `" is not a number from 0 to 100`
		}
		if c > 1 {
			c /= 100
		}
		out["confidence"] = math.Floor(c*100+0.5) / 100
	}
	return out, ""
}
