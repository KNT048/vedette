package feeds

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

// Reason counts rejected rows with the same cause (quoted values masked). Example is the first of those rows with
// its value shown (quoteVal), for the status line of a pull (note, accepted; D-229 (3)); it is not part of the API.
type Reason struct {
	Reason  string `json:"reason"`
	Count   int    `json:"count"`
	Example string `json:"-"`
}

// Reject is one rejected row. Row is the line of the input for a plain list
// (comments and blank lines counted); for the other formats the record number
// (from 1, after header and comments). Reason shows the value (quoteVal); only
// parse-test returns Rejects over the API; a pull keeps the masked Reasons (INV-3).
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

// maxReasons bounds the distinct reasons kept; the rest are counted as "other".
const maxReasons = 50

// tally accumulates accepted/rejected counts the same way for every parser.
// Reasons are grouped by message template (the static text, with the echoed
// values left out), so a hostile value can neither split nor flood the groups.
type tally struct {
	Stats
	counts   map[string]int
	examples map[string]string // the first row of each reason, value shown
	order    []string
	other    int
}

func newTally() *tally {
	return &tally{Stats: Stats{Reasons: []Reason{}, Rejects: []Reject{}}, counts: map[string]int{}, examples: map[string]string{}}
}

func fill(tmpl string, vals []string, show func(string) string) string {
	args := make([]any, len(vals))
	for i, v := range vals {
		args[i] = show(v)
	}
	return fmt.Sprintf(tmpl, args...)
}

// reject records a rejected row. tmpl is a static message with one %s per
// value in vals; values are shown quoted (Go escapes) and truncated.
func (t *tally) reject(row int, tmpl string, vals ...string) {
	t.Rejected++
	key := fill(tmpl, vals, func(string) string { return "\"…\"" })
	if _, seen := t.counts[key]; seen {
		t.counts[key]++
	} else if len(t.order) < maxReasons {
		t.order = append(t.order, key)
		t.counts[key] = 1
		t.examples[key] = fill(tmpl, vals, quoteVal)
	} else {
		t.other++
	}
	if len(t.Rejects) < MaxRejects {
		t.Rejects = append(t.Rejects, Reject{Row: row, Reason: fill(tmpl, vals, quoteVal)})
	}
}

func (t *tally) rejectR(row int, r rej) { t.reject(row, r.tmpl, r.vals...) }

func (t *tally) stats() Stats {
	s := t.Stats
	s.Reasons = make([]Reason, 0, len(t.order)+1)
	for _, k := range t.order {
		s.Reasons = append(s.Reasons, Reason{Reason: k, Count: t.counts[k], Example: t.examples[k]})
	}
	sort.SliceStable(s.Reasons, func(i, j int) bool { return s.Reasons[i].Count > s.Reasons[j].Count })
	if t.other > 0 {
		s.Reasons = append(s.Reasons, Reason{Reason: "other", Count: t.other})
	}
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
			return nil, fail(ErrBadConfig, "Unknown field %s.", quoteVal(id))
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
			re, why := compileRegex(f.Regex)
			if why != "" {
				return nil, fail(ErrBadConfig, "%s for %s.", why, spec.id)
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

// ctxCheckEvery is how many rows are built between context checks.
const ctxCheckEvery = 8

// maxRegexCell is the longest cell a customer regex is run on; a longer one
// rejects the row. RE2 is linear, but cell size times program size times rows
// must stay small.
const maxRegexCell = 4096

// ParseFeed parses untrusted feed data with a custom parser, fail-closed (INV-2, INV-3):
// input over MaxBodyBytes is ErrTooLarge; rows over MaxRows set Truncated; an
// invalid row is rejected and counted, never half-accepted. Configuration
// problems are ErrBadConfig, undecodable data is ErrBadSample. ctx is checked
// every few rows; on cancellation nothing is returned (ctx.Err()).
func ParseFeed(ctx context.Context, data []byte, kind Kind, p Parser) (Result, error) {
	return parseWith(ctx, data, kind, p, MaxRows)
}

// ParseSource parses the data of a built-in source with the source's own row limit.
func ParseSource(ctx context.Context, src Source, data []byte) (Result, error) {
	if src.Decoder != DecoderParser || src.Parser == nil {
		return Result{}, fail(ErrBadConfig, "%s has a dedicated parser.", src.Name)
	}
	return parseWith(ctx, data, src.Kind, *src.Parser, src.rowLimit())
}

func parseWith(ctx context.Context, data []byte, kind Kind, p Parser, maxRows int) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
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
		raws, err = extractCSV(text, p, pl.active, pl.delim)
	case FormatRSS:
		raws, err = extractRSS(text, p, pl.active)
	case FormatSTIX:
		raws, err = extractSTIX(text)
	default:
		raws = extractLines(text, maxRows)
	}
	if err != nil {
		return Result{}, err
	}
	res := Result{Records: []Record{}}
	t := newTally()
	t.Truncated = len(raws) > maxRows
	if len(raws) > maxRows {
		raws = raws[:maxRows]
	}
	for i, raw := range raws {
		if i%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
		}
		rec, why := pl.build(raw)
		if !why.none() {
			row := i + 1
			if raw.line > 0 {
				row = raw.line
			}
			t.rejectR(row, why)
			continue
		}
		t.Accepted++
		res.Records = append(res.Records, rec)
	}
	res.Stats = t.stats()
	return res, nil
}

func prefixed(id string, r rej) rej { return rej{id + ": " + r.tmpl, r.vals} }

// applyField runs one field's rules: regex, trim, lowercase, date. A nil value
// is "no value"; the rejection is set when the row must be refused. Identifiers
// refuse control and format characters; free-text fields (spec.free) have the
// format characters and C1 controls stripped instead.
func (pl *plan) applyField(spec fieldSpec, c cell) (val any, why rej) {
	id := spec.id
	if c.reject != nil {
		return nil, prefixed(id, *c.reject)
	}
	if !c.set {
		return nil, rej{}
	}
	f, has := pl.field(id)
	v := c.s
	if re := pl.res[id]; re != nil {
		if len(v) > maxRegexCell {
			return nil, rj(id + ": value is longer than 4096 bytes")
		}
		loc := re.FindStringSubmatchIndex(v)
		if loc == nil {
			return nil, rj(id + ": regex did not match")
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
	if spec.free {
		v = stripFormat(v)
	}
	if v == "" {
		return nil, rej{}
	}
	if (spec.free && hasControl(v)) || (!spec.free && hasControlStrict(v)) {
		return nil, rj(id + ": contains control or invisible characters")
	}
	if spec.date {
		df := DateAuto
		if has && f.DateFormat != "" {
			df = f.DateFormat
		}
		d, ok := normDate(v, df)
		if !ok {
			return nil, rj(id+": unrecognised date %s", v)
		}
		return d, rej{}
	}
	return v, rej{}
}

func (pl *plan) build(raw rawRow) (Record, rej) {
	if raw.reject != nil {
		return nil, *raw.reject
	}
	out := Record{}
	for _, spec := range fieldSpecs(pl.kind) {
		v, why := pl.applyField(spec, raw.get(spec.id))
		if !why.none() {
			return nil, why
		}
		if v == nil && spec.required {
			return nil, rj(spec.id + ": missing")
		}
		out[spec.id] = v
	}
	if pl.kind == KindVulnerabilities {
		return buildVuln(out)
	}
	return buildIOC(out)
}

func buildVuln(out Record) (Record, rej) {
	cve := strings.ToUpper(out["cve"].(string))
	if !cveRE.MatchString(cve) {
		return nil, rj("cve: %s is not a CVE ID", cve)
	}
	out["cve"] = cve
	if l, ok := out["link"].(string); ok && !validLink(l) {
		return nil, rj("link: not an http(s) address")
	}
	if d, ok := out["description"].(string); ok {
		out["description"] = jsSlice(d, 500)
	}
	return out, rej{}
}

func buildIOC(out Record) (Record, rej) {
	ind := out["indicator"].(string)
	var given string
	hasKind := false
	if k, ok := out["kind"].(string); ok {
		a, known := kindAlias[strings.ToLower(k)]
		if !known {
			return nil, rj("kind: unknown value %s", k)
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
	if kind == "" {
		return nil, rj("indicator: %s is not a valid indicator", ind)
	}
	value, why := normaliseIOC(kind, value)
	if !why.none() {
		return nil, rej{"indicator: " + why.tmpl, append([]string{ind}, why.vals...)}
	}
	out["indicator"], out["kind"] = value, kind
	if cs, ok := out["confidence"].(string); ok {
		c, ok := jsNumber(cs)
		if !ok || c < 0 || c > 100 {
			return nil, rj("confidence: %s is not a number from 0 to 100", cs)
		}
		if c > 1 {
			c /= 100
		}
		out["confidence"] = math.Floor(c*100+0.5) / 100
	}
	return out, rej{}
}

// maxRegexProg bounds the compiled RE2 program of a customer regex.
const maxRegexProg = 1000

func compileRegex(expr string) (*regexp.Regexp, string) {
	if len(expr) > MaxRegexLen {
		return nil, "Invalid regular expression (longer than 200 characters)"
	}
	tree, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil, "Invalid regular expression"
	}
	prog, err := syntax.Compile(tree.Simplify())
	if err != nil || len(prog.Inst) > maxRegexProg {
		return nil, "Invalid regular expression (too complex)"
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, "Invalid regular expression"
	}
	return re, ""
}
