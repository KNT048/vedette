package feeds

// Kind is what a feed carries.
type Kind string

// Kinds of feed.
const (
	KindVulnerabilities Kind = "vulnerabilities"
	KindIOC             Kind = "ioc"
)

// Format is how a custom feed is encoded (D-37).
type Format string

// Formats of a custom feed.
const (
	FormatJSON  Format = "json"
	FormatCSV   Format = "csv"
	FormatRSS   Format = "rss"
	FormatSTIX  Format = "stix"
	FormatLines Format = "lines"
)

// DateFormat tells the date normaliser how to read a date field.
type DateFormat string

// Date formats of a date field.
const (
	DateAuto  DateFormat = "auto"
	DateDMY   DateFormat = "dmy"
	DateMDY   DateFormat = "mdy"
	DateEpoch DateFormat = "epoch"
)

// Limits (INV-2).
const (
	MaxBodyBytes = 5_000_000 // bigger input is ErrTooLarge (413 too_large)
	MaxRows      = 50_000    // more rows stops parsing and sets Truncated
	PreviewRows  = 20        // records kept by Result.Preview
	MaxRejects   = 20        // rejected rows listed individually
	MaxRegexLen  = 200
	MaxPathLen   = 200
	MaxURLLen    = 500
	MaxNameLen   = 60
)

// FieldMap is the per-field rule of a custom parser. JSON tags match api/openapi.json.
type FieldMap struct {
	Source     string     `json:"source"`
	Regex      string     `json:"regex"`
	Trim       bool       `json:"trim"`
	Lowercase  bool       `json:"lowercase"`
	DateFormat DateFormat `json:"date_format"`
}

// Parser is the stored parsing rule set of a feed (feeds_source.parser).
type Parser struct {
	Format      Format              `json:"format"`
	RecordsPath string              `json:"records_path"`
	Delimiter   string              `json:"delimiter"`
	HasHeader   bool                `json:"has_header"`
	Fields      map[string]FieldMap `json:"fields"`
}

type fieldSpec struct {
	id       string
	required bool
	date     bool
	free     bool // free text: invisible characters are stripped, not rejected
}

var vulnFields = []fieldSpec{
	{"cve", true, false, false}, {"vendor", false, false, false}, {"product", false, false, false},
	{"date", false, true, false}, {"description", false, false, true}, {"link", false, false, false},
}

var iocFields = []fieldSpec{
	{"indicator", true, false, false}, {"kind", false, false, false}, {"confidence", false, false, false}, {"first_seen", false, true, false},
}

func fieldSpecs(k Kind) []fieldSpec {
	if k == KindVulnerabilities {
		return vulnFields
	}
	return iocFields
}

// FieldIDs lists the record fields of a kind, in order.
func FieldIDs(k Kind) []string {
	var ids []string
	for _, f := range fieldSpecs(k) {
		ids = append(ids, f.id)
	}
	return ids
}

// FormatsFor is the INV-5 compatibility table.
func FormatsFor(k Kind) []Format {
	switch k {
	case KindVulnerabilities:
		return []Format{FormatJSON, FormatCSV, FormatRSS}
	case KindIOC:
		return []Format{FormatJSON, FormatCSV, FormatRSS, FormatSTIX, FormatLines}
	}
	return nil
}

// FormatAllowed reports whether a custom feed of this kind may use the format.
func FormatAllowed(k Kind, f Format) bool {
	for _, x := range FormatsFor(k) {
		if x == f {
			return true
		}
	}
	return false
}

func fm(source string) FieldMap {
	return FieldMap{Source: source, Trim: true, DateFormat: DateAuto}
}

// DefaultParser returns the starting rules for a kind and format; they match
// the built-in sample of that format (defaults.ts).
func DefaultParser(kind Kind, format Format) Parser {
	src := map[string]FieldMap{}
	records := ""
	switch {
	case kind == KindVulnerabilities && format == FormatJSON:
		records = "$.vulnerabilities[*]"
		src = map[string]FieldMap{"cve": fm("$.cveID"), "vendor": fm("$.vendorProject"), "product": fm("$.product"), "date": fm("$.dateAdded"), "description": fm("$.shortDescription"), "link": fm("$.notes")}
	case kind == KindVulnerabilities && format == FormatCSV:
		d := fm("published")
		d.DateFormat = DateDMY
		src = map[string]FieldMap{"cve": fm("cve"), "vendor": fm("vendor"), "product": fm("product"), "date": d, "description": fm("summary"), "link": fm("url")}
	case kind == KindVulnerabilities && format == FormatRSS:
		c := fm("title")
		c.Regex = `(CVE-\d{4}-\d{4,})`
		src = map[string]FieldMap{"cve": c, "product": fm("category"), "date": fm("pubDate"), "description": fm("description"), "link": fm("link")}
	case kind == KindIOC && format == FormatJSON:
		records = "$.data[*]"
		k := fm("$.type")
		k.Lowercase = true
		src = map[string]FieldMap{"indicator": fm("$.ioc"), "kind": k, "confidence": fm("$.score"), "first_seen": fm("$.first_seen")}
	case kind == KindIOC && format == FormatCSV:
		src = map[string]FieldMap{"indicator": fm("dst_ip"), "first_seen": fm("first_seen_utc")}
	case kind == KindIOC && format == FormatRSS:
		src = map[string]FieldMap{"indicator": fm("title"), "first_seen": fm("published")}
	}
	fields := map[string]FieldMap{}
	for _, f := range fieldSpecs(kind) {
		if m, ok := src[f.id]; ok {
			fields[f.id] = m
		} else {
			fields[f.id] = fm("")
		}
	}
	return Parser{Format: format, RecordsPath: records, Delimiter: ",", HasHeader: true, Fields: fields}
}
