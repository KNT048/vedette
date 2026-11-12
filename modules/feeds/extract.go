package feeds

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// rej is a rejection: a message template whose %s placeholders take
// feed-supplied values. The template is the grouping key of reasons[]; the
// values are quoted and truncated only when the message is shown.
type rej struct {
	tmpl string
	vals []string
}

func rj(tmpl string, vals ...string) rej { return rej{tmpl, vals} }

func (r rej) none() bool { return r.tmpl == "" }

// cell is one raw value before field rules: unset is null; reject marks a row
// that cannot be read at all (the reason is shown to the user).
type cell struct {
	s      string
	set    bool
	reject *rej
}

// rawRow is one extracted record, keyed by record field id. A row-level reject
// stops the row before any field is built. line is the 1-based line of the
// input it came from, set by the plain-list and CSV formats (0 = use the record number).
type rawRow struct {
	reject *rej
	cells  []idCell
	line   int
}

type idCell struct {
	id string
	c  cell
}

func (r *rawRow) put(id string, c cell) { r.cells = append(r.cells, idCell{id, c}) }

func (r rawRow) get(id string) cell {
	for _, x := range r.cells {
		if x.id == id {
			return x.c
		}
	}
	return cell{}
}

// ---------- JSON

func extractJSON(text string, p Parser, ids []string) ([]rawRow, error) {
	root, err := decodeJSON(text)
	if err != nil {
		switch {
		case errors.Is(err, errJSONDepth):
			return nil, fail(ErrBadSample, "The sample is nested too deeply.")
		case errors.Is(err, errJSONNodes):
			return nil, fail(ErrBadSample, "The sample has too many values.")
		}
		return nil, fail(ErrBadSample, "The sample is not valid JSON.")
	}
	recPath := p.RecordsPath
	if jsTrim(recPath) == "" {
		recPath = "$[*]"
	}
	rtoks, err := compilePath(recPath)
	if err != nil {
		return nil, err
	}
	type fieldPath struct {
		id   string
		toks []tok
	}
	var paths []fieldPath
	for _, id := range ids {
		if src := jsTrim(p.Fields[id].Source); src != "" {
			t, err := compilePath(src)
			if err != nil {
				return nil, err
			}
			paths = append(paths, fieldPath{id, t})
		}
	}
	nodes := evalPath(root, rtoks)
	if len(nodes) > MaxRows+1 {
		nodes = nodes[:MaxRows+1]
	}
	rows := make([]rawRow, 0, len(nodes))
	for _, n := range nodes {
		r := rawRow{}
		for _, fp := range paths {
			var first *jnode
			if m := evalPath(n, fp.toks); len(m) > 0 {
				first = m[0]
			}
			r.put(fp.id, scalar(first))
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// ---------- CSV (RFC 4180 quotes, CRLF, # comment lines)

// maxCSVFields bounds the fields kept per row; a row with more is rejected.
const maxCSVFields = 1000

// csvRow is one record; bad is a reason when the row cannot be used.
type csvRow struct {
	cells []string
	bad   string
	line  int // the 1-based line of the text where the record starts (a quoted field can span lines)
}

const (
	csvTooWide    = "row has more than 1000 fields"
	csvOpenQuote  = "a quote is opened on this row and never closed"
	csvHeaderNote = "The header row is not usable: "
)

// parseCSV mirrors parsers.ts parseCsv and stops once MaxRows+2 rows exist.
// A quote still open at the end of the text does not swallow the rows after
// it: that row is flagged and the text from its start is read again with
// quotes taken literally, so every physical row is accounted for.
func parseCSV(text string, delim rune) []csvRow {
	return parseCSVFrom(text, delim, true, 1)
}

// parseCSVFrom is parseCSV for a text whose first line is number line0 of the original (the re-read after an open quote).
func parseCSVFrom(text string, delim rune, quotes bool, line0 int) []csvRow {
	var rows []csvRow
	var cells []string
	var cur strings.Builder
	fields, rowStart := 0, 0
	line, rowLine, startLine := line0, line0, line0 // the current line, where this record began, where the text at rowStart began
	inQuote := false
	endField := func() {
		fields++
		if fields <= maxCSVFields {
			cells = append(cells, cur.String())
		}
		cur.Reset()
	}
	endRow := func() {
		endField()
		r := csvRow{cells: cells, line: rowLine}
		if fields > maxCSVFields {
			r.bad = csvTooWide
		}
		if (fields != 1 || cells[0] != "") && !strings.HasPrefix(cells[0], "#") {
			rows = append(rows, r)
		}
		cells, fields = nil, 0
	}
	for i := 0; i < len(text); {
		c, w := utf8.DecodeRuneInString(text[i:])
		i += w
		switch {
		case inQuote:
			if c == '"' {
				if i < len(text) && text[i] == '"' {
					cur.WriteByte('"')
					i++
				} else {
					inQuote = false
				}
			} else {
				if c == '\n' || (c == '\r' && (i >= len(text) || text[i] != '\n')) {
					line++
				}
				if fields < maxCSVFields {
					cur.WriteRune(c)
				}
			}
		case quotes && c == '"' && cur.Len() == 0:
			inQuote = true
		case c == delim:
			endField()
		case c == '\n' || c == '\r':
			if c == '\r' && i < len(text) && text[i] == '\n' {
				i++
			}
			endRow()
			rowStart = i
			line++
			rowLine, startLine = line, line
		default:
			if fields < maxCSVFields {
				cur.WriteRune(c)
			}
		}
		if len(rows) > MaxRows+1 {
			return rows
		}
	}
	if inQuote {
		rest := parseCSVFrom(text[rowStart:], delim, false, startLine)
		if len(rest) > 0 && rest[0].line == startLine { // not when the row that opened the quote was a comment
			rest[0].bad = csvOpenQuote
		}
		return append(rows, rest...)
	}
	if cur.Len() > 0 || fields > 0 || len(cells) > 0 {
		endRow()
	}
	return rows
}

func extractCSV(text string, p Parser, ids []string, delim rune) ([]rawRow, error) {
	rows := parseCSV(text, delim)
	var header []string
	if p.HasHeader && len(rows) > 0 {
		if rows[0].bad != "" {
			return nil, fail(ErrBadSample, "%s%s.", csvHeaderNote, rows[0].bad)
		}
		for _, h := range rows[0].cells {
			header = append(header, strings.ToLower(jsTrim(h)))
		}
		rows = rows[1:]
	}
	if len(rows) > MaxRows+1 {
		rows = rows[:MaxRows+1]
	}
	type col struct {
		id  string
		idx int
	}
	var cols []col
	for _, id := range ids {
		src := jsTrim(p.Fields[id].Source)
		if src == "" {
			continue
		}
		idx := -1
		for i, h := range header {
			if h == strings.ToLower(src) {
				idx = i
				break
			}
		}
		if idx < 0 && isDigits(src) {
			if n, err := strconv.Atoi(src); err == nil {
				idx = n - 1
			}
		}
		cols = append(cols, col{id, idx})
	}
	out := make([]rawRow, 0, len(rows))
	for _, row := range rows {
		r := rawRow{line: row.line}
		if row.bad != "" {
			bad := rj(row.bad)
			r.reject = &bad
			out = append(out, r)
			continue
		}
		for _, c := range cols {
			if c.idx >= 0 && c.idx < len(row.cells) {
				r.put(c.id, cell{s: row.cells[c.idx], set: true})
			} else {
				r.put(c.id, cell{})
			}
		}
		out = append(out, r)
	}
	return out, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------- lines

// nextLine splits at the first line ending: CRLF, CR or LF.
func nextLine(s string) (line, rest string) {
	i := strings.IndexAny(s, "\r\n")
	if i < 0 {
		return s, ""
	}
	if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
		return s[:i], s[i+2:]
	}
	return s[:i], s[i+1:]
}

// isHostsSink reports the addresses a hosts-file blocklist maps names to.
func isHostsSink(tok string) bool {
	a, err := netip.ParseAddr(tok)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsUnspecified() || a.IsLoopback()
}

// extractLines reads a list of indicators, one token per line (the first),
// comments with #. A hosts-file line ("0.0.0.0 evil.example.com [more names]")
// yields its names, never the sink address. Every row keeps its line number,
// comments and blank lines counted, so a rejection points at the line.
func extractLines(text string, maxRows int) []rawRow {
	var out []rawRow
	n := 0
	add := func(v string) {
		out = append(out, rawRow{cells: []idCell{{"indicator", cell{s: v, set: true}}}, line: n})
	}
	for rest := text; rest != "" && len(out) <= maxRows; {
		var line string
		line, rest = nextLine(rest)
		n++
		line = jsTrim(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.FieldsFunc(line, jsIsSpace)
		if len(fields) > 1 && isHostsSink(fields[0]) && !isDigits(fields[1]) && !strings.HasPrefix(fields[1], "#") {
			for _, name := range fields[1:] {
				if strings.HasPrefix(name, "#") {
					break
				}
				add(name)
			}
			continue
		}
		add(fields[0])
	}
	return out
}

// ---------- STIX 2.1 bundle or TAXII 2.1 envelope

var stixObj = map[string]string{"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url", "file": "hash"}

var (
	stixCompareRE = regexp.MustCompile(`([a-z0-9-]+):([A-Za-z0-9_.'-]+)\s*=\s*'((?:[^'\\]|\\.)*)'`)
	stixUnescape  = regexp.MustCompile(`\\(.)`)
	hashesRE      = regexp.MustCompile(`[Hh][Aa][Ss][Hh][Ee][Ss]`)
)

// extractSTIX returns one row per `object:path = 'value'` comparison inside an indicator pattern.
func extractSTIX(text string) ([]rawRow, error) {
	root, err := decodeJSON(text)
	if err != nil {
		if errors.Is(err, errJSONNodes) {
			return nil, fail(ErrBadSample, "The sample has too many values.")
		}
		return nil, fail(ErrBadSample, "The sample is not valid JSON.")
	}
	objs, _ := root.get("objects")
	if objs == nil || objs.k != jArr {
		return nil, fail(ErrBadSample, `No "objects" array: expected a STIX 2.1 bundle or a TAXII 2.1 envelope.`)
	}
	var out []rawRow
	for _, o := range objs.children() {
		if len(out) > MaxRows {
			break
		}
		if t, _ := o.get("type"); o.k != jObj || t == nil || t.k != jStr || t.s != "indicator" {
			continue
		}
		base := []idCell{{"confidence", cell{}}, {"first_seen", cell{}}}
		if c, ok := o.get("confidence"); ok {
			base[0].c = cell{s: jsString(c), set: true}
		}
		if v, ok := o.get("valid_from"); ok && v.k == jStr {
			base[1].c = cell{s: v.s, set: true}
		}
		withBase := func(extra ...idCell) []idCell {
			return append(append(make([]idCell, 0, len(base)+len(extra)), base...), extra...)
		}
		rejectRow := func(r rej) {
			out = append(out, rawRow{reject: &r, cells: withBase()})
		}
		pat, _ := o.get("pattern")
		if pat == nil || pat.k != jStr || jsLen(pat.s) > 2000 {
			rejectRow(rj("indicator has no usable pattern"))
			continue
		}
		matches := stixCompareRE.FindAllStringSubmatch(pat.s, -1)
		for _, m := range matches {
			kind, known := stixObj[m[1]]
			if !known || (m[1] == "file" && !hashesRE.MatchString(m[2])) {
				rejectRow(rj("unsupported pattern object %s", m[1]+":"+m[2]))
				continue
			}
			val := stixUnescape.ReplaceAllString(m[3], "$1")
			out = append(out, rawRow{cells: withBase(idCell{"indicator", cell{s: val, set: true}}, idCell{"kind", cell{s: kind, set: true}})})
		}
		if len(matches) == 0 {
			rejectRow(rj("pattern has no comparison this parser understands"))
		}
	}
	if len(out) > MaxRows+1 {
		out = out[:MaxRows+1]
	}
	return out, nil
}

// ---------- RSS 2.0 / Atom

const (
	maxXMLDepth = 100
	// maxXMLNodes bounds elements and text pieces together; maxXMLAttrs the attributes
	// (including xmlns declarations), which cost more each.
	maxXMLNodes = 500_000
	maxXMLAttrs = 100_000
	// maxXMLNamespaces bounds xmlns declarations: the decoder keeps a stack entry for each.
	maxXMLNamespaces = 200
)

// xnode is an element inside an item/entry, or a text node (local == "").
type xnode struct {
	local    string
	attrs    []xml.Attr
	children []*xnode
	tb       []byte // text nodes only; adjacent text pieces are merged
}

// maxTextContent caps what one field can read; a legitimate value is far smaller.
const maxTextContent = 16 << 10

// textContent is the DOM textContent of the element, truncated at maxTextContent bytes.
func (n *xnode) textContent() string {
	var b strings.Builder
	var walk func(x *xnode)
	walk = func(x *xnode) {
		for _, c := range x.children {
			if b.Len() >= maxTextContent {
				return
			}
			if c.local == "" {
				b.Write(c.tb)
			} else {
				walk(c)
			}
		}
	}
	walk(n)
	out := b.String()
	if len(out) > maxTextContent {
		out = strings.ToValidUTF8(out[:maxTextContent], "") // drop a cut rune
	}
	return out
}

func (n *xnode) attr(name string) (string, bool) {
	for _, a := range n.attrs {
		if a.Name.Space == "" && a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// latin1 lets Decoder read ISO-8859-1 feeds; other declared encodings are refused.
type latin1 struct{ r io.Reader }

func (l latin1) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)/2)
	if len(buf) == 0 {
		return 0, io.ErrShortBuffer
	}
	n, err := l.r.Read(buf)
	out := 0
	for _, b := range buf[:n] {
		out += utf8.EncodeRune(p[out:], rune(b))
	}
	return out, err
}

func charsetReader(label string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(label) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return in, nil
	case "iso-8859-1", "latin1", "latin-1":
		return latin1{in}, nil
	}
	return nil, errors.New("unsupported encoding " + quoteVal(label))
}

var errXMLBudget = errors.New("xml too large or too deeply nested")

// parseXML returns the outermost item/entry elements with their subtrees.
// Nothing outside an item is kept, and the whole document is bounded in depth
// and in the number of elements, attributes and text pieces. Go's decoder
// never expands DTD entities (an undefined entity is an error), and a DTD that
// declares any is refused outright. Parsing stops once more than MaxRows items
// were seen: the caller only needs to know the limit was crossed.
func parseXML(text string) ([]*xnode, error) {
	if tagTooLong(text) {
		return nil, errXMLBudget
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.CharsetReader = charsetReader
	var stack, items []*xnode
	outside, roots, budget, attrs, namespaces := 0, 0, 0, 0, 0
	for {
		t, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch e := t.(type) {
		case xml.StartElement:
			for _, a := range e.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					namespaces++
				}
			}
			budget++
			if namespaces > maxXMLNamespaces {
				return nil, errXMLBudget
			}
			if attrs += len(e.Attr); budget > maxXMLNodes || attrs > maxXMLAttrs || len(stack)+outside >= maxXMLDepth {
				return nil, errXMLBudget
			}
			if len(stack) == 0 {
				if outside == 0 {
					if roots++; roots > 1 {
						return nil, errors.New("more than one root element")
					}
				}
				if e.Name.Local != "item" && e.Name.Local != "entry" {
					outside++
					continue
				}
			}
			n := &xnode{local: e.Name.Local, attrs: e.Attr}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				outside--
				continue
			}
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				items = append(items, n)
				if len(items) > MaxRows {
					return items, nil
				}
			}
		case xml.CharData:
			if budget++; budget > maxXMLNodes {
				return nil, errXMLBudget
			}
			if len(stack) == 0 || len(e) == 0 {
				continue
			}
			p := stack[len(stack)-1]
			if k := len(p.children); k > 0 && p.children[k-1].local == "" {
				p.children[k-1].tb = append(p.children[k-1].tb, e...)
			} else {
				p.children = append(p.children, &xnode{tb: append([]byte(nil), e...)})
			}
		case xml.Directive:
			if bytes.Contains(bytes.ToUpper(e), []byte("<!ENTITY")) {
				return nil, errors.New("DTD entities are not allowed")
			}
		}
	}
	if roots == 0 {
		return nil, errors.New("no root element")
	}
	return items, nil
}

func collectItems(n *xnode, out *[]*xnode) {
	if n.local == "item" || n.local == "entry" {
		*out = append(*out, n)
	}
	for _, c := range n.children {
		if c.local != "" {
			collectItems(c, out)
		}
	}
}

var rssAlias = map[string][]string{
	"description": {"description", "summary", "content"},
	"pubdate":     {"pubDate", "published", "updated"},
	"published":   {"published", "pubDate", "updated"},
	"link":        {"link"},
	"id":          {"guid", "id"},
	"guid":        {"guid", "id"},
}

func rssGet(el *xnode, name string) cell {
	tags, ok := rssAlias[strings.ToLower(name)]
	if !ok {
		tags = []string{name}
	}
	for _, tag := range tags {
		var found *xnode
		for _, c := range el.children {
			if c.local != "" && strings.EqualFold(c.local, tag) {
				found = c
				break
			}
		}
		if found == nil {
			continue
		}
		if tag == "link" {
			if v, ok := found.attr("href"); ok {
				return cell{s: v, set: true}
			}
		}
		if tag == "category" {
			if v, ok := found.attr("term"); ok {
				return cell{s: v, set: true}
			}
		}
		return cell{s: found.textContent(), set: true}
	}
	return cell{}
}

func extractRSS(text string, p Parser, ids []string) ([]rawRow, error) {
	tops, err := parseXML(text)
	if err != nil {
		return nil, fail(ErrBadSample, "The sample is not valid XML.")
	}
	var items []*xnode
	for _, t := range tops {
		collectItems(t, &items)
	}
	if len(items) > MaxRows+1 {
		items = items[:MaxRows+1]
	}
	out := make([]rawRow, 0, len(items))
	for _, it := range items {
		r := rawRow{}
		for _, id := range ids {
			if src := jsTrim(p.Fields[id].Source); src != "" {
				r.put(id, rssGet(it, src))
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// maxXMLRun is the longest stretch of text without a closing angle bracket. The
// decoder reads every attribute of a start tag before it returns the tag, so a
// 5 MB tag full of attributes would be built in memory before any budget
// applies; this keeps any one tag small.
const maxXMLRun = 1 << 20

func tagTooLong(text string) bool {
	for len(text) > 0 {
		j := strings.IndexByte(text, '>')
		if j < 0 {
			return len(text) > maxXMLRun
		}
		if j > maxXMLRun {
			return true
		}
		text = text[j+1:]
	}
	return false
}
