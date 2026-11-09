package feeds

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// cell is one raw value before field rules: unset is null; reject marks a row
// that cannot be read at all (the reason is shown to the user).
type cell struct {
	s      string
	set    bool
	reject string
}

// rawRow is one extracted record, keyed by record field id. A row-level reject
// stops the row before any field is built.
type rawRow struct {
	reject string
	cells  map[string]cell
}

// ---------- JSON

func extractJSON(text string, p Parser, ids []string) ([]rawRow, error) {
	root, err := decodeJSON(text)
	if err != nil {
		if errors.Is(err, errJSONDepth) {
			return nil, fail(ErrBadSample, "The sample is nested too deeply.")
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
		r := rawRow{cells: map[string]cell{}}
		for _, fp := range paths {
			var first *jnode
			if m := evalPath(n, fp.toks); len(m) > 0 {
				first = m[0]
			}
			r.cells[fp.id] = scalar(first)
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// ---------- CSV (RFC 4180 quotes, CRLF, # comment lines)

// parseCSV mirrors parsers.ts parseCsv. It stops once MaxRows+2 rows exist.
func parseCSV(text string, delim rune) [][]string {
	var rows [][]string
	var row []string
	var cur strings.Builder
	inQuote := false
	push := func() {
		row = append(row, cur.String())
		cur.Reset()
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
				cur.WriteRune(c)
			}
		case c == '"' && cur.Len() == 0:
			inQuote = true
		case c == delim:
			push()
		case c == '\n' || c == '\r':
			if c == '\r' && i < len(text) && text[i] == '\n' {
				i++
			}
			push()
			if (len(row) != 1 || row[0] != "") && !strings.HasPrefix(row[0], "#") {
				rows = append(rows, row)
			}
			row = nil
		default:
			cur.WriteRune(c)
		}
		if len(rows) > MaxRows+1 {
			break
		}
	}
	if cur.Len() > 0 || len(row) > 0 {
		push()
		if !strings.HasPrefix(row[0], "#") {
			rows = append(rows, row)
		}
	}
	return rows
}

func extractCSV(text string, p Parser, ids []string, delim rune) []rawRow {
	rows := parseCSV(text, delim)
	var header []string
	if p.HasHeader && len(rows) > 0 {
		for _, h := range rows[0] {
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
	for _, cells := range rows {
		r := rawRow{cells: map[string]cell{}}
		for _, c := range cols {
			if c.idx >= 0 && c.idx < len(cells) {
				r.cells[c.id] = cell{s: cells[c.idx], set: true}
			} else {
				r.cells[c.id] = cell{}
			}
		}
		out = append(out, r)
	}
	return out
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

func extractLines(text string) []rawRow {
	var out []rawRow
	for rest := text; rest != "" && len(out) <= MaxRows; {
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		line = jsTrim(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first := line
		if i := strings.IndexFunc(line, jsIsSpace); i >= 0 {
			first = line[:i]
		}
		out = append(out, rawRow{cells: map[string]cell{"indicator": {s: first, set: true}}})
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
		return nil, fail(ErrBadSample, "The sample is not valid JSON.")
	}
	objs, _ := root.get("objects")
	if objs == nil || objs.k != jArr {
		return nil, fail(ErrBadSample, `No "objects" array: expected a STIX 2.1 bundle or a TAXII 2.1 envelope.`)
	}
	var out []rawRow
	for _, o := range objs.arr {
		if len(out) > MaxRows {
			break
		}
		if t, _ := o.get("type"); o.k != jObj || t == nil || t.k != jStr || t.s != "indicator" {
			continue
		}
		base := map[string]cell{"confidence": {}, "first_seen": {}}
		if c, ok := o.get("confidence"); ok {
			base["confidence"] = cell{s: jsString(c), set: true}
		}
		if v, ok := o.get("valid_from"); ok && v.k == jStr {
			base["first_seen"] = cell{s: v.s, set: true}
		}
		withBase := func(extra map[string]cell) map[string]cell {
			m := map[string]cell{}
			for k, v := range base {
				m[k] = v
			}
			for k, v := range extra {
				m[k] = v
			}
			return m
		}
		rejectRow := func(why string) {
			out = append(out, rawRow{reject: why, cells: withBase(nil)})
		}
		pat, _ := o.get("pattern")
		if pat == nil || pat.k != jStr || jsLen(pat.s) > 2000 {
			rejectRow("indicator has no usable pattern")
			continue
		}
		matches := stixCompareRE.FindAllStringSubmatch(pat.s, -1)
		for _, m := range matches {
			kind, known := stixObj[m[1]]
			if !known || (m[1] == "file" && !hashesRE.MatchString(m[2])) {
				rejectRow("unsupported pattern object \"" + m[1] + ":" + m[2] + "\"")
				continue
			}
			val := stixUnescape.ReplaceAllString(m[3], "$1")
			out = append(out, rawRow{cells: withBase(map[string]cell{"indicator": {s: val, set: true}, "kind": {s: kind, set: true}})})
		}
		if len(matches) == 0 {
			rejectRow("pattern has no comparison this parser understands")
		}
	}
	if len(out) > MaxRows+1 {
		out = out[:MaxRows+1]
	}
	return out, nil
}

// ---------- RSS 2.0 / Atom

const (
	maxXMLDepth    = 100
	maxXMLElements = 500_000
)

type xnode struct {
	local    string
	attrs    []xml.Attr
	children []*xnode // elements, and text nodes (local == "")
	text     string   // text nodes only
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
				b.WriteString(c.text)
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
	return nil, errors.New("unsupported encoding " + strconv.Quote(jsSlice(label, 20)))
}

// parseXML builds a bounded element tree. Go's decoder never expands DTD
// entities (an undefined entity is an error), and a DTD that declares any is
// refused outright.
func parseXML(text string) (*xnode, error) {
	dec := xml.NewDecoder(strings.NewReader(text))
	dec.CharsetReader = charsetReader
	var root *xnode
	var stack []*xnode
	count := 0
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
			count++
			if count > maxXMLElements || len(stack) >= maxXMLDepth {
				return nil, errors.New("xml too large or too deeply nested")
			}
			n := &xnode{local: e.Name.Local, attrs: e.Attr}
			if len(stack) == 0 {
				if root != nil {
					return nil, errors.New("more than one root element")
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 && len(e) > 0 {
				p := stack[len(stack)-1]
				p.children = append(p.children, &xnode{text: string(e)})
			}
		case xml.Directive:
			if bytes.Contains(bytes.ToUpper(e), []byte("<!ENTITY")) {
				return nil, errors.New("DTD entities are not allowed")
			}
		}
	}
	if root == nil {
		return nil, errors.New("no root element")
	}
	return root, nil
}

func collectItems(n *xnode, out *[]*xnode) {
	if n.local == "item" || n.local == "entry" {
		*out = append(*out, n)
	}
	for _, c := range n.children {
		collectItems(c, out)
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
	root, err := parseXML(text)
	if err != nil {
		return nil, fail(ErrBadSample, "The sample is not valid XML.")
	}
	var items []*xnode
	collectItems(root, &items)
	if len(items) > MaxRows+1 {
		items = items[:MaxRows+1]
	}
	out := make([]rawRow, 0, len(items))
	for _, it := range items {
		r := rawRow{cells: map[string]cell{}}
		for _, id := range ids {
			if src := jsTrim(p.Fields[id].Source); src != "" {
				r.cells[id] = rssGet(it, src)
			}
		}
		out = append(out, r)
	}
	return out, nil
}
