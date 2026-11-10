// Package logexport builds the file of GET /core/logs/export (S-CORE-6, D-48, core INV-13): the log
// categories of the box in one JSON or CSV download.
//
// Each module owns its log rows and registers a Source for its category (Registry.Register, called from
// cmd/vedette); core never reads another module's table. A Source writes JSON lines, one object per line,
// keeping the chain fields (id, ts, ..., prev_hash, hash) exactly as stored so a hash-chained category
// verifies offline. Build runs the sources into a temporary spool, removes every secret-looking field at
// any depth (Scrub; defence in depth on top of what each source leaves out), refuses what is over the size
// cap, and returns a reader over the finished file. The mock is the contract: web/src/features/core/logExport.ts.
package logexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Categories are the only log categories an export has (INV-13), in the order of the GUI.
var Categories = []string{"audit", "ai_activity", "response", "scan_probes", "alerts", "device_logs", "known_bad", "honeypot"}

// Valid reports whether id is one of the Categories.
func Valid(id string) bool {
	for _, c := range Categories {
		if c == id {
			return true
		}
	}
	return false
}

// Source writes the rows of one category between from and to, both inclusive, as JSON lines on w. A zero
// time is open on that side. Timestamps compare as store.FormatTS strings (UTC, milliseconds).
type Source func(ctx context.Context, from, to time.Time, w io.Writer) error

// Registry holds the sources of the categories.
type Registry struct {
	mu  sync.RWMutex
	src map[string]Source
}

// New returns an empty Registry.
func New() *Registry { return &Registry{src: map[string]Source{}} }

// Register adds the source of a category. An unknown category, a nil source or a second source for the same
// category is a programming error and panics at wiring time.
func (r *Registry) Register(category string, src Source) {
	if !Valid(category) {
		panic(fmt.Sprintf("logexport: %q is not a log category (INV-13: %s)", category, strings.Join(Categories, ", ")))
	}
	if src == nil {
		panic("logexport: nil source for " + category)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.src[category]; dup {
		panic("logexport: " + category + " is registered twice")
	}
	r.src[category] = src
}

func (r *Registry) source(category string) Source {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.src[category]
}

// Has reports whether a source is registered for the category.
func (r *Registry) Has(category string) bool { return r.source(category) != nil }

// ErrTooLarge is returned by Build when the scrubbed rows pass Request.MaxBytes.
var ErrTooLarge = errors.New("logexport: the export is larger than the cap")

// Format is the file format.
type Format string

// The two formats of the file.
const (
	JSON Format = "json"
	CSV  Format = "csv"
)

// ChainNote is the `verification` field of the JSON envelope (same text as the mock).
const ChainNote = "Hash-chained categories: hash = SHA-256(prev_hash + canonical JSON of the entry without hash, keys sorted). The first entry is the anchor."

// Request is one export. Categories are distinct valid ids in the order of the file.
type Request struct {
	Categories []string
	From, To   time.Time // inclusive, zero = open
	FromDay    string    // the dates as the caller wrote them (YYYY-MM-DD), for the envelope; "" = none
	ToDay      string
	Format     Format
	MaxBytes   int64     // cap on the scrubbed rows of all categories together
	ExportedAt time.Time // for the envelope
	Dir        string    // where the spool goes ("" = os.TempDir())
}

// Export is a finished file. Read it to the end, then Close it (that removes the spool).
type Export struct {
	Rows    int            // rows of all categories
	Counts  map[string]int // rows per category
	Missing []string       // requested categories that have no registered source
	r       io.Reader
	closers []func()
}

// Read implements io.Reader.
func (e *Export) Read(p []byte) (int, error) { return e.r.Read(p) }

// Close removes the spool. It is safe to call twice.
func (e *Export) Close() error {
	for _, c := range e.closers {
		c()
	}
	e.closers = nil
	return nil
}

// Build runs the sources of req.Categories into a spool and returns the file. The spool lives on disk, so a
// large log costs disk (up to MaxBytes), never memory beyond one row. ponytail: the spool is in os.TempDir;
// an install that mounts it as tmpfs pays the cap in RAM, so the cap is small (core sets 128 MiB); a spool
// dir in core_data is the upgrade.
func (r *Registry) Build(ctx context.Context, req Request) (*Export, error) {
	dir, err := os.MkdirTemp(req.Dir, "vedette-logs-*")
	if err != nil {
		return nil, fmt.Errorf("logexport: spool: %w", err)
	}
	e := &Export{Counts: map[string]int{}, Missing: []string{}}
	e.closers = append(e.closers, func() { _ = os.RemoveAll(dir) })
	ok := false
	defer func() {
		if !ok {
			_ = e.Close()
		}
	}()

	type spooled struct {
		id   string
		f    *os.File
		cols []string
	}
	var spools []spooled
	used := int64(0)
	for _, id := range req.Categories {
		src := r.source(id)
		if src == nil {
			e.Missing = append(e.Missing, id)
			continue
		}
		f, err := os.CreateTemp(dir, "cat-*")
		if err != nil {
			return nil, fmt.Errorf("logexport: spool: %w", err)
		}
		e.closers = append(e.closers, func() { _ = f.Close() })
		sink := &sink{f: f, bw: bufio.NewWriter(f), used: &used, max: req.MaxBytes}
		if err := src(ctx, req.From, req.To, sink); err != nil {
			if errors.Is(err, ErrTooLarge) {
				return nil, ErrTooLarge
			}
			return nil, fmt.Errorf("logexport: read %s: %w", id, err)
		}
		if err := sink.finish(); err != nil {
			return nil, err
		}
		e.Counts[id] = sink.rows
		e.Rows += sink.rows
		spools = append(spools, spooled{id, f, sink.cols})
	}

	byID := map[string]spooled{}
	for _, s := range spools {
		byID[s.id] = s
	}
	var parts []part
	switch req.Format {
	case CSV:
		for i, id := range req.Categories {
			s, has := byID[id]
			if i > 0 {
				parts = append(parts, litPart("\n"))
			}
			if !has {
				parts = append(parts, litPart("# "+id+" (no source)\n\n"))
				continue
			}
			parts = append(parts, litPart("# "+id+"\n"+strings.Join(csvCells(s.cols), ",")+"\n"))
			parts = append(parts, rowsPart(s.f, csvRow(s.cols)))
		}
	default:
		head := struct {
			Format       string   `json:"format"`
			ExportedAt   string   `json:"exported_at"`
			From         *string  `json:"from"`
			To           *string  `json:"to"`
			Verification string   `json:"verification"`
			Missing      []string `json:"missing"`
		}{"vedette-logs/1", req.ExportedAt.UTC().Format("2006-01-02T15:04:05.000Z"), optional(req.FromDay), optional(req.ToDay), ChainNote, e.Missing}
		hb, err := json.Marshal(head)
		if err != nil {
			return nil, err
		}
		parts = append(parts, litPart(string(hb[:len(hb)-1])+`,"categories":{`))
		for i, id := range req.Categories {
			sep := ","
			if i == 0 {
				sep = ""
			}
			idb, _ := json.Marshal(id)
			parts = append(parts, litPart(sep+string(idb)+":["))
			if s, has := byID[id]; has {
				parts = append(parts, rowsPart(s.f, jsonRow))
			}
			parts = append(parts, litPart("]"))
		}
		parts = append(parts, litPart("}}\n"))
	}
	e.r = &multi{parts: parts}
	ok = true
	return e, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---- the sink: one source's output, scrubbed and counted ----

// sink is the io.Writer a source writes JSON lines to. Each complete line is decoded, scrubbed and spooled.
type sink struct {
	f    *os.File
	bw   *bufio.Writer
	pend []byte
	used *int64 // bytes of all categories so far
	max  int64
	rows int
	cols []string // top-level keys in order of first appearance
	seen map[string]bool
}

func (s *sink) Write(p []byte) (int, error) {
	s.pend = append(s.pend, p...)
	for {
		i := bytes.IndexByte(s.pend, '\n')
		if i < 0 {
			break
		}
		if err := s.line(s.pend[:i]); err != nil {
			return 0, err
		}
		s.pend = s.pend[i+1:]
	}
	if s.max > 0 && int64(len(s.pend)) > s.max { // one endless line
		return 0, ErrTooLarge
	}
	return len(p), nil
}

func (s *sink) finish() error {
	if len(bytes.TrimSpace(s.pend)) > 0 {
		if err := s.line(s.pend); err != nil {
			return err
		}
	}
	s.pend = nil
	if err := s.bw.Flush(); err != nil {
		return fmt.Errorf("logexport: spool: %w", err)
	}
	_, err := s.f.Seek(0, io.SeekStart)
	return err
}

func (s *sink) line(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil
	}
	v, err := decodeLine(b)
	if err != nil {
		return err
	}
	o, isObj := v.(*object)
	if !isObj {
		return errors.New("logexport: a source line is not a JSON object")
	}
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	for _, k := range o.keys {
		if !s.seen[k] {
			s.seen[k] = true
			s.cols = append(s.cols, k)
		}
	}
	var out bytes.Buffer
	writeValue(&out, o)
	out.WriteByte('\n')
	*s.used += int64(out.Len())
	if s.max > 0 && *s.used > s.max {
		return ErrTooLarge
	}
	if _, err := s.bw.Write(out.Bytes()); err != nil {
		return fmt.Errorf("logexport: spool: %w", err)
	}
	s.rows++
	return nil
}

// ---- scrubbing, with the key order of the source kept ----

// secretKey is the mock's SECRET_KEY (logExport.ts), same words. key_last4 and tokens_in do not match.
var secretKey = regexp.MustCompile(`(?i)^(password|passwd|secret|token|api_?key|key|private_?key|passphrase|credential|credentials|webhook|webhook_url|authorization)$|(_secret|_password|_token|_api_key|_webhook(_url)?|_credential)$`)

// IsSecretKey reports whether a field name is dropped from an export.
func IsSecretKey(k string) bool { return secretKey.MatchString(k) }

type object struct {
	keys []string
	vals []any
}

const maxDepth = 64

func decodeLine(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, fmt.Errorf("logexport: a source line is not valid JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("logexport: a source line has more than one JSON value")
	}
	return v, nil
}

// decodeValue reads one value; an object comes back without its secret-looking fields, at any depth.
func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("nested too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // string, json.Number, bool or nil
	}
	if d == '[' {
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token() // ]
		return arr, err
	}
	o := &object{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := kt.(string)
		v, err := decodeValue(dec, depth+1)
		if err != nil {
			return nil, err
		}
		if IsSecretKey(k) {
			continue
		}
		o.keys = append(o.keys, k)
		o.vals = append(o.vals, v)
	}
	_, err = dec.Token() // }
	return o, err
}

func writeString(b *bytes.Buffer, s string) {
	var t bytes.Buffer
	enc := json.NewEncoder(&t)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a Go string always encodes
	b.Write(bytes.TrimRight(t.Bytes(), "\n"))
}

func writeValue(b *bytes.Buffer, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		fmt.Fprint(b, x)
	case json.Number:
		b.WriteString(x.String())
	case string:
		writeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeValue(b, e)
		}
		b.WriteByte(']')
	case *object:
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			writeValue(b, x.vals[i])
		}
		b.WriteByte('}')
	}
}

// Scrub returns raw JSON without its secret-looking fields at any depth; the order of the other keys is kept.
func Scrub(raw []byte) ([]byte, error) {
	v, err := decodeLine(bytes.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	writeValue(&b, v)
	return b.Bytes(), nil
}

// ---- the output: literal text and spooled rows, read in turn ----

type part struct {
	lit  string
	f    *os.File
	line func(b *bytes.Buffer, row []byte, first bool) error
	br   *bufio.Reader
	n    int
}

func litPart(s string) part { return part{lit: s} }

func rowsPart(f *os.File, line func(*bytes.Buffer, []byte, bool) error) part {
	return part{f: f, line: line}
}

func jsonRow(b *bytes.Buffer, row []byte, first bool) error {
	if !first {
		b.WriteString(",\n")
	}
	b.Write(row)
	return nil
}

// multi reads its parts one after the other, one row at a time.
type multi struct {
	parts []part
	i     int
	buf   bytes.Buffer
}

func (m *multi) Read(p []byte) (int, error) {
	for m.buf.Len() == 0 {
		if m.i >= len(m.parts) {
			return 0, io.EOF
		}
		cur := &m.parts[m.i]
		if cur.f == nil {
			m.buf.WriteString(cur.lit)
			m.i++
			continue
		}
		if cur.br == nil {
			if _, err := cur.f.Seek(0, io.SeekStart); err != nil {
				return 0, err
			}
			cur.br = bufio.NewReader(cur.f)
		}
		row, err := cur.br.ReadBytes('\n')
		if len(row) > 0 {
			if lerr := cur.line(&m.buf, bytes.TrimRight(row, "\n"), cur.n == 0); lerr != nil {
				return 0, lerr
			}
			cur.n++
		}
		if err == io.EOF {
			m.i++
			continue
		}
		if err != nil {
			return 0, err
		}
	}
	return m.buf.Read(p)
}

// ---- CSV, the same shape as toCsv of the mock ----

// csvCell quotes a field like the mock's cell(), and defuses a spreadsheet formula (a text that starts with
// = + - @ tab or CR gets a leading apostrophe, as /core/audit/export does): logs hold text an attacker chose.
func csvCell(s string, formulaSafe bool) string {
	if formulaSafe && s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	if strings.ContainsAny(s, "\",\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

func csvCells(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = csvCell(c, false)
	}
	return out
}

func csvRow(cols []string) func(*bytes.Buffer, []byte, bool) error {
	return func(b *bytes.Buffer, row []byte, _ bool) error {
		v, err := decodeLine(row)
		if err != nil {
			return err
		}
		o, _ := v.(*object)
		cells := make([]string, len(cols))
		for i, c := range cols {
			for j, k := range o.keys {
				if k == c {
					cells[i] = cellText(o.vals[j])
					break
				}
			}
		}
		b.WriteString(strings.Join(cells, ","))
		b.WriteByte('\n')
		return nil
	}
}

// cellText is the mock's cell(): null is empty, an object or array is compact JSON, text is quoted when needed.
func cellText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return csvCell(x, true)
	case json.Number:
		return x.String()
	case bool:
		return fmt.Sprint(x)
	default:
		var b bytes.Buffer
		writeValue(&b, x)
		return csvCell(b.String(), false)
	}
}
