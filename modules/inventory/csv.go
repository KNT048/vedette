package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ImportError is one rejected row, by row number (INV-13).
type ImportError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// ImportResult is POST /inventory/import.
type ImportResult struct {
	Created int           `json:"created"`
	Skipped int           `json:"skipped"`
	Errors  []ImportError `json:"errors"`
}

const bom = "\uFEFF"

// csvCell quotes a value for CSV; a leading = + - @ tab or CR gets a quote in front so a spreadsheet never
// runs it as a formula.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	if strings.ContainsAny(s, "\",\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// detectDelimiter guesses ; or tab from the header line (Excel in some locales writes those), else a comma.
func detectDelimiter(text string) byte {
	first := ""
	for _, l := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.TrimSpace(l) != "" {
			first = l
			break
		}
	}
	best := byte(',')
	for _, d := range []byte{';', '\t'} {
		if strings.Count(first, string(d)) > strings.Count(first, string(best)) {
			best = d
		}
	}
	return best
}

// parseCSV reads CSV text (RFC 4180 quoting, any of CRLF, LF, CR as a line end) into rows of cells. It never
// fails: it is fed by people and by Excel (SYS-6). Memory stays proportional to the input.
func parseCSV(text string) [][]string {
	delim := detectDelimiter(text)
	var rows [][]string
	var row []string
	var cell strings.Builder
	quoted := false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quoted:
			if c == '"' {
				if i+1 < len(text) && text[i+1] == '"' {
					cell.WriteByte('"')
					i++
				} else {
					quoted = false
				}
			} else {
				cell.WriteByte(c)
			}
		case c == '"':
			quoted = true
		case c == delim:
			row = append(row, cell.String())
			cell.Reset()
		case c == '\n' || c == '\r':
			if c == '\r' && i+1 < len(text) && text[i+1] == '\n' {
				i++
			}
			row = append(row, cell.String())
			rows = append(rows, row)
			row, cell = nil, strings.Builder{}
		default:
			cell.WriteByte(c)
		}
	}
	if cell.Len() > 0 || len(row) > 0 {
		row = append(row, cell.String())
		rows = append(rows, row)
	}
	return rows
}

// foldKey lower-cases, strips accents and turns every other character into "_": "IP Address" -> ip_address.
func foldKey(s string) string { return strings.ReplaceAll(fold(s), " ", "_") }

var headerAlias = map[string]string{
	"device": "name", "device_name": "name", "hostname": "name", "host_name": "name", "software": "product", "application": "product",
	"ip_address": "ip", "address": "ip", "product_name": "product", "ver": "version", "type": "kind", "device_type": "kind",
}

// The labels the interface shows for a type ("Wi-Fi (AP)", "Camera recorder") are accepted next to the keys.
var kindLabel = map[string]string{
	"wi_fi_ap": "ap", "wifi": "ap", "access_point": "ap", "camera_recorder": "nvr", "iot_device": "iot", "website": "web", "laptop": "pc", "computer": "pc", "desktop": "pc", "other": "unknown",
}

func parseKind(text string) string {
	k := foldKey(text)
	if validKind(k) {
		return k
	}
	return kindLabel[k]
}

// Import adds devices from CSV text (S-INV-2, INV-13): at most 200 KB and 500 rows; the header needs a name or
// product column; a bad row is reported by its number and the valid rows are still added.
func (s *Service) Import(ctx context.Context, actor, filename, text string) (ImportResult, error) {
	if strings.TrimSpace(text) == "" {
		return ImportResult{}, badRequest("empty_file", "The file is empty. Download the template, fill in your devices and choose it again.")
	}
	if len(text) > MaxImportBytes {
		return ImportResult{}, badRequest("too_large", fmt.Sprintf("The file is too large (max %d KB). Split it into smaller files.", MaxImportBytes/1000))
	}
	table := parseCSV(strings.TrimPrefix(text, bom))
	hi := 0
	for hi < len(table) && !anyText(table[hi]) {
		hi++
	}
	if hi == len(table) {
		return ImportResult{}, badRequest("bad_header", "The first row must be column headers with at least a name or product column. Download the template to see the format.")
	}
	header := make([]string, len(table[hi]))
	hasName, hasProduct := false, false
	for i, h := range table[hi] {
		k := foldKey(h)
		if a, ok := headerAlias[k]; ok {
			k = a
		}
		header[i] = k
		hasName = hasName || k == "name"
		hasProduct = hasProduct || k == "product"
	}
	if !hasName && !hasProduct {
		return ImportResult{}, badRequest("bad_header", "The first row must be column headers with at least a name or product column. Download the template to see the format.")
	}
	data := table[hi+1:]
	if len(data) > MaxImportRows {
		return ImportResult{}, badRequest("too_many_rows", fmt.Sprintf("At most %d rows per import. This file has %d rows.", MaxImportRows, len(data)))
	}
	cat, err := s.Catalog(ctx)
	if err != nil {
		return ImportResult{}, err
	}

	// Everything that costs CPU (parsing, the catalog search) happens here, before the write transaction: the
	// single writer must never wait on a hostile file (SYS-6).
	type row struct {
		line int
		err  string // "" = the row passed the checks that need no database
		a    addChecked
		kind string
	}
	rows := make([]row, 0, len(data))
	for i, cells := range data {
		if !anyText(cells) {
			continue
		}
		r := row{line: hi + i + 2}
		get := func(k string) string {
			for j, h := range header {
				if h == k && j < len(cells) {
					v := strings.TrimSpace(cells[j])
					// Excel switches formulas off with a leading quote (csvCell does the same on export): drop it again.
					if len(v) > 1 && v[0] == '\'' && strings.ContainsRune("=+-@", rune(v[1])) {
						v = v[1:]
					}
					return v
				}
			}
			return ""
		}
		r.err, r.a, r.kind = prepareRow(cat, get)
		rows = append(rows, r)
	}

	res := ImportResult{Errors: []ImportError{}}
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		res = ImportResult{Errors: []ImportError{}} // the transaction body must be safe to start from scratch
		noIPNames, err := namesWithoutIP(ctx, tx)
		if err != nil {
			return err
		}
		seenIPs, seenNames := map[string]bool{}, map[string]bool{}
		for _, r := range rows {
			rowErr := func(msg string) {
				res.Errors = append(res.Errors, ImportError{Line: r.line, Message: msg})
				res.Skipped++
			}
			if r.err != "" {
				rowErr(r.err)
				continue
			}
			a := r.a
			if a.ip != "" {
				if seenIPs[a.ip] {
					rowErr(fmt.Sprintf("IP %s appears twice in the file.", a.ip))
					continue
				}
				seenIPs[a.ip] = true
				if owner, err := ipOwner(ctx, tx, a.ip); err != nil {
					return err
				} else if owner != "" {
					rowErr(fmt.Sprintf("IP %s is already in the list (%s). Open that device instead of adding a new one.", a.ip, owner))
					continue
				}
			} else if a.name != "" {
				// Importing a file just exported: a device without an IP must not be doubled.
				key := strings.ToLower(a.name)
				if noIPNames[key] || seenNames[key] {
					rowErr(fmt.Sprintf(`A device named "%s" (no IP yet) is already in the list. Add an IP to this row if it is a different device.`, clip(a.name, 40)))
					continue
				}
				seenNames[key] = true
			}
			if _, err := s.createManual(ctx, tx, o, a, r.kind); err != nil {
				return err
			}
			res.Created++
		}
		name := "csv"
		if filename != "" {
			name = clip(filename, 80)
		}
		return s.auditTx(ctx, tx, actor, "inventory.import", name, fmt.Sprintf("%d devices, %d errors", res.Created, len(res.Errors)))
	})
	if err != nil {
		return ImportResult{}, err
	}
	return res, nil
}

// prepareRow runs the checks of one CSV row that need no database. It returns the message of the first problem,
// or the declaration to create. A product cell longer than a label (64 characters) is refused before the
// catalog is searched (INV-4 limit; the search costs time in proportion to the words).
func prepareRow(cat *Catalog, get func(string) string) (msg string, a addChecked, kind string) {
	productText := get("product")
	var entry *catEntry
	if productText != "" {
		if utf8.RuneCountInString(productText) > maxLabel {
			return fmt.Sprintf(`Product "%s…" is too long (at most %d characters). Use names as in the suggestion box when declaring by hand, for example FortiGate, Synology, WordPress.`, clip(productText, 40), maxLabel), a, ""
		}
		if entry = cat.find(productText); entry == nil {
			return fmt.Sprintf(`Product "%s" not recognised. Use names as in the suggestion box when declaring by hand, for example FortiGate, Synology, WordPress.`, clip(productText, 40)), a, ""
		}
	}
	if productText == "" && get("name") == "" {
		return "This row has neither name nor product. At least one is needed.", a, ""
	}
	if kindText := get("kind"); kindText != "" {
		if kind = parseKind(kindText); kind == "" {
			return fmt.Sprintf(`Type "%s" is not valid. Use one of: %s.`, clip(kindText, 20), strings.Join(Kinds, ", ")), a, ""
		}
	}
	a, aerr := checkAdd(cat, AddInput{Version: get("version"), Name: get("name"), IP: get("ip")}, false)
	if aerr != nil {
		return aerr.Message, a, ""
	}
	a.entry = entry
	return "", a, kind
}

func anyText(cells []string) bool {
	for _, c := range cells {
		if strings.TrimSpace(c) != "" {
			return true
		}
	}
	return false
}

func namesWithoutIP(ctx context.Context, q querier) (map[string]bool, error) {
	rows, err := q.QueryContext(ctx, `SELECT lower(hostname) FROM inv_asset WHERE ip IS NULL AND hostname IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read names: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("inventory: read names: %w", err)
		}
		out[n] = true
	}
	return out, rows.Err()
}

// ipOwner returns the name of the device that has ip, or "".
func ipOwner(ctx context.Context, q querier, ip string) (string, error) {
	var n string
	err := q.QueryRowContext(ctx, `SELECT coalesce(hostname, id) FROM inv_asset WHERE ip = ?`, ip).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inventory: check IP: %w", err)
	}
	return n, nil
}

// ExportCSV writes the device list as CSV, UTF-8 with a BOM so Excel opens it right (INV-13). Values that
// start like a formula are defused (csvCell).
func (s *Service) ExportCSV(ctx context.Context, actor string) (io.Reader, error) {
	items, err := s.loadDevices(ctx, s.db.Reader(), "", 0)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(bom)
	b.WriteString("name,ip,mac,kind,vendor,model,os,software,approved,fragile,origin,source,confidence,last_seen\r\n")
	now := s.now()
	for i := range items {
		d := &items[i]
		if d.IsBox {
			d.LastSeen = now
		}
		sum := summaryOf(d)
		var sw []string
		for _, x := range d.Software {
			t := x.Display
			if x.Version != nil {
				t += " " + *x.Version
			}
			sw = append(sw, t)
		}
		ip := ""
		if d.IP != noIP {
			ip = d.IP
		}
		src, conf := "", ""
		if sum != nil {
			src, conf = sum.Source, strconv.FormatFloat(sum.Confidence, 'f', 2, 64)
		}
		cells := []string{deref(d.Hostname), ip, deref(d.MAC), d.Kind, obsValue(d.Vendor), obsValue(d.Model), obsValue(d.OS), strings.Join(sw, "; "), yesNo(d.Approved), yesNo(d.Fragile), d.Origin, src, conf, d.LastSeen}
		for j, c := range cells {
			if j > 0 {
				b.WriteByte(',')
			}
			b.WriteString(csvCell(c))
		}
		b.WriteString("\r\n")
	}
	if err := s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		return s.auditTx(ctx, tx, actor, "inventory.export", "devices.csv", fmt.Sprintf("%d rows", len(items)))
	}); err != nil {
		return nil, err
	}
	return strings.NewReader(b.String()), nil
}

// ImportTemplate is the sample file offered next to the import button.
func ImportTemplate() io.Reader {
	return strings.NewReader(bom + "name,ip,product,version,kind\r\nBranch firewall,192.168.30.1,FortiGate,7.2.5,firewall\r\nCompany website,,WordPress,6.5.2,web\r\n")
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func obsValue(o *Observed) string {
	if o == nil {
		return ""
	}
	return o.Value
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
