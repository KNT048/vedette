package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/knt048/vedette/core/conn/read"
	"github.com/knt048/vedette/modules/ai/provider"
)

// The read tools of "Ask your data" (S-AI-5, INV-14, D-211): five of the box (search_assets, list_findings, get_finding, lookup_cve,
// lookup_ioc) and the read tools of the connections. All of them only read. Arguments are checked at the edge against a closed
// schema (unknown fields, wrong types, out-of-range numbers and malformed ids are refused before anything is read), the answer is
// capped in rows and bytes, and every text field is cleaned: the loop fences it and runs the hooks on it (ask_loop.go).

// toolOut is what a tool returns: the text the model reads, a short line for the person (never the data), the table the box builds
// from a list result and the source it cites.
type toolOut struct {
	Text    string
	Summary string
	Cite    string
	Table   *AskTable
}

// errBadArgs is an argument error the model is told about, so it can correct the call.
type errBadArgs struct{ msg string }

func (e errBadArgs) Error() string { return e.msg }

// errToolFailed is a failure of the read itself; msg is safe to show the model and the person.
type errToolFailed struct{ msg string }

func (e errToolFailed) Error() string { return e.msg }

// toolImpl is a tool the model may be offered with the code that runs it.
type toolImpl struct {
	Tool
	// parse checks the arguments at the edge; nil = one JSON object, whose names and types the code that runs the tool checks (the
	// reader of a connection against the tool's own schema).
	parse func(raw json.RawMessage) (map[string]any, error)
	// internal: the connection of a connection tool is inside the network (private, loopback, ULA or CGNAT address); false when that
	// could not be checked (D-212).
	internal bool
	run      func(ctx context.Context, args map[string]any) (toolOut, error)
}

// Limits of the result of one call (D-211, D-482). Every turn of a question sends the whole conversation again, so a result is paid for
// once per turn that follows it: the lists are summaries (counts over everything that matched, then the first rows) and small.
const (
	askResultBytes = 4 << 10  // what one call returns to the model
	askTotalBytes  = 12 << 10 // what all calls of one question return
	askRowsDefault = 10
	askRowsMax     = 50
	askMaxArgs     = 4 << 10 // the arguments of one call, encoded
	askTopDevices  = 8       // devices in the per-device counts of list_findings
)

// argSpec is one argument of a tool.
type argSpec struct {
	kind     string // "string", "int", "bool"
	re       *regexp.Regexp
	enum     []string
	min, max int // int bounds, or the length bound of a string (max)
}

var (
	cveArgRE   = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)
	idArgRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)
	kindArgRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	statusEnum = []string{"open", "any", "confirmed", "suspected", "mitigated", "patched", "false_positive", "not_relevant", "risk_accepted"}
	sevEnum    = []string{"critical", "high", "medium", "low", "info"}
)

// parseArgs reads the arguments of a call strictly: one JSON object, only the declared names, each of its type and within its bounds.
// What comes back holds string, int and bool values only.
func parseArgs(raw json.RawMessage, spec map[string]argSpec, required ...string) (map[string]any, error) {
	if len(raw) > askMaxArgs {
		return nil, errBadArgs{"the arguments are too long"}
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var in map[string]any
	if err := dec.Decode(&in); err != nil || in == nil || dec.More() {
		return nil, errBadArgs{"the arguments must be one JSON object"}
	}
	out := map[string]any{}
	for k, v := range in {
		sp, ok := spec[k]
		if !ok {
			return nil, errBadArgs{fmt.Sprintf("unknown argument %q", clipRunes(cleanText(k), 40))}
		}
		switch sp.kind {
		case "bool":
			b, ok := v.(bool)
			if !ok {
				return nil, errBadArgs{k + " must be true or false"}
			}
			out[k] = b
		case "int":
			n, ok := v.(json.Number)
			i, err := n.Int64()
			if !ok || err != nil || i < int64(sp.min) || i > int64(sp.max) {
				return nil, errBadArgs{fmt.Sprintf("%s must be a whole number from %d to %d", k, sp.min, sp.max)}
			}
			out[k] = int(i)
		default:
			s, ok := v.(string)
			if !ok {
				return nil, errBadArgs{k + " must be text"}
			}
			s = strings.TrimSpace(s)
			if sp.max > 0 && len([]rune(s)) > sp.max {
				return nil, errBadArgs{fmt.Sprintf("%s is longer than %d characters", k, sp.max)}
			}
			if cleanText(s) != s {
				return nil, errBadArgs{k + " has control characters"}
			}
			if len(sp.enum) > 0 && !containsStr(sp.enum, s) {
				return nil, errBadArgs{fmt.Sprintf("%s must be one of: %s", k, strings.Join(sp.enum, ", "))}
			}
			if sp.re != nil && !sp.re.MatchString(s) {
				return nil, errBadArgs{k + " is not in the expected form"}
			}
			out[k] = s
		}
	}
	for _, k := range required {
		if _, ok := out[k]; !ok {
			return nil, errBadArgs{k + " is required"}
		}
	}
	return out, nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func limitOf(m map[string]any) int {
	if n, ok := m["limit"].(int); ok {
		return n
	}
	return askRowsDefault
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// fit returns the JSON of build(rows, extra) with as many rows, and then as many extra entries (the per-device counts), as fit the
// byte cap. build puts the totals and the note first (a struct, whose fields keep their order), so they are never what gets cut, and a
// result whose totals alone are over the cap still starts with them (W1-27: a model read the first page as the whole and reported 39
// findings of 126).
func fit(rows, extra int, build func(rows, extra int) any) (string, int) {
	for {
		b, err := json.Marshal(build(rows, extra))
		if err == nil && len(b) <= askResultBytes {
			return string(b), rows
		}
		switch {
		case rows > 0:
			rows--
		case extra > 0:
			extra--
		default:
			return string(b), 0
		}
	}
}

func shownNote(what string, total, shown int) string {
	switch {
	case total == 0:
		return fmt.Sprintf("No %s match.", what)
	case shown >= total:
		return fmt.Sprintf("All %d matching %s are listed.", total, what)
	}
	return fmt.Sprintf("%d %s match and only the first %d are listed. The total and every count here cover all %d: say \"%d %s (showing %d)\", never the number of rows listed as the total. Ask with a filter to see others.",
		total, what, shown, total, total, what, shown)
}

// put sets m[k] only when v says something: empty text and empty lists are left out, which is most of what a device of a small
// network does not have.
func put(m map[string]any, k string, v any) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return
		}
	case []string:
		if len(x) == 0 {
			return
		}
	}
	m[k] = v
}

func clip(s string, n int) string { return cleanLine(s, n) }

// ---------- the tools of the box

const (
	searchAssetsDesc = "Search the devices in the inventory. All arguments are optional filters that are combined: free text (words must all appear in the name, IP, vendor, model, operating system, services or software), the device kind, an open TCP/UDP port, whether the device is approved, a word of the operating system. Returns how many devices match and the first limit of them (default 10) with vendor, model, operating system, open ports and software; detail=true adds when each was first and last seen, how it was added (found on the network or added by hand) and which source saw it."
	listFindingsDesc = "List findings: devices matched to an exploited vulnerability. Filters: status (open = confirmed or suspected, the default; any; or one status), severity, CVE id, asset_id of one device. Returns how many findings match, counts by severity, status and basis and per device (the devices with the most first), then the riskiest first limit findings (default 10). Use get_finding for the evidence of one."
	getFindingDesc   = "Get one finding by its id, with the scan evidence if a scan confirmed it."
	lookupCVEDesc    = "Look a CVE up on the exploited-vulnerabilities list this box holds, and list the devices of this network that it matches."
	lookupIOCDesc    = "Check whether an IP address or a domain name is listed by the threat feeds this box pulls."
)

const (
	searchAssetsSchema = `{"type":"object","properties":{"text":{"type":"string","maxLength":80},"kind":{"type":"string","maxLength":32},"port":{"type":"integer","minimum":1,"maximum":65535},"approved":{"type":"boolean"},"os_contains":{"type":"string","maxLength":40},"limit":{"type":"integer","minimum":1,"maximum":50},"detail":{"type":"boolean"}},"additionalProperties":false}`
	listFindingsSchema = `{"type":"object","properties":{"status":{"type":"string","enum":["open","any","confirmed","suspected","mitigated","patched","false_positive","not_relevant","risk_accepted"]},"severity":{"type":"string","enum":["critical","high","medium","low","info"]},"cve":{"type":"string","maxLength":24},"asset_id":{"type":"string","maxLength":96},"limit":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}`
	getFindingSchema   = `{"type":"object","properties":{"id":{"type":"string","maxLength":96}},"required":["id"],"additionalProperties":false}`
	lookupCVESchema    = `{"type":"object","properties":{"cve":{"type":"string","maxLength":24}},"required":["cve"],"additionalProperties":false}`
	lookupIOCSchema    = `{"type":"object","properties":{"kind":{"type":"string","enum":["ip","domain"]},"value":{"type":"string","maxLength":253}},"required":["kind","value"],"additionalProperties":false}`
)

var (
	searchAssetsArgs = map[string]argSpec{"text": {kind: "string", max: 80}, "kind": {kind: "string", re: kindArgRE, max: 32}, "port": {kind: "int", min: 1, max: 65535},
		"approved": {kind: "bool"}, "os_contains": {kind: "string", max: 40}, "limit": {kind: "int", min: 1, max: askRowsMax}, "detail": {kind: "bool"}}
	listFindingsArgs = map[string]argSpec{"status": {kind: "string", enum: statusEnum}, "severity": {kind: "string", enum: sevEnum}, "cve": {kind: "string", re: cveArgRE, max: 24},
		"asset_id": {kind: "string", re: idArgRE, max: 96}, "limit": {kind: "int", min: 1, max: askRowsMax}}
)

// productTool is a tool of the box for "Ask your data" and the jobs named; log investigation gets the four of D-223.
func productTool(name, desc, schema string, spec map[string]argSpec, required []string, run func(context.Context, map[string]any) (toolOut, error), jobs ...Job) toolImpl {
	return toolImpl{Tool: Tool{Name: name, Description: desc, Access: AccessRead, Enabled: true, Jobs: append([]Job{JobAskMyData}, jobs...), Schema: json.RawMessage(schema)},
		parse: func(raw json.RawMessage) (map[string]any, error) { return parseArgs(raw, spec, required...) }, run: run}
}

// productTools are the tools of the box. A tool whose data door is missing is not offered: the model is never told of a tool that
// would only fail.
func (s *Service) productTools() []toolImpl {
	var out []toolImpl
	if d := s.cfg.Data; d != nil {
		out = append(out,
			productTool("search_assets", searchAssetsDesc, searchAssetsSchema, searchAssetsArgs, nil, func(ctx context.Context, a map[string]any) (toolOut, error) { return toolSearchAssets(ctx, d, a) }, JobLogInvestigate),
			productTool("list_findings", listFindingsDesc, listFindingsSchema, listFindingsArgs, nil, func(ctx context.Context, a map[string]any) (toolOut, error) { return toolListFindings(ctx, d, a) }),
			productTool("get_finding", getFindingDesc, getFindingSchema, map[string]argSpec{"id": {kind: "string", re: idArgRE, max: 96}}, []string{"id"}, func(ctx context.Context, a map[string]any) (toolOut, error) { return toolGetFinding(ctx, d, a) }),
			productTool("lookup_ioc", lookupIOCDesc, lookupIOCSchema, map[string]argSpec{"kind": {kind: "string", enum: []string{"ip", "domain"}}, "value": {kind: "string", max: 253}}, []string{"kind", "value"}, func(ctx context.Context, a map[string]any) (toolOut, error) { return toolLookupIOC(ctx, d, a) }, JobLogInvestigate),
		)
	}
	if f := s.cfg.Facts; f != nil {
		out = append(out, productTool("lookup_cve", lookupCVEDesc, lookupCVESchema, map[string]argSpec{"cve": {kind: "string", re: cveArgRE, max: 24}}, []string{"cve"}, func(ctx context.Context, a map[string]any) (toolOut, error) { return toolLookupCVE(ctx, f, a) }, JobLogInvestigate))
	}
	if s.cfg.LogAround != nil {
		t := productTool("events_around", eventsAroundDesc, eventsAroundSchema, eventsAroundArgs, []string{"ip"}, s.toolEventsAround)
		t.Jobs = []Job{JobLogInvestigate}
		out = append(out, t)
	}
	return out
}

func readFailed(err error) error {
	var bad errBadArgs
	if errors.As(err, &bad) {
		return err
	}
	return errToolFailed{"the box could not read that data"}
}

func (a AssetRow) matches(f map[string]any) bool {
	hay := strings.ToLower(strings.Join(append(append([]string{a.Name, a.IP, a.Kind, a.Vendor, a.Model, a.OS}, a.Ports...), a.Software...), " "))
	if t := strings.ToLower(str(f, "text")); t != "" {
		for _, w := range strings.Fields(t) {
			if !strings.Contains(hay, w) {
				return false
			}
		}
	}
	if k := str(f, "kind"); k != "" && !strings.EqualFold(a.Kind, k) {
		return false
	}
	if o := strings.ToLower(str(f, "os_contains")); o != "" && !strings.Contains(strings.ToLower(a.OS), o) {
		return false
	}
	if ap, ok := f["approved"].(bool); ok && a.Approved != ap {
		return false
	}
	if p, ok := f["port"].(int); ok {
		found := false
		for _, port := range a.Ports {
			found = found || strings.HasPrefix(port, fmt.Sprintf("%d/", p))
		}
		if !found {
			return false
		}
	}
	return true
}

// boxApart counts devices with the Vedette box named apart (D-422): Devices says "Only the Vedette box so far" and Reports counts no
// device then, so "1 device" would read as a device of the network that the rest of the app does not show. "3 devices", "only the
// Vedette box", "2 devices and the Vedette box".
func boxApart(others int, box bool) string {
	switch {
	case !box:
		return plural(others, "device", "devices")
	case others == 0:
		return "only the Vedette box"
	}
	return plural(others, "device", "devices") + " and the Vedette box"
}

// countAssets splits rows into devices of the network and the box itself.
func countAssets(rows []AssetRow) (others int, box bool) {
	for _, a := range rows {
		if a.IsBox {
			box = true
		} else {
			others++
		}
	}
	return others, box
}

// inventoryCite says what search_assets looked through, the box named apart.
func inventoryCite(all []AssetRow) string {
	return "Inventory: " + boxApart(countAssets(all)) + " searched"
}

func toolSearchAssets(ctx context.Context, d Data, raw map[string]any) (toolOut, error) {
	all, err := d.Assets(ctx)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	var matched []AssetRow
	for _, a := range all {
		if a.matches(raw) {
			matched = append(matched, a)
		}
	}
	hit := matched
	if limit := limitOf(raw); len(hit) > limit {
		hit = hit[:limit]
	}
	detail, _ := raw["detail"].(bool)
	rows := make([]map[string]any, len(hit))
	for i, a := range hit {
		nPorts, nSw := 6, 4
		if detail {
			nPorts, nSw = 12, 8
		}
		r := map[string]any{"id": clip(a.ID, 96), "name": clip(a.Name, 80), "approved": a.Approved}
		put(r, "ip", clip(a.IP, 45))
		put(r, "kind", clip(a.Kind, 32))
		put(r, "vendor", clip(a.Vendor, 60))
		put(r, "model", clip(a.Model, 60))
		put(r, "os", clip(a.OS, 80))
		put(r, "ports", cleanAll(a.Ports[:min(len(a.Ports), nPorts)], 40))
		put(r, "software", cleanAll(a.Software[:min(len(a.Software), nSw)], 80))
		if detail {
			put(r, "first_seen", clip(a.FirstSeen, 32))
			put(r, "last_seen", clip(a.LastSeen, 32))
			put(r, "added", addedHow(a.Origin))
			put(r, "seen_by", clip(a.SeenBy, 32))
		}
		rows[i] = r
	}
	total := len(matched)
	text, shown := fit(len(rows), 0, func(n, _ int) any {
		return struct {
			MatchingDevices int              `json:"matching_devices"`
			Shown           int              `json:"shown"`
			Note            string           `json:"note"`
			Devices         []map[string]any `json:"devices"`
		}{total, n, shownNote("devices", total, n), rows[:n]}
	})
	t := &AskTable{Columns: []string{"Device", "IP", "Type", "Operating system"}, Rows: []AskRow{}}
	for _, a := range hit[:shown] {
		os := clip(a.OS, 80)
		if os == "" {
			os = "Unknown"
		}
		t.Rows = append(t.Rows, AskRow{Href: "/devices/" + clip(a.ID, 96), Cells: []string{clip(a.Name, 80), clip(a.IP, 45), clip(a.Kind, 32), os}})
	}
	out := toolOut{Text: text, Summary: boxApart(countAssets(matched)), Cite: inventoryCite(all)}
	if len(t.Rows) > 0 {
		out.Table = t
	}
	return out, nil
}

// addedHow says how a device came into the inventory, in words the model repeats as they are.
func addedHow(origin string) string {
	switch origin {
	case "manual":
		return "added by hand"
	case "discovered":
		return "found on the network"
	}
	return "unknown"
}

func cleanAll(in []string, n int) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, clip(s, n))
	}
	return out
}

func findingMap(f FindingRow) map[string]any {
	return map[string]any{"id": clip(f.ID, 96), "device": clip(f.Asset, 80), "device_ip": clip(f.AssetIP, 45), "asset_id": clip(f.AssetID, 96), "cve": clip(f.CVE, 24), "status": clip(f.Status, 20),
		"severity": clip(f.Severity, 12), "basis": clip(f.Basis, 12), "confidence": f.Confidence, "first_seen": clip(f.FirstSeen, 32), "last_seen": clip(f.LastSeen, 32)}
}

// riskRank orders findings riskiest first: confirmed, then suspected, then closed ones (status=any), then severity, then how the match was made (a scan, the version, the
// product name only), then confidence. Equal ones keep the box's order (newest first).
func riskRank(f FindingRow) [4]int {
	sev := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	basis := map[string]int{"scan": 0, "version": 1}
	s, ok := sev[f.Severity]
	if !ok {
		s = 4
	}
	b, ok := basis[f.Basis]
	if !ok {
		b = 2
	}
	st := map[string]int{"confirmed": 0, "suspected": 1}[f.Status] // open ones first: a closed critical one is not the risk now
	if f.Status != "confirmed" && f.Status != "suspected" {
		st = 2
	}
	return [4]int{st, s, b, -int(f.Confidence * 100)}
}

func lessRank(a, b [4]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func toolListFindings(ctx context.Context, d Data, raw map[string]any) (toolOut, error) {
	all, err := d.Findings(ctx)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	status := str(raw, "status")
	if status == "" {
		status = "open"
	}
	var hit []FindingRow
	for _, f := range all {
		switch {
		case status == "open" && f.Status != "confirmed" && f.Status != "suspected",
			status != "open" && status != "any" && f.Status != status,
			str(raw, "severity") != "" && f.Severity != str(raw, "severity"),
			str(raw, "cve") != "" && !strings.EqualFold(f.CVE, str(raw, "cve")),
			str(raw, "asset_id") != "" && f.AssetID != str(raw, "asset_id"):
			continue
		}
		hit = append(hit, f)
	}
	sort.SliceStable(hit, func(i, j int) bool { return lessRank(riskRank(hit[i]), riskRank(hit[j])) })
	total := len(hit)
	// the counts cover every match, so the model never has to count rows (and cannot mistake the first rows for the whole)
	count := func(key func(FindingRow) string) map[string]int {
		m := map[string]int{}
		for _, f := range hit {
			m[clip(key(f), 20)]++
		}
		return m
	}
	type dev struct {
		row           map[string]any
		n, crit, sure int
		first         int // position of its riskiest finding
	}
	devs := map[string]*dev{}
	var order []string
	for i, f := range hit {
		v, ok := devs[f.AssetID]
		if !ok {
			v = &dev{row: map[string]any{"asset_id": clip(f.AssetID, 96), "device": clip(f.Asset, 80)}, first: i}
			put(v.row, "ip", clip(f.AssetIP, 45))
			devs[f.AssetID] = v
			order = append(order, f.AssetID)
		}
		v.n++
		if f.Severity == "critical" {
			v.crit++
		}
		if f.Status == "confirmed" {
			v.sure++
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := devs[order[i]], devs[order[j]]
		if a.sure != b.sure {
			return a.sure > b.sure
		}
		if a.n != b.n {
			return a.n > b.n
		}
		return a.first < b.first
	})
	byDevice := []map[string]any{}
	for _, id := range order[:min(len(order), askTopDevices)] {
		v := devs[id]
		v.row["findings"], v.row["critical"], v.row["confirmed"] = v.n, v.crit, v.sure
		byDevice = append(byDevice, v.row)
	}
	bySev, byStatus, byBasis := count(func(f FindingRow) string { return f.Severity }), count(func(f FindingRow) string { return f.Status }), count(func(f FindingRow) string { return f.Basis })
	list := hit
	if limit := limitOf(raw); len(list) > limit {
		list = list[:limit]
	}
	rows := make([]map[string]any, len(list))
	for i, f := range list {
		r := map[string]any{"id": clip(f.ID, 96), "cve": clip(f.CVE, 24), "status": clip(f.Status, 20), "severity": clip(f.Severity, 12), "basis": clip(f.Basis, 12)}
		put(r, "device", clip(f.Asset, 80))
		rows[i] = r
	}
	text, shown := fit(len(rows), len(byDevice), func(n, k int) any {
		note := shownNote("findings", total, n)
		if k < len(order) {
			note += fmt.Sprintf(" by_device lists the top %d of %d devices by count.", k, len(order))
		}
		return struct {
			MatchingFindings    int              `json:"matching_findings"`
			Shown               int              `json:"shown"`
			Note                string           `json:"note"`
			DevicesWithFindings int              `json:"devices_with_findings"`
			BySeverity          map[string]int   `json:"by_severity"`
			ByStatus            map[string]int   `json:"by_status"`
			ByBasis             map[string]int   `json:"by_basis"`
			ByDevice            []map[string]any `json:"by_device"`
			Findings            []map[string]any `json:"findings"`
		}{total, n, note, len(order), bySev, byStatus, byBasis, byDevice[:k], rows[:n]}
	})
	t := &AskTable{Columns: []string{"Device", "CVE", "Status", "Severity"}, Rows: []AskRow{}}
	for _, f := range list[:shown] {
		t.Rows = append(t.Rows, AskRow{Href: "/findings/" + clip(f.ID, 96), Cells: []string{clip(f.Asset, 80), clip(f.CVE, 24), clip(f.Status, 20), clip(f.Severity, 12)}})
	}
	out := toolOut{Text: text, Summary: plural(total, "finding", "findings"), Cite: "Findings: " + plural(len(all), "record", "records") + " searched"}
	if len(t.Rows) > 0 {
		out.Table = t
	}
	return out, nil
}

func toolGetFinding(ctx context.Context, d Data, raw map[string]any) (toolOut, error) {
	f, ok, err := d.Finding(ctx, str(raw, "id"))
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	if !ok {
		return toolOut{Text: `{"found":false}`, Summary: "no such finding"}, nil
	}
	m := findingMap(f)
	m["found"] = true
	if f.Evidence != "" {
		m["evidence"] = clip(f.Evidence, 600)
	}
	b, _ := json.Marshal(m)
	return toolOut{Text: string(b), Summary: "1 finding", Cite: "Findings"}, nil
}

func toolLookupCVE(ctx context.Context, f Facts, raw map[string]any) (toolOut, error) {
	id := strings.ToUpper(str(raw, "cve"))
	facts, ok, err := f.CVE(ctx, id)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	if !ok {
		return toolOut{Text: `{"found":false,"note":"This CVE is not on the exploited list the box holds."}`, Summary: "not on the list"}, nil
	}
	assets, err := f.AffectedAssets(ctx, id)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	var links []string
	for _, l := range facts.Links {
		if (strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://")) && len(links) < 4 {
			links = append(links, clip(l, 300))
		}
	}
	devs := []map[string]any{}
	for _, a := range assets[:min(len(assets), 20)] {
		devs = append(devs, map[string]any{"name": clip(a.Name, 80), "ip": clip(a.IP, 45), "kind": clip(a.Kind, 32), "matched_by": clip(a.Basis, 12), "finding_status": clip(a.Status, 20)})
	}
	total := len(assets)
	text, _ := fit(len(devs), 0, func(n, _ int) any {
		return struct {
			Found                bool             `json:"found"`
			CVE                  string           `json:"cve"`
			MatchingDevicesTotal int              `json:"matching_devices_total"`
			Shown                int              `json:"shown"`
			Note                 string           `json:"note"`
			Vendor               string           `json:"vendor"`
			Product              string           `json:"product"`
			Name                 string           `json:"name"`
			Description          string           `json:"description"`
			RequiredAction       string           `json:"required_action"`
			DateAdded            string           `json:"date_added"`
			Ransomware           bool             `json:"ransomware"`
			Links                []string         `json:"links"`
			MatchingDevices      []map[string]any `json:"matching_devices"`
		}{true, clip(facts.CVE, 24), total, n, shownNote("devices", total, n), clip(facts.Vendor, 80), clip(facts.Product, 80), clip(facts.Name, 160),
			clip(facts.Description, 800), clip(facts.RequiredAction, 400), clip(facts.DateAdded, 20), facts.Ransomware, links, devs[:n]}
	})
	return toolOut{Text: text, Summary: "on the list, " + plural(len(assets), "device", "devices"), Cite: "Exploited list: " + id}, nil
}

func toolLookupIOC(ctx context.Context, d Data, raw map[string]any) (toolOut, error) {
	kind, value := str(raw, "kind"), str(raw, "value")
	switch kind {
	case "ip":
		a, err := netip.ParseAddr(value)
		if err != nil || a.Zone() != "" {
			return toolOut{}, errBadArgs{"value is not an IP address"}
		}
		value = a.Unmap().String()
	default:
		if !validDomain(value) {
			return toolOut{}, errBadArgs{"value is not a domain name"}
		}
	}
	r, ok, err := d.IOC(ctx, kind, value)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	if !ok || len(r.Sources) == 0 {
		return toolOut{Text: `{"listed":false}`, Summary: "not listed", Cite: "Threat feeds"}, nil
	}
	m := map[string]any{"listed": true, "kind": clip(r.Kind, 8), "value": clip(r.Value, 253), "first_seen": clip(r.FirstSeen, 32), "last_seen": clip(r.LastSeen, 32), "feeds": cleanAll(r.Sources, 80)}
	b, _ := json.Marshal(m)
	return toolOut{Text: string(b), Summary: "listed by " + plural(len(r.Sources), "feed", "feeds"), Cite: "Threat feeds"}, nil
}

// validDomain is a copy of the rule of modules/feeds (normalize.go validDomain; modules do not import each other), so the tool takes
// every name a feed can list, an IDN top-level domain in its ASCII form (`discord.xn--q9jyb4c`) among them: at most 253 bytes, two or
// more labels; every label but the last is 1 to 63 of a-z, A-Z, 0-9 and "-" with no "-" at either end, the last is 2 to 63 letters or
// "xn--" and letters, digits and "-" not ending in "-".
func validDomain(v string) bool {
	if len(v) > 253 {
		return false
	}
	labels := 0
	for len(v) > 0 {
		i := strings.IndexByte(v, '.')
		if i < 0 {
			if labels == 0 || len(v) < 2 || len(v) > 63 {
				return false
			}
			if len(v) > 4 && strings.EqualFold(v[:4], "xn--") {
				return v[len(v)-1] != '-' && strings.IndexFunc(v[4:], func(r rune) bool { return r != '-' && !isLetter(r) && (r < '0' || r > '9') }) < 0
			}
			return strings.IndexFunc(v, func(r rune) bool { return !isLetter(r) }) < 0
		}
		l := v[:i]
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for j := 0; j < len(l); j++ {
			if c := l[j]; c != '-' && !isLetter(rune(c)) && (c < '0' || c > '9') {
				return false
			}
		}
		labels++
		v = v[i+1:]
	}
	return false // empty, or a trailing dot
}

func isLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// ---------- the read tools of the connections (core/conn/read, D-127)

var nameCharsRE = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// connToolName is the name the model sees for a connection's tool: the connection id and the tool name, so two connections that
// offer a tool of the same name stay apart.
func connToolName(rt read.ReadTool) string {
	n := "conn_" + nameCharsRE.ReplaceAllString(rt.ConnectionID, "_") + "__" + nameCharsRE.ReplaceAllString(rt.Name, "_")
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

// schemaKeywords are the only keywords of a connection tool's schema the model is shown. A device or an MCP server writes the schema,
// and free text in it (description, title, examples, default, x-* extensions, a pattern) is the best place to hide an instruction
// (tool poisoning), so what is not on this list is dropped. enum values, types and bounds stay: they are what the call has to be. The
// reader (core/conn/read) also hands over only the part of the schema it enforces; this list does not depend on that.
var schemaKeywords = map[string]bool{"type": true, "properties": true, "required": true, "items": true, "enum": true, "minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true, "minLength": true, "maxLength": true, "minItems": true, "maxItems": true, "additionalProperties": true,
	"anyOf": true, "oneOf": true, "allOf": true}

func stripSchemaText(raw json.RawMessage) json.RawMessage {
	empty := json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return empty
	}
	var schema func(v any) any
	schema = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, e := range x {
				switch {
				case !schemaKeywords[k]:
				case k == "properties":
					props := map[string]any{}
					if m, ok := e.(map[string]any); ok {
						for name, sub := range m { // the names are arguments, not keywords
							props[name] = schema(sub)
						}
					}
					out[k] = props
				case k == "items" || k == "additionalProperties":
					out[k] = schema(e)
				case k == "anyOf" || k == "oneOf" || k == "allOf":
					if l, ok := e.([]any); ok {
						subs := make([]any, len(l))
						for i, sub := range l {
							subs[i] = schema(sub)
						}
						out[k] = subs
					}
				default:
					out[k] = e
				}
			}
			return out
		}
		return v // true/false of additionalProperties, a bare value
	}
	b, err := json.Marshal(schema(v))
	if err != nil {
		return empty
	}
	return b
}

// internalTarget reports whether the address a connection points to is inside the network: a literal private, loopback, unique-local or
// CGNAT IP address, judged like the address of a profile (INV-3). A name is not trusted (it could resolve to a public address after
// this check), so it is not internal; the same for anything that does not parse.
func internalTarget(target string) bool {
	host := strings.TrimSpace(target)
	if i := strings.Index(host, "://"); i >= 0 {
		u, err := url.Parse(host)
		if err != nil {
			return false
		}
		host = u.Hostname()
	} else {
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && provider.IsInternalAddr(ip)
}

// connectionTools lists the read tools of the connections that are on and ready. A reader that cannot list adds none: the question is
// answered from the box's own tools.
func (s *Service) connectionTools(ctx context.Context) []toolImpl {
	cr := s.cfg.Conns
	if cr == nil {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, read.ListBudget+2*time.Second)
	defer cancel()
	list, err := cr.ListReadTools(lctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "ai: could not list the read tools of the connections", "error", err)
		return nil
	}
	// Whether the connection is inside the network is read from the connection list of core (Config.ConnTargets). While the privacy rule
	// is on, a tool of a connection that is not inside, or whose address cannot be read, is not offered (fail closed, D-212).
	targets := map[string]string{}
	if s.cfg.ConnTargets != nil {
		t, err := s.cfg.ConnTargets(ctx)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "ai: could not read the addresses of the connections", "error", err)
		} else {
			targets = t
		}
	}
	internalOnly := s.snap.Load().assign.InternalOnly
	var out []toolImpl
	seen := map[string]bool{}
	for _, rt := range list {
		inside := internalTarget(targets[rt.ConnectionID])
		if internalOnly && !inside {
			continue
		}
		name := connToolName(rt)
		if seen[name] || rt.ConnectionID == "" || rt.Name == "" {
			continue
		}
		seen[name] = true
		connID, tool, connName := rt.ConnectionID, rt.Name, clip(rt.ConnectionName, 60)
		out = append(out, toolImpl{
			internal: inside,
			Tool: Tool{Name: name, Access: AccessRead, Enabled: true, Jobs: []Job{JobAskMyData}, ConnectorID: connID, Schema: stripSchemaText(rt.Schema),
				Description: fmt.Sprintf("Read-only call on the connection %q (%s): %s. It can change nothing. Give the arguments exactly as the schema allows.", connName, clip(rt.Kind, 20), clip(tool, 60))},
			run: func(ctx context.Context, args map[string]any) (toolOut, error) {
				text, err := cr.CallRead(read.WithActor(ctx, "ai:ask-my-data"), connID, tool, args)
				switch {
				case errors.Is(err, read.ErrUnavailable):
					return toolOut{}, errToolFailed{"that read tool is not available"}
				case err != nil:
					return toolOut{}, errToolFailed{"the read failed: " + clip(err.Error(), 200)}
				}
				// The box's own record of the read, the only thing a config_read evidence can name (D-311). Its id is not shown to the model.
				s.recordRead(ctx, JobAskMyData, connID, connName, tool)
				return toolOut{Text: sanitizeWeb(text), Summary: fmt.Sprintf("read %d bytes", len(text)), Cite: connName + ": " + clip(tool, 60)}, nil
			},
		})
	}
	return out
}
