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
	"unicode/utf8"

	"github.com/knt048/vedette/core/conn/read"
)

// The read tools of "Ask your data" (S-AI-5, INV-14): six of the box (search_assets, list_findings, get_finding,
// device_updates, lookup_cve, lookup_ioc) and the read tools of the connections. All of them only read. Arguments are checked at the edge against a closed
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

// errConnFailed is a read of a connection that failed with words the box did not write (an MCP server's error result, a device's
// error page): the tool loop sends them to the model as fenced data, like a result, never as its own words.
type errConnFailed struct{ text string }

func (e errConnFailed) Error() string { return e.text }

// toolImpl is a tool the model may be offered with the code that runs it.
type toolImpl struct {
	Tool
	// parse checks the arguments at the edge; nil = one JSON object, whose names and types the code that runs the tool checks (the
	// reader of a connection against the tool's own schema).
	parse func(raw json.RawMessage) (map[string]any, error)
	// internal: the connection of a connection tool is inside the network (private, loopback, ULA or CGNAT address); false when that
	// could not be checked.
	internal bool
	// class is what the tool reaches with its arguments (jobPowers decides which classes a job may call).
	class toolClass
	// catalog is what the connection's server wrote about a connection tool (its name, its connection, the values it allows), one
	// line of the fenced data block of connection tools; "" for a tool of the box.
	catalog string
	run     func(ctx context.Context, args map[string]any) (toolOut, error)
}

// Limits of the result of one call. Every turn of a question sends the whole conversation again, so a result is paid for
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
// result whose totals alone are over the cap still starts with them (a model read the first page as the whole and reported 39
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
	searchAssetsDesc = "Search the inventory's devices. Optional filters, combined: text (every word in the name, IP, vendor, model, OS, services or software), kind, an open port, approved, os_contains. Returns how many match and the first limit (default 10) with vendor, model, OS, open ports and software; detail=true adds first and last seen, how it was added and which source saw it."
	listFindingsDesc = "List findings: devices matched to a known vulnerability (urgency: none or under_attack means attackers use it; public_exploit, critical_edge, update_recommended do not). Filters: status (open = confirmed or suspected, the default; any; or one status), severity, CVE id, asset_id of one device. Returns the match count, counts by severity, status, basis and device, then the riskiest limit findings (default 10). get_finding: evidence of one."
	getFindingDesc   = "Get one finding by its id, with the scan evidence if a scan confirmed it."
	lookupCVEDesc    = "Look a CVE up in the box's catalogue; lists the devices it matches. on_exploited_list false: no list says it is exploited."
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

// productTool is a tool of the box for "Ask your data" and the jobs named; log investigation gets its own four.
func productTool(name, desc, schema string, spec map[string]argSpec, required []string, run func(context.Context, map[string]any) (toolOut, error), jobs ...Job) toolImpl {
	return toolImpl{Tool: Tool{Name: name, Description: desc, Access: AccessRead, Enabled: true, Jobs: append([]Job{JobAskMyData}, jobs...), Schema: json.RawMessage(schema)},
		parse: func(raw json.RawMessage) (map[string]any, error) { return parseArgs(raw, spec, required...) }, run: run, class: toolBox}
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
	if d, up := s.cfg.Data, s.cfg.Updates; d != nil && up != nil {
		out = append(out, productTool("device_updates", deviceUpdatesDesc, deviceUpdatesSchema, deviceUpdatesArgs, []string{"device"}, func(ctx context.Context, a map[string]any) (toolOut, error) {
			return s.toolDeviceUpdates(ctx, d, up, a)
		}))
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

// boxApart counts devices with the Vedette box named apart: Devices says "Only the Vedette box so far" and Reports counts no
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
		if a.Ignored { // An ignored device is not one waiting for review
			r["ignored"] = true
		}
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
		return "added manually"
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

// findingMap is one finding for the model. Its times are named for what they are: when Vedette first and last matched the
// vulnerability to the device (a finding's first_seen and last_seen), not when the device or its software was seen.
func findingMap(f FindingRow) map[string]any {
	m := map[string]any{"id": clip(f.ID, 96), "device": clip(f.Asset, 80), "device_ip": clip(f.AssetIP, 45), "asset_id": clip(f.AssetID, 96), "cve": clip(f.CVE, 24), "status": clip(f.Status, 20),
		"severity": clip(f.Severity, 12), "urgency": clip(f.Urgency, 20), "basis": clip(f.Basis, 12), "confidence": f.Confidence, "first_matched": clip(f.FirstSeen, 32), "last_matched": clip(f.LastSeen, 32)}
	if f.AcceptedUntil != "" { // When an accepted risk comes back by itself
		m["accepted_until"] = clip(f.AcceptedUntil, 10)
	}
	put(m, "fix", clip(f.Fix, 300))
	put(m, "confirmation", clip(f.Confirmation, 200))
	return m
}

// urgencyRank orders the urgency statuses, most urgent first; a finding that states none ranks with update_recommended.
func urgencyRank(u string) int {
	if r, ok := map[string]int{"under_attack": 0, "exploited": 1, "public_exploit": 2, "critical_edge": 3}[u]; ok {
		return r
	}
	return 4
}

// riskRank orders findings riskiest first: open ones first (confirmed, suspected, then closed ones with status=any), then the most urgent layer, then severity, then how the match was made (confirmed: a scan, a person or the version the device reports; the version, the
// product name only), then confidence. Equal ones keep the box's order (newest first).
func riskRank(f FindingRow) [5]int {
	sev := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	basis := map[string]int{"scan": 0, "person": 0, "version": 1}
	s, ok := sev[f.Severity]
	if !ok {
		s = 4
	}
	b, ok := basis[f.Basis]
	if !ok {
		b = 2
	}
	if f.Status == "confirmed" { // a scan, a person or the version the device itself reports (basis version): confirmed all the same
		b = 0
	}
	st := map[string]int{"confirmed": 0, "suspected": 1}[f.Status] // open ones first: a closed critical one is not the risk now
	if f.Status != "confirmed" && f.Status != "suspected" {
		st = 2
	}
	return [5]int{st, urgencyRank(f.Urgency), s, b, -int(f.Confidence * 100)}
}

func lessRank(a, b [5]int) bool {
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
		if f.Urgency != "exploited" { // the common case is left out: no urgency means exploited in the wild
			put(r, "urgency", clip(f.Urgency, 20))
		}
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
	put(m, "workaround", clip(f.Workaround, 600))
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
		return toolOut{Text: `{"found":false,"note":"The box's catalogue has no record of this CVE."}`, Summary: "not in the catalogue"}, nil
	}
	assets, err := f.AffectedAssets(ctx, id)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	listed := facts.Listed()
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
			OnExploitedList      bool             `json:"on_exploited_list"`
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
		}{true, listed, clip(facts.CVE, 24), total, n, shownNote("devices", total, n), clip(facts.Vendor, 80), clip(facts.Product, 80), clip(facts.Name, 160),
			clip(facts.Description, 800), clip(facts.RequiredAction, 400), clip(facts.DateAdded, 20), facts.Ransomware, links, devs[:n]}
	})
	if !listed {
		return toolOut{Text: text, Summary: "not on an exploited list, " + plural(len(assets), "device", "devices"), Cite: "CVE record: " + id}, nil
	}
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

// ---------- the read tools of the connections (core/conn/read)

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
// (tool poisoning), so what is not on this list is dropped, enum values too (they go as fenced data: connToolSchema); types, names and
// bounds stay: they are what the call has to be. The
// reader (core/conn/read) also hands over only the part of the schema it enforces; this list does not depend on that.
var schemaKeywords = map[string]bool{"type": true, "properties": true, "required": true, "items": true, "minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true, "minLength": true, "maxLength": true, "minItems": true, "maxItems": true, "additionalProperties": true,
	"anyOf": true, "oneOf": true, "allOf": true}

// connToolDesc is the whole description of a connection tool the model is offered: the box's own words. What the server wrote about
// the tool is data (connCatalog).
const connToolDesc = "Read-only call of a tool of a connection. Which tool and connection it is, and the values its arguments allow, are in the data block of connection tools. It can change nothing."

var argNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// The limits of the values a connection tool's schema may list.
const (
	connMaxValues    = 64
	connMaxValueLen  = 200
	connMaxDepth     = 6
	connMaxValueText = 4000 // all the values of one tool, as listed in the data block
)

// schemaNumberKeywords are the kept keywords whose value is a number.
var schemaNumberKeywords = []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems"}

var schemaTypes = map[string]bool{"string": true, "number": true, "integer": true, "boolean": true, "object": true, "array": true, "null": true}

// schemaType reports whether v is a JSON Schema type: one type name, or a non-empty list of them.
func schemaType(v any) bool {
	switch x := v.(type) {
	case string:
		return schemaTypes[x]
	case []any:
		for _, e := range x {
			if s, ok := e.(string); !ok || !schemaTypes[s] {
				return false
			}
		}
		return len(x) > 0
	}
	return false
}

// connToolSchema checks the schema a connection's server wrote and splits it (tool poisoning, OWASP LLM01): the shape the model is
// offered (types, argument names, required, bounds, no enum value and no free text: stripSchemaText), and the values it allows, as
// "argument: one of ..." lines for the fenced data block. ok is false, and the tool is not offered, when the schema does not hold up: not
// one JSON object schema of type object, a type that is not a JSON Schema type, a bound or length that is not a number, an argument
// name that is not an identifier, a value with a control or invisible character or
// longer than 200 characters, more than 64 values, deeper than 6 levels, or values longer than 4,000 characters in all.
func connToolSchema(raw json.RawMessage) (shape json.RawMessage, values []string, ok bool) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil || root["type"] != "object" {
		return nil, nil, false
	}
	n, size := 0, 0
	var walk func(v any, path string, depth int) bool
	walk = func(v any, path string, depth int) bool {
		m, isMap := v.(map[string]any)
		if !isMap {
			_, isBool := v.(bool) // additionalProperties: true/false
			return isBool
		}
		if depth > connMaxDepth {
			return false
		}
		// the kept keywords other than enum reach the tool definition as written, so they may hold no free text
		if ty, has := m["type"]; has && !schemaType(ty) {
			return false
		}
		for _, k := range schemaNumberKeywords {
			if x, has := m[k]; has {
				if _, isNum := x.(float64); !isNum {
					return false
				}
			}
		}
		if e, has := m["enum"]; has {
			l, isList := e.([]any)
			if !isList {
				return false
			}
			var vals []string
			for _, x := range l {
				n++
				b, _ := json.Marshal(x)
				if str, isStr := x.(string); isStr && (str != cleanUntrusted(str) || strings.ContainsAny(str, "\n\t") || utf8.RuneCountInString(str) > connMaxValueLen) {
					return false
				}
				vals = append(vals, string(b))
				size += len(b)
			}
			if n > connMaxValues || size > connMaxValueText {
				return false
			}
			name := path
			if name == "" {
				name = "the value"
			}
			values = append(values, name+": one of "+strings.Join(vals, ", "))
		}
		if p, has := m["properties"]; has {
			props, isMap := p.(map[string]any)
			if !isMap {
				return false
			}
			for k, sub := range props {
				if !argNameRE.MatchString(k) || !walk(sub, strings.TrimPrefix(path+"."+k, "."), depth+1) {
					return false
				}
			}
		}
		if r, has := m["required"]; has {
			l, isList := r.([]any)
			if !isList {
				return false
			}
			for _, x := range l {
				if str, isStr := x.(string); !isStr || !argNameRE.MatchString(str) {
					return false
				}
			}
		}
		for _, k := range []string{"items", "additionalProperties"} {
			if sub, has := m[k]; has && !walk(sub, path, depth+1) {
				return false
			}
		}
		for _, k := range []string{"anyOf", "oneOf", "allOf"} {
			if sub, has := m[k]; has {
				l, isList := sub.([]any)
				if !isList {
					return false
				}
				for _, x := range l {
					if !walk(x, path, depth+1) {
						return false
					}
				}
			}
		}
		return true
	}
	if !walk(root, "", 0) {
		return nil, nil, false
	}
	sort.Strings(values)
	return stripSchemaText(raw), values, true
}

// connCatalog is the fenced data block of the connection tools a session offers: what their servers wrote about them. Empty when there
// is none.
func (ts *toolSession) connCatalog() []DataBlock {
	var lines []string
	for _, t := range ts.tools {
		if impl := ts.impl[t.Name]; impl.catalog != "" {
			lines = append(lines, impl.catalog)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	sort.Strings(lines)
	return []DataBlock{Untrusted(SourceTool, "connection tools: what their servers wrote about them", strings.Join(lines, "\n"))}
}

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

// internalTarget reports whether the address a connection points to is inside the network: a literal private IPv4 address (10/8,
// 172.16/12, 192.168/16) or an IPv6 unique-local one (fc00::/7), an IPv4-mapped form judged as its IPv4 address. Everything else is
// outside, failing closed: the ISP's shared space (CGNAT 100.64/10, also a tailnet's, whose nodes may be other people's machines),
// link-local, loopback, global and public addresses, a name (it could resolve anywhere after this check) and what does not parse.
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
	return err == nil && ip.Zone() == "" && ip.Unmap().IsPrivate()
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
	// is on, a tool of a connection that is not inside, or whose address cannot be read, is not offered (fail closed).
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
	allowed, err := s.askConnections(ctx, s.cfg.DB.Reader())
	if err != nil { // a setting that cannot be read allows no connection outside the network
		s.cfg.Log.WarnContext(ctx, "ai: could not read which connections Ask may use", "error", err)
		allowed = askConnSetting{Connections: map[string]askConnChoice{}}
	}
	var out []toolImpl
	seen := map[string]bool{}
	for _, rt := range list {
		inside := internalTarget(targets[rt.ConnectionID])
		if internalOnly && !inside {
			continue
		}
		// A connection outside the network gets the arguments the model writes, and the model reads untrusted text: it is offered only
		// after an administrator allowed it for Ask (Settings, AI assistant), whatever the privacy rule.
		class := toolConnLAN
		if !inside {
			class = toolConnOut
			if ok, _ := allowed.choice(rt.ConnectionID, targets[rt.ConnectionID]); !ok {
				continue
			}
		}
		name := connToolName(rt)
		if seen[name] || rt.ConnectionID == "" || rt.Name == "" {
			continue
		}
		// The server wrote the schema: a schema that does not hold up is not offered; its values go as fenced data (connCatalog)
		shape, values, ok := connToolSchema(rt.Schema)
		if !ok {
			continue
		}
		seen[name] = true
		connID, tool, connName := rt.ConnectionID, rt.Name, clip(rt.ConnectionName, 60)
		line := fmt.Sprintf("- %s: the tool %q of the connection %q (%s)", name, clip(tool, 60), connName, clip(rt.Kind, 20))
		if len(values) > 0 {
			line += "; allowed values: " + strings.Join(values, "; ")
		}
		out = append(out, toolImpl{
			internal: inside,
			class:    class,
			catalog:  line,
			Tool: Tool{Name: name, Access: AccessRead, Enabled: true, Jobs: []Job{JobAskMyData}, ConnectorID: connID, Schema: shape,
				Description: connToolDesc},
			run: func(ctx context.Context, args map[string]any) (toolOut, error) {
				text, err := cr.CallRead(read.WithActor(ctx, "ai:ask-my-data"), connID, tool, args)
				switch {
				case errors.Is(err, read.ErrUnavailable):
					return toolOut{}, errToolFailed{"that read tool is not available"}
				case err != nil:
					return toolOut{}, errConnFailed{clip(err.Error(), 200)}
				}
				// The box's own record of the read, the only thing a config_read evidence can name. Its id is not shown to the model.
				s.recordRead(ctx, JobAskMyData, connID, connName, tool)
				return toolOut{Text: sanitizeWeb(text), Summary: fmt.Sprintf("read %d bytes", len(text)), Cite: connName + ": " + clip(tool, 60)}, nil
			},
		})
	}
	return out
}
