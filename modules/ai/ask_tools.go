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

// Limits of the result of one call (D-211).
const (
	askResultBytes = 12 << 10 // what one call returns to the model
	askTotalBytes  = 48 << 10 // what all calls of one question return
	askRowsDefault = 15
	askRowsMax     = 50
	askMaxArgs     = 4 << 10 // the arguments of one call, encoded
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
	domainRE   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$`)
	statusEnum = []string{"open", "any", "confirmed", "suspected", "mitigated", "patched", "false_positive", "not_relevant"}
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

// rowsJSON writes {"<count>":total, "shown":n, "<key>":[rows]} with as many rows as fit the byte cap, and says how many that is.
func rowsJSON(key string, total int, rows []map[string]any) (string, int) {
	for n := len(rows); ; n-- {
		b, err := json.Marshal(map[string]any{"matches": total, "shown": n, key: rows[:n]})
		if err == nil && (len(b) <= askResultBytes || n == 0) {
			return string(b), n
		}
	}
}

func clip(s string, n int) string { return cleanLine(s, n) }

// ---------- the tools of the box

const (
	searchAssetsDesc = "Search the devices in the inventory. All arguments are optional filters that are combined: free text (words must all appear in the name, IP, vendor, model, operating system, services or software), the device kind, an open TCP/UDP port, whether the device is approved, a word of the operating system. Returns the matching devices, at most limit of them."
	listFindingsDesc = "List findings: devices matched to an exploited vulnerability. Filters: status (open = confirmed or suspected, the default; any; or one status), severity, CVE id, asset_id of one device. Returns at most limit findings."
	getFindingDesc   = "Get one finding by its id, with the scan evidence if a scan confirmed it."
	lookupCVEDesc    = "Look a CVE up on the exploited-vulnerabilities list this box holds, and list the devices of this network that it matches."
	lookupIOCDesc    = "Check whether an IP address or a domain name is listed by the threat feeds this box pulls."
)

const (
	searchAssetsSchema = `{"type":"object","properties":{"text":{"type":"string","maxLength":80},"kind":{"type":"string","maxLength":32},"port":{"type":"integer","minimum":1,"maximum":65535},"approved":{"type":"boolean"},"os_contains":{"type":"string","maxLength":40},"limit":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}`
	listFindingsSchema = `{"type":"object","properties":{"status":{"type":"string","enum":["open","any","confirmed","suspected","mitigated","patched","false_positive","not_relevant"]},"severity":{"type":"string","enum":["critical","high","medium","low","info"]},"cve":{"type":"string","maxLength":24},"asset_id":{"type":"string","maxLength":96},"limit":{"type":"integer","minimum":1,"maximum":50}},"additionalProperties":false}`
	getFindingSchema   = `{"type":"object","properties":{"id":{"type":"string","maxLength":96}},"required":["id"],"additionalProperties":false}`
	lookupCVESchema    = `{"type":"object","properties":{"cve":{"type":"string","maxLength":24}},"required":["cve"],"additionalProperties":false}`
	lookupIOCSchema    = `{"type":"object","properties":{"kind":{"type":"string","enum":["ip","domain"]},"value":{"type":"string","maxLength":253}},"required":["kind","value"],"additionalProperties":false}`
)

var (
	searchAssetsArgs = map[string]argSpec{"text": {kind: "string", max: 80}, "kind": {kind: "string", re: kindArgRE, max: 32}, "port": {kind: "int", min: 1, max: 65535},
		"approved": {kind: "bool"}, "os_contains": {kind: "string", max: 40}, "limit": {kind: "int", min: 1, max: askRowsMax}}
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

func toolSearchAssets(ctx context.Context, d Data, raw map[string]any) (toolOut, error) {
	all, err := d.Assets(ctx)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	var hit []AssetRow
	for _, a := range all {
		if a.matches(raw) {
			hit = append(hit, a)
		}
	}
	limit := limitOf(raw)
	if len(hit) > limit {
		hit = hit[:limit]
	}
	rows := make([]map[string]any, len(hit))
	for i, a := range hit {
		sw := a.Software
		if len(sw) > 8 {
			sw = sw[:8]
		}
		ports := a.Ports
		if len(ports) > 12 {
			ports = ports[:12]
		}
		rows[i] = map[string]any{"id": clip(a.ID, 96), "name": clip(a.Name, 80), "ip": clip(a.IP, 45), "kind": clip(a.Kind, 32), "vendor": clip(a.Vendor, 60), "model": clip(a.Model, 60),
			"os": clip(a.OS, 80), "approved": a.Approved, "last_seen": clip(a.LastSeen, 32), "ports": cleanAll(ports, 40), "software": cleanAll(sw, 80)}
	}
	total := 0
	for _, a := range all {
		if a.matches(raw) {
			total++
		}
	}
	text, shown := rowsJSON("devices", total, rows)
	t := &AskTable{Columns: []string{"Device", "IP", "Type", "Operating system"}, Rows: []AskRow{}}
	for _, a := range hit[:shown] {
		os := clip(a.OS, 80)
		if os == "" {
			os = "Unknown"
		}
		t.Rows = append(t.Rows, AskRow{Href: "/devices/" + clip(a.ID, 96), Cells: []string{clip(a.Name, 80), clip(a.IP, 45), clip(a.Kind, 32), os}})
	}
	out := toolOut{Text: text, Summary: plural(total, "device", "devices"), Cite: "Inventory: " + plural(len(all), "device", "devices")}
	if len(t.Rows) > 0 {
		out.Table = t
	}
	return out, nil
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
	total := len(hit)
	if limit := limitOf(raw); len(hit) > limit {
		hit = hit[:limit]
	}
	rows := make([]map[string]any, len(hit))
	for i, f := range hit {
		rows[i] = findingMap(f)
	}
	text, shown := rowsJSON("findings", total, rows)
	t := &AskTable{Columns: []string{"Device", "CVE", "Status", "Severity"}, Rows: []AskRow{}}
	for _, f := range hit[:shown] {
		t.Rows = append(t.Rows, AskRow{Href: "/findings/" + clip(f.ID, 96), Cells: []string{clip(f.Asset, 80), clip(f.CVE, 24), clip(f.Status, 20), clip(f.Severity, 12)}})
	}
	out := toolOut{Text: text, Summary: plural(total, "finding", "findings"), Cite: "Findings: " + plural(len(all), "record", "records")}
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
	for _, a := range assets {
		if len(devs) < askRowsMax {
			devs = append(devs, map[string]any{"name": clip(a.Name, 80), "ip": clip(a.IP, 45), "kind": clip(a.Kind, 32), "matched_by": clip(a.Basis, 12), "finding_status": clip(a.Status, 20)})
		}
	}
	m := map[string]any{"found": true, "cve": clip(facts.CVE, 24), "vendor": clip(facts.Vendor, 80), "product": clip(facts.Product, 80), "name": clip(facts.Name, 160),
		"description": clip(facts.Description, 800), "required_action": clip(facts.RequiredAction, 400), "date_added": clip(facts.DateAdded, 20), "ransomware": facts.Ransomware,
		"links": links, "matching_devices": devs}
	b, _ := json.Marshal(m)
	text := string(b)
	for len(text) > askResultBytes && len(devs) > 0 { // the description is capped, so only a flood of devices can be too long
		devs = devs[:len(devs)/2]
		m["matching_devices"] = devs
		b, _ = json.Marshal(m)
		text = string(b)
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
		if len(value) > 253 || !domainRE.MatchString(value) {
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
