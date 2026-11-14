package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Scopes a token may hold (INV-2). Each tool needs exactly one.
const (
	ScopeAssets   = "assets"
	ScopeFindings = "findings"
	ScopeFeeds    = "feeds"
)

// AllScopes in the order the GUI shows them.
var AllScopes = []string{ScopeAssets, ScopeFindings, ScopeFeeds}

// Caps of one answer (SYS-6, D-232). A list is paged with offset and limit; one page and every text field are bounded, so an
// answer stays well under maxResult whatever the box holds.
const (
	defaultLimit = 25
	maxLimit     = 100
	maxOffset    = 100_000
	maxSoftware  = 200 // software rows of one device
	maxServices  = 100 // services of one device
	maxHistory   = 50  // newest history steps of one finding
	maxLinks     = 10
	maxText      = 4000 // characters of one text field (a description, an evidence summary)
	maxResult    = 512 << 10
)

// Tool is one read tool: its MCP definition and the scope it needs.
type Tool struct {
	Name        string
	Title       string
	Description string
	Scope       string
	Input       json.RawMessage // JSON Schema 2020-12 of the arguments
	Output      json.RawMessage // JSON Schema 2020-12 of structuredContent
	run         func(ctx context.Context, src Source, args args) (any, int, error)
}

var (
	cveRE   = regexp.MustCompile(`^(?i)cve-\d{4}-\d{4,7}$`)
	idRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	statusE = []string{"open", "all", "confirmed", "suspected", "mitigated", "patched", "false_positive", "not_relevant", "risk_accepted"}
)

// Schemas. Kept as literal JSON so tools/list sends exactly what is written here; tools_test.go checks every answer against them.
const (
	pageProps  = `"offset":{"type":"integer","minimum":0,"maximum":100000,"default":0,"description":"How many items to skip."},"limit":{"type":"integer","minimum":1,"maximum":100,"default":25,"description":"How many items to return."}`
	strOrNull  = `{"type":["string","null"]}`
	numOrNull  = `{"type":["number","null"]}`
	pageOutput = `"total":{"type":"integer","description":"Items that match, over all pages."},"next_offset":{"type":["integer","null"],"description":"Offset of the next page; null on the last page."}`

	assetRowSchema = `{"type":"object","additionalProperties":false,"required":["id","name","ip","hostname","kind","vendor","model","os","approved","first_seen","last_seen"],"properties":{` +
		`"id":{"type":"string"},"name":{"type":"string"},"ip":` + strOrNull + `,"hostname":` + strOrNull + `,"kind":{"type":"string"},` +
		`"vendor":` + strOrNull + `,"model":` + strOrNull + `,"os":` + strOrNull + `,"approved":{"type":"boolean","description":"False while the device waits for a person to confirm it."},` +
		`"first_seen":{"type":"string","format":"date-time"},"last_seen":{"type":"string","format":"date-time"}}}`
	serviceSchema  = `{"type":"object","additionalProperties":false,"required":["port","proto","name","product","version"],"properties":{"port":{"type":"integer"},"proto":{"type":"string"},"name":{"type":"string"},"product":` + strOrNull + `,"version":` + strOrNull + `}}`
	softwareSchema = `{"type":"object","additionalProperties":false,"required":["name","vendor","product","version"],"properties":{"name":{"type":"string"},"vendor":{"type":"string"},"product":{"type":"string"},"version":` + strOrNull + `}}`
	assetSchema    = `{"type":"object","additionalProperties":false,"required":["id","name","ip","hostname","kind","vendor","model","os","approved","first_seen","last_seen","services","software"],"properties":{` +
		`"id":{"type":"string"},"name":{"type":"string"},"ip":` + strOrNull + `,"hostname":` + strOrNull + `,"kind":{"type":"string"},` +
		`"vendor":` + strOrNull + `,"model":` + strOrNull + `,"os":` + strOrNull + `,"approved":{"type":"boolean"},` +
		`"first_seen":{"type":"string","format":"date-time"},"last_seen":{"type":"string","format":"date-time"},` +
		`"services":{"type":"array","maxItems":100,"items":` + serviceSchema + `},"software":{"type":"array","maxItems":200,"items":` + softwareSchema + `}}}`

	findingRowSchema = `{"type":"object","additionalProperties":false,"required":["id","asset_id","cve","status","severity","confidence","basis","first_seen","last_seen","resolved_at"],"properties":{` +
		`"id":{"type":"string"},"asset_id":{"type":"string"},"cve":{"type":"string"},` +
		`"status":{"type":"string","enum":["confirmed","suspected","mitigated","patched","false_positive","not_relevant","risk_accepted"]},` +
		`"severity":{"type":"string"},"confidence":{"type":"number","minimum":0,"maximum":1},"basis":{"type":"string"},` +
		`"first_seen":{"type":"string","format":"date-time"},"last_seen":{"type":"string","format":"date-time"},"resolved_at":{"type":["string","null"],"format":"date-time"},"accepted_until":{"type":"string","format":"date","description":"risk_accepted only: the last day; the finding reopens by itself after it."}}}`
	findingSchema = `{"type":"object","additionalProperties":false,"required":["id","asset_id","cve","status","severity","confidence","basis","first_seen","last_seen","resolved_at","evidence","history"],"properties":{` +
		`"id":{"type":"string"},"asset_id":{"type":"string"},"cve":{"type":"string"},` +
		`"status":{"type":"string","enum":["confirmed","suspected","mitigated","patched","false_positive","not_relevant","risk_accepted"]},` +
		`"severity":{"type":"string"},"confidence":{"type":"number","minimum":0,"maximum":1},"basis":{"type":"string"},` +
		`"first_seen":{"type":"string","format":"date-time"},"last_seen":{"type":"string","format":"date-time"},"resolved_at":{"type":["string","null"],"format":"date-time"},"accepted_until":{"type":"string","format":"date","description":"risk_accepted only: the last day; the finding reopens by itself after it."},` +
		`"evidence":{"type":["object","null"],"additionalProperties":false,"required":["template","checked_at"],"properties":{"template":{"type":"string","description":"The scan check that confirmed it."},"checked_at":{"type":"string","format":"date-time"}}},` +
		`"history":{"type":"array","maxItems":50,"items":{"type":"object","additionalProperties":false,"required":["at","action"],"properties":{"at":{"type":"string","format":"date-time"},"action":{"type":"string"}}}}}}`

	cveEntrySchema = `{"type":"object","additionalProperties":false,"required":["cve","vendor","product","name","description","required_action","date_added","due_date","ransomware","epss","has_scan_template","links"],"properties":{` +
		`"cve":{"type":"string"},"vendor":{"type":"string"},"product":{"type":"string"},"name":{"type":"string"},"description":{"type":"string"},` +
		`"required_action":{"type":"string"},"source":{"type":"string","description":"The list that has it: cisa-kev, vulncheck-kev (VulnCheck KEV) or a feed the administrator added."},"date_added":{"type":"string","format":"date"},"due_date":{"type":["string","null"],"format":"date"},` +
		`"ransomware":{"type":"boolean","description":"Known to be used in ransomware campaigns."},"epss":` + numOrNull + `,` +
		`"has_scan_template":{"type":"boolean","description":"The box has a check that can confirm it by scanning."},"links":{"type":"array","maxItems":10,"items":{"type":"string"}}}}`
	hotSchema = `{"type":"object","additionalProperties":false,"required":["cve","vendor","product","date_added","ransomware","epss","has_scan_template"],"properties":{` +
		`"cve":{"type":"string"},"vendor":{"type":"string"},"product":{"type":"string"},"date_added":{"type":"string","format":"date"},"ransomware":{"type":"boolean"},"epss":` + numOrNull + `,"has_scan_template":{"type":"boolean"}}}`
)

func page(item string) json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["items","total","next_offset"],"properties":{"items":{"type":"array","maxItems":100,"items":` + item + `},` + pageOutput + `}}`)
}

// Tools are the seven read tools, in the order tools/list sends them (INV-1). There is no write tool and none may be added
// (FORBID-1): a new read tool goes in one of the three scopes and in CONTRACT.md.
var Tools = []Tool{
	{
		Name: "list_assets", Title: "List devices", Scope: ScopeAssets,
		Description: "List the devices in the Vedette inventory (IP, hostname, kind, vendor, model, OS), sorted by name. Filter with query (part of the name, IP, vendor or model) and kind. Paged with offset and limit.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"query":{"type":"string","maxLength":64,"description":"Part of the name, IP address, vendor or model, any case."},"kind":{"type":"string","maxLength":40,"description":"Device kind, for example firewall, server, printer."},` + pageProps + `}}`),
		Output:      page(assetRowSchema),
		run:         listAssets,
	},
	{
		Name: "get_asset", Title: "Show one device", Scope: ScopeAssets,
		Description: "Show one device of the inventory with the services seen listening on it and the software found on it.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string","maxLength":96,"description":"Device id from list_assets."}}}`),
		Output:      json.RawMessage(assetSchema),
		run:         getAsset,
	},
	{
		Name: "list_findings", Title: "List findings", Scope: ScopeFindings,
		Description: "List exploited vulnerabilities matched to devices (findings), newest first. status: open (confirmed or suspected, the default), all, or one status. Filter by asset_id or cve. Paged with offset and limit.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"status":{"type":"string","enum":["open","all","confirmed","suspected","mitigated","patched","false_positive","not_relevant","risk_accepted"],"default":"open"},"asset_id":{"type":"string","maxLength":96},"cve":{"type":"string","pattern":"^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,7}$"},` + pageProps + `}}`),
		Output:      page(findingRowSchema),
		run:         listFindings,
	},
	{
		Name: "get_finding", Title: "Show one finding", Scope: ScopeFindings,
		Description: "Show one finding: status, how it was found, the scan check that confirmed it, and when its status changed.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"required":["id"],"properties":{"id":{"type":"string","maxLength":96,"description":"Finding id from list_findings."}}}`),
		Output:      json.RawMessage(findingSchema),
		run:         getFinding,
	},
	{
		Name: "lookup_cve", Title: "Look up a CVE", Scope: ScopeFeeds,
		Description: "Look a CVE up in the exploited-vulnerability lists on the box (CISA KEV, VulnCheck KEV when the administrator turned it on, and the feeds the administrator added); the entry names its list in source. listed is false when no list has it.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"required":["cve"],"properties":{"cve":{"type":"string","pattern":"^[Cc][Vv][Ee]-[0-9]{4}-[0-9]{4,7}$","description":"For example CVE-2024-3400."}}}`),
		Output:      json.RawMessage(`{"type":"object","additionalProperties":false,"required":["cve","listed","entry"],"properties":{"cve":{"type":"string"},"listed":{"type":"boolean"},"entry":{"oneOf":[{"type":"null"},` + cveEntrySchema + `]}}}`),
		run:         lookupCVE,
	},
	{
		Name: "lookup_ioc", Title: "Look up an IP or domain", Scope: ScopeFeeds,
		Description: "Look an IP address or a domain up in the threat-indicator feeds on the box. verdict is block (two independent lists, or one strong list), alert (one list), or null when no list has it.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"required":["value"],"properties":{"value":{"type":"string","minLength":1,"maxLength":253,"description":"An IPv4 or IPv6 address, or a domain name."}}}`),
		Output: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["value","type","listed","verdict","category","sources","score","first_seen","last_seen"],"properties":{` +
			`"value":{"type":"string"},"type":{"type":"string","enum":["ip","domain"]},"listed":{"type":"boolean"},"verdict":{"type":["string","null"],"enum":["block","alert",null]},` +
			`"category":{"type":"string"},"sources":{"type":"array","items":{"type":"string"}},"score":` + numOrNull + `,"first_seen":{"type":["string","null"],"format":"date"},"last_seen":{"type":["string","null"],"format":"date"}}}`),
		run: lookupIOC,
	},
	{
		Name: "hot_vulnerabilities", Title: "Recently exploited vulnerabilities", Scope: ScopeFeeds,
		Description: "Vulnerabilities added to the exploited lists in the last 24 hours or 7 days, newest first. Paged with offset and limit.",
		Input:       json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"window":{"type":"string","enum":["24h","7d"],"default":"7d"},` + pageProps + `}}`),
		Output:      page(hotSchema),
		run:         hotVulnerabilities,
	},
}

// ToolByName returns the tool of that name.
func ToolByName(name string) (Tool, bool) {
	i := slices.IndexFunc(Tools, func(t Tool) bool { return t.Name == name })
	if i < 0 {
		return Tool{}, false
	}
	return Tools[i], true
}

// argError is a bad argument: reported to the agent as a tool error it can correct (isError), not as a protocol error.
type argError struct{ msg string }

func (e argError) Error() string { return e.msg }

// args are the decoded arguments of one call, checked against the tool's input schema by hand: only the names the schema
// lists, of the right type. Unknown names are refused (additionalProperties false).
type args map[string]json.RawMessage

func parseArgs(raw json.RawMessage, allowed ...string) (args, error) {
	a := args{}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return a, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&a); err != nil || a == nil {
		return nil, argError{"arguments must be a JSON object."}
	}
	for k := range a {
		if !slices.Contains(allowed, k) {
			return nil, argError{fmt.Sprintf("unknown argument %q; this tool takes: %s.", clip(k, 40), strings.Join(allowed, ", "))}
		}
	}
	return a, nil
}

func (a args) str(name string, maxLen int) (string, bool, error) {
	raw, ok := a[name]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, argError{name + " must be a string."}
	}
	if utf8.RuneCountInString(s) > maxLen || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", false, argError{fmt.Sprintf("%s must be at most %d characters with no control characters.", name, maxLen)}
	}
	return s, true, nil
}

func (a args) num(name string, minV, maxV, def int) (int, error) {
	raw, ok := a[name]
	if !ok || string(raw) == "null" {
		return def, nil
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || f != float64(int(f)) || f < float64(minV) || f > float64(maxV) {
		return 0, argError{fmt.Sprintf("%s must be a whole number from %d to %d.", name, minV, maxV)}
	}
	return int(f), nil
}

func (a args) id(name string) (string, error) {
	s, ok, err := a.str(name, 96)
	if err != nil {
		return "", err
	}
	if !ok || !idRE.MatchString(s) {
		return "", argError{name + " is required: an id from a list tool."}
	}
	return s, nil
}

func (a args) page() (offset, limit int, err error) {
	if offset, err = a.num("offset", 0, maxOffset, 0); err != nil {
		return 0, 0, err
	}
	limit, err = a.num("limit", 1, maxLimit, defaultLimit)
	return offset, limit, err
}

// pageOf is one page of a list result.
type pageOf[T any] struct {
	Items      []T  `json:"items"`
	Total      int  `json:"total"`
	NextOffset *int `json:"next_offset"`
}

func paginate[T any](all []T, offset, limit int) pageOf[T] {
	p := pageOf[T]{Items: []T{}, Total: len(all)}
	if offset < len(all) {
		end := min(offset+limit, len(all))
		p.Items = all[offset:end]
		if end < len(all) {
			p.NextOffset = &end
		}
	}
	return p
}

// clip cuts s to n characters.
func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func clipPtr(s *string, n int) *string {
	if s == nil {
		return nil
	}
	c := clip(*s, n)
	return &c
}

// assetRow is a device in a list: without its services and software.
type assetRow struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	IP        *string `json:"ip"`
	Hostname  *string `json:"hostname"`
	Kind      string  `json:"kind"`
	Vendor    *string `json:"vendor"`
	Model     *string `json:"model"`
	OS        *string `json:"os"`
	Approved  bool    `json:"approved"`
	FirstSeen string  `json:"first_seen"`
	LastSeen  string  `json:"last_seen"`
}

func containsFold(p *string, q string) bool {
	return p != nil && strings.Contains(strings.ToLower(*p), q)
}

func listAssets(ctx context.Context, src Source, a args) (any, int, error) {
	q, _, err := a.str("query", 64)
	if err != nil {
		return nil, 0, err
	}
	kind, _, err := a.str("kind", 40)
	if err != nil {
		return nil, 0, err
	}
	offset, limit, err := a.page()
	if err != nil {
		return nil, 0, err
	}
	all, err := src.Assets(ctx)
	if err != nil {
		return nil, 0, err
	}
	q = strings.ToLower(strings.TrimSpace(q))
	rows := []assetRow{}
	for _, d := range all {
		if kind != "" && !strings.EqualFold(d.Kind, kind) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(d.Name), q) && !containsFold(d.IP, q) && !containsFold(d.Vendor, q) && !containsFold(d.Model, q) {
			continue
		}
		rows = append(rows, assetRow{d.ID, clip(d.Name, 256), d.IP, clipPtr(d.Hostname, 256), d.Kind, clipPtr(d.Vendor, 256), clipPtr(d.Model, 256), clipPtr(d.OS, 256), d.Approved, d.FirstSeen, d.LastSeen})
	}
	slices.SortStableFunc(rows, func(x, y assetRow) int { return strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)) })
	p := paginate(rows, offset, limit)
	return p, len(p.Items), nil
}

func getAsset(ctx context.Context, src Source, a args) (any, int, error) {
	id, err := a.id("id")
	if err != nil {
		return nil, 0, err
	}
	d, ok, err := src.Asset(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, argError{"There is no device with that id. Use list_assets to find it."}
	}
	d.Name, d.Hostname, d.Vendor, d.Model, d.OS = clip(d.Name, 256), clipPtr(d.Hostname, 256), clipPtr(d.Vendor, 256), clipPtr(d.Model, 256), clipPtr(d.OS, 256)
	if d.Services == nil {
		d.Services = []NetService{}
	}
	if d.Software == nil {
		d.Software = []Software{}
	}
	d.Services = d.Services[:min(len(d.Services), maxServices)]
	d.Software = d.Software[:min(len(d.Software), maxSoftware)]
	for i := range d.Services {
		s := &d.Services[i]
		s.Name, s.Product, s.Version = clip(s.Name, 128), clipPtr(s.Product, 256), clipPtr(s.Version, 128)
	}
	for i := range d.Software {
		s := &d.Software[i]
		s.Name, s.Vendor, s.Product, s.Version = clip(s.Name, 256), clip(s.Vendor, 256), clip(s.Product, 256), clipPtr(s.Version, 128)
	}
	return d, 1, nil
}

// findingRow is a finding in a list: without its evidence and history.
type findingRow struct {
	ID            string  `json:"id"`
	AssetID       string  `json:"asset_id"`
	CVE           string  `json:"cve"`
	Status        string  `json:"status"`
	Severity      string  `json:"severity"`
	Confidence    float64 `json:"confidence"`
	Basis         string  `json:"basis"`
	FirstSeen     string  `json:"first_seen"`
	LastSeen      string  `json:"last_seen"`
	ResolvedAt    *string `json:"resolved_at"`
	AcceptedUntil string  `json:"accepted_until,omitempty"`
}

func listFindings(ctx context.Context, src Source, a args) (any, int, error) {
	status, ok, err := a.str("status", 20)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		status = "open"
	}
	if !slices.Contains(statusE, status) {
		return nil, 0, argError{"status must be one of: " + strings.Join(statusE, ", ") + "."}
	}
	assetID, hasAsset, err := a.str("asset_id", 96)
	if err != nil {
		return nil, 0, err
	}
	cve, hasCVE, err := a.str("cve", 20)
	if err != nil {
		return nil, 0, err
	}
	if hasCVE && !cveRE.MatchString(cve) {
		return nil, 0, argError{"cve must look like CVE-2024-3400."}
	}
	offset, limit, err := a.page()
	if err != nil {
		return nil, 0, err
	}
	all, err := src.Findings(ctx)
	if err != nil {
		return nil, 0, err
	}
	rows := []findingRow{}
	for _, f := range all {
		switch {
		case status == "open" && f.Status != "confirmed" && f.Status != "suspected":
			continue
		case status != "open" && status != "all" && f.Status != status:
			continue
		case hasAsset && f.AssetID != assetID:
			continue
		case hasCVE && !strings.EqualFold(f.CVE, cve):
			continue
		}
		rows = append(rows, findingRow{f.ID, f.AssetID, f.CVE, f.Status, f.Severity, f.Confidence, f.Basis, f.FirstSeen, f.LastSeen, f.ResolvedAt, f.AcceptedUntil})
	}
	p := paginate(rows, offset, limit)
	return p, len(p.Items), nil
}

func getFinding(ctx context.Context, src Source, a args) (any, int, error) {
	id, err := a.id("id")
	if err != nil {
		return nil, 0, err
	}
	f, ok, err := src.Finding(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, argError{"There is no finding with that id. Use list_findings to find it."}
	}
	if f.Evidence != nil {
		e := *f.Evidence
		e.Template = clip(e.Template, 256)
		f.Evidence = &e
	}
	if f.History == nil {
		f.History = []HistoryStep{}
	}
	if n := len(f.History); n > maxHistory {
		f.History = f.History[n-maxHistory:]
	}
	return f, 1, nil
}

// cveAnswer is the result of lookup_cve.
type cveAnswer struct {
	CVE    string    `json:"cve"`
	Listed bool      `json:"listed"`
	Entry  *CVEEntry `json:"entry"`
}

func lookupCVE(ctx context.Context, src Source, a args) (any, int, error) {
	cve, ok, err := a.str("cve", 20)
	if err != nil {
		return nil, 0, err
	}
	if !ok || !cveRE.MatchString(cve) {
		return nil, 0, argError{"cve is required and must look like CVE-2024-3400."}
	}
	cve = strings.ToUpper(cve)
	e, found, err := src.CVE(ctx, cve)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return cveAnswer{CVE: cve}, 0, nil
	}
	e.Vendor, e.Product, e.Name = clip(e.Vendor, 256), clip(e.Product, 256), clip(e.Name, 512)
	e.Description, e.RequiredAction = clip(e.Description, maxText), clip(e.RequiredAction, maxText)
	links := []string{}
	for _, l := range e.Links[:min(len(e.Links), maxLinks)] {
		links = append(links, clip(l, 512))
	}
	e.Links = links
	return cveAnswer{CVE: cve, Listed: true, Entry: &e}, 1, nil
}

func lookupIOC(ctx context.Context, src Source, a args) (any, int, error) {
	v, ok, err := a.str("value", 253)
	if err != nil {
		return nil, 0, err
	}
	if !ok || strings.TrimSpace(v) == "" {
		return nil, 0, argError{"value is required: an IP address or a domain."}
	}
	v = strings.TrimSpace(v)
	if _, ipErr := netip.ParseAddr(v); ipErr != nil && !validDomain(v) { // checked here: no feeds search for a word
		return nil, 0, argError{"value must be an IP address or a domain name (no URL, no port)."}
	}
	ans, err := src.IOC(ctx, v)
	if errors.Is(err, ErrNotIOC) {
		return nil, 0, argError{"value must be an IP address or a domain name (no URL, no port)."}
	}
	if err != nil {
		return nil, 0, err
	}
	if ans.Sources == nil {
		ans.Sources = []string{}
	}
	ans.Category = clip(ans.Category, 256)
	for i := range ans.Sources {
		ans.Sources[i] = clip(ans.Sources[i], 128)
	}
	n := 0
	if ans.Listed {
		n = 1
	}
	return ans, n, nil
}

func hotVulnerabilities(ctx context.Context, src Source, a args) (any, int, error) {
	window, ok, err := a.str("window", 3)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		window = "7d"
	}
	if window != "24h" && window != "7d" {
		return nil, 0, argError{"window must be 24h or 7d."}
	}
	offset, limit, err := a.page()
	if err != nil {
		return nil, 0, err
	}
	all, err := src.Hot(ctx, window)
	if err != nil {
		return nil, 0, err
	}
	for i := range all {
		all[i].Vendor, all[i].Product = clip(all[i].Vendor, 256), clip(all[i].Product, 256)
	}
	slices.SortStableFunc(all, func(x, y HotCVE) int {
		if c := strings.Compare(y.DateAdded, x.DateAdded); c != 0 {
			return c
		}
		return strings.Compare(y.CVE, x.CVE)
	})
	p := paginate(all, offset, limit)
	return p, len(p.Items), nil
}

// allowedArgs are the argument names of each tool's input schema.
var allowedArgs = map[string][]string{
	"list_assets":         {"query", "kind", "offset", "limit"},
	"get_asset":           {"id"},
	"list_findings":       {"status", "asset_id", "cve", "offset", "limit"},
	"get_finding":         {"id"},
	"lookup_cve":          {"cve"},
	"lookup_ioc":          {"value"},
	"hot_vulnerabilities": {"window", "offset", "limit"},
}

// validDomain is a copy of the rule of modules/feeds (normalize.go validDomain; modules do not import each other), as the AI's
// lookup_ioc has it, so the tool takes every name a feed can list, an IDN top-level domain in its ASCII form (`discord.xn--q9jyb4c`)
// among them: at most 253 bytes, two or more labels; every label but the last is 1 to 63 of a-z, A-Z, 0-9 and "-" with no "-" at
// either end, the last is 2 to 63 letters or "xn--" and letters, digits and "-" not ending in "-". Feeds decides whether it can be
// an indicator.
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
