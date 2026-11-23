package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
)

// The Devices search (#849, S-INV-1, S-INV-3): two lists (approved, To review) and one search box with filters, in the style of
// runZero and Lansweeper. GET /inventory/devices and GET /inventory/export.csv take the same query, so the page, its URL and the CSV
// it exports mean the same devices.

// SourceWords are the words of the search's source: filter and of DeviceRow.sources, in this order (contract.ts DeviceSource).
// scan is nmap or a vulnerability scan. osquery and Wazuh both write source agent: osquery is the device its node key is bound to
// (inv_asset.agent_key), Wazuh a device at an address or MAC the saved Wazuh connection delivered to (Config.WazuhAgents).
var SourceWords = []string{"manual", "passive", "scan", "snmp", "osquery", "wazuh"}

// DeviceFilter is the query of the Devices search. Every set field narrows the list (AND); a list matches any of its values (OR).
// The zero filter keeps every device (Devices, for the other modules: the honeypot names an ignored device too).
type DeviceFilter struct {
	Approved, Fragile, HasFindings *bool
	// Ignored keeps only the ignored devices (true) or leaves them out (false); nil keeps both. ParseDeviceFilter, the query of
	// the page and the export, never leaves it nil: an ignored device is out of the Devices list unless asked for.
	Ignored *bool
	Types   []string // device type ids; a type also matches the types that act as it
	Sources []string // SourceWords
	Risks   []string // RiskLevels
	Q       string   // free text: name, IP, MAC (any notation), vendor, model
	// Software keeps the devices with a software line whose "name vendor product" holds one of these words (lower case): the
	// search's software: (SoftwareWords). GET /inventory/devices then lists the matching lines of each row.
	Software []string
}

// SoftwareWords reads the software filter: comma-separated words, lower case, each once, at most 80 characters each.
func SoftwareWords(v string) ([]string, error) {
	words := listFilter(v)
	for _, w := range words {
		if len([]rune(w)) > 80 {
			return nil, badFilter("Search software for at most 80 characters.")
		}
	}
	return words, nil
}

func badFilter(msg string) *apierr.Error { return apierr.New(400, "bad_filter", msg) }

// ParseDeviceFilter checks the query of GET /inventory/devices: approved, fragile and has_findings are "true", "false" or empty; type
// and source are comma-separated lists of known words (a type id of content/devicetypes, SourceWords). Anything else is 400
// bad_filter. The schema already bounds the lengths and the boolean words (400 invalid); this is the same check for a caller
// that does not go through it. ignored is "true" (only the ignored devices) or "false"/empty (leave them out).
func ParseDeviceFilter(approved, fragile, hasFindings, ignored, types, sources, q string) (DeviceFilter, error) {
	return ParseDeviceSearch(approved, fragile, hasFindings, ignored, types, sources, "", q)
}

// ParseDeviceSearch is ParseDeviceFilter with the risk filter: a comma-separated list of RiskLevels.
func ParseDeviceSearch(approved, fragile, hasFindings, ignored, types, sources, risks, q string) (DeviceFilter, error) {
	var f DeviceFilter
	var err error
	if f.Ignored, err = boolFilter("ignored", ignored); err != nil {
		return f, err
	}
	if f.Ignored == nil {
		no := false
		f.Ignored = &no
	}
	if f.Approved, err = boolFilter("approved", approved); err != nil {
		return f, err
	}
	if f.Fragile, err = boolFilter("fragile", fragile); err != nil {
		return f, err
	}
	if f.HasFindings, err = boolFilter("has_findings", hasFindings); err != nil {
		return f, err
	}
	for _, t := range listFilter(types) {
		if !devicetypes.Valid(t) {
			return f, badFilter(fmt.Sprintf("%q is not a device type. Use a type id such as server, switch, firewall or printer.", clipText(t, 40)))
		}
		f.Types = append(f.Types, t)
	}
	for _, src := range listFilter(sources) {
		if !slices.Contains(SourceWords, src) {
			return f, badFilter(fmt.Sprintf("%q is not a source. Use one of: %s.", clipText(src, 40), strings.Join(SourceWords, ", ")))
		}
		f.Sources = append(f.Sources, src)
	}
	for _, r := range listFilter(risks) {
		if !slices.Contains(RiskLevels, r) {
			return f, badFilter(fmt.Sprintf("%q is not a risk. Use one of: %s.", clipText(r, 40), strings.Join(RiskLevels, ", ")))
		}
		f.Risks = append(f.Risks, r)
	}
	f.Q = strings.TrimSpace(q)
	if len([]rune(f.Q)) > 80 {
		return f, badFilter("Search for at most 80 characters.")
	}
	return f, nil
}

func boolFilter(name, v string) (*bool, error) {
	switch v {
	case "":
		return nil, nil
	case "true", "false":
		b := v == "true"
		return &b, nil
	}
	return nil, badFilter(fmt.Sprintf("%s takes true or false.", name))
}

// listFilter splits a comma-separated value into its words, lower case, each once; empty words are ignored.
func listFilter(v string) []string {
	var out []string
	for _, w := range strings.Split(v, ",") {
		if w = strings.ToLower(strings.TrimSpace(w)); w != "" && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

func clipText(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

var (
	macColons = regexp.MustCompile(`^[0-9a-f]{2}([:-][0-9a-f]{2})+$`)             // aa:bb, AA-BB-CC: two bytes or more
	macDotted = regexp.MustCompile(`^([0-9a-f]{4}\.)+[0-9a-f]{2}([0-9a-f]{2})?$`) // Cisco: aabb.ccdd.eeff, aabb.cc
	macPlain  = regexp.MustCompile(`^([0-9a-f]{2}){3,6}$`)                        // aabbcc (an OUI) up to the whole MAC
)

// macFragment is the search text as whole bytes of a MAC in the stored form ("aa:bb:cc"), when it is written like at least two bytes
// of one: colons or dashes between pairs of digits, Cisco's dotted groups of four, or 6 to 12 plain hex digits. Matched against the
// stored aa:bb:cc:dd:ee:ff, the colons line the bytes up, so "bc:c0" never matches aa:bb:cc:00 across a byte boundary. "1-2", "10-20",
// "192.168" and "cafe" are not MAC pieces (#855 r1 L4).
func macFragment(q string) (string, bool) {
	q = strings.ToLower(q)
	if !macColons.MatchString(q) && !macDotted.MatchString(q) && !macPlain.MatchString(q) {
		return "", false
	}
	hex := strings.NewReplacer(":", "", "-", "", ".", "").Replace(q)
	bytes := make([]string, 0, len(hex)/2)
	for i := 0; i+1 < len(hex); i += 2 {
		bytes = append(bytes, hex[i:i+2])
	}
	return strings.Join(bytes, ":"), true
}

// where is the WHERE clause on inv_asset a that keeps the devices of f, and its arguments. sources and risks are every device's
// sources and statuses (deviceSources, risks); has_findings reads the open findings from the statuses. Sets of ids go in as one JSON argument (json_each),
// never as text.
func (f DeviceFilter) where(sources map[string][]string, risks map[string]*Risk) (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, arg any) { conds, args = append(conds, cond), append(args, arg) }
	jsonList := func(v []string) string {
		if v == nil {
			v = []string{}
		}
		raw, _ := json.Marshal(v)
		return string(raw)
	}
	if f.Ignored != nil {
		add("(a.ignored_at IS NOT NULL) = ?", *f.Ignored)
	}
	if f.Approved != nil {
		if *f.Approved { // the Devices list: approved, and the quiet ones (INV-49); To review is everything else not approved
			conds = append(conds, "NOT "+toReviewSQL)
		} else {
			conds = append(conds, toReviewSQL)
		}
	}
	if f.Fragile != nil {
		add("a.fragile = ?", *f.Fragile)
	}
	if len(f.Types) > 0 { // every type that acts as one asked too: type=server finds a hypervisor
		add("a.kind IN (SELECT value FROM json_each(?))", jsonList(devicetypes.ActingAs(f.Types)))
	}
	if len(f.Sources) > 0 {
		var ids []string
		for id, list := range sources {
			if slices.ContainsFunc(list, func(s string) bool { return slices.Contains(f.Sources, s) }) {
				ids = append(ids, id)
			}
		}
		add("a.id IN (SELECT value FROM json_each(?))", jsonList(ids))
	}
	if f.HasFindings != nil { // open findings: the device has a status of one of the five layers (needs_input alone is no finding)
		var ids []string
		for id, r := range risks {
			if r != nil && r.Code != RiskNeedsInput {
				ids = append(ids, id)
			}
		}
		op := "IN"
		if !*f.HasFindings {
			op = "NOT IN"
		}
		add("a.id "+op+" (SELECT value FROM json_each(?))", jsonList(ids))
	}
	if len(f.Risks) > 0 { // none is every device without a marker, so it is the complement of the marked ones not asked
		var in, out []string
		for id, r := range risks {
			if slices.Contains(f.Risks, riskLevel(r)) {
				in = append(in, id)
			} else {
				out = append(out, id)
			}
		}
		// the box is never marked: it is "none" whatever findings say of it
		if slices.Contains(f.Risks, RiskNone) {
			add("(a.is_box = 1 OR a.id NOT IN (SELECT value FROM json_each(?)))", jsonList(out))
		} else {
			add("(a.is_box = 0 AND a.id IN (SELECT value FROM json_each(?)))", jsonList(in))
		}
	}
	if f.Q != "" {
		// lower() on both sides: SQLite folds ASCII only, so the text and the data fold the same way. The text is passed once per use
		// (no numbered parameters: the clause is also used inside the subqueries of loadDevices).
		const like = "instr(lower(%s), lower(?)) > 0"
		parts := []string{
			fmt.Sprintf(like, "coalesce(a.user_name, '')"), fmt.Sprintf(like, "coalesce(a.hostname, '')"), "instr(coalesce(a.ip, ''), ?) > 0",
			fmt.Sprintf(like, "coalesce(a.vendor, '')"), fmt.Sprintf(like, "coalesce(a.model, '')"),
			"(a.origin = 'manual' AND EXISTS (SELECT 1 FROM inv_software sq WHERE sq.asset_id = a.id AND sq.state = 'present' AND " + fmt.Sprintf(like, "sq.display") + "))",
			// the maker a person's declared OS row may give the device (INV-45); Device.shows keeps it only when the row shows it
			"EXISTS (SELECT 1 FROM inv_software sv WHERE sv.asset_id = a.id AND sv.source = 'manual' AND sv.state = 'present' AND " + fmt.Sprintf(like, "sv.vendor") + ")",
		}
		qa := []any{f.Q, f.Q, f.Q, f.Q, f.Q, f.Q, f.Q}
		if keys := modelKeys(f.Q); len(keys) > 0 { // the model a person's declared OS row may give the device (INV-45: "FortiGate"); Device.shows decides
			parts = append(parts, "EXISTS (SELECT 1 FROM inv_software sm WHERE sm.asset_id = a.id AND sm.source = 'manual' AND sm.state = 'present' AND lower(sm.vendor) || '|' || lower(sm.product) IN (SELECT value FROM json_each(?)))")
			qa = append(qa, jsonList(keys))
		}
		if hex, ok := macFragment(f.Q); ok {
			parts, qa = append(parts, "instr(coalesce(a.mac, ''), ?) > 0"), append(qa, hex) // a.mac is stored lower case aa:bb:…
		}
		conds, args = append(conds, "("+strings.Join(parts, " OR ")+")"), append(args, qa...)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// deviceSources says, for every device, what feeds it in the words of SourceWords: a device added manually is manual; passive,
// snmp and nmap or scan (as scan) when that source left an observation, software or an open port on it; osquery when an osquery node
// is bound to it; Wazuh when it has data of source agent and its address or MAC is one the saved Wazuh connection delivered
// to. The box's own software (vedette-host's dpkg list) is source agent too and is neither.
func (s *Service) deviceSources(ctx context.Context, q querier) (map[string][]string, error) {
	have := map[string]map[string]bool{}
	mark := func(id, src string) {
		if have[id] == nil {
			have[id] = map[string]bool{}
		}
		have[id][src] = true
	}
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT asset_id, source FROM inv_observation
		UNION `+readingSourcesSQL+`
		UNION SELECT DISTINCT asset_id, source FROM inv_service`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read sources: %w", err)
	}
	for rows.Next() {
		var id, src string
		if err := rows.Scan(&id, &src); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read sources: %w", err)
		}
		switch src {
		case "passive", "snmp", "agent":
			mark(id, src)
		case "nmap", "scan":
			mark(id, "scan")
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("inventory: read sources: %w", err)
	}
	wIPs, wMACs := map[string]bool{}, map[string]bool{}
	if s.wazuh != nil {
		ips, macs, err := s.wazuh(ctx)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: the Wazuh agents could not be read; no device shows the source wazuh", "error", err.Error())
		}
		for _, ip := range ips {
			wIPs[ip] = true
		}
		for _, m := range macs {
			if n, ok := normMAC(m); ok {
				wMACs[n] = true
			}
		}
	}
	rows, err = q.QueryContext(ctx, `SELECT id, origin, coalesce(agent_key, ''), coalesce(ip, ''), coalesce(mac, '') FROM inv_asset`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read sources: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var id, origin, key, ip, mac string
		if err := rows.Scan(&id, &origin, &key, &ip, &mac); err != nil {
			return nil, fmt.Errorf("inventory: read sources: %w", err)
		}
		h := have[id]
		if origin == "manual" {
			mark(id, "manual")
			h = have[id]
		}
		if strings.HasPrefix(key, "osquery:") {
			mark(id, "osquery")
			h = have[id]
		}
		if h["agent"] && (ip != "" && wIPs[ip] || mac != "" && wMACs[mac]) {
			mark(id, "wazuh")
			h = have[id]
		}
		list := []string{}
		for _, src := range SourceWords {
			if h[src] {
				list = append(list, src)
			}
		}
		out[id] = list
	}
	return out, rows.Err()
}

// shows says whether what the device's row shows holds the search text q (DeviceFilter.Q, case-insensitive): the name a person gave
// it, its host name, IP, MAC (any notation), the maker and model the row shows (a person's declared OS row may give them, INV-45),
// and, for a device added by hand, the products it runs. The query finds candidates by the stored values; this keeps only the devices
// whose row shows the text, so the search never returns a device for a model, OS or software its row does not show.
func (d Device) shows(q string) bool {
	has := func(v string) bool { return strings.Contains(strings.ToLower(v), strings.ToLower(q)) }
	if has(deref(d.UserName)) || has(deref(d.Hostname)) || d.IP != noIP && strings.Contains(d.IP, q) || has(obsValue(d.Vendor)) || has(obsValue(d.Model)) {
		return true
	}
	if hex, ok := macFragment(q); ok && strings.Contains(deref(d.MAC), hex) {
		return true
	}
	return d.Origin == "manual" && slices.ContainsFunc(d.Running(), func(s Software) bool { return has(s.Display) })
}
