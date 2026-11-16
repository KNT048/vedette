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

// DeviceSources are the words of the search's source: filter and of DeviceRow.sources, in this order (contract.ts DeviceSource).
// scan is nmap or a vulnerability scan. osquery and Wazuh both write source agent: osquery is the device its node key is bound to
// (D-598, inv_asset.agent_key), Wazuh a device at an address or MAC the saved Wazuh connection delivered to (Config.WazuhAgents).
var DeviceSources = []string{"manual", "passive", "scan", "snmp", "osquery", "wazuh"}

// DeviceFilter is the query of the Devices search. Every set field narrows the list (AND); a list matches any of its values (OR).
// The zero filter keeps every device.
type DeviceFilter struct {
	Approved, Fragile, HasFindings *bool
	Types                          []string // device type ids; a type also matches the types that act as it (D-511)
	Sources                        []string // DeviceSources
	Q                              string   // free text: name, IP, MAC (any notation), vendor, model
}

func badFilter(msg string) *apierr.Error { return apierr.New(400, "bad_filter", msg) }

// ParseDeviceFilter checks the query of GET /inventory/devices: approved, fragile and has_findings are "true", "false" or empty; type
// and source are comma-separated lists of known words (a type id of content/devicetypes, DeviceSources). Anything else is 400
// bad_filter. The schema already bounds the lengths and the boolean words (400 invalid, D-73); this is the same check for a caller
// that does not go through it.
func ParseDeviceFilter(approved, fragile, hasFindings, types, sources, q string) (DeviceFilter, error) {
	var f DeviceFilter
	var err error
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
		if !slices.Contains(DeviceSources, src) {
			return f, badFilter(fmt.Sprintf("%q is not a source. Use one of: %s.", clipText(src, 40), strings.Join(DeviceSources, ", ")))
		}
		f.Sources = append(f.Sources, src)
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
	macDotted = regexp.MustCompile(`^([0-9a-f]{4}\.)+[0-9a-f]{1,4}$`)          // Cisco: aabb.ccdd.eeff
	macColons = regexp.MustCompile(`^[0-9a-f]{1,2}([:-][0-9a-f]{1,2})+[:-]?$`) // aa:bb:cc, aa-bb-cc
	macPlain  = regexp.MustCompile(`^[0-9a-f]{4,12}$`)                         // aabbcc
	hexLetter = regexp.MustCompile(`[a-f]`)
)

// macFragment is the search text as the hex digits of a piece of MAC, when it is written like one: with colons or dashes, Cisco's
// dotted groups of four, or plain hex of at least 6 digits (4 when it has a letter). "192.168" and "10" are not MAC pieces: they find
// addresses only.
func macFragment(q string) (string, bool) {
	q = strings.ToLower(q)
	switch {
	case macDotted.MatchString(q), macColons.MatchString(q):
	case macPlain.MatchString(q) && (len(q) >= 6 || hexLetter.MatchString(q)):
	default:
		return "", false
	}
	return strings.NewReplacer(":", "", "-", "", ".", "").Replace(q), true
}

// where is the WHERE clause on inv_asset a that keeps the devices of f, and its arguments. sources and counts are every device's
// sources and finding counts (deviceSources, findingCounts). Sets of ids go in as one JSON argument (json_each), never as text.
func (f DeviceFilter) where(sources map[string][]string, counts map[string]int) (string, []any) {
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
	if f.Approved != nil {
		add("a.approved = ?", *f.Approved)
	}
	if f.Fragile != nil {
		add("a.fragile = ?", *f.Fragile)
	}
	if len(f.Types) > 0 { // every type that acts as one asked too: type=server finds a hypervisor (D-511)
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
	if f.HasFindings != nil {
		var ids []string
		for id, n := range counts {
			if n > 0 {
				ids = append(ids, id)
			}
		}
		op := "IN"
		if !*f.HasFindings {
			op = "NOT IN"
		}
		add("a.id "+op+" (SELECT value FROM json_each(?))", jsonList(ids))
	}
	if f.Q != "" {
		// lower() on both sides: SQLite folds ASCII only, so the text and the data fold the same way. The text is passed once per use
		// (no numbered parameters: the clause is also used inside the subqueries of loadDevices).
		const like = "instr(lower(%s), lower(?)) > 0"
		parts := []string{
			fmt.Sprintf(like, "coalesce(a.hostname, '')"), "instr(coalesce(a.ip, ''), ?) > 0",
			fmt.Sprintf(like, "coalesce(a.vendor, '')"), fmt.Sprintf(like, "coalesce(a.model, '')"),
			"(a.origin = 'manual' AND EXISTS (SELECT 1 FROM inv_software sq WHERE sq.asset_id = a.id AND " + fmt.Sprintf(like, "sq.display") + "))",
		}
		qa := []any{f.Q, f.Q, f.Q, f.Q, f.Q}
		if hex, ok := macFragment(f.Q); ok {
			parts, qa = append(parts, "instr(replace(coalesce(a.mac, ''), ':', ''), ?) > 0"), append(qa, hex)
		}
		conds, args = append(conds, "("+strings.Join(parts, " OR ")+")"), append(args, qa...)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// deviceSources says, for every device, what feeds it in the words of DeviceSources: a device added manually is manual; passive,
// snmp and nmap or scan (as scan) when that source left an observation, software or an open port on it; osquery when an osquery node
// is bound to it (D-598); Wazuh when it has data of source agent and its address or MAC is one the saved Wazuh connection delivered
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
		UNION SELECT DISTINCT asset_id, source FROM inv_software
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
		for _, src := range DeviceSources {
			if h[src] {
				list = append(list, src)
			}
		}
		out[id] = list
	}
	return out, rows.Err()
}
