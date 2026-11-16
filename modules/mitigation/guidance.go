package mitigation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/findings"
)

// Provider is the "What to do" provider findings asks for (PRE-1, POST-1). Register it with
// findings.FindingHandlers.SetGuidance.
type Provider struct {
	db      *store.DB
	vendors Vendors
	ai      AI
}

// NewProvider returns the provider.
func NewProvider(db *store.DB, vendors Vendors, ai AI) (*Provider, error) {
	if db == nil || vendors == nil || ai == nil {
		return nil, errors.New("mitigation: creating provider: db, vendors and ai are required")
	}
	return &Provider{db: db, vendors: vendors, ai: ai}, nil
}

// inventoryVendor maps a guide's vendor to the vendor name the inventory records (INV-5). The generic
// guide has no vendor and is never "detected".
var inventoryVendor = map[string]string{"fortigate": "fortinet", "mikrotik": "mikrotik"}

// Guidance implements findings.Guidance.
func (p *Provider) Guidance(ctx context.Context, r findings.Row) (findings.Guide, error) {
	var g findings.Guide
	repl := deviceReplacer(r.Asset)

	pack, compromise, recheck, err := p.loadPack(ctx, r.CVE, repl)
	if err != nil {
		return g, err
	}
	if pack != nil {
		for i := range pack.Firewall {
			v, ok := inventoryVendor[pack.Firewall[i].Vendor]
			if !ok {
				continue
			}
			if pack.Firewall[i].Detected, err = p.vendors.HasFirewallVendor(ctx, v); err != nil {
				return g, fmt.Errorf("mitigation: looking up firewall vendor: %w", err)
			}
		}
	}
	g.Pack, g.Compromise = pack, compromise
	g.Recheck = genericRecheck(r)
	if recheck != nil {
		g.Recheck = *recheck
	}
	if g.Applied, err = p.applied(ctx, r.ID); err != nil {
		return g, err
	}
	if g.AI, err = p.aiOutputs(ctx, r.ID); err != nil {
		return g, err
	}
	g.AIAvailable = findings.AIAvailable{Explain: p.ai.Available(ctx, SkillExplain), Config: p.ai.Available(ctx, SkillConfig)}
	return g, nil
}

func (p *Provider) loadPack(ctx context.Context, cve string, repl *strings.Replacer) (*findings.MitigationPack, *findings.CompromiseCheck, *findings.Recheck, error) {
	var (
		body, by, drafted, at string
		comp                  sql.NullString
	)
	err := p.db.Reader().QueryRowContext(ctx, `SELECT body, compromise, confirmed_by, confirmed_at, drafted_with FROM mit_pack WHERE cve = ?`, cve).
		Scan(&body, &comp, &by, &at, &drafted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil, nil // no confirmed pack: pack is null (INV-2)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitigation: reading pack: %w", err)
	}
	confirmedAt, err := time.Parse("2006-01-02T15:04:05.000Z", at)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mitigation: reading pack: %w", err)
	}
	var b packBody
	if err := substituteInto(body, repl, &b); err != nil {
		return nil, nil, nil, fmt.Errorf("mitigation: reading pack: %w", err)
	}
	pack := &findings.MitigationPack{
		CVE: cve, ConfirmedBy: by, ConfirmedAt: confirmedAt, DraftedWith: drafted,
		Sources: b.Sources, Patch: b.Patch, Workaround: b.Workaround, Firewall: b.Firewall, Checklist: b.Checklist,
	}
	var check *findings.CompromiseCheck
	if comp.Valid {
		check = new(findings.CompromiseCheck)
		if err := substituteInto(comp.String, repl, check); err != nil {
			return nil, nil, nil, fmt.Errorf("mitigation: reading pack: %w", err)
		}
	}
	return pack, check, b.Recheck, nil
}

func (p *Provider) applied(ctx context.Context, findingID string) ([]findings.AppliedEntry, error) {
	rows, err := p.db.Reader().QueryContext(ctx, `SELECT item, ts, user FROM mit_applied WHERE finding_id = ? ORDER BY ts, item`, findingID)
	if err != nil {
		return nil, fmt.Errorf("mitigation: reading applied items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []findings.AppliedEntry
	for rows.Next() {
		var e findings.AppliedEntry
		var ts string
		if err := rows.Scan(&e.Item, &ts, &e.User); err != nil {
			return nil, fmt.Errorf("mitigation: reading applied items: %w", err)
		}
		if e.TS, err = time.Parse("2006-01-02T15:04:05.000Z", ts); err != nil {
			return nil, fmt.Errorf("mitigation: reading applied items: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (p *Provider) aiOutputs(ctx context.Context, findingID string) (findings.AIResults, error) {
	var out findings.AIResults
	rows, err := p.db.Reader().QueryContext(ctx, `SELECT skill, payload FROM mit_ai_output WHERE finding_id = ?`, findingID)
	if err != nil {
		return out, fmt.Errorf("mitigation: reading AI results: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var skill, payload string
		if err := rows.Scan(&skill, &payload); err != nil {
			return out, fmt.Errorf("mitigation: reading AI results: %w", err)
		}
		var r findings.AIResult
		if err := json.Unmarshal([]byte(payload), &r); err != nil {
			return out, fmt.Errorf("mitigation: reading AI results: %w", err)
		}
		switch Skill(skill) {
		case SkillExplain:
			out.Explain = &r
		case SkillConfig:
			out.Config = &r
		}
	}
	return out, rows.Err()
}

// genericRecheck is the "check again" text when the pack carries none (the mock's wording). The device is named as the
// Devices page names it, never by its id, and "Rescan this device" is only offered for a device with an IP (D-484).
func genericRecheck(r findings.Row) findings.Recheck {
	reachable := r.Asset.HasIP()
	if r.Basis == findings.BasisScan && reachable {
		return findings.Recheck{Steps: []string{`Run the scan template again with the "Rescan this device" button.`}}
	}
	device, software, hasTemplate := "the device", "the software", false
	if r.Asset != nil && r.Asset.Name != "" {
		device = r.Asset.Name
	}
	if r.Kev != nil {
		software, hasTemplate = r.Kev.Display, r.Kev.HasTemplate
		if software == "" {
			software = r.Kev.Vendor + " " + r.Kev.Product
		}
	}
	if r.Evidence != nil && r.Evidence.Agent { // D-548: the agent reports the installed version; nothing to look up
		steps := []string{
			fmt.Sprintf("Nothing to look up: the agent on %s reports the installed version of %s, and Vedette compared it with the affected versions (Evidence above).", device, software),
			"Install the update (What to do below). The agent reports the new version by itself, usually within two hours (after the restart the update needs), and Vedette then closes this finding by itself.",
		}
		if hasTemplate && reachable {
			steps = append(steps, `This CVE also has a safe scan template: "Rescan this device" checks it from the network.`)
		}
		return findings.Recheck{Steps: steps}
	}
	if k := r.Known; k != nil && k.Version != "" { // M2-3: the box has the version, whoever gave it; never "find which version"
		return knownRecheck(r, k, device, hasTemplate, reachable)
	}
	last := "This CVE has no safe scan template yet, so Vedette can only conclude from the version. Check by hand as above."
	first := fmt.Sprintf("Check which version of %s runs on %s (in its settings, its admin page or its About screen).", software, device)
	if r.Evidence != nil && r.Evidence.AgentRow { // N52-2: the agent reported the installed version; it is the comparison that failed
		first = fmt.Sprintf("Nothing to look up on %s: its agent reports the installed version of %s (Evidence above), but Vedette cannot compare it with the versions NVD lists for this CVE.", device, software)
	}
	switch {
	case hasTemplate && reachable:
		last = `This CVE has a safe scan template: click "Rescan this device" to confirm.`
	case hasTemplate:
		last = "This CVE has a safe scan template, but this device has no IP address in your inventory, so it cannot be scanned. Add its IP on the device page to scan it, or check by hand as above."
	}
	return findings.Recheck{Steps: []string{
		first,
		"Compare it with the fixed version in the vendor advisory (link in the source section). An older version means the flaw is still there.",
		last,
	}}
}

// knownRecheck is genericRecheck for a finding whose software has a version on the box (M2-3, widening D-548/D-612 to every
// source): it says the version, who gave it, and how a newer one reaches Vedette, then what a scan template adds.
func knownRecheck(r findings.Row, k *findings.KnownVersion, device string, hasTemplate, reachable bool) findings.Recheck {
	sw := k.Software + " " + k.Version
	var from, again string
	switch k.Source {
	case findings.VersionByAgent:
		from = fmt.Sprintf("the agent on %s reports %s", device, sw)
		again = "its agent reports the new one by itself, usually within two hours"
	case findings.VersionBySNMP:
		from = fmt.Sprintf("Vedette read %s from %s over SNMP", sw, device)
		again = `press "Read with SNMP now" on its device page (Vedette also reads it again in each scan window)`
	case findings.VersionByStated:
		from = fmt.Sprintf("%s states on the network (LLDP) that it runs %s", device, sw)
		again = "it states the new one on the network by itself"
	case findings.VersionByScan:
		from = fmt.Sprintf("a network scan read %s from %s", sw, device)
		again = `rescan it with "Rescan this device"`
		if !reachable {
			again = "the next network scan of it reads the new one"
		}
	default: // findings.VersionByManual
		from = fmt.Sprintf("%s was entered for %s on the Devices page", sw, device)
		again = fmt.Sprintf(`press "I updated %s" at the top of this page and type the new one`, k.Software)
	}
	first := fmt.Sprintf("Nothing to look up: %s. Vedette compared it with the affected versions (Evidence above).", from)
	if r.Basis == findings.BasisProduct {
		first = fmt.Sprintf("Nothing to look up: %s (Evidence above), but Vedette cannot compare it with the versions NVD lists for this CVE: compare it with the fixed version in the vendor advisory (link in the source section).", from)
	}
	steps := []string{first, fmt.Sprintf("If %s now runs another version, %s: Vedette then closes the findings that version fixes.", device, again)}
	switch {
	case hasTemplate && reachable:
		steps = append(steps, `This CVE has a safe scan template: click "Rescan this device" to confirm.`)
	case hasTemplate:
		steps = append(steps, "This CVE has a safe scan template, but this device has no IP address in your inventory, so it cannot be scanned. Add its IP on the device page to scan it.")
	default:
		steps = append(steps, "This CVE has no safe scan template yet, so Vedette concludes from the version alone.")
	}
	return findings.Recheck{Steps: steps}
}

// hostRE is the host name rule of the product (rules/security.md): letters, digits, dot, dash, underscore.
var hostRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// deviceReplacer builds the {IP} and {HOST} substitution (INV-4). Device values are untrusted data
// that people paste into a shell or a firewall prompt, so a value goes in only if it is made of
// harmless characters: an IP must parse (no zone), a host name must match hostRE. Anything else is
// replaced by a visible placeholder, never escaped into the text, and a replaced value is never
// scanned again for placeholders (strings.Replacer works in one pass).
func deviceReplacer(a *findings.AssetView) *strings.Replacer {
	ip, host := "<IP>", "<HOST>"
	if a != nil {
		if addr, err := netip.ParseAddr(a.IP); err == nil && addr.Zone() == "" {
			ip = addr.String()
			host = ip
		}
		if a.Hostname != nil && hostRE.MatchString(*a.Hostname) {
			host = *a.Hostname
		}
	}
	return strings.NewReplacer("{IP}", ip, "{HOST}", host)
}

// substituteInto decodes the JSON document, replaces placeholders in every string value (never in
// keys) and decodes the result into dst.
func substituteInto(doc string, repl *strings.Replacer, dst any) error {
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		return err
	}
	b, err := json.Marshal(replaceStrings(v, repl))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

func replaceStrings(v any, repl *strings.Replacer) any {
	switch t := v.(type) {
	case string:
		return repl.Replace(t)
	case []any:
		for i := range t {
			t[i] = replaceStrings(t[i], repl)
		}
	case map[string]any:
		for k := range t {
			t[k] = replaceStrings(t[k], repl)
		}
	}
	return v
}

var _ findings.Guidance = (*Provider)(nil)
