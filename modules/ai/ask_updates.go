package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

// device_updates (J4, kien G9): "what do I upgrade on this device to clear its CVEs" in ONE call. The owner asked for the CVEs of a
// Windows PC with an osquery agent and the applications to upgrade; the model paged through 178 findings with get_finding until the
// tool limit, then guessed from the software list and said all of them "need confirming". The box already groups the findings by the
// update that fixes them (findings.DeviceUpdates: the Findings page's fix groups and "Recommended updates"), so the tool hands that
// over, with how each finding is known in words that never call an agent's version a guess.

const (
	// Every turn sends the descriptions again (D-482, TestAskBetaBoxQuestionStaysInBudget): the words are few, statusWords in the
	// result says the rest.
	deviceUpdatesDesc   = "What to install on one device to clear its CVEs, in one call (device: IP, name or asset_id): open exploited findings grouped by the update that fixes them, those with no named update, and recommended updates. Use it for what to upgrade. status: detected = the device's agent reported the version (not a guess, never \"needs confirming\"); suspected = a network guess; confirmed = a scan proved it."
	deviceUpdatesSchema = `{"type":"object","properties":{"device":{"type":"string","maxLength":96}},"required":["device"],"additionalProperties":false}`
	// statusWords is sent with every answer, so the model reads the words from the data and not only from the description.
	statusWords = "confirmed = a scan proved it. detected = the device's own agent or another trusted source reported the installed version and it is inside the affected range: not a guess, do not say it needs confirming. suspected = a network guess (banner, fingerprint, product name only): only these need confirming."
)

var deviceUpdatesArgs = map[string]argSpec{"device": {kind: "string", max: 96}}

// findDevice finds the device a model names by asset_id, IP address or name: an exact id, IP or name (any case) first, else the one
// device whose name contains it. more lists the candidates when several match (none is picked).
func findDevice(all []AssetRow, q string) (one AssetRow, more []AssetRow, ok bool) {
	q = strings.TrimSpace(q)
	if ip, err := netip.ParseAddr(q); err == nil {
		q = ip.Unmap().String()
	}
	pick := func(match func(AssetRow) bool) []AssetRow {
		var out []AssetRow
		for _, a := range all {
			if match(a) {
				out = append(out, a)
			}
		}
		return out
	}
	for _, match := range []func(AssetRow) bool{
		func(a AssetRow) bool { return a.ID == q },
		func(a AssetRow) bool { return a.IP != "" && a.IP == q },
		func(a AssetRow) bool { return strings.EqualFold(a.Name, q) },
		func(a AssetRow) bool { return q != "" && strings.Contains(strings.ToLower(a.Name), strings.ToLower(q)) },
	} {
		switch hit := pick(match); {
		case len(hit) == 1:
			return hit[0], nil, true
		case len(hit) > 1:
			return AssetRow{}, hit, false
		}
	}
	return AssetRow{}, nil, false
}

// knownAs says how the findings of an update are known, in the words of statusWords.
func knownAs(u UpdateRow) string {
	var parts []string
	for _, p := range []struct {
		n    int
		word string
	}{{u.Confirmed, "confirmed"}, {u.Detected, "detected"}, {u.Suspected, "suspected"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.word))
		}
	}
	if len(parts) == 1 {
		return strings.SplitN(parts[0], " ", 2)[1]
	}
	return strings.Join(parts, ", ")
}

func updateMap(u UpdateRow, exploited bool) map[string]any {
	m := map[string]any{"action": clip(u.Action, 200), "cves": len(u.CVEs)}
	put(m, "worst", clip(u.Worst, 12))
	if u.Ransomware > 0 {
		m["ransomware"] = u.Ransomware
	}
	if u.Likely > 0 {
		m["likely_exploited_soon"] = u.Likely
	}
	if exploited {
		m["status"] = knownAs(u)
	}
	m["top_cves"] = cleanAll(u.CVEs[:min(len(u.CVEs), 3)], 24)
	return m
}

func (s *Service) toolDeviceUpdates(ctx context.Context, d Data, up Updates, raw map[string]any) (toolOut, error) {
	all, err := d.Assets(ctx)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	dev, more, ok := findDevice(all, str(raw, "device"))
	if !ok {
		if len(more) > 0 {
			cands := []map[string]any{}
			for _, a := range more[:min(len(more), 8)] {
				c := map[string]any{"asset_id": clip(a.ID, 96), "name": clip(a.Name, 80)}
				put(c, "ip", clip(a.IP, 45))
				cands = append(cands, c)
			}
			b, _ := json.Marshal(map[string]any{"found": false, "note": fmt.Sprintf("%d devices match; call again with the asset_id of one.", len(more)), "candidates": cands})
			return toolOut{Text: string(b), Summary: plural(len(more), "device matches", "devices match"), Cite: inventoryCite(all)}, nil
		}
		return toolOut{Text: `{"found":false,"note":"No device has that IP address, name or id. search_assets finds devices by other words."}`, Summary: "no such device", Cite: inventoryCite(all)}, nil
	}
	u, ok, err := up.DeviceUpdates(ctx, dev.ID)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	if !ok {
		return toolOut{Text: `{"found":false,"note":"That device is no longer in the inventory."}`, Summary: "no such device", Cite: inventoryCite(all)}, nil
	}
	rows := func(us []UpdateRow, exploited bool) []map[string]any {
		out := []map[string]any{}
		for _, x := range us[:min(len(us), askRowsDefault)] {
			out = append(out, updateMap(x, exploited))
		}
		return out
	}
	ex, none, plan := rows(u.Exploited, true), rows(u.NoUpdate, true), rows(u.Planned, false)
	device := map[string]any{"asset_id": clip(dev.ID, 96), "name": clip(dev.Name, 80)}
	put(device, "ip", clip(dev.IP, 45))
	put(device, "os", clip(dev.OS, 80))
	exCVEs := 0
	for _, x := range u.Exploited {
		exCVEs += len(x.CVEs)
	}
	planNote := ""
	if !u.PlanRan {
		planNote = "The recommended updates are not compared yet (the box compares them a few minutes after it starts): say so, do not say there are none."
	}
	build := func(ne, nn, np int) any {
		note := fmt.Sprintf("%d open exploited findings: %d of them are fixed by the %d updates in exploited, %d have no named update. ", u.Open, exCVEs, len(u.Exploited), u.Open-exCVEs)
		for _, l := range []struct {
			what         string
			shown, total int
		}{{"exploited", ne, len(u.Exploited)}, {"no_named_update", nn, len(u.NoUpdate)}, {"recommended", np, len(u.Planned)}} {
			if l.shown < l.total {
				note += fmt.Sprintf("%s lists the first %d of %d: say \"%d (showing %d)\". ", l.what, l.shown, l.total, l.total, l.shown)
			}
		}
		return struct {
			Found          bool             `json:"found"`
			Device         map[string]any   `json:"device"`
			OpenFindings   int              `json:"open_exploited_findings"`
			Note           string           `json:"note"`
			StatusWords    string           `json:"status_words"`
			Updates        int              `json:"exploited_updates_total"`
			NoUpdates      int              `json:"no_named_update_total"`
			Recommended    int              `json:"recommended_total"`
			PlanNote       string           `json:"recommended_note,omitempty"`
			Exploited      []map[string]any `json:"exploited"`
			NoUpdate       []map[string]any `json:"no_named_update"`
			RecommendedTop []map[string]any `json:"recommended"`
		}{true, device, u.Open, strings.TrimSpace(note), statusWords, len(u.Exploited), len(u.NoUpdate), len(u.Planned), planNote, ex[:ne], none[:nn], plan[:np]}
	}
	text, ne := fitUpdates(len(ex), len(none), len(plan), build)
	t := &AskTable{Columns: []string{"Update", "Fixes", "Worst", "Status"}, Rows: []AskRow{}}
	for _, x := range u.Exploited[:ne] {
		t.Rows = append(t.Rows, AskRow{Href: "/devices/" + clip(dev.ID, 96), Cells: []string{clip(x.Action, 200), plural(len(x.CVEs), "exploited CVE", "exploited CVEs"), clip(x.Worst, 12), knownAs(x)}})
	}
	out := toolOut{Text: text, Summary: fmt.Sprintf("%s, %s", plural(len(u.Exploited), "update", "updates"), plural(len(u.Planned), "recommended", "recommended")),
		Cite: "Findings and Recommended updates: " + clip(dev.Name, 80)}
	if len(t.Rows) > 0 {
		out.Table = t
	}
	return out, nil
}

// fitUpdates returns the JSON of build with as many rows of the three lists as fit askResultBytes: the recommended ones go first,
// then the ones with no named update, then the exploited updates; the totals and the note are never cut (W1-27). ne is how many
// exploited rows were kept.
func fitUpdates(ne, nn, np int, build func(ne, nn, np int) any) (string, int) {
	for {
		b, err := json.Marshal(build(ne, nn, np))
		if err == nil && len(b) <= askResultBytes {
			return string(b), ne
		}
		switch {
		case np > 3:
			np--
		case nn > 3:
			nn--
		case ne > 5:
			ne--
		case np > 0:
			np--
		case nn > 0:
			nn--
		case ne > 0:
			ne--
		default:
			return string(b), 0
		}
	}
}
