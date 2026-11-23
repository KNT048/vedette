package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// device_updates: "what do I upgrade on this device to clear its CVEs" in ONE call. The owner asked for the CVEs of a
// Windows PC with an osquery agent and the applications to upgrade; the model paged through 178 findings with get_finding until the
// tool limit, then guessed from the software list and said all of them "need confirming". The box already groups the findings by the
// update that fixes them (findings.DeviceUpdates: the Findings page's fix groups and "Recommended updates"), so the tool hands that
// over, with how each finding is known in words that never call an agent's version a guess.

// How it fits the loop (review r2 M of #935): a question gets 12 KB of tool results (askTotalBytes) and, after the first turn, tool
// turns only while the input budget holds (askInputBudget), which in practice is two calls of this tool. So a row is one line
// ("Upgrade X from a to b or later; 12 CVEs, worst critical, detected"), the CVE ids are left out (list_findings with the asset_id and
// a cve, or get_finding, give the evidence of one), the status words and the device go only with the first call, and a call fills
// up to 4 KB with as many rows as fit: about 30 on the first call, 40 on a page, so a device with 70 updates is read in two calls.
// The loop's caps are unchanged.

const (
	// Every turn sends the descriptions again (TestAskBetaBoxQuestionStaysInBudget): the words are few, statusWords in the
	// result says the rest.
	deviceUpdatesDesc   = "What to install on one device to clear its CVEs, in one call (device: IP, name or asset_id): open exploited findings grouped by the update that fixes them, those with no named update, and recommended updates. Use it for what to upgrade; part and offset page one list. status: detected = the agent reported the version (never say it needs confirming); suspected = a network guess."
	deviceUpdatesSchema = `{"type":"object","properties":{"device":{"type":"string","minLength":1,"maxLength":96},"part":{"type":"string","enum":["exploited","no_named_update","recommended"]},"offset":{"type":"integer","minimum":0,"maximum":1000}},"required":["device"],"additionalProperties":false}`
	// statusWords is sent with the first call of a device, so the model reads the words from the data and not only from the description.
	statusWords = "confirmed = a scan proved it. detected = the device's own agent or another trusted source reported the installed version and it is inside the affected range: not a guess, do not say it needs confirming. suspected = a network guess (banner, fingerprint, product name only): only these need confirming."
	// updatesRowsMax is how many rows of one list a call returns at most, before what fits askResultBytes.
	updatesRowsMax = askRowsMax
)

var (
	updateParts       = []string{"exploited", "no_named_update", "recommended"}
	deviceUpdatesArgs = map[string]argSpec{"device": {kind: "string", re: regexp.MustCompile(`\S`), max: 96}, "part": {kind: "string", enum: updateParts},
		"offset": {kind: "int", min: 0, max: 1000}}
	// updateFloors are the rows each list keeps on a first call before another list loses one (exploited, no_named_update,
	// recommended): the recommended rows go first, then those with no named update, then the exploited ones, so each list is seen.
	updateFloors = []int{5, 3, 3}
)

// findDevice finds the device a model names (review r1 M2, L4 of #935). An IP address matches only a device with that IP, never a
// name that contains it ("192.168.1.10" is not "192.168.1.100"). Otherwise an exact id is the device; then a name: the one device
// whose name is the text (any case) or, partial, the one whose name contains it. When several devices match, by IP, by exact name, or
// one exact name beside other names that contain the text ("ws-07" and "ws-07.corp.local"), none is picked: more lists them, exact
// matches first.
func findDevice(all []AssetRow, q string) (one AssetRow, more []AssetRow, partial, ok bool) {
	q = strings.TrimSpace(q)
	pick := func(match func(AssetRow) bool) []AssetRow {
		var out []AssetRow
		for _, a := range all {
			if match(a) {
				out = append(out, a)
			}
		}
		return out
	}
	decide := func(hit []AssetRow, partial bool) (AssetRow, []AssetRow, bool, bool) {
		if len(hit) == 1 {
			return hit[0], nil, partial, true
		}
		return AssetRow{}, hit, false, false
	}
	if ip, err := netip.ParseAddr(q); err == nil {
		q = ip.Unmap().String()
		return decide(pick(func(a AssetRow) bool { return a.IP == q }), false)
	}
	if q == "" {
		return AssetRow{}, nil, false, false
	}
	if hit := pick(func(a AssetRow) bool { return a.ID == q }); len(hit) == 1 {
		return hit[0], nil, false, true
	}
	exact := pick(func(a AssetRow) bool { return strings.EqualFold(a.Name, q) })
	part := pick(func(a AssetRow) bool {
		return !strings.EqualFold(a.Name, q) && strings.Contains(strings.ToLower(a.Name), strings.ToLower(q))
	})
	if len(exact) > 0 {
		return decide(append(exact, part...), false)
	}
	return decide(part, true)
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

// updateLine is one row as the model reads it: "Upgrade X from a to b or later; 12 CVEs, worst critical, detected, 2 ransomware".
func updateLine(u UpdateRow, exploited bool) string {
	b := strings.Builder{}
	b.WriteString(clip(u.Action, 200))
	switch {
	case len(u.CVEs) == 0: // Microsoft's newest Windows update with no CVE in NVD's data for the release: no count to give
		b.WriteString("; " + noCVEsYet())
		return b.String()
	default:
		b.WriteString("; " + plural(len(u.CVEs), "CVE", "CVEs"))
	}
	if w := clip(u.Worst, 12); w != "" {
		b.WriteString(", worst " + w)
	}
	if exploited {
		b.WriteString(", " + knownAs(u))
	}
	return b.String()
}

// noCVEsYet is what a recommended Windows update with no CVE says instead of a count, as the plan page: NVD lists none of them for the release yet.
func noCVEsYet() string {
	return "NVD lists no CVE of it for this release yet"
}

// planNote says why the recommended list is empty or not known, so the model never reads "0" as "nothing to update" (review r1 M4,
// L1 of #935).
func planNote(u DeviceUpdates) string {
	switch {
	case u.PlanOff:
		return "Recommended updates are off (the feeds module is off): say they are not available, not that there are none."
	}
	return ""
}

// updateList is one list of the answer: its rows from start, n of them shown.
type updateList struct {
	name      string
	rows      []UpdateRow
	exploited bool
	start, n  int
}

func (l updateList) shown() []string {
	var out []string
	for _, x := range l.rows[l.start : l.start+l.n] {
		out = append(out, updateLine(x, l.exploited))
	}
	return out
}

// pageNote says which rows of a list are shown and how to read the rest (review r1 M3 of #935: every row is readable through this
// tool, never through get_finding one by one).
func (l updateList) pageNote(paged bool) string {
	total, end := len(l.rows), l.start+l.n
	switch {
	case total == 0 || !paged && end >= total:
		return ""
	case l.n == 0 && l.start >= total:
		return fmt.Sprintf("%s has %d rows; that offset is past the end. ", l.name, total)
	case end >= total:
		return fmt.Sprintf("%s: rows %d to %d of %d, the last ones. ", l.name, l.start+1, end, total)
	}
	return fmt.Sprintf("%s: rows %d to %d of %d (say \"%d (showing %d)\"); call again with part \"%s\" and offset %d for the next. ", l.name, l.start+1, end, total, total, l.n, l.name, end)
}

// updatesAnswer is the JSON of a call: the totals and the note first (never cut), the status words and the device only on the
// first call (part empty).
type updatesAnswer struct {
	Found        bool           `json:"found"`
	Device       map[string]any `json:"device"`
	OpenFindings int            `json:"open_exploited_findings"`
	Note         string         `json:"note"`
	StatusWords  string         `json:"status_words,omitempty"`
	Updates      int            `json:"exploited_updates_total"`
	NoUpdates    int            `json:"no_named_update_total"`
	Recommended  int            `json:"recommended_total"`
	PlanNote     string         `json:"recommended_note,omitempty"`
	Exploited    []string       `json:"exploited,omitempty"`
	NoUpdate     []string       `json:"no_named_update,omitempty"`
	RecTop       []string       `json:"recommended,omitempty"`
}

func (s *Service) toolDeviceUpdates(ctx context.Context, d Data, up Updates, raw map[string]any) (toolOut, error) {
	partArg := str(raw, "part")
	offset, hasOffset := raw["offset"].(int)
	if hasOffset && partArg == "" {
		return toolOut{}, errBadArgs{"offset needs part: the list to page through"}
	}
	all, err := d.Assets(ctx)
	if err != nil {
		return toolOut{}, readFailed(err)
	}
	dev, more, partial, ok := findDevice(all, str(raw, "device"))
	if !ok {
		if len(more) > 0 {
			cands := []map[string]any{}
			for _, a := range more[:min(len(more), 8)] {
				c := map[string]any{"asset_id": clip(a.ID, 96), "name": clip(a.Name, 80)}
				put(c, "ip", clip(a.IP, 45))
				cands = append(cands, c)
			}
			b, _ := json.Marshal(map[string]any{"found": false, "note": fmt.Sprintf("%d devices match; none was picked. Call again with the asset_id of the one meant (ask the person when unsure).", len(more)), "candidates": cands})
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
	lists := []updateList{{name: "exploited", rows: u.Exploited, exploited: true}, {name: "no_named_update", rows: u.NoUpdate, exploited: true}, {name: "recommended", rows: u.Planned}}
	for i := range lists {
		l := &lists[i]
		switch partArg {
		case "":
			l.n = min(len(l.rows), updatesRowsMax)
		case l.name:
			l.start = min(offset, len(l.rows))
			l.n = min(len(l.rows)-l.start, updatesRowsMax)
		}
	}
	device := map[string]any{"asset_id": clip(dev.ID, 96)}
	first := partArg == ""
	if first { // a page names the device by its id only: the first call gave the rest
		device["name"] = clip(dev.Name, 80)
		put(device, "ip", clip(dev.IP, 45))
		put(device, "os", clip(dev.OS, 80))
	}
	exCVEs := 0
	for _, x := range u.Exploited {
		exCVEs += len(x.CVEs)
	}
	lead := ""
	if partial { // review r2 L2 of #935: the only device whose name contains the text, not one named so
		lead = fmt.Sprintf("No device is named %q: this is the only one whose name contains it. Say which device this is before answering. ", clip(str(raw, "device"), 96))
	}
	build := func(ls []updateList) any {
		note := lead
		if first {
			note += fmt.Sprintf("%d open exploited findings: %d of them are fixed by the %d updates in exploited, %d have no named update. The CVE ids are not listed: list_findings with asset_id gives them. ", u.Open, exCVEs, len(u.Exploited), u.Open-exCVEs)
		}
		for _, l := range ls {
			if first || partArg == l.name {
				note += l.pageNote(!first)
			}
		}
		a := updatesAnswer{Found: true, Device: device, OpenFindings: u.Open, Note: strings.TrimSpace(note), Updates: len(u.Exploited), NoUpdates: len(u.NoUpdate),
			Recommended: len(u.Planned), Exploited: ls[0].shown(), NoUpdate: ls[1].shown(), RecTop: ls[2].shown()}
		if first {
			a.StatusWords = statusWords
		}
		if first || partArg == "recommended" {
			a.PlanNote = planNote(u)
		}
		return a
	}
	text, lists := fitUpdates(lists, first, build)
	t := &AskTable{Columns: []string{"Update", "CVEs", "Worst", "Status"}, Rows: []AskRow{}}
	for _, l := range lists {
		for _, x := range l.rows[l.start : l.start+l.n] {
			status := "recommended"
			if l.exploited {
				status = knownAs(x)
			}
			t.Rows = append(t.Rows, AskRow{Href: "/devices/" + clip(dev.ID, 96), Cells: []string{clip(x.Action, 200), cveCell(x), clip(x.Worst, 12), status}})
		}
	}
	out := toolOut{Text: text, Summary: fmt.Sprintf("%s, %s", plural(len(u.Exploited), "update", "updates"), plural(len(u.Planned), "recommended", "recommended")),
		Cite: "Findings and Recommended updates: " + clip(dev.Name, 80)}
	if len(t.Rows) > 0 {
		out.Table = t
	}
	return out, nil
}

// cveCell is the table's CVE count of a row: "12 CVEs", never "0 CVEs" for an update whose CVEs
// NVD has not listed yet (its words instead).
func cveCell(u UpdateRow) string {
	switch {
	case len(u.CVEs) == 0:
		return noCVEsYet()
	}
	return plural(len(u.CVEs), "CVE", "CVEs")
}

// fitUpdates returns the JSON of build with as many rows as fit askResultBytes, and the lists as kept. On a first call the recommended
// rows go first, then those with no named update, then the exploited updates, each down to its floor (updateFloors), then to none;
// a page has one list. The totals and the note, which says where the next call starts, are never cut.
func fitUpdates(lists []updateList, first bool, build func([]updateList) any) (string, []updateList) {
	floor := updateFloors
	if !first {
		floor = []int{0, 0, 0}
	}
	for {
		b, err := json.Marshal(build(lists))
		if err == nil && len(b) <= askResultBytes {
			return string(b), lists
		}
		cut := false
		for _, keep := range []bool{true, false} {
			for i := len(lists) - 1; i >= 0 && !cut; i-- {
				if lists[i].n > 0 && (!keep || lists[i].n > floor[i]) {
					lists[i].n--
					cut = true
				}
			}
			if cut {
				break
			}
		}
		if !cut {
			return string(b), lists
		}
	}
}
