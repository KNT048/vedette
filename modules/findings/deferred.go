package findings

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
)

// CVEs a needed update already covers. When a software line of a device has an open finding Vedette decided from data or a person
// decided (an anchor), the customer's action for the line is already known: update it to the anchor's fix (or, with no fix on the
// line, move to a supported release). Another CVE of the same line that Vedette cannot decide changes nothing in that action unless
// it is exploited, so researching it one by one spends the customer's AI tokens and attention for nothing. Such a possible CVE is
// deferred: grouped under the anchor's fix, counted apart (PossibleCounts.Deferred), left out of the automatic research, and checked
// again by itself once the anchor closes. The leading scanners group findings by the patch that removes them the same way.
//
// A possible CVE is deferred when every one of these holds:
//   - it is undecided (state possible: not a proposal waiting for a person, not settled) and does not wait for its distribution's word
//     (DistroPending: its own group, never researched);
//   - its CVE is on no exploited list and no exploitation signal keeps it (Feeds.Kept): an exploited CVE is researched as always;
//   - its line has an anchor: an open finding of the same device and software line whose range origin is not the AI's reading
//     (RangeAIRead) and that was not opened through the product the AI chose for the line (Evidence.Identity). An accepted or handled
//     finding is not open, so it is no anchor. A line with no such finding has an anchor when the CVE record of another of its
//     possible CVEs states the line unsupported by its vendor: the record is tagged unsupported when assigned (Feeds.Unsupported) and
//     one of its rows that applies to the line covers the installed release, or might (an edition or platform the box does not know
//     decides it; unsupportedAnchors). The action is then to move to a supported release; the tagged CVE itself stays an ordinary
//     possible row (it is the reason), and is researched as before.
//
// It is derived when the possible CVEs are read (possibleItemsOf), never stored: the question, its cause and every decision stay as
// they are (a deferred CVE is never closed, never not affected and never goes through the closing gate). When the anchor closes (the
// version moved, a person handled it) the next read finds no anchor, and the research worker, woken by the match or the handling,
// researches the line. A person's "Research deeper" still researches a deferred row (deeperUnit does not read the deferral).

// The kinds of anchor (Deferred.AnchorKind).
const (
	AnchorFinding     = "finding"          // an open finding decided by data or a person: its fix is the action
	AnchorUnsupported = "unsupported_line" // the CVE record states the line unsupported: move to a supported release
)

// Deferred is the anchor a deferred possible CVE is grouped under and the group's target.
type Deferred struct {
	Anchor     string // the anchor finding; for AnchorUnsupported the question of the tagged CVE (PossibleRow.id)
	AnchorKind string // AnchorFinding or AnchorUnsupported
	AnchorCVE  string
	FixKey     string // the anchor finding's stored fix key: its "By fix" group; "" for AnchorUnsupported
	// Fix is the group's target: the anchor's fix, or the lowest later release the data names that is outside every range of the
	// line's deferred CVEs (Raised; raiseTargets).
	Fix    Fix
	Raised bool
}

// anchor is what decides what a line needs: an open finding, or a record that states the line unsupported.
type anchor struct {
	id, kind, cve, fixKey string
	fix                   Fix
	urgency               int
}

// anchorsOf reads the anchor of each (device, line) of a device (of every device when device is ""): of the line's open findings
// decided by data or a person, the one whose fix names the most: a release to install first (the newest of them), then a move to
// another release, a restart, no fix yet, and no fix data last.
func (s *Service) anchorsOf(ctx context.Context, device string) (map[[2]string]anchor, error) {
	rows, err := s.rd(ctx).QueryContext(ctx, `SELECT id, asset_id, software_id, cve, fix_kind, ifnull(fix_version, ''), ifnull(fix_ref, ''),
		fix_channel, fix_key, urgency FROM fnd_finding WHERE state = 'open' AND software_id IS NOT NULL AND (?1 = '' OR asset_id = ?1)
		AND range_origin <> ?2 AND ifnull(json_extract(evidence, '$.identity.method'), '') <> ?3`, device, RangeAIRead, IdentityAI)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the anchors of deferred CVEs: %w", err)
	}
	out := map[[2]string]anchor{}
	for rows.Next() {
		a := anchor{kind: AnchorFinding}
		var asset, sw, kind, channel string
		if err := rows.Scan(&a.id, &asset, &sw, &a.cve, &kind, &a.fix.Version, &a.fix.Ref, &channel, &a.fixKey, &a.urgency); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("findings: reading the anchors of deferred CVEs: %w", err)
		}
		a.fix.Kind = FixKind(kind)
		if FixChannel(channel) != ChannelPublic {
			a.fix.Channel = FixChannel(channel)
		}
		k := [2]string{asset, sw}
		if b, ok := out[k]; !ok || betterAnchor(a, b) {
			out[k] = a
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("findings: reading the anchors of deferred CVEs: %w", err)
	}
	return out, nil
}

// fixRank orders fixes by how much they tell the customer to do: a release to install, a move to another release, a restart, no fix
// yet, no fix data.
func fixRank(f Fix) int {
	switch {
	case f.Kind == FixFeatureUpdate:
		return 1
	case f.Kind == FixRestart:
		return 2
	case f.Version != "" && f.Kind != FixNoneYet && f.Kind != FixUnknown:
		return 0
	case f.Kind == FixNoneYet:
		return 3
	}
	return 4
}

// betterAnchor says a is the line's anchor rather than b: the fix that names more, then the newer release of one kind, then the more
// urgent finding, then the lower id (one answer for every read).
func betterAnchor(a, b anchor) bool {
	if ra, rb := fixRank(a.fix), fixRank(b.fix); ra != rb {
		return ra < rb
	}
	if a.fix.Kind == b.fix.Kind && a.fix.Chan() == b.fix.Chan() && a.fix.Version != "" && b.fix.Version != "" {
		if c, ok := compareFix(a.fix.Kind, productPart(Finding{FixKey: a.fixKey, Fix: a.fix}), a.fix.Version, b.fix.Version); ok && c != 0 {
			return c > 0
		}
	}
	return cmp.Or(cmp.Compare(a.urgency, b.urgency), cmp.Compare(a.id, b.id)) < 0
}

// deferrable says the item may be grouped under its line's anchor (the first two conditions at the top of this file, but the signal).
func deferrable(it PossibleItem) bool {
	return it.State == PossibleOpen && !it.Exploited && it.Question.SoftwareID != "" && !it.DistroPending()
}

// markDeferred sets Deferred on every item of a line with an anchor that is not exploited (deferrable, and no exploitation signal
// keeps its CVE). A signal that cannot be read defers nothing: the CVEs are researched as before.
func (s *Service) markDeferred(ctx context.Context, device string, items []PossibleItem) error {
	if !slices.ContainsFunc(items, deferrable) {
		return nil
	}
	anchors, err := s.anchorsOf(ctx, device)
	if err != nil {
		return err
	}
	s.unsupportedAnchors(ctx, items, anchors)
	if len(anchors) == 0 {
		return nil
	}
	var cves []string
	for _, it := range items {
		if _, ok := anchors[[2]string{it.Question.AssetID, it.Question.SoftwareID}]; ok && deferrable(it) {
			cves = append(cves, it.CVE)
		}
	}
	if len(cves) == 0 {
		return nil
	}
	kept, err := s.cfg.Feeds.Kept(ctx, uniqueIDs(cves))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading the exploitation signals of possible CVEs failed; none is deferred", "error", err)
		return nil
	}
	for i := range items {
		it := &items[i]
		a, ok := anchors[[2]string{it.Question.AssetID, it.Question.SoftwareID}]
		if !ok || !deferrable(*it) || kept[it.CVE] || a.kind == AnchorUnsupported && a.cve == it.CVE {
			continue
		}
		it.Deferred = &Deferred{Anchor: a.id, AnchorKind: a.kind, AnchorCVE: a.cve, FixKey: a.fixKey, Fix: a.fix}
	}
	return nil
}

// raiseTargets raises the target of each group of deferred items (one device and line) whose anchor's fix is a release to install, when
// that release does not clear every deferred CVE of the line: one whose ranges list the release as affected ("from 115.10.0 before
// 115.20.0" on 115.12.0) is still there after the update. The target is then the lowest release, at or above the anchor's fix, among
// the ends of the deferred CVEs' ranges, that is outside every range of theirs that applies to the line (the rule planReleases applies
// to the CVEs of a block); a range that does not tell (a row with no version, an edition the box does not know) never clears a release.
// No such release: the anchor's fix stays. It reads only the catalogue and the device, never the AI. A catalogue or device that cannot
// be read leaves the anchors' fixes. Only the groups of only (device, line) are judged: the list judges those its page shows.
func (s *Service) raiseTargets(ctx context.Context, items []PossibleItem, only map[[2]string]bool) {
	groups := map[[2]string][]int{}
	cves := map[string]bool{}
	for i, it := range items {
		k := [2]string{it.Question.AssetID, it.Question.SoftwareID}
		if d := it.Deferred; d != nil && d.Fix.Kind == FixUpdate && d.Fix.Version != "" && only[k] {
			groups[k] = append(groups[k], i)
			cves[it.CVE] = true
		}
	}
	if len(groups) == 0 {
		return
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope(nil, keys(cves)))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the ranges of deferred CVEs could not be read", "error", err)
		return
	}
	byCVE := make(map[string]Vuln, len(cves))
	for _, v := range vulns {
		if cves[v.CVE] {
			byCVE[v.CVE] = v
		}
	}
	devices := map[string]Asset{}
	order := slices.Collect(mapsKeys(groups))
	slices.SortFunc(order, func(x, y [2]string) int { return cmp.Or(cmp.Compare(x[0], y[0]), cmp.Compare(x[1], y[1])) })
	for _, k := range order {
		a, ok := devices[k[0]]
		if !ok {
			got, found, err := s.cfg.Inventory.MatchInput(ctx, k[0])
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "findings: a device of deferred CVEs could not be read", "asset", k[0], "error", err)
			}
			a = got
			if !found || err != nil {
				a = Asset{}
			}
			devices[k[0]] = a
		}
		i := slices.IndexFunc(deviceSoftware(a), func(sw Software) bool { return sw.ID == k[1] })
		if i < 0 {
			continue
		}
		var lineCVEs []Vuln
		for _, j := range groups[k] {
			if v, ok := byCVE[items[j].CVE]; ok && !slices.ContainsFunc(lineCVEs, func(w Vuln) bool { return w.CVE == v.CVE }) {
				lineCVEs = append(lineCVEs, v)
			}
		}
		d := items[groups[k][0]].Deferred
		x, ok := clearingRelease(a, deviceSoftware(a)[i], lineCVEs, d.Fix.Version, productPart(Finding{FixKey: d.FixKey, Fix: d.Fix}))
		if !ok || x == d.Fix.Version {
			continue
		}
		for _, j := range groups[k] {
			raised := *items[j].Deferred
			raised.Fix.Version, raised.Raised = x, true
			items[j].Deferred = &raised
		}
	}
}

// clearingRelease is the lowest release of product at or above target, among target and the exclusive ends of vs' ranges that apply to
// line s of device a, that is outside every such range (evalAffected says No for each); false when none is.
func clearingRelease(a Asset, s Software, vs []Vuln, target, product string) (string, bool) {
	in := swInfoOn(s, a)
	var entries []fixedEntry
	cands := map[string]bool{target: true}
	for _, v := range vs {
		var key []identity
		if keyedTo(s, v) {
			key = keyIDs(v)
		}
		for _, e := range fixedPartsOf(in, v, key).usable {
			entries = append(entries, e)
			if e.r.EndExcl != "" {
				cands[clean(e.r.EndExcl)] = true
			}
		}
	}
	var list []string
	for x := range cands {
		if c, ok := compareFix(FixUpdate, product, x, target); x == target || ok && c > 0 {
			list = append(list, x)
		}
	}
	slices.Sort(list)
	slices.SortStableFunc(list, func(x, y string) int { c, _ := compareFix(FixUpdate, product, x, y); return c })
	for _, x := range list {
		if !slices.ContainsFunc(entries, func(e fixedEntry) bool { t, _ := evalAffected(e.c, e.r, x, in.cpe, in.hasCPE); return t != No }) {
			return x, true
		}
	}
	return "", false
}

// unsupportedAnchors adds to anchors, for each line with a deferrable item and no anchor finding, the statement of a CVE record that
// the line is unsupported by its vendor: a possible CVE of the line (not settled; exploited or not) whose record is tagged unsupported
// when assigned and one of whose rows that apply to the line covers the installed release or might (lineCovered). Of several, the
// lowest CVE id. Only the tag's records are read further (the catalogue's ranges, the device), so a box with none reads nothing more. A
// tag, catalogue or device that cannot be read adds none: the CVEs are researched as before.
func (s *Service) unsupportedAnchors(ctx context.Context, items []PossibleItem, anchors map[[2]string]anchor) {
	open := map[[2]string]bool{}
	for _, it := range items {
		k := [2]string{it.Question.AssetID, it.Question.SoftwareID}
		if _, ok := anchors[k]; !ok && deferrable(it) {
			open[k] = true
		}
	}
	var cves []string
	for _, it := range items {
		if open[[2]string{it.Question.AssetID, it.Question.SoftwareID}] && it.State != PossibleSettled {
			cves = append(cves, it.CVE)
		}
	}
	if len(cves) == 0 {
		return
	}
	tagged, err := s.cfg.Feeds.Unsupported(ctx, uniqueIDs(cves))
	if err != nil || len(tagged) == 0 {
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "findings: reading the records tagged unsupported failed", "error", err)
		}
		return
	}
	var cands []int
	for i, it := range items {
		if tagged[it.CVE] && it.State != PossibleSettled && open[[2]string{it.Question.AssetID, it.Question.SoftwareID}] {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope(nil, keys(tagged)))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the ranges of records tagged unsupported could not be read", "error", err)
		return
	}
	byCVE := map[string]Vuln{}
	for _, v := range vulns {
		if tagged[v.CVE] {
			byCVE[v.CVE] = v
		}
	}
	devices := map[string]*Asset{}
	slices.SortStableFunc(cands, func(x, y int) int { return cmp.Compare(items[x].CVE, items[y].CVE) })
	for _, i := range cands {
		it := items[i]
		k := [2]string{it.Question.AssetID, it.Question.SoftwareID}
		v, ok := byCVE[it.CVE]
		if _, done := anchors[k]; done || !ok {
			continue
		}
		a, read := devices[k[0]]
		if !read {
			got, found, err := s.cfg.Inventory.MatchInput(ctx, k[0])
			if err != nil {
				s.cfg.Log.WarnContext(ctx, "findings: a device of a record tagged unsupported could not be read", "asset", k[0], "error", err)
			}
			if found && err == nil {
				a = &got
			}
			devices[k[0]] = a
		}
		if a == nil {
			continue
		}
		sws := deviceSoftware(*a)
		j := slices.IndexFunc(sws, func(sw Software) bool { return sw.ID == k[1] })
		if j >= 0 && lineCovered(*a, sws[j], v) {
			anchors[k] = anchor{id: it.Question.ID, kind: AnchorUnsupported, cve: it.CVE, fix: Fix{Kind: FixFeatureUpdate}}
		}
	}
}

// lineCovered says a row of v that applies to line s of device a and names versions (a range, or an exact release) covers the installed
// release, or might: evalAffected does not say No (an edition or platform the box does not know leaves it open). A row with no version
// says nothing about this line.
func lineCovered(a Asset, s Software, v Vuln) bool {
	in := swInfoOn(s, a)
	if !in.given {
		return false
	}
	var key []identity
	if keyedTo(s, v) {
		key = keyIDs(v)
	}
	for _, e := range fixedPartsOf(in, v, key).ents {
		if e.r.IsZero() && e.c.Version.Kind != Value {
			continue // no version: "the product", not this line
		}
		if t, _ := evalAffected(e.c, e.r, in.ver, in.cpe, in.hasCPE); t != No {
			return true
		}
	}
	return false
}
