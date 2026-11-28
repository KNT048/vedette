package findings

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/knt048/vedette/core/productid"
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
//   - its CVE is on no exploited list and no exploitation signal of any age names it (Feeds.Exploited: an exploited statement, a public
//     exploit or scan template, an intrusion alert here, whatever its date): an exploited CVE is researched as always;
//   - the line's action covers it: when the action is a release to install, no range the CVE states for the line still holds that
//     release (updateTarget); a CVE the release does not leave stays an ordinary undecided row, researched. A CVE with no stated range
//     for the line is grouped (the group says it was not checked one by one, never that the update fixes it);
//   - its line has an anchor: an open finding of the same device and software line whose range origin is not the AI's reading
//     (RangeAIRead) and that was not opened through the product the AI chose for the line (Evidence.Identity). An accepted or handled
//     finding is not open, so it is no anchor. A line with no such finding has an anchor when the CVE record of another of its
//     possible CVEs states the line unsupported by its vendor: the record is tagged unsupported when assigned (Feeds.Unsupported) and
//     one of its rows matches the installed product, edition and line strictly (lineCovered: never on "might"). The action is then to
//     move to a supported release; the tagged CVE itself stays an ordinary possible row (it is the reason), researched as before.
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
	// Fix is the group's target: the anchor's fix, or the lowest later release the data names that leaves every range of the line's
	// deferred CVEs (Raised; updateTarget).
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

// lineRefs reads, once per markDeferred, the catalogue entries of some CVEs and the devices of some lines: what the target of an update
// group and the unsupported statement of a record are judged on. A read that fails is logged and leaves the entry or device absent.
type lineRefs struct {
	s       *Service
	vulns   map[string]Vuln
	devices map[string]*Asset
}

func (s *Service) lineRefs(ctx context.Context, cves []string) *lineRefs {
	r := &lineRefs{s: s, vulns: map[string]Vuln{}, devices: map[string]*Asset{}}
	if len(cves) == 0 {
		return r
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope(nil, cves)) // only the pinned CVEs: the adapter reads nothing more
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the ranges of possible CVEs could not be read; their lines group nothing", "error", err)
		return nil
	}
	want := map[string]bool{}
	for _, c := range cves {
		want[c] = true
	}
	for _, v := range vulns {
		if want[v.CVE] {
			r.vulns[v.CVE] = v
		}
	}
	return r
}

// line is software line sw of device id as the matcher reads it; false when the device or the line cannot be read.
func (r *lineRefs) line(ctx context.Context, id, sw string) (Asset, Software, bool) {
	a, read := r.devices[id]
	if !read {
		got, found, err := r.s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			r.s.cfg.Log.WarnContext(ctx, "findings: a device of possible CVEs could not be read", "asset", id, "error", err)
		}
		if found && err == nil {
			a = &got
		}
		r.devices[id] = a
	}
	if a == nil {
		return Asset{}, Software{}, false
	}
	sws := deviceSoftware(*a)
	i := slices.IndexFunc(sws, func(s Software) bool { return s.ID == sw })
	if i < 0 {
		return Asset{}, Software{}, false
	}
	return *a, sws[i], true
}

// markDeferred sets Deferred on every item of a line with an anchor that is not exploited (deferrable, and no exploitation signal of
// any age names its CVE: Feeds.Exploited) and that the line's action covers (updateTarget). A signal, catalogue or device that cannot
// be read defers nothing: the CVEs are researched as before.
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
	signalled, err := s.cfg.Feeds.Exploited(ctx, uniqueIDs(cves))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading the exploitation signals of possible CVEs failed; none is deferred", "error", err)
		return nil
	}
	groups := map[[2]string][]int{} // the candidates of each line
	var ranged []string             // the CVEs of the lines whose action is a release to install: their ranges decide what it covers
	for i, it := range items {
		k := [2]string{it.Question.AssetID, it.Question.SoftwareID}
		a, ok := anchors[k]
		if !ok || !deferrable(it) || signalled[it.CVE] || a.kind == AnchorUnsupported && a.cve == it.CVE {
			continue
		}
		groups[k] = append(groups[k], i)
		if versioned(a.fix) {
			ranged = append(ranged, it.CVE)
		}
	}
	var refs *lineRefs
	if len(ranged) > 0 {
		if refs = s.lineRefs(ctx, uniqueIDs(ranged)); refs == nil {
			return nil
		}
	}
	for k, is := range groups {
		a := anchors[k]
		d := Deferred{Anchor: a.id, AnchorKind: a.kind, AnchorCVE: a.cve, FixKey: a.fixKey, Fix: a.fix}
		covered := map[string]bool{}
		if versioned(a.fix) {
			dev, sw, ok := refs.line(ctx, k[0], k[1])
			if !ok {
				continue
			}
			var vs []Vuln
			for _, i := range is {
				v, ok := refs.vulns[items[i].CVE]
				if !ok {
					v = Vuln{CVE: items[i].CVE} // no stated range: nothing it says holds the target
				}
				vs = append(vs, v)
			}
			d.Fix.Version, covered = updateTarget(dev, sw, vs, a.fix.Version, productPart(Finding{FixKey: a.fixKey, Fix: a.fix}))
			d.Raised = d.Fix.Version != a.fix.Version
		}
		for _, i := range is {
			if versioned(a.fix) && !covered[items[i].CVE] {
				continue // the update does not leave a range it states: an ordinary undecided CVE, researched
			}
			g := d
			items[i].Deferred = &g
		}
	}
	return nil
}

// versioned says the fix is a release of the software to install: the target whose cover of each grouped CVE is judged (updateTarget).
// Another fix (a distribution's package, a system build, a move with no release named, no fix) names no release the CVE's upstream
// ranges compare with: the group says "not checked one by one", never that the fix covers it.
func versioned(f Fix) bool { return f.Kind == FixUpdate && f.Version != "" }

// updateTarget is the release a line's update group advises, and the CVEs of vs it covers: the lowest release at or above the anchor's
// fix, among the fix and the exclusive ends of the CVEs' ranges, that leaves every stated range of every CVE (the rule planReleases
// applies to a block); when none leaves them all, the lowest that leaves the most. A CVE the target does not leave is not covered and
// is not deferred, so the group never says an update covers a CVE it does not. It reads only the catalogue and the device, never the AI.
func updateTarget(a Asset, s Software, vs []Vuln, fix, product string) (string, map[string]bool) {
	in := swInfoOn(s, a)
	stated := make([][]fixedEntry, len(vs))
	cands := map[string]bool{fix: true}
	for i, v := range vs {
		var key []identity
		if keyedTo(s, v) {
			key = keyIDs(v)
		}
		for _, e := range fixedPartsOf(in, v, key).ents {
			if e.r.IsZero() && e.c.Version.Kind != Value {
				continue // no version: says nothing about a release
			}
			stated[i] = append(stated[i], e)
			if e.r.EndExcl != "" {
				cands[clean(e.r.EndExcl)] = true
			}
		}
	}
	var list []string
	for x := range cands {
		if c, ok := compareFix(FixUpdate, product, x, fix); x == fix || ok && c > 0 {
			list = append(list, x)
		}
	}
	slices.Sort(list)
	slices.SortStableFunc(list, func(x, y string) int { c, _ := compareFix(FixUpdate, product, x, y); return c })
	best, most := fix, -1
	var cover map[string]bool
	for _, x := range list {
		got := map[string]bool{}
		for i, v := range vs {
			if !slices.ContainsFunc(stated[i], func(e fixedEntry) bool { return holds(in, product, e, x) }) {
				got[v.CVE] = true
			}
		}
		if len(got) > most {
			best, most, cover = x, len(got), got
		}
		if len(got) == len(vs) {
			break
		}
	}
	return best, cover
}

// holds says a stated row of a CVE may still hold release x of the line: its range holds x or might (evalAffected is not No: a range
// with no end, an inclusive end at or past x, an edition the box does not know), or it lists one release of the line at or above x (the
// fix is later than the listed release). A release that cannot be ordered against x holds it.
func holds(in swInfo, product string, e fixedEntry, x string) bool {
	if t, _ := evalAffected(e.c, e.r, x, in.cpe, in.hasCPE); t != No {
		return true
	}
	if !e.r.IsZero() {
		return false
	}
	lit, _ := e.c.Version.Literal()
	if !sameLine(lit, in.ver) {
		return false
	}
	c, ok := compareFix(FixUpdate, product, lit, x)
	return !ok || c >= 0
}

// unsupportedAnchors adds to anchors, for each line with a deferrable item and no anchor finding, the statement of a CVE record that
// the line is unsupported by its vendor: a possible CVE of the line (not settled; exploited or not) whose record is tagged unsupported
// when assigned and one of whose rows covers the installed product, edition and line strictly (lineCovered). Of several, the lowest CVE
// id. Only the tag's records are read further (their catalogue entries, the device), so a box with none reads nothing more. A tag,
// catalogue or device that cannot be read adds none: the CVEs are researched as before.
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
	refs := s.lineRefs(ctx, keys(tagged))
	if refs == nil {
		return
	}
	slices.SortStableFunc(cands, func(x, y int) int { return cmp.Compare(items[x].CVE, items[y].CVE) })
	for _, i := range cands {
		it := items[i]
		k := [2]string{it.Question.AssetID, it.Question.SoftwareID}
		v, ok := refs.vulns[it.CVE]
		if _, done := anchors[k]; done || !ok {
			continue
		}
		if dev, sw, ok := refs.line(ctx, k[0], k[1]); ok && lineCovered(dev, sw, v) {
			anchors[k] = anchor{id: it.Question.ID, kind: AnchorUnsupported, cve: it.CVE, fix: Fix{Kind: FixFeatureUpdate}}
		}
	}
}

// lineCovered says a row of v covers line s of device a strictly: the row is about the installed product and edition (evalAffected says
// Yes, never "might": an edition or platform the box does not know is no match) and either holds the installed release, or names a
// release of the installed line (its first or last affected release, or the one release it lists) when the product's own scheme names
// release lines (productid). A row with no version, or a product whose lines the catalogue does not name, covers no line by a release
// it does not hold.
func lineCovered(a Asset, s Software, v Vuln) bool {
	in := swInfoOn(s, a)
	if !in.given {
		return false
	}
	var key []identity
	if keyedTo(s, v) {
		key = keyIDs(v)
	}
	line := ""
	p, known := productid.ResolveStored(s.Vendor, s.Product, s.Display, s.CPE)
	if known {
		line = p.Line(p.Canonical(in.ver))
	}
	for _, e := range fixedPartsOf(in, v, key).ents {
		if e.r.IsZero() && e.c.Version.Kind != Value {
			continue // no version: "the product", not this line
		}
		if t, _ := evalAffected(e.c, e.r, in.ver, in.cpe, in.hasCPE); t == Yes {
			return true
		}
		if line == "" {
			continue
		}
		lit, _ := e.c.Version.Literal()
		for _, x := range []string{e.r.StartIncl, e.r.EndIncl, lit} {
			if x == "" || p.Line(p.Canonical(x)) != line {
				continue
			}
			if t, _ := evalAffected(e.c, e.r, x, in.cpe, in.hasCPE); t == Yes {
				return true
			}
		}
	}
	return false
}
