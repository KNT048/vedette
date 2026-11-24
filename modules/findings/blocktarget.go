package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// The release a block names must clear every CVE the block lists. The newest of the findings' own fixes does not always: a CVE fixed
// in 1.30.7 that affects 1.31.0-<1.31.9 again is still open on 1.31.6, the fix of another CVE of the line. So when the open findings of
// one line need different releases of one product, the block's release is the lowest release the CVEs' ranges name (a finding's own
// fix, or a range's exclusive end) that is outside every range of every CVE of the block that applies to the line: the rule FixOf reads
// one CVE's fix by, applied to all of them. Ranges sort by release, so a fix in the line's own train comes first when it clears all.
// When no named release clears them all, the block splits: the lowest release that clears the most findings takes them, the rest
// get theirs the same way, so every block's release clears every CVE it lists. A CVE whose fix is not read from those ranges (a
// vendor's own notation, no catalogue entry, the device not readable) is taken as cleared by its own fix and any later release, as
// before.

// releaseJudge reads, for the lines whose open findings need different releases, the ranges of their CVEs that apply to them.
type releaseJudge struct {
	cves  map[[3]string][]string               // (device, line, stored fix key) -> the CVEs of its open findings
	lines map[[2]string]map[string]*fixedParts // (device, line) -> CVE -> its ranges that apply to the line; nil: not judged by ranges
}

// ends are the releases the ranges of g's CVEs name as exclusive ends: candidates for the block's release.
func (j *releaseJudge) ends(g lineGroup) []string {
	if j == nil {
		return nil
	}
	parts := j.lines[[2]string{g.Asset, g.Software}]
	var out []string
	for _, c := range j.cves[[3]string{g.Asset, g.Software, g.Key}] {
		if p := parts[c]; p != nil {
			for _, e := range p.usable {
				if e.r.EndExcl != "" {
					out = append(out, clean(e.r.EndExcl))
				}
			}
		}
	}
	return out
}

// clears reports whether release x of g's line clears every CVE of g: at or above g's own fix, and outside every range that applies of
// each CVE judged by its ranges.
func (j *releaseJudge) clears(g lineGroup, x string) bool {
	if x != g.Fix.Version {
		if c, ok := compareFix(g.Fix.Kind, x, g.Fix.Version); !ok || c < 0 {
			return false
		}
	}
	if j == nil {
		return true
	}
	parts := j.lines[[2]string{g.Asset, g.Software}]
	for _, c := range j.cves[[3]string{g.Asset, g.Software, g.Key}] {
		if p := parts[c]; p != nil && !p.outside(x) {
			return false
		}
	}
	return true
}

// planReleases sets the blocks of the groups is of one device, line and product, each with an update to a release that compares with
// every other (combine checked it), as the comment at the top of this file says.
func planReleases(gs []lineGroup, is []int, product string, j *releaseJudge) {
	kind := gs[is[0]].Fix.Kind
	var stored, cands []string
	for _, i := range is {
		stored = append(stored, gs[i].Fix.Version)
		cands = append(cands, gs[i].Fix.Version)
		cands = append(cands, j.ends(gs[i])...)
	}
	cands = slices.DeleteFunc(cands, func(x string) bool { // only releases that compare with every stored fix can be ordered with them
		for _, v := range stored {
			if _, ok := compareFix(kind, x, v); !ok && x != v {
				return true
			}
		}
		return false
	})
	slices.SortStableFunc(cands, func(a, b string) int {
		c, _ := compareFix(kind, a, b)
		return c
	})
	cands = slices.Compact(cands)
	left := slices.Clone(is)
	for len(left) > 0 {
		best, set, most := "", []int(nil), 0
		for _, x := range cands {
			var cleared []int
			n := 0
			for _, i := range left {
				if j.clears(gs[i], x) {
					cleared, n = append(cleared, i), n+gs[i].All
				}
			}
			if len(cleared) == len(left) { // the lowest release that clears them all
				best, set = x, cleared
				break
			}
			if n > most { // else the lowest that clears the most findings
				best, set, most = x, cleared, n
			}
		}
		if len(set) == 0 {
			return // the data moved since the match stored these fixes: each group keeps its own until the next match
		}
		fx := Fix{Kind: kind, Version: best}
		for _, i := range is {
			if gs[i].Fix.Version == best {
				fx = gs[i].Fix
				break
			}
		}
		key := FixKey(product, fx)
		for _, i := range set {
			gs[i].Block, gs[i].BlockFix = key, fx
		}
		left = slices.DeleteFunc(left, func(i int) bool { return slices.Contains(set, i) })
	}
}

// releaseJudge reads what planReleases needs for the lines of gs (grouped from the rows of the condition rows) whose groups of one
// product need different update releases: the CVEs of each group, the line as the matcher reads it and the CVEs' ranges. nil when no
// line needs it. A device or catalogue that cannot be read leaves its CVEs unjudged (each cleared by its own fix and later releases),
// with a warning: the lists still show.
func (s *Service) releaseJudge(ctx context.Context, gs []lineGroup, rows string, args []any) (*releaseJudge, error) {
	type bucket struct{ asset, software, product string }
	versions := map[bucket]map[string]bool{}
	for _, g := range gs {
		if g.Fix.Kind != FixUpdate || g.Fix.Version == "" {
			continue
		}
		b := bucket{g.Asset, g.Software, g.Product}
		if versions[b] == nil {
			versions[b] = map[string]bool{}
		}
		versions[b][g.Fix.Version] = true
	}
	need := map[[2]string]bool{}
	assets := map[string]bool{}
	for b, vs := range versions {
		if len(vs) > 1 {
			need[[2]string{b.asset, b.software}] = true
			assets[b.asset] = true
		}
	}
	if len(need) == 0 {
		return nil, nil
	}
	j := &releaseJudge{cves: map[[3]string][]string{}, lines: map[[2]string]map[string]*fixedParts{}}
	as, _ := json.Marshal(keys(assets))
	r, err := s.rd(ctx).QueryContext(ctx, `SELECT asset_id, ifnull(software_id, ''), fix_key, cve FROM fnd_finding WHERE `+rows+
		` AND asset_id IN (SELECT value FROM json_each(?)) ORDER BY cve`, append(slices.Clone(args), string(as))...)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the CVEs of fix blocks: %w", err)
	}
	cves := map[string]bool{}
	for r.Next() {
		var k [3]string
		var cve string
		if err := r.Scan(&k[0], &k[1], &k[2], &cve); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: reading the CVEs of fix blocks: %w", err)
		}
		if need[[2]string{k[0], k[1]}] {
			j.cves[k] = append(j.cves[k], cve)
			cves[cve] = true
		}
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: reading the CVEs of fix blocks: %w", err)
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope(nil, keys(cves)))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the ranges of fix blocks could not be read", "error", err)
		return j, nil
	}
	byCVE := make(map[string]Vuln, len(cves))
	for _, v := range vulns {
		if cves[v.CVE] {
			byCVE[v.CVE] = v
		}
	}
	for _, id := range keys(assets) {
		a, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			s.cfg.Log.WarnContext(ctx, "findings: a device of fix blocks could not be read", "asset", id, "error", err)
			continue
		}
		if !ok {
			continue
		}
		for _, sw := range deviceSoftware(a) {
			k := [2]string{id, sw.ID}
			if !need[k] || j.lines[k] != nil {
				continue
			}
			parts := map[string]*fixedParts{}
			for gk, cs := range j.cves {
				if gk[0] != id || gk[1] != sw.ID {
					continue
				}
				for _, c := range cs {
					if v, ok := byCVE[c]; ok {
						parts[c] = rangeParts(a, sw, v)
					}
				}
			}
			j.lines[k] = parts
		}
	}
	return j, nil
}

// rangeParts are the ranges of v that apply to line s of device a when FixOf reads v's fix on it from them (the nearest release
// outside every one of them); nil when it reads it otherwise (the vendor's notation, Microsoft's release data, the distribution's
// package) or reads none.
func rangeParts(a Asset, s Software, v Vuln) *fixedParts {
	if _, ok := schemeFix(a, s, v); ok {
		return nil
	}
	in := newSWInfo(s, a.OS)
	if _, ok := windowsFixedIn(in, v); ok {
		return nil
	}
	var key []identity
	if keyedTo(s, v) {
		key = keyIDs(v)
	}
	if f := fixedInSoftware(in, v, key); f == nil || f.Kind != "fixed" {
		return nil
	}
	p := fixedPartsOf(in, v, key)
	return &p
}
