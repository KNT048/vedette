package main

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// A finding as every place that talks about it reads it: findings.View (the device, the software line, the fix and the confirmation as
// the finding page shows them) and feeds.Brief (everything the box holds about the CVE). The assistant's context, the MCP tools, the
// response triggers and the AI answers are built here and nowhere else, so the fixed version a person is told equals the one the page
// shows, and a finding a person confirmed reads "confirmed by <person>" in all of them.

// findingCase is one finding with the brief of its CVE.
type findingCase struct {
	View  findings.View
	Brief feeds.Brief
	Known bool // the catalogue holds the CVE; false: Brief is empty
}

// caseSource reads findingCases from the findings service and the catalogue.
type caseSource struct {
	findings *findings.Service
	feeds    *feeds.Store
}

// briefOf reads the brief of a CVE once per call of a list.
func (c caseSource) briefOf(ctx context.Context, memo map[string]*feeds.Brief, cve string) (*feeds.Brief, error) {
	if b, ok := memo[cve]; ok {
		return b, nil
	}
	var out *feeds.Brief
	if c.feeds != nil {
		b, ok, err := c.feeds.Brief(ctx, cve)
		if err != nil {
			return nil, err
		}
		if ok {
			out = &b
		}
	}
	memo[cve] = out
	return out, nil
}

func (c caseSource) wrap(ctx context.Context, memo map[string]*feeds.Brief, v findings.View) (findingCase, error) {
	b, err := c.briefOf(ctx, memo, v.Finding.CVE)
	if err != nil {
		return findingCase{}, fmt.Errorf("the brief of %s: %w", v.Finding.CVE, err)
	}
	fc := findingCase{View: v}
	if b != nil {
		fc.Brief, fc.Known = *b, true
	}
	return fc, nil
}

// One reads the case of one finding, with the urgency reasons of its own page. findings.ErrNotFound when there is none.
func (c caseSource) One(ctx context.Context, id string) (findingCase, error) {
	v, err := c.findings.View(ctx, id)
	if err != nil {
		return findingCase{}, err
	}
	return c.wrap(ctx, map[string]*feeds.Brief{}, v)
}

// Many reads the cases of the findings a filter selects.
func (c caseSource) Many(ctx context.Context, f findings.ViewFilter) ([]findingCase, error) {
	vs, err := c.findings.Views(ctx, f)
	if err != nil {
		return nil, err
	}
	memo := map[string]*feeds.Brief{}
	out := make([]findingCase, 0, len(vs))
	for _, v := range vs {
		fc, err := c.wrap(ctx, memo, v)
		if err != nil {
			return nil, err
		}
		out = append(out, fc)
	}
	return out, nil
}

// ---- the words ----

// FixText is the fix of the finding in one sentence, the one the finding page shows (findings.View.FixText).
func (c findingCase) FixText() string { return c.View.FixText() }

// matchingRange is the range row of the brief that this device's fix comes from ("your device"), nil when the fix names none or no
// counting row states it.
func (c findingCase) matchingRange() *feeds.BriefRange {
	fix := c.View.Finding.Fix.Version
	if fix == "" {
		return nil
	}
	for i, r := range c.Brief.Ranges {
		if r.Counts && (r.FixedRelease == fix || r.Fixed == fix) {
			return &c.Brief.Ranges[i]
		}
	}
	return nil
}

// ConfirmText says what confirmed the finding, or that nothing has; never who (findings.View.ConfirmText).
func (c findingCase) ConfirmText() string { return c.View.ConfirmText() }

// WorkaroundText is the workaround the CVE record gives, or the plain sentence when it gives none.
func (c findingCase) WorkaroundText() string { return briefWorkaround(c.Brief) }

func briefWorkaround(b feeds.Brief) string {
	if w := aiVal(b.Workaround, 800); w != "" {
		return w
	}
	return "No workaround is published: install the fix."
}

// caseLink is a reference the answer may link: the box builds every link of an answer from these, a model only names one by its number.
type caseLink struct{ Title, URL string }

var refLabels = map[string]string{
	"vendor-advisory": "Vendor advisory", "patch": "Patch", "mitigation": "Mitigation", "release-notes": "Release notes", "exploit": "Exploit",
	"government-resource": "Government resource", "third-party-advisory": "Third-party advisory", "technical-description": "Technical description",
	"issue-tracking": "Issue tracking", "mailing-list": "Mailing list", "vdb-entry": "Vulnerability database entry", "media-coverage": "Media coverage",
}

// refsMax is how many references an answer may cite: the groups the questions need first (vendor advisory, patch, mitigation).
const refsMax = 12

// Links are the references an answer may cite, numbered from 1 by their position: the vendor's own pages first, then the exploited
// list's links, then NVD and the CVE Program. Only plain http(s) addresses.
func (c findingCase) Links() []caseLink {
	var out []caseLink
	seen := map[string]bool{}
	add := func(title, raw string) {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" || len(raw) > 500 || seen[raw] || strings.ContainsAny(raw, " \n\t") || len(out) >= refsMax {
			return
		}
		seen[raw] = true
		out = append(out, caseLink{Title: aiVal(title, 80), URL: raw})
	}
	for _, r := range c.Brief.References {
		if r.Group == "vendor-advisory" || r.Group == "patch" || r.Group == "mitigation" {
			add(refLabels[r.Group], r.URL)
		}
	}
	for _, l := range c.Brief.Lists {
		for _, u := range l.Links {
			add(cmp.Or(l.SourceName, "Exploited list")+" link", u)
		}
	}
	for _, r := range c.Brief.References {
		if r.Group != "vendor-advisory" && r.Group != "patch" && r.Group != "mitigation" && r.Group != feeds.RefOther {
			add(refLabels[r.Group], r.URL)
		}
	}
	if c.Known {
		add("NVD", c.Brief.NVDURL)
		add("CVE record", c.Brief.RecordURL)
	}
	return out
}

// StatusWords is why the finding matters now, in plain words, for the status the view carries.
func (c findingCase) StatusWords() string {
	s := aiUrgencyText(findings.LayerCode(c.View.Finding.Urgency))
	if c.View.Finding.State != findings.StateOpen {
		return "handled: " + string(c.View.Finding.Resolution) + " (" + s + " when it was open)"
	}
	var rs []string
	for _, r := range c.View.Reasons {
		x := r.Name
		if r.Detail != "" {
			x += " (" + aiVal(r.Detail, 120) + ")"
		}
		if r.Due != "" {
			x += ", the list asks for the fix by " + r.Due
		}
		rs = append(rs, x)
	}
	if len(rs) > 0 {
		s += "; reasons: " + strings.Join(rs, ", ")
	}
	return s
}

// attackWords says how the flaw is reached, from the CVSS vector of the brief read into words.
func (c findingCase) attackWords() string {
	b := c.Brief.CVSS
	if b == nil || b.Reading == nil {
		return "Attack conditions: not known (no CVSS vector)."
	}
	r := b.Reading
	s := "Attack conditions (" + aiVal(b.Source, 10) + " CVSS " + aiVal(b.Version, 5) + " vector): attack vector: " + aiVal(r.AttackVector, 20) + "; privileges required: " +
		aiVal(r.PrivilegesRequired, 20)
	if r.UserInteraction != "" {
		s += "; user interaction: " + aiVal(r.UserInteraction, 20)
	}
	return s + "."
}

// briefFeedText is the CVE brief as the text of a data block (the numbered references go with it): every line is a fact of the stored
// catalogue, each value one line and cut, since a feed wrote it.
func (c findingCase) briefFeedText(links []caseLink) string { return c.briefText(links, true) }

// briefKeyText is briefFeedText without the numbers that change every day (EPSS), for the key of a saved answer: the next day's score
// is no reason to ask again.
func (c findingCase) briefKeyText(links []caseLink) string { return c.briefText(links, false) }

func (c findingCase) briefText(links []caseLink, volatile bool) string {
	b := c.Brief
	var t strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&t, format+"\n", a...) }
	p("CVE: %s", b.CVE)
	if !c.Known {
		p("The box's catalogue has no record of this CVE.")
		return t.String()
	}
	if b.Title != "" {
		p("Title: %s", aiVal(b.Title, 200))
	}
	if b.Description != "" {
		p("Description: %s", aiVal(b.Description, 700))
	}
	if len(b.Products) > 0 {
		p("Products named by the affected versions: %s", aiVal(strings.Join(b.Products, "; "), 300))
	}
	if len(b.CWE) > 0 {
		var ws []string
		for _, w := range b.CWE {
			ws = append(ws, strings.TrimSpace(w.ID+" "+w.Name))
		}
		p("Weakness: %s", aiVal(strings.Join(ws, "; "), 300))
	}
	if cv := b.CVSS; cv != nil {
		p("CVSS %s base score: %.1f (%s), vector %s", aiVal(cv.Version, 5), cv.Score, strings.ToLower(aiVal(cv.Severity, 12)), aiVal(cv.Vector, 200))
	}
	p("%s", c.attackWords())
	for _, l := range b.Lists {
		line := fmt.Sprintf("Exploited list: %s lists it, added %s", aiVal(cmp.Or(l.SourceName, l.Source), 60), aiVal(l.DateAdded, 20))
		if a := aiVal(l.RequiredAction, 400); a != "" {
			line += "; required action from the list: " + a
		}
		p("%s; used in ransomware campaigns: %t", line, l.Ransomware)
	}
	for _, g := range b.Signals {
		if g.Kind == feeds.SignalAttackedHere {
			continue // this network's own alerts: the urgency line says what the AI may know of them, no dates of the alerts
		}
		p("Signal: %s from %s, first seen %s", aiVal(g.Kind, 40), aiVal(g.SourceName, 60), g.FirstSeen.UTC().Format(time.DateOnly))
	}
	if e := b.EPSS; e != nil && volatile {
		p("EPSS: %.1f%% chance of exploitation in the next 30 days (FIRST, %s)", e.Score*100, aiVal(e.Day, 20))
	}
	if b.RangesFrom != "" {
		p("Affected versions come from %s.%s", rangesSource(b), nvdLagWords(b))
	}
	if n := countingRanges(b); len(n) > 0 {
		var rs []string
		for _, r := range n[:min(len(n), 8)] {
			rs = append(rs, aiVal(r.Versions, 80))
		}
		more := ""
		if len(n) > 8 {
			more = fmt.Sprintf(" (and %d more)", len(n)-8)
		}
		p("Affected versions: %s%s", strings.Join(rs, "; "), more)
	}
	if len(b.Fixes) > 0 {
		var fs []string
		for _, f := range b.Fixes[:min(len(b.Fixes), 8)] {
			fs = append(fs, "release train "+aiVal(f.Train, 30)+" is fixed in "+aiVal(f.Release, 60))
		}
		p("Fixed releases the record states, per release train: %s", strings.Join(fs, "; "))
	}
	if s := aiVal(b.Solution, 600); s != "" {
		p("Solution (from the CVE record): %s", s)
	}
	p("Workaround: %s", c.WorkaroundText())
	if b.SSVC.Exploitation != "" {
		p("CISA SSVC: exploitation %s, automatable %s, technical impact %s", aiVal(b.SSVC.Exploitation, 20), aiVal(b.SSVC.Automatable, 20), aiVal(b.SSVC.Impact, 20))
	}
	for i, l := range links {
		p("Reference [%d]: %s, %s", i+1, l.Title, l.URL)
	}
	return t.String()
}

func countingRanges(b feeds.Brief) []feeds.BriefRange {
	var out []feeds.BriefRange
	for _, r := range b.Ranges {
		if r.Counts && r.Versions != "" {
			out = append(out, r)
		}
	}
	return out
}

func rangesSource(b feeds.Brief) string {
	switch b.RangesFrom {
	case feeds.OriginNVD:
		return "NVD"
	case feeds.OriginADP:
		return "CISA's data in the CVE record"
	}
	return "the CVE record (the vendor)"
}

// nvdLagWords: the affected versions of a CVE NVD has not analysed are the vendor's own, and the finding says so.
func nvdLagWords(b feeds.Brief) string {
	if b.RangesFrom == feeds.OriginNVD {
		return ""
	}
	return " NVD has not analysed this CVE yet."
}

// deviceFactsText is the finding's own facts as the text of a data block: what was matched, the fix and who confirmed it.
func (c findingCase) deviceFactsText() string {
	v := c.View
	f := v.Finding
	var t strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&t, format+"\n", a...) }
	if l := v.Line; l != nil {
		p("Software line of the finding: %s", strings.TrimSpace(aiVal(cmp.Or(l.Display, l.ProductKey), 100)+" "+aiVal(l.Version, 60)))
	}
	if f.MatchedVersion != "" {
		p("Version Vedette compared with the affected versions: %s", aiVal(f.MatchedVersion, 60))
	}
	if f.RangeOrigin == feeds.OriginCNA || f.RangeOrigin == feeds.OriginADP {
		p("The affected versions it was compared with are the vendor's own, from the CVE record; NVD has not analysed this CVE yet.")
	}
	p("Fix for this device: %s", c.FixText())
	if r := c.matchingRange(); r != nil {
		p("Your device matches: %s (fixed release %s).", aiVal(r.Versions, 100), aiVal(cmp.Or(r.FixedRelease, r.Fixed), 80))
	}
	p("Confirmation: %s", c.ConfirmText())
	p("Finding status: %s", c.StatusWords())
	if f.Evidence != nil && f.Evidence.Summary != "" {
		p("Evidence (installed version and affected range): %s", aiVal(f.Evidence.Summary, 600))
	}
	return t.String()
}
