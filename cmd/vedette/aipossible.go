package main

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/modreg"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// possibleChecker is findings' PossibleChecker: the CVE record from feeds, the reference pages and the AI's proposal from the ai module
// (findings imports neither). The ai module off, or no profile for explaining findings: Ready says why, and no check runs.
type possibleChecker struct {
	feeds *feeds.Store
	ai    *ai.Service
	reg   *modreg.Registry
}

func (c possibleChecker) Ready(context.Context) error {
	if c.ai == nil || c.reg != nil && !c.reg.Enabled("ai") {
		return readyError("Checking possible findings needs the AI assistant module turned on (Settings, Modules).")
	}
	if err := c.ai.ResearchReady(); err != nil {
		if ae, ok := apierr.As(err); ok {
			return readyError(ae.Message)
		}
		return err
	}
	return nil
}

// readyError is why a check cannot run, in the words a person reads.
type readyError string

func (e readyError) Error() string { return string(e) }

func (c possibleChecker) Record(ctx context.Context, cve string) (findings.CVERecordText, error) {
	b, ok, err := c.feeds.Brief(ctx, cve)
	if err != nil || !ok {
		return findings.CVERecordText{}, err
	}
	kept, err := c.feeds.Kept(ctx, []string{cve}, time.Now())
	if err != nil {
		return findings.CVERecordText{}, err
	}
	stamps, err := c.feeds.RecordStamps(ctx, []string{cve})
	if err != nil {
		return findings.CVERecordText{}, err
	}
	out := findings.CVERecordText{Description: b.Description, Solution: b.Solution, Workaround: b.Workaround, Read: b.RecordAt != nil,
		Kept: kept[cve], Rows: recordRows(b.Ranges), Stamp: stamps[cve]}
	for _, r := range b.References {
		out.Refs = append(out.Refs, findings.RefLink{URL: r.URL, Tags: r.Tags})
	}
	return out, nil
}

// rowPins are the CPE 2.3 attributes a record row's text names (sw_edition, target_sw, target_hw), with the words for a value and for
// the build of none of the values other rows name.
var rowPins = []struct {
	i         int
	word, not string
}{{9, "edition", "edition not"}, {10, "on", "not on"}, {11, "hardware", "hardware not"}}

// cpeValue is the attribute of a row's CPE at i as a person reads it ("" for ANY, "-" for NA), "" when the CPE has no such field.
func cpeValue(f []string, i int) string {
	if len(f) != 13 || f[i] == "*" {
		return ""
	}
	return strings.ReplaceAll(f[i], "\\", "")
}

// recordRows is each affected row of a CVE record as findings reads it (recordRowText), with the edition its CPE pins, or the editions
// it is not (a "-" beside other rows of its product that pin one).
func recordRows(rs []feeds.BriefRange) []findings.RecordRow {
	named := map[string]map[int][]string{} // vendor:product of the CPE -> attribute -> the values its rows pin
	key := func(f []string) string { return f[3] + ":" + f[4] }
	for _, r := range rs {
		f := strings.Split(r.CPE, ":")
		for _, p := range rowPins {
			if v := cpeValue(f, p.i); v != "" && v != "-" {
				if named[key(f)] == nil {
					named[key(f)] = map[int][]string{}
				}
				if !slices.Contains(named[key(f)][p.i], v) {
					named[key(f)][p.i] = append(named[key(f)][p.i], v)
				}
			}
		}
	}
	out := make([]findings.RecordRow, 0, len(rs))
	for _, r := range rs {
		f := strings.Split(r.CPE, ":")
		var others map[int][]string
		if len(f) == 13 {
			others = named[key(f)]
		}
		row := findings.RecordRow{Vendor: r.Vendor, Product: r.Product, Text: recordRowText(r, others), Origin: r.Origin, DefaultStatus: r.DefaultStatus,
			VendorCNA: r.VendorCNA}
		switch v := cpeValue(f, 9); v {
		case "":
		case "-":
			row.NotEditions = slices.Sorted(slices.Values(others[9]))
		default:
			row.Edition = v // the edition the row's CPE pins (sw_edition)
		}
		out = append(out, row)
	}
	return out
}

// recordRowText is one affected row of a CVE record as a person reads it: the product, the edition, system or hardware its CPE pins,
// the systems it runs on, the versions and its fixed release, and who wrote the row ("acme browser (edition esr): affected from
// 115.1.0 before 115.42.0 [nvd]"). A "-" (CPE 2.3's NA: no value) where other rows of the product name values (others, by attribute)
// is the build of none of them ("acme browser (edition not esr)"): read as no pin, it would seem to speak for every build.
func recordRowText(r feeds.BriefRange, others map[int][]string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSpace(r.Vendor + " " + r.Product))
	if f := strings.Split(r.CPE, ":"); len(f) == 13 {
		var pins []string
		for _, p := range rowPins {
			switch v := cpeValue(f, p.i); {
			case v == "-" && len(others[p.i]) > 0:
				pins = append(pins, p.not+" "+strings.Join(slices.Sorted(slices.Values(others[p.i])), " or "))
			case v != "" && v != "-":
				pins = append(pins, p.word+" "+v)
			}
		}
		slices.Sort(pins)
		if len(pins) > 0 {
			b.WriteString(" (" + strings.Join(pins, ", ") + ")")
		}
	}
	if len(r.Platforms) > 0 {
		b.WriteString(" on " + strings.Join(r.Platforms, ", "))
	}
	b.WriteString(": affected " + r.Versions)
	if r.Fixed != "" && r.Fixed != r.EndExcl {
		b.WriteString(", fixed in " + r.Fixed)
	}
	if r.Origin != "" {
		b.WriteString(" [" + r.Origin + "]")
	}
	return b.String()
}

func (c possibleChecker) Fetch(ctx context.Context, urls []string) []findings.FetchedPage {
	var out []findings.FetchedPage
	for _, p := range c.ai.FetchReferences(ctx, urls) {
		out = append(out, findings.FetchedPage{URL: p.URL, Title: p.Title, Status: p.Status, Note: p.Note, Text: p.Text, JSON: p.JSON, Empty: p.Empty})
	}
	return out
}

// Research hands one research of a CVE's release line to the ai module (its research job: quick and strong profiles, mode, budget) and
// reads its answer for findings.
func (c possibleChecker) Research(ctx context.Context, actor string, req findings.ResearchRequest) (findings.ResearchAnswer, error) {
	r := ai.ResearchRequest{CVE: req.CVE, Vendor: req.Item.Vendor, Product: req.Item.Product, Line: req.Item.Line, Versions: req.Item.Version,
		Edition: req.Item.Edition, Platforms: req.Platforms, Digest: req.Digest, Deeper: req.Deeper}
	for _, p := range req.Pages {
		r.Pages = append(r.Pages, ai.RefPage{URL: p.URL, Title: p.Title, Status: p.Status, Text: p.Text, JSON: p.JSON})
	}
	ans, err := c.ai.Research(ctx, actor, r)
	if err != nil {
		return findings.ResearchAnswer{}, aiCallError(ctx, err)
	}
	out := findings.ResearchAnswer{Verdict: findings.ProposeVerdict{Status: ans.Verdict, Introduced: ans.Introduced, FixedIn: ans.FixedIn, LastAffected: ans.LastAffected,
		Line: ans.Line, Reason: ans.Reason, Quote: ans.Quote}, Confidence: ans.Confidence, Basis: ans.Basis, Trap: ans.Trap, URL: ans.URL,
		QuoteCheck: ans.QuoteCheck, QuotedText: ans.QuotedText, Mode: ans.Mode, Layer: ans.Layer, Note: ans.Note, Model: ans.Model, Profile: ans.Profile,
		ActivityID: ans.ActivityID, TokensIn: ans.TokensIn, TokensOut: ans.TokensOut}
	for _, st := range ans.Steps {
		out.Steps = append(out.Steps, findings.ResearchStep{Layer: st.Layer, Model: st.Model, Profile: st.Profile, Web: st.Web, TokensIn: st.TokensIn,
			TokensOut: st.TokensOut, Searches: st.Searches, Pages: st.Pages, Verdict: st.Verdict, Confidence: st.Confidence, QuoteCheck: st.QuoteCheck, Error: st.Error})
	}
	return out, nil
}

// refusedRetry is how long a background run leaves the items of a refused call: the same text is refused again until the record,
// the page, the names or the hooks change.
const refusedRetry = 24 * time.Hour

// aiCallError sorts the error of one call of a background AI run over items (the reading of advisories, the identification of
// software), the same way for both: a refusal of that call's text or answer (a hook's decision, an answer outside the schema or cut off)
// is that call's items alone (findings.ItemRefused) and the run goes on with the next items; an unusable answer is Systemic too (several
// in a row stop the run: the model cannot do the reading). The AI unavailable (no profile, the skill or the reading switched off, the
// provider unreachable), a budget reached, the runaway fuse or the run's own time up (ctx ended) stops the run (findings.CheckStop).
// Anything else, hooks that could not finish in time among them (they decided nothing: retry_after), is that call's failure, and its
// items wait for a later run.
func aiCallError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return &findings.CheckStop{Reason: "The run took longer than it may and stopped; it goes on at the next run."}
	}
	ae, ok := apierr.As(err)
	switch {
	case !ok:
		return err
	case ae.Code == "blocked_by_hook" && ae.Extra["retry_after"] != nil:
		return err
	case ae.Code == "blocked_by_hook":
		return &findings.ItemRefused{Reason: ae.Message, RetryAfter: refusedRetry}
	case ae.Code == "ai_bad_format", ae.Code == "ai_cut_off":
		return &findings.ItemRefused{Reason: ae.Message, RetryAfter: refusedRetry, Systemic: true}
	case ae.Status == http.StatusConflict, ae.Status == http.StatusTooManyRequests, ae.Code == "unreachable":
		return &findings.CheckStop{Reason: ae.Message}
	}
	return err
}

// Budget is how the automatic reading stands in the AI settings: on or off, and whether today's reads or this month's budget for
// background jobs hold it.
func (c possibleChecker) Budget(ctx context.Context) findings.ReadBudget {
	if c.ai == nil {
		return findings.ReadBudget{}
	}
	st := c.ai.AutoReadState(ctx)
	return findings.ReadBudget{Auto: st.Auto, Reached: st.Left <= 0 || st.Paused, ResearchReached: c.ai.ResearchShareUsed(ctx)}
}

// softwareIdentifier is findings' Identifier: the catalogue's products from feeds, the AI's choice from the ai module, and the names of
// the box's own devices and accounts, which never go to the AI inside a software name.
type softwareIdentifier struct {
	feeds *feeds.Store
	ai    *ai.Service
	inv   findings.Inventory
	users func(ctx context.Context) ([]auth.User, error)
}

func (c softwareIdentifier) Products(ctx context.Context) ([]findings.CatalogueName, error) {
	ps, err := c.feeds.CatalogueProducts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]findings.CatalogueName, len(ps))
	for i, p := range ps {
		out[i] = findings.CatalogueName{Vendor: p.Vendor, Product: p.Product, Record: p.Record, Kev: p.Kev, CVEs: p.CVEs, Exploited: p.Exploited}
	}
	return out, nil
}

func (c softwareIdentifier) Identify(ctx context.Context, actor string, req findings.IdentifyRequest) (findings.IdentifyAnswer, error) {
	items := make([]ai.IdentifyItem, 0, len(req.Items))
	for _, it := range req.Items {
		x := ai.IdentifyItem{Index: it.Index, Publisher: it.Publisher, Name: it.Name, Version: it.Version}
		for _, cand := range it.Candidates {
			x.Candidates = append(x.Candidates, ai.IdentifyCandidate{ID: cand.ID, Title: cand.Title, Product: cand.Product, CVEs: cand.CVEs})
		}
		items = append(items, x)
	}
	ans, err := c.ai.IdentifyProducts(ctx, actor, items)
	if err != nil {
		return findings.IdentifyAnswer{}, aiCallError(ctx, err)
	}
	out := findings.IdentifyAnswer{Model: ans.Model, ActivityID: ans.ActivityID}
	for _, ch := range ans.Choices {
		out.Choices = append(out.Choices, findings.IdentifyChoice{Index: ch.Index, Choice: ch.Choice, Match: ch.Match, Reason: ch.Reason})
	}
	return out, nil
}

// PrivateNames are every device's name and hostname, and every account's name, email address and the part of it before the @.
func (c softwareIdentifier) PrivateNames(ctx context.Context) ([]string, error) {
	var out []string
	if c.inv != nil {
		ids, err := c.inv.AssetIDs(ctx)
		if err != nil {
			return nil, err
		}
		views, err := c.inv.Assets(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, v := range views {
			out = append(out, v.Name)
			if v.Hostname != nil {
				out = append(out, *v.Hostname)
			}
		}
	}
	if c.users != nil {
		us, err := c.users(ctx)
		if err != nil {
			return nil, err
		}
		for _, u := range us {
			local, _, _ := strings.Cut(u.Email, "@")
			out = append(out, u.Name, u.Email, local)
		}
	}
	return out, nil
}
