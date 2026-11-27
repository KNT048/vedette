package main

import (
	"context"

	"github.com/knt048/vedette/core/apierr"
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
	if err := c.ai.PossibleReady(); err != nil {
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
	out := findings.CVERecordText{Description: b.Description}
	for _, r := range b.References {
		out.Refs = append(out.Refs, findings.RefLink{URL: r.URL, Tags: r.Tags})
	}
	return out, nil
}

func (c possibleChecker) Fetch(ctx context.Context, urls []string) []findings.FetchedPage {
	var out []findings.FetchedPage
	for _, p := range c.ai.FetchReferences(ctx, urls) {
		out = append(out, findings.FetchedPage{URL: p.URL, Title: p.Title, Status: p.Status, Note: p.Note, Text: p.Text, JSON: p.JSON, Empty: p.Empty})
	}
	return out
}

func (c possibleChecker) Propose(ctx context.Context, actor string, req findings.ProposeRequest) (findings.ProposeAnswer, error) {
	r := ai.PossibleRequest{CVE: req.CVE, Description: req.Description, Rows: req.Rows}
	for _, it := range req.Items {
		r.Items = append(r.Items, ai.PossibleItem{Index: it.Index, Vendor: it.Vendor, Product: it.Product, Version: it.Version, Line: it.Line})
	}
	for _, p := range req.Pages {
		r.Pages = append(r.Pages, ai.RefPage{URL: p.URL, Title: p.Title, Status: p.Status, Text: p.Text, JSON: p.JSON})
	}
	ans, err := c.ai.ProposePossible(ctx, actor, r)
	if err != nil {
		if ae, ok := apierr.As(err); ok && (ae.Status == 409 || ae.Status == 429) {
			return findings.ProposeAnswer{}, &findings.CheckStop{Reason: ae.Message} // no profile, or a budget: the check stops
		}
		return findings.ProposeAnswer{}, err
	}
	out := findings.ProposeAnswer{Model: ans.Model, Profile: ans.Profile, ActivityID: ans.ActivityID}
	for _, v := range ans.Verdicts {
		out.Verdicts = append(out.Verdicts, findings.ProposeVerdict{Index: v.Index, Verdict: v.Verdict, Reason: v.Reason, Quote: v.Quote, Source: v.Source})
	}
	return out, nil
}
