package main

import (
	"context"
	"strings"

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
		out.Verdicts = append(out.Verdicts, findings.ProposeVerdict{Index: v.Index, Status: v.Status, Introduced: v.Introduced, FixedIn: v.FixedIn,
			LastAffected: v.LastAffected, Line: v.Line, Reason: v.Reason, Quote: v.Quote, Source: v.Source})
	}
	return out, nil
}

// Budget is how the automatic reading stands in the AI settings: on or off, and whether today's reads or this month's budget for
// background jobs hold it.
func (c possibleChecker) Budget(ctx context.Context) findings.ReadBudget {
	if c.ai == nil {
		return findings.ReadBudget{}
	}
	st := c.ai.AutoReadState(ctx)
	return findings.ReadBudget{Auto: st.Auto, Reached: st.Left <= 0 || st.Paused}
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
		return findings.IdentifyAnswer{}, identifyErr(err)
	}
	out := findings.IdentifyAnswer{Model: ans.Model, ActivityID: ans.ActivityID}
	for _, ch := range ans.Choices {
		out.Choices = append(out.Choices, findings.IdentifyChoice{Index: ch.Index, Choice: ch.Choice, Match: ch.Match, Reason: ch.Reason})
	}
	return out, nil
}

// identifyErr is the error of one identification call as the run reads it: no profile, or a budget, stops the whole run
// (findings.CheckStop); a hook that stopped the call is about the names of that call, so the call failed and its names wait while the
// run goes on (a deterministic hook would otherwise stop every run at the same names).
func identifyErr(err error) error {
	if ae, ok := apierr.As(err); ok && (ae.Status == 409 || ae.Status == 429) && ae.Code != "blocked_by_hook" {
		return &findings.CheckStop{Reason: ae.Message}
	}
	return err
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
