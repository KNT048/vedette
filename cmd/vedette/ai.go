package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/chain/chainhead"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/mitigation"
)

// newAI builds the ai service once, in buildServices (deps.AI): the handlers and the mitigation door share one router and one
// meter. It reads the box time zone from core's general settings once, at start (the meter's day boundary); a change of zone
// applies after a restart. The data it explains from comes through aiFacts, the ports of feeds, findings and the inventory.
func newAI(ctx context.Context, d *deps, facts ai.Facts) (*ai.Service, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cfg := ai.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Zone: orgZone(d), Facts: facts, ChainPruner: aiChainPruner{}}
	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil
		cfg.Modules = d.Reg
	}
	return ai.New(ctx, cfg)
}

// aiFacts implements ai.Facts: the exploited-list entry from feeds, the devices a CVE matches from findings and the inventory.
type aiFacts struct {
	feeds    *feeds.Store
	findings *findings.Service
	inv      findings.Inventory
}

func (f aiFacts) CVE(ctx context.Context, id string) (ai.CVEFacts, bool, error) {
	v, ok, err := f.feeds.VulnByCVE(ctx, id)
	if err != nil || !ok {
		return ai.CVEFacts{}, false, err
	}
	return ai.CVEFacts{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Name: v.Name, Description: v.Description, RequiredAction: v.RequiredAction,
		DateAdded: v.DateAdded, Links: v.Links, Ransomware: v.Ransomware, HasTemplate: v.HasTemplate}, true, nil
}

func (f aiFacts) AffectedAssets(ctx context.Context, cve string) ([]ai.AssetFact, error) {
	recs, err := f.findings.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var open []findings.Record
	var ids []string
	for _, r := range recs {
		if r.CVE == cve && r.Status.Open() {
			open = append(open, r)
			ids = append(ids, r.AssetID)
		}
	}
	if len(open) == 0 {
		return nil, nil
	}
	assets, err := f.inv.Assets(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]ai.AssetFact, 0, len(open))
	for _, r := range open {
		a, ok := assets[r.AssetID]
		if !ok {
			continue
		}
		name := a.IP
		if a.Hostname != nil && *a.Hostname != "" {
			name = *a.Hostname
		}
		out = append(out, ai.AssetFact{Name: name, IP: a.IP, Kind: a.Kind, Basis: string(r.Basis), Status: string(r.Status)})
	}
	return out, nil
}

// aiMitigation is mitigation's door to the AI (mitigation.AI): it turns a finding into data blocks for ai.Service.Brief and the
// answer back into text. The AI never gets a write tool here (SYS-8); mitigation stores the answer as an AI result.
type aiMitigation struct{ svc *ai.Service }

func jobOf(s mitigation.Skill) ai.Job {
	if s == mitigation.SkillConfig {
		return ai.JobMitigationConfig
	}
	return ai.JobExplainFinding
}

func (m aiMitigation) Available(_ context.Context, s mitigation.Skill) bool {
	return m.svc.Available(jobOf(s))
}

func (m aiMitigation) Run(ctx context.Context, req mitigation.AIRequest) (mitigation.AIOutput, error) {
	row := req.Finding
	var feed, dev strings.Builder
	var links []string
	if k := row.Kev; k != nil {
		fmt.Fprintf(&feed, "CVE: %s\nVendor: %s\nProduct: %s\nName: %s\nRequired action (CISA): %s\nAdded to the exploited list: %s\nUsed in ransomware campaigns: %t\nPublic check template exists: %t\nLinks: %s\n",
			row.CVE, k.Vendor, k.Product, k.Name, k.RequiredAction, k.DateAdded, k.Ransomware, k.HasTemplate, strings.Join(k.Links, " "))
		links = k.Links
	} else {
		fmt.Fprintf(&feed, "CVE: %s\n", row.CVE)
	}
	if a := row.Asset; a != nil {
		name := a.IP
		if a.Hostname != nil && *a.Hostname != "" {
			name = *a.Hostname
		}
		fmt.Fprintf(&dev, "Device: %s (%s), kind %s, %s\n", name, a.IP, a.Kind, a.Display)
	}
	fmt.Fprintf(&dev, "Finding status: %s, severity %s, matched by %s, confidence %.2f\nA confirmed recommendation pack exists: %t\n", row.Status, row.Severity, row.Basis, row.Confidence, req.HasPack)
	q := "Explain this finding."
	if req.Skill == mitigation.SkillConfig {
		q = "Draft a recommendation for this finding."
	}
	ans, err := m.svc.Brief(ctx, ai.BriefRequest{Job: jobOf(req.Skill), Actor: req.User, Target: row.CVE, Question: q,
		Data: []ai.DataBlock{{Kind: ai.DataFeed, Source: "exploited list entry " + row.CVE, Text: feed.String()}, {Kind: "inventory", Source: "the device of the finding", Text: dev.String()}}})
	if err != nil {
		if ae, ok := apierr.As(err); ok && (ae.Code == "ai_unavailable" || ae.Code == "daily_cap") {
			return mitigation.AIOutput{}, fmt.Errorf("%w: %s", mitigation.ErrAIUnavailable, ae.Message)
		}
		return mitigation.AIOutput{}, err
	}
	out := mitigation.AIOutput{Model: ans.Model, Profile: ans.Profile, InputTok: ans.TokensIn, OutputTok: ans.TokensOut, Paragraphs: ans.Paragraphs, Steps: ans.Steps, ActivityID: ans.ActivityID}
	for _, l := range links { // the box builds the sources from the feed entry; a model never supplies a link
		if u, err := url.Parse(l); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && len(out.Citations) < 2 {
			out.Citations = append(out.Citations, findings.Citation{Title: strings.TrimPrefix(u.Hostname(), "www."), URL: l})
		}
	}
	return out, nil
}

// aiChainPruner hands the retention prune of the activity log to core's chainhead.Prune, which moves the anchor and lowers the head in
// the prune's own transaction: the ai module never writes those core tables.
type aiChainPruner struct{}

func (aiChainPruner) Prune(ctx context.Context, tx *sql.Tx, chain, lastPrunedID, lastPrunedHash string, removed int64, now time.Time) error {
	return chainhead.Prune(ctx, tx, chain, lastPrunedID, lastPrunedHash, removed, now)
}

// aiJobs is the Jobs func of the ai entry in wiredModules: the "activity-prune" job.
func aiJobs(d deps) []jobs.Job { return d.AI.Jobs() }
