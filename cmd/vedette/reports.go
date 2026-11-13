package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/reports"
)

var (
	reportsMu       sync.Mutex
	reportsServices = map[*store.DB]*reports.Service{}
)

// reportsService builds the reports service once per database, so the handlers and the weekly-send job share it (and its
// one-send-at-a-time lock). It reads every other module through the adapters below (reports FORBID-4).
func reportsService(d deps) *reports.Service {
	reportsMu.Lock()
	defer reportsMu.Unlock()
	if s := reportsServices[d.DB]; s != nil {
		return s
	}
	cfg := reports.Config{DB: d.DB, Audit: d.Audit, Inventory: reportsInventory{d.Inventory}, Findings: reportsFindings{d.Findings}, KEV: reportsKEV{&d},
		Remedies: reportsRemedies{d: &d, feed: findingsFeeds{cache: &vulnCache{}}}, Incidents: reportsIncidents{&d},
		Mail: reportsMailer{newNotify(&d)}, AI: reportsAI{d.AI}, OrgName: d.Core.OrgName, Zone: orgZone(&d), Log: d.Log, Clock: d.Clock}
	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil
		cfg.Modules = d.Reg
	}
	svc, err := reports.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	reportsServices[d.DB] = svc
	return svc
}

// reportsJobs is the Jobs func of the reports entry in wiredModules.
func reportsJobs(d deps) []jobs.Job { return reports.Jobs(reportsService(d)) }

// ---- inventory -> reports ----

type reportsInventory struct{ inv *inventory.Service }

func (a reportsInventory) Devices(ctx context.Context) ([]reports.Device, error) {
	devs, err := a.inv.AllDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]reports.Device, 0, len(devs))
	for _, d := range devs {
		// The box is listed: the weekly report counts what the Devices page counts (D-485); the PDPL report leaves it out.
		r := reports.Device{ID: d.ID, Name: deviceLabel(d.AssetCore), IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile, Box: d.IsBox}
		if t, err := time.Parse(time.RFC3339, d.FirstSeen); err == nil {
			r.FirstSeen = t
		}
		if d.OS != nil {
			r.OS = d.OS.Value
		}
		for _, o := range []*inventory.Observed{d.Vendor, d.Model, d.OS} {
			if o != nil {
				r.Sources = append(r.Sources, o.Source)
			}
		}
		for _, s := range d.Services {
			r.Ports = append(r.Ports, s.Port)
		}
		for _, sw := range d.Software {
			r.KevKeys = append(r.KevKeys, sw.Kev...)
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- findings -> reports ----

type reportsFindings struct{ svc *findings.Service }

func (a reportsFindings) All(ctx context.Context) ([]reports.Finding, error) {
	recs, err := a.svc.List(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]reports.Finding, len(recs))
	for i, r := range recs {
		out[i] = reports.Finding{ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status), Severity: string(r.Severity), FirstSeen: r.FirstSeen, ResolvedAt: r.ResolvedAt, ResolvedBy: r.ResolvedBy}
	}
	return out, nil
}

// ---- feeds -> reports ----

type reportsKEV struct{ d *deps }

func (a reportsKEV) Entries(ctx context.Context) ([]reports.KEVEntry, time.Time, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled("feeds") {
		return nil, time.Time{}, nil // feeds is off: the report has no exploited-list figures, and says so by their source time
	}
	fs, err := feedsService(*a.d)
	if err != nil {
		return nil, time.Time{}, err
	}
	st := fs.Store()
	rows, err := st.KevVulns(ctx)
	if err != nil {
		return nil, time.Time{}, err
	}
	out := make([]reports.KEVEntry, 0, len(rows))
	for _, v := range rows {
		day, err := time.Parse(time.DateOnly, v.DateAdded)
		if err != nil {
			continue // a row with an odd date is not counted in any week
		}
		out = append(out, reports.KEVEntry{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Display: feeds.DisplayOf(v.Vendor, v.Product), Key: feeds.ProductKey(v.Vendor, v.Product), DateAdded: day})
	}
	at, err := st.KevPulledAt(ctx)
	return out, at, err
}

// NewlyExploited is the Home headline (feeds.Service.NewlyExploited), so the report and Home agree (D-485).
func (a reportsKEV) NewlyExploited(ctx context.Context) (int, int, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled("feeds") {
		return 0, 0, nil
	}
	fs, err := feedsService(*a.d)
	if err != nil {
		return 0, 0, err
	}
	return fs.NewlyExploited(ctx)
}

// ---- findings + inventory -> reports ----

// maxFixes bounds how many findings one report asks a fixed release for (a box with more open findings names the fixes of the
// first ones, which are the worst: Findings.All is newest first and the report only names three risks).
const maxFixes = 2000

// reportsRemedies says the release that closes each open finding on its device, with findings.FixedInFor, the function behind
// the "What to do" part of a finding page (D-488, D-490). It informs the text only: a device it cannot read is skipped.
type reportsRemedies struct {
	d    *deps
	feed findingsFeeds // st is set at first use (feeds is built after reports on some paths)
}

func (a reportsRemedies) Fixes(ctx context.Context, fs []reports.Finding) (map[string]reports.Fix, error) {
	if a.d.Inventory == nil || (a.d.Reg != nil && !a.d.Reg.Enabled("feeds")) {
		return nil, nil
	}
	svc, err := feedsService(*a.d)
	if err != nil {
		return nil, err
	}
	feed := a.feed
	feed.st = svc.Store()
	vulns, err := feed.Vulns(ctx)
	if err != nil {
		return nil, err
	}
	byCVE := make(map[string]findings.Vuln, len(vulns))
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	inv := findingsInventory{a.d.Inventory}
	assets := map[string]*findings.Asset{} // nil: the device cannot be read
	out := map[string]reports.Fix{}
	for i, f := range fs {
		if i == maxFixes {
			break
		}
		v, ok := byCVE[f.CVE]
		if !ok {
			continue
		}
		as, seen := assets[f.AssetID]
		if !seen {
			if m, ok, err := inv.MatchInput(ctx, f.AssetID); err == nil && ok {
				as = &m
			}
			assets[f.AssetID] = as
		}
		if as == nil {
			continue
		}
		if fx := findings.FixedInFor(*as, v); fx != nil {
			out[f.ID] = reports.Fix{Kind: fx.Kind, Version: fx.Version, Fixed: fx.Fixed, Distro: fx.Distro}
		}
	}
	return out, nil
}

// ---- notify -> reports ----

type reportsIncidents struct{ d *deps }

// Since lists the incidents of notify last seen since the time. The kind a person cares about is read from notify's kind and, for
// the two log anomalies the failed-login rule raises, from the title it writes (modules/logs/authfail.go; notify keeps no target on
// the API row): "N failed logins from <address> on <source> in M minutes" and "A login from <address> was ACCEPTED after failed
// attempts on <source>". New-device incidents are left out: the Devices count says them.
func (a reportsIncidents) Since(ctx context.Context, since time.Time) ([]reports.Incident, bool, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled("notify") {
		return nil, false, nil
	}
	list, err := newNotify(a.d).Incidents(ctx)
	if err != nil {
		return nil, false, err
	}
	var out []reports.Incident
	for _, in := range list {
		at, err := time.Parse(time.RFC3339, in.LastSeen)
		if err != nil || !at.After(since) {
			continue
		}
		kind := incidentKind(in.Kind, in.Title)
		if kind == "" {
			continue
		}
		out = append(out, reports.Incident{Kind: kind, Severity: string(in.Severity), Title: in.Title, Count: in.Count, LastSeen: at})
	}
	return out, true, nil
}

// incidentKind is the kind reports names an incident by ("" = not in the report).
func incidentKind(k notify.IncidentKind, title string) string {
	switch k {
	case notify.IncidentTrap:
		return "trap"
	case notify.IncidentBadAddress:
		return "bad_connection"
	case notify.IncidentLogAnomaly:
		switch {
		case strings.Contains(title, "was ACCEPTED after failed attempts"):
			return "login_accepted"
		case strings.Contains(title, " failed logins from "):
			return "failed_logins"
		}
		return "anomaly"
	}
	return ""
}

type reportsMailer struct{ svc *notify.Service }

func (m reportsMailer) Ready(ctx context.Context) (bool, string) { return m.svc.EmailReady(ctx) }

func (m reportsMailer) Send(ctx context.Context, to []string, r reports.Mail) error {
	return m.svc.SendReport(ctx, to, notify.ReportMail{Title: r.Title, What: r.What, Action: r.Action, Items: r.Items, Path: r.Path})
}

// ---- ai -> reports ----

type reportsAI struct{ svc *ai.Service }

func (a reportsAI) Available(job string) bool { return a.svc.Available(ai.Job(job)) }

const reportsAISchema = `{"type":"object","properties":{"paragraphs":{"type":"array","items":{"type":"string"}}},"required":["paragraphs"],"additionalProperties":false}`

var errReportsAIBad = errors.New("reports: the AI answer is not the expected shape")

// parseParagraphs reads the answer: one object with 1 to 4 paragraphs, each cleaned and bounded. Anything else is refused.
func parseParagraphs(text string) ([]string, error) {
	var b struct {
		Paragraphs []string `json:"paragraphs"`
	}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(text)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil || dec.More() {
		return nil, errReportsAIBad
	}
	var out []string
	for _, p := range b.Paragraphs {
		p = strings.Join(strings.Fields(p), " ")
		if utf8.RuneCountInString(p) > 1200 {
			p = string([]rune(p)[:1200])
		}
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 || len(out) > 4 {
		return nil, errReportsAIBad
	}
	return out, nil
}

func (a reportsAI) Summarize(ctx context.Context, actor, job, task string, data []reports.Block) (reports.Summary, error) {
	blocks := make([]ai.DataBlock, len(data))
	for i, b := range data {
		blocks[i] = ai.DataBlock{Kind: ai.DataFeed, Source: b.Source, Text: b.Text}
	}
	var paragraphs []string
	res, err := a.svc.RunJob(ctx, ai.JobSpec{
		Job: ai.Job(job), Actor: actor, Task: task, Question: "Write the commentary.", Data: blocks,
		Schema: &provider.Schema{Name: "report_commentary", JSON: json.RawMessage(reportsAISchema)},
		// at most 4 paragraphs, about 1,200 tokens; the rest is room for what the model thinks first (a cut answer is asked again once)
		MaxTokens: 4000, Summary: fmt.Sprintf("Commentary on the %s", strings.ReplaceAll(job, "-", " ")),
		Check: func(text string) error {
			var perr error
			paragraphs, perr = parseParagraphs(text)
			return perr
		},
	})
	if err != nil {
		return reports.Summary{}, err
	}
	return reports.Summary{Paragraphs: paragraphs, Model: res.Model, Profile: res.Profile, TokensIn: res.TokensIn, TokensOut: res.TokensOut}, nil
}
