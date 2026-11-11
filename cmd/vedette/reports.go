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
		if d.IsBox {
			continue // the box itself is not a device of the customer's network
		}
		r := reports.Device{ID: d.ID, Name: d.IP, IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile}
		if d.Hostname != nil && *d.Hostname != "" {
			r.Name = *d.Hostname
		}
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
		out[i] = reports.Finding{ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status), Severity: string(r.Severity), FirstSeen: r.FirstSeen, ResolvedAt: r.ResolvedAt}
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
		out = append(out, reports.KEVEntry{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Key: feeds.ProductKey(v.Vendor, v.Product), DateAdded: day})
	}
	at, err := st.KevPulledAt(ctx)
	return out, at, err
}

// ---- notify -> reports ----

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
		Schema:    &provider.Schema{Name: "report_commentary", JSON: json.RawMessage(reportsAISchema)},
		MaxTokens: 900, Summary: fmt.Sprintf("Commentary on the %s", strings.ReplaceAll(job, "-", " ")),
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
