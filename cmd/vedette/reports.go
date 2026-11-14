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
	cfg := reports.Config{DB: d.DB, Audit: d.Audit, Inventory: reportsInventory{d.Inventory}, Findings: reportsFindings{d.Findings, &d}, KEV: reportsKEV{&d},
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
		name := deviceLabel(d)
		r := reports.Device{ID: d.ID, Name: name, IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile, Box: d.IsBox,
			NoDevice: strings.HasSuffix(name, inventory.NoDevice)}
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

type reportsFindings struct {
	svc *findings.Service
	d   *deps
}

func (a reportsFindings) All(ctx context.Context) ([]reports.Finding, error) {
	recs, err := a.svc.List(ctx, "")
	if err != nil {
		return nil, err
	}
	source := a.vulnCheckCVEs(ctx, recs)
	out := make([]reports.Finding, len(recs))
	for i, r := range recs {
		out[i] = reports.Finding{Source: source[r.CVE], ID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Status: string(r.Status), Severity: string(r.Severity), FirstSeen: r.FirstSeen, ResolvedAt: r.ResolvedAt, ResolvedBy: r.ResolvedBy, AcceptedUntil: r.AcceptedUntil}
	}
	return out, nil
}

// vulnCheckCVEs is the CVEs of these findings that only VulnCheck KEV lists, so the report can name it among its sources (D-557).
// A feeds store that cannot be read gives none: the report is then missing a source line, never wrong about a figure.
func (a reportsFindings) vulnCheckCVEs(ctx context.Context, recs []findings.Record) map[string]string {
	out := map[string]string{}
	if a.d == nil || (a.d.Reg != nil && !a.d.Reg.Enabled("feeds")) {
		return out
	}
	fs, err := feedsService(*a.d)
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	var cves []string
	for _, r := range recs {
		if !seen[r.CVE] {
			seen[r.CVE] = true
			cves = append(cves, r.CVE)
		}
	}
	rows, err := fs.Store().KevVulnsByCVE(ctx, cves)
	if err != nil {
		return out
	}
	for _, v := range rows {
		if v.SourceID == "vulncheck-kev" {
			out[v.CVE] = v.SourceID
		}
	}
	return out
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
		if v.SourceID != "cisa-kev" {
			continue // VulnCheck KEV (D-557) stays on the box: a report is a document that may be shared
		}
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

// reportsRemedies says the one release that closes each installed software on each device, with findings.FixedInForAll, the sibling of the
// function behind the "What to do" part of a finding page (D-488, D-490). It informs the text only: a device it cannot read is skipped.
// The report asks only for the findings of the products its page names.
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
	type device struct {
		vulns []findings.Vuln
		ids   map[string]string // finding id -> CVE
	}
	devs := map[string]*device{}
	var order []string
	for _, f := range fs {
		v, ok := byCVE[f.CVE]
		if !ok {
			continue
		}
		d := devs[f.AssetID]
		if d == nil {
			d = &device{ids: map[string]string{}}
			devs[f.AssetID] = d
			order = append(order, f.AssetID)
		}
		d.vulns = append(d.vulns, v)
		d.ids[f.ID] = f.CVE
	}
	out := map[string]reports.Fix{}
	for _, id := range order {
		d := devs[id]
		as, ok, err := inv.MatchInput(ctx, id)
		if err != nil || !ok {
			continue
		}
		groups := findings.FixedInForAll(as, d.vulns) // by CVE: one group per software of the device
		for fid, cve := range d.ids {
			if g := groups[cve]; g != nil {
				out[fid] = reports.Fix{Kind: g.Kind, Group: g.Software, Version: g.Version, Fixed: g.Fixed, Distro: g.Distro, Closed: true}
			}
		}
	}
	return out, nil
}

// ---- notify -> reports ----

type reportsIncidents struct{ d *deps }

// Week counts the incidents of notify last seen since the time, all of them, and names the first few (notify.IncidentsSince reads
// the class of each, so a busy week is not cut at the list size).
func (a reportsIncidents) Week(ctx context.Context, since time.Time, top int) (reports.IncidentWeek, bool, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled("notify") {
		return reports.IncidentWeek{}, false, nil
	}
	w, err := newNotify(a.d).IncidentsSince(ctx, since, top)
	if err != nil {
		return reports.IncidentWeek{}, false, err
	}
	out := reports.IncidentWeek{Traps: w.Counts["trap"], FailedLogins: w.Counts["failed_logins"], AcceptedLogins: w.Counts["login_accepted"],
		BadConnections: w.Counts["bad_connection"], Other: w.Counts["anomaly"]}
	for _, b := range w.Top {
		out.Top = append(out.Top, reports.Incident{Kind: b.Class, Severity: string(b.Severity), Title: b.Title, LastSeen: b.LastSeen})
	}
	return out, true, nil
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
