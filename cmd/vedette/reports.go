package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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

// reportsService builds the reports service once per database, so the handlers, the send job and the schedule share it (and its
// one-send-at-a-time lock); its schedule owner registers with core/schedule then. It reads every other module through the adapters
// below (reports FORBID-4).
func reportsService(d deps) *reports.Service {
	reportsMu.Lock()
	defer reportsMu.Unlock()
	if s := reportsServices[d.DB]; s != nil {
		return s
	}
	cfg := reports.Config{DB: d.DB, Audit: d.Audit, Inventory: reportsInventory{d.Inventory}, Findings: reportsFindings{d.Findings},
		Views: reportsViews{d.Findings}, KEV: reportsKEV{&d}, Exposure: reportsExposure{&d}, Detections: reportsDetections{&d}, Feeds: reportsFeeds{&d},
		AI: reportsAI{d.AI}, OrgName: d.Core.OrgName, Zone: orgZone(&d), Log: d.Log, Clock: d.Clock}
	mailer := &reportsMailer{svc: newNotify(&d)}
	cfg.Mail = mailer
	if d.Reg != nil { // a nil *modreg.Registry inside the interface would not compare equal to nil
		cfg.Modules = d.Reg
	}
	svc, err := reports.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	mailer.document = svc.Document
	if d.Schedules != nil {
		if err := d.Schedules.Register(svc.ScheduleOwner()); err != nil {
			panic("vedette: " + err.Error()) // the owner is a constant of the package: registered once per database
		}
	}
	reportsServices[d.DB] = svc
	return svc
}

// reportsJobs is the Jobs func of the reports entry in wiredModules.
func reportsJobs(d deps) []jobs.Job { return reports.Jobs(reportsService(d)) }

// ---- inventory -> reports ----

type reportsInventory struct{ inv *inventory.Service }

// Devices lists the devices a person did not ignore, as the Devices page counts them (the box included).
func (a reportsInventory) Devices(ctx context.Context) ([]reports.Device, error) {
	devs, err := a.inv.AllDevices(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]reports.Device, 0, len(devs))
	for _, d := range devs {
		if d.IgnoredAt != nil {
			continue // A device a person ignored is in no count of the Devices page, so in none of a report
		}
		r := reports.Device{ID: d.ID, Name: deviceLabel(d), IP: d.IP, Kind: d.Kind, Approved: d.Approved, Fragile: d.Fragile, Box: d.IsBox}
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
		for _, sw := range d.Software { // an agent (osquery, Wazuh, the box's own host agent) reports the software of the device
			if sw.Source == "agent" {
				r.Agent = true
				break
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- findings -> reports ----

// reportsFindings is the PDPL assessment's read of findings: the open findings as findings.View reads them (a device a person ignored
// is left out with its findings, as on every list), in the assessment's own status words: "confirmed" when a scan or a person
// confirmed it, "suspected" otherwise; the severity is the CVSS band of the CVE as every page shows it ("medium" while it has no score).
type reportsFindings struct{ svc *findings.Service }

func (a reportsFindings) All(ctx context.Context) ([]reports.Finding, error) {
	vs, err := a.svc.Views(ctx, findings.ViewFilter{OpenOnly: true})
	if err != nil {
		return nil, err
	}
	out := make([]reports.Finding, len(vs))
	for i, v := range vs {
		f := v.Finding
		status, severity := "suspected", "medium"
		if f.Confirmed() {
			status = "confirmed"
		}
		if v.Severity != nil {
			if severity = findings.SeverityBand(*v.Severity); severity == "none" { // a score of 0: the assessment's lowest word
				severity = "info"
			}
		}
		out[i] = reports.Finding{ID: f.ID, AssetID: f.AssetID, CVE: f.CVE, Status: status, Severity: severity, FirstSeen: f.FirstSeen,
			Agent: f.Evidence != nil && f.Evidence.Agent}
	}
	return out, nil
}

// reportsViews reads findings.View for the periodic report: the same status, severity, verification, fix and handled line as every
// findings page, and the state events of each finding (fnd_finding_event) that say how it was handled in the period. findings.Views
// leaves out the findings of a device a person ignored, as every list does.
type reportsViews struct{ svc *findings.Service }

func (a reportsViews) Views(ctx context.Context) ([]reports.FindingView, error) {
	vs, err := a.svc.Views(ctx, findings.ViewFilter{})
	if err != nil {
		return nil, err
	}
	// an open finding is listed under its block's fix, as By device and By fix list it: the report names the same fix
	listed, err := a.svc.ListedFixes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]reports.FindingView, 0, len(vs))
	for _, v := range vs {
		r := reportView(v)
		if l, ok := listed[v.Finding.ID]; ok && v.Finding.State == findings.StateOpen {
			r.Fix = listedFix(r.Fix, l)
		}
		out = append(out, r)
	}
	return out, nil
}

// listedFix is the fix the Findings lists name for an open finding (its block's combined release), keeping the kind, product and
// advisory of the finding's own fix (a block combines only fixes of one kind).
func listedFix(own reports.Fix, l findings.ListedFix) reports.Fix {
	return reports.Fix{Key: l.Key, Kind: own.Kind, Product: own.Product, Version: optionalText(l.Fix.Version), Ref: optionalText(l.Fix.Ref), URL: own.URL}
}

// reportView maps one view through its API shape (View.JSON), so the report and the findings pages cannot disagree.
func reportView(v findings.View) reports.FindingView {
	j := v.JSON()
	r := reports.FindingView{ID: j.ID, CVE: j.CVE, Device: reports.DeviceRef{ID: j.Device.ID, Name: j.Device.Name, Added: j.Device.Added},
		Status: j.Status, Urgency: v.Finding.Urgency, FirstSeen: v.Finding.FirstSeen,
		Verification: reports.Verification{Verified: j.Verification.Verified, Basis: j.Verification.Basis, By: j.Verification.By, At: j.Verification.At},
		Fix:          reports.Fix{Key: j.Fix.Key, Kind: j.Fix.Kind, Product: j.Fix.Product, Version: j.Fix.Version, Ref: j.Fix.Ref, URL: j.Fix.URL}}
	if j.Software != nil {
		r.Product = j.Software.Name
		if j.Software.Version != nil {
			r.Version = *j.Software.Version
		}
	}
	if c := j.Severity; c != nil {
		r.Severity = &reports.CveSeverity{Band: c.Band, Score: c.Score, Version: c.Version, Vector: c.Vector}
	}
	if h := j.Handled; h != nil {
		r.Handled = &reports.Handled{Resolution: h.Resolution, Via: h.Via, By: h.By, At: h.At, Note: h.Note, AcceptedUntil: h.AcceptedUntil,
			FromVersion: h.FromVersion, ToVersion: h.ToVersion}
	}
	for _, e := range v.Events {
		ev := reports.FindingEvent{At: e.TS, Kind: string(e.Kind)}
		switch e.Kind {
		case findings.EvCreated, findings.EvReopened, findings.EvAcceptanceExpire:
		case findings.EvHandled:
			if !e.Detail.Resolution.Valid() {
				continue
			}
			via := e.Detail.Via
			if !via.Valid() {
				via = findings.ViaPerson
			}
			ev.Handled = &reports.Handled{Resolution: string(e.Detail.Resolution), Via: string(via), By: e.Actor, At: store.FormatTS(e.TS),
				Note: optionalText(e.Detail.Note), FromVersion: optionalText(e.Detail.FromVersion), ToVersion: optionalText(e.Detail.ToVersion)}
			if _, err := time.Parse(time.DateOnly, e.Detail.AcceptedUntil); err == nil {
				ev.Handled.AcceptedUntil = optionalText(e.Detail.AcceptedUntil)
			}
		default:
			continue
		}
		r.Events = append(r.Events, ev)
	}
	return r
}

func optionalText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Reasons reads the urgency reasons of the findings the report lists, from the finding's own read (findings.Service.View), so the
// reasons line is the finding page's.
func (a reportsViews) Reasons(ctx context.Context, ids []string) (map[string][]reports.Reason, error) {
	out := make(map[string][]reports.Reason, len(ids))
	for _, id := range ids {
		v, err := a.svc.View(ctx, id)
		if err != nil {
			return out, err
		}
		rs := []reports.Reason{}
		for _, x := range v.JSON().Urgency.Reasons {
			if x.Layer < 1 || x.Layer > 4 {
				continue
			}
			rs = append(rs, reports.Reason{Layer: x.Layer, Source: x.Source, Name: x.Name, Date: x.Date, URL: x.URL, Detail: x.Detail, Due: x.Due})
		}
		out[id] = rs
	}
	return out, nil
}

// ---- feeds -> reports ----

type reportsKEV struct{ d *deps }

// Entries is CISA's list only (VulnCheck KEV stays on the box: a report is a document that may be shared).
func (a reportsKEV) Entries(ctx context.Context) ([]reports.KEVEntry, error) {
	if a.d.Reg != nil && !a.d.Reg.Enabled("feeds") {
		return nil, nil
	}
	fs, err := feedsService(*a.d)
	if err != nil {
		return nil, err
	}
	rows, err := fs.Store().KevVulns(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]reports.KEVEntry, 0, len(rows))
	for _, v := range rows {
		if v.SourceID == "cisa-kev" {
			out = append(out, reports.KEVEntry{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, Display: feeds.DisplayOf(v.Vendor, v.Product)})
		}
	}
	return out, nil
}

// reportsFeeds is the health of the enabled vulnerability feeds, read through the feeds module's own API answers (GET /feeds/sources
// for the feeds and their schedule, GET /feeds/status for each one's last good pull), so Coverage and Settings, Feeds agree.
type reportsFeeds struct{ d *deps }

func (a reportsFeeds) Health(ctx context.Context) ([]reports.FeedHealth, error) {
	h := feedsHandlers(*a.d)
	srcs, err := h.FeedsGetFeedsSources(ctx)
	if err != nil {
		return nil, err
	}
	st, err := h.FeedsGetFeedsStatus(ctx)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []struct {
			ID            string `json:"id"`
			Name          string `json:"name"`
			Kind          string `json:"kind"`
			Enabled       bool   `json:"enabled"`
			IntervalHours int    `json:"interval_hours"`
		} `json:"items"`
	}
	var status struct {
		Sources []struct {
			Name      string    `json:"name"`
			FetchedAt time.Time `json:"fetched_at"`
		} `json:"sources"`
	}
	if err := reencode(srcs, &list); err != nil {
		return nil, err
	}
	if err := reencode(st, &status); err != nil {
		return nil, err
	}
	ok := map[string]time.Time{}
	for _, s := range status.Sources {
		ok[s.Name] = s.FetchedAt
	}
	now := clockOf(a.d)
	var out []reports.FeedHealth
	for _, f := range list.Items {
		if !f.Enabled || f.Kind != string(feeds.KindVulnerabilities) || !feedSlug.MatchString(f.ID) {
			continue
		}
		last := ok[f.Name]
		out = append(out, reports.FeedHealth{ID: f.ID, Name: f.Name, LastOK: last, Stale: feeds.IsStale(now, last, f.IntervalHours)})
	}
	return out, nil
}

// feedSlug is the shape of a feed id the report's contract accepts.
var feedSlug = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// clipRunesN cuts s to at most n characters (a banner a service sent is not bounded).
func clipRunesN(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// reencode reads a generated API answer as the plain struct it is written into.
func reencode(v json.Marshaler, into any) error {
	b, err := v.MarshalJSON()
	if err != nil {
		return err
	}
	return json.Unmarshal(b, into)
}

// ---- exposure -> reports ----

type reportsExposure struct{ d *deps }

// Targets is every enabled target with its open services, the services closed in the period, and its open issues by engine and
// severity: "what changed" is the rows' first_seen, last_seen and state (exposure 3.6), never a diff of two scans.
func (a reportsExposure) Targets(ctx context.Context, from, to time.Time) ([]reports.ExposureTarget, error) {
	svc := exposureService(*a.d)
	tree, err := svc.Tree(ctx)
	if err != nil {
		return nil, err
	}
	in := func(s string) bool {
		t, err := time.Parse(time.RFC3339Nano, s)
		return err == nil && t.After(from) && !t.After(to)
	}
	values := map[string]string{}
	for _, n := range tree.Items {
		values[n.ID] = n.Value
	}
	out := []reports.ExposureTarget{}
	for _, n := range tree.Items {
		if !n.Enabled {
			continue
		}
		t := reports.ExposureTarget{TargetID: n.ID, Kind: string(n.Kind), Value: n.Value, Proof: n.Proof.State, Services: []reports.ExposureService{}, Issues: []reports.ExposureIssues{}}
		if n.ParentID != nil {
			if v, ok := values[*n.ParentID]; ok {
				t.Parent = &v
			}
		}
		if s := n.LastScan; s != nil {
			t.LastScanAt = cmp.Or(s.EndedAt, s.StartedAt)
		}
		services, err := svc.Services(ctx, n.ID)
		if err != nil {
			return nil, err
		}
		for _, s := range services {
			if (s.Proto != "tcp" && s.Proto != "udp") || s.Port < 1 || s.Port > 65535 {
				continue
			}
			x := reports.ExposureService{IP: s.IP, Port: s.Port, Proto: s.Proto, Name: optionalText(clipRunesN(s.Name, 80)), Product: optionalText(clipRunesN(s.Product, 200)),
				Version: optionalText(clipRunesN(s.Version, 80))}
			switch {
			case s.State == "open" && in(s.FirstSeen):
				x.Change = optionalText("new")
			case s.State == "closed" && in(s.LastSeen):
				x.Change = optionalText("closed")
			case s.State != "open":
				continue // closed before the period
			}
			if s.Cert != nil {
				if _, err := time.Parse(time.RFC3339Nano, s.Cert.ExpiresAt); err == nil {
					x.CertExpiresAt = optionalText(s.Cert.ExpiresAt)
				}
			}
			t.Services = append(t.Services, x)
		}
		issues, err := svc.Issues(ctx, n.ID)
		if err != nil {
			return nil, err
		}
		type key struct{ engine, severity string }
		at := map[key]int{}
		for _, is := range issues {
			if is.State != "open" || !is.Engine.Valid() {
				continue
			}
			k := key{string(is.Engine), is.Severity}
			i, ok := at[k]
			if !ok {
				i = len(t.Issues)
				at[k] = i
				t.Issues = append(t.Issues, reports.ExposureIssues{Engine: k.engine, Severity: k.severity})
			}
			t.Issues[i].Open++
			if in(is.FirstSeen) {
				t.Issues[i].New++
			}
		}
		out = append(out, t)
	}
	return out, nil
}

// ---- notify -> reports ----

type reportsDetections struct{ d *deps }

// Period counts the incidents of notify with activity in the period, every kind whole, and names the top few by severity.
func (a reportsDetections) Period(ctx context.Context, from, to time.Time, top int) ([]reports.DetectionCount, []reports.Detection, error) {
	p, err := newNotify(a.d).IncidentsIn(ctx, from, to, top)
	if err != nil {
		return nil, nil, err
	}
	var counts []reports.DetectionCount
	for _, k := range p.Kinds {
		counts = append(counts, reports.DetectionCount{Kind: string(k.Kind), N: k.Incidents, LastAt: k.LastSeenAt})
	}
	var tops []reports.Detection
	for _, x := range p.Top {
		tops = append(tops, reports.Detection{Kind: string(x.Kind), Title: x.Title, Severity: string(x.Severity), DeviceID: x.DeviceID, DeviceName: x.DeviceName, At: x.LastSeen})
	}
	return counts, tops, nil
}

// reportsMailer mails a report through notify's email channel: the report itself (its sections as HTML with a plain-text alternative,
// reportMailDoc) and, when the document cannot be read, the digest the reports module wrote. reports.Mail does not carry the document
// it was made from, so the document is made again here with the same definition, inside the same send (the period and the figures
// are those of the stored one unless a finding changed in between).
type reportsMailer struct {
	svc      *notify.Service
	document func(ctx context.Context) (reports.Document, error)
}

func (m *reportsMailer) Ready(ctx context.Context) (bool, string) { return m.svc.EmailReady(ctx) }

func (m *reportsMailer) Send(ctx context.Context, to []string, r reports.Mail) error {
	mail := notify.ReportMail{Title: r.Title, What: r.What, Action: r.Action, Items: r.Items, Path: r.Path}
	if m.document != nil {
		if doc, err := m.document(ctx); err == nil {
			mail.Doc = reportMailDoc(doc)
		}
	}
	return m.svc.SendReport(ctx, to, mail)
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
