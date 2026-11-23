package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
)

// liveFindings is a finding directory whose answers a test changes between events (a finding rises, is handled).
type liveFindings struct {
	mu sync.Mutex
	m  map[string]notify.FindingInfo
}

func (l *liveFindings) Finding(_ context.Context, id string) (notify.FindingInfo, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	x, ok := l.m[id]
	return x, ok, nil
}

// at puts a finding at a layer, open, with the status words findings gives that layer.
func (l *liveFindings) at(id string, layer int, f notify.FindingInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f.Open, f.Layer = true, layer
	f.Status, f.Meaning = findings.StatusName(layer), findings.StatusMeaning(layer)
	if l.m == nil {
		l.m = map[string]notify.FindingInfo{}
	}
	l.m[id] = f
}

func (l *liveFindings) handle(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[id]
	f.Open = false
	l.m[id] = f
}

var qnap = notify.FindingInfo{CVE: "CVE-2026-100", Product: "QNAP Photo Station", Severity: notify.High, Action: "Apply updates per vendor instructions.",
	Devices: []string{"NAS-01"}, Reasons: "Exploited in the wild: CISA KEV (19 Nov 2026)"}

// noticeEnv is an env with a Telegram channel that takes everything, the directory and the bus wired.
func noticeEnv(t *testing.T, dir *liveFindings) (*env, func(name string, data any)) {
	t.Helper()
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.telegram(notify.Low)
	e.plain()
	e.svc.Subscribe(e.bus)
	return e, func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), events.Event{Name: name, Data: data}); err != nil {
			t.Fatal(err)
		}
	}
}

// queued is the notices waiting to be sent, oldest first.
func queued(e *env) []notify.Notice {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT notice FROM notify_pending ORDER BY created_at, rowid`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []notify.Notice
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			e.t.Fatal(err)
		}
		var n notify.Notice
		if err := json.Unmarshal([]byte(raw), &n); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func rise(id string, from, to int, at time.Time) findings.UrgencyRaisedEvent {
	return findings.UrgencyRaisedEvent{FindingID: id, AssetID: "a-1", CVE: "CVE-2026-100", Severity: findings.SeverityHigh, From: from, To: to, At: at.UTC().Format(time.RFC3339Nano)}
}

// Each kind of finding notice says what the finding page says: the status name, what it asks of a person and the reasons, from the
// directory (findings), framed for the event.
func TestFindingNoticesGolden(t *testing.T) {
	const why = " Why: Exploited in the wild: CISA KEV (19 Nov 2026)."
	for _, c := range []struct {
		name         string
		layer        int
		publish      func(pub func(string, any), id string, at time.Time)
		event        notify.NoticeEvent
		title, what  string
		change       string
		wantIDPrefix string
	}{
		{name: "created, exploited", layer: 2, event: notify.NoticeCreated, wantIDPrefix: "nt-f-1-created",
			publish: func(pub func(string, any), id string, _ time.Time) {
				pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, AssetID: "a-1", CVE: "CVE-2026-100", Severity: findings.SeverityHigh, Basis: findings.BasisProduct})
			},
			title: "QNAP Photo Station on NAS-01: exploited in the wild (CVE-2026-100)",
			what:  "Attackers use this flaw in real attacks. Patch it now." + why},
		{name: "created, public exploit", layer: 3, event: notify.NoticeCreated, wantIDPrefix: "nt-f-1-created",
			publish: func(pub func(string, any), id string, _ time.Time) {
				pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-2026-100", Severity: findings.SeverityHigh})
			},
			title: "QNAP Photo Station on NAS-01: public exploit available (CVE-2026-100)",
			what:  "Working exploit code is public. Patch it this week." + why},
		{name: "urgency changed", layer: 1, event: notify.NoticeUrgencyChanged, wantIDPrefix: "nt-f-1-urgency_changed",
			publish: func(pub func(string, any), id string, at time.Time) {
				pub(notify.EventUrgencyRaised, rise(id, 2, 1, at))
			},
			title:  "QNAP Photo Station on NAS-01: now under attack here (CVE-2026-100)",
			what:   "Someone on your network sent this exploit, and this device is affected. Isolate or patch it now." + why,
			change: "now under attack here"},
		{name: "reopened", layer: 4, event: notify.NoticeReopened, wantIDPrefix: "nt-f-1-reopened-",
			publish: func(pub func(string, any), id string, _ time.Time) {
				pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: id, From: findings.StatusNotRelevant, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain})
			},
			title:  "Vedette reopened CVE-2026-100 on NAS-01: it matches again",
			what:   "Vedette had closed this finding by itself, and the device matches the entry again. A critical flaw that needs no login, on a device class attackers target first. Patch it now." + why,
			change: "reopened, it matches again"},
		{name: "reopened, still detected after a person marked it patched", layer: 2, event: notify.NoticeReopened, wantIDPrefix: "nt-f-1-reopened-",
			publish: func(pub func(string, any), id string, _ time.Time) {
				pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: id, From: findings.StatusPatched, To: findings.StatusSuspected, Reason: findings.ReasonStillDetected})
			},
			title:  "Vedette reopened CVE-2026-100 on NAS-01: it is still detected",
			what:   "It was marked patched, but a newer reading of the device still shows the flaw. Attackers use this flaw in real attacks. Patch it now." + why,
			change: "reopened, still detected"},
		{name: "acceptance expired", layer: 2, event: notify.NoticeAcceptanceExpired, wantIDPrefix: "nt-f-1-acceptance_expired-",
			publish: func(pub func(string, any), id string, _ time.Time) {
				pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: id, From: findings.StatusRiskAccepted, To: findings.StatusConfirmed,
					Reason: findings.ReasonRiskExpired, AcceptedBy: "it@acme.example", AcceptedUntil: "2027-02-12"})
			},
			title:  "Risk acceptance ended: CVE-2026-100 on NAS-01 is open again",
			what:   "it@acme.example accepted this risk until 12 Feb 2027; that date has passed. Attackers use this flaw in real attacks. Patch it now." + why,
			change: "risk acceptance ended, open again"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := &liveFindings{}
			dir.at("f-1", c.layer, qnap)
			e, pub := noticeEnv(t, dir)
			c.publish(pub, "f-1", e.clock.Now())
			got := queued(e)
			if len(got) != 1 {
				t.Fatalf("queued %d notices, want 1", len(got))
			}
			n := got[0]
			if !strings.HasPrefix(n.ID, c.wantIDPrefix) || n.Event != c.event || n.Kind != notify.KindVuln {
				t.Errorf("id %q event %q kind %q", n.ID, n.Event, n.Kind)
			}
			if n.Title != c.title || n.What != c.what || n.Change != c.change {
				t.Errorf("title %q\nwhat %q\nchange %q", n.Title, n.What, n.Change)
			}
			if n.Action != qnap.Action || n.Layer != c.layer || n.Severity != notify.High || n.Product != qnap.Product ||
				fmt.Sprint(n.CVEs) != "[CVE-2026-100]" || fmt.Sprint(n.FindingIDs) != "[f-1]" || fmt.Sprint(n.Devices) != "[NAS-01]" {
				t.Errorf("notice = %+v", n)
			}
			if e.count(`SELECT count(*) FROM notify_notice WHERE event = ?`, string(c.event)) != 1 {
				t.Errorf("the notice is not recorded with its event %q", c.event)
			}
		})
	}
}

// The words come from findings for every layer: the notice says no more and no less than the finding page.
func TestFindingNoticeWordsAreFindingsWords(t *testing.T) {
	for layer := 1; layer <= 4; layer++ {
		dir := &liveFindings{}
		dir.at("f-1", layer, qnap)
		e, pub := noticeEnv(t, dir)
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", Severity: findings.SeverityHigh})
		n := queued(e)[0]
		if !strings.Contains(n.Title, strings.ToLower(findings.StatusName(layer))) || !strings.HasPrefix(n.What, findings.StatusMeaning(layer)) {
			t.Errorf("layer %d: %q / %q", layer, n.Title, n.What)
		}
	}
}

// Layer 5 (update recommended) never alerts, whatever event arrives, and neither does a finding handled since its event.
func TestLayerFiveNeverAlertsAndOnlyOpenFindingsAreTold(t *testing.T) {
	dir := &liveFindings{}
	dir.at("f-5", 5, qnap)
	dir.at("f-closed", 2, qnap)
	dir.handle("f-closed")
	e, pub := noticeEnv(t, dir)
	at := e.clock.Now()
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-5", Severity: findings.SeverityHigh})
	pub(notify.EventUrgencyRaised, rise("f-5", 5, 5, at))
	pub(notify.EventUrgencyRaised, rise("f-5", 6, 5, at))
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-5", Reason: findings.ReasonMatchesAgain})
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-5", Reason: findings.ReasonRiskExpired, AcceptedBy: "it@acme.example", AcceptedUntil: "2027-02-12"})
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-closed", Severity: findings.SeverityHigh})
	pub(notify.EventUrgencyRaised, rise("f-closed", 3, 2, at))
	// a notice that arrives at layer 5 by any other way is refused as well
	n := notify.Notice{ID: "nt-direct", Event: notify.NoticeCreated, Kind: notify.KindVuln, Severity: notify.High, Product: "QNAP", CVEs: []string{"CVE-2026-100"},
		FindingIDs: []string{"f-5"}, Devices: []string{"NAS-01"}, Title: "t", Layer: 5, At: at}
	if err := e.svc.Publish(e.ctx(), n); err != nil {
		t.Fatal(err)
	}
	if got := e.count(`SELECT count(*) FROM notify_notice`) + e.count(`SELECT count(*) FROM notify_pending`); got != 0 {
		t.Fatalf("%d notices or queued messages for layer 5 or a handled finding", got)
	}
}

// One alert per escalation: a finding is told when it first qualifies and again only at a more urgent layer; the same layer or a lower one
// again, after a drop and a rise, a redelivered event or a later pass, is not told.
func TestOneAlertPerEscalation(t *testing.T) {
	dir := &liveFindings{}
	dir.at("f-1", 3, qnap)
	e, pub := noticeEnv(t, dir)
	step := func(d time.Duration) time.Time { e.clock.Add(d); return e.clock.Now() }
	layers := func() []int {
		var out []int
		for _, n := range queued(e) {
			out = append(out, n.Layer)
		}
		return out
	}
	want := func(l ...int) {
		t.Helper()
		if got := layers(); fmt.Sprint(got) != fmt.Sprint(l) {
			t.Fatalf("told at layers %v, want %v", got, l)
		}
	}
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", Severity: findings.SeverityHigh})
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", Severity: findings.SeverityHigh}) // redelivered
	want(3)
	pub(notify.EventUrgencyRaised, rise("f-1", 4, 3, step(time.Hour))) // a rise into the layer it was told at, at another time
	want(3)
	dir.at("f-1", 2, qnap)
	pub(notify.EventUrgencyRaised, rise("f-1", 3, 2, step(time.Hour))) // an escalation
	pub(notify.EventUrgencyRaised, rise("f-1", 3, 2, step(time.Hour))) // the same one again, stamped later
	want(3, 2)
	dir.at("f-1", 3, qnap) // it drops to 3 and rises to 2 again: not an escalation
	dir.at("f-1", 2, qnap)
	pub(notify.EventUrgencyRaised, rise("f-1", 3, 2, step(time.Hour)))
	want(3, 2)
	dir.at("f-1", 1, qnap)
	pub(notify.EventUrgencyRaised, rise("f-1", 2, 1, step(time.Hour)))
	want(3, 2, 1)
	// a finding handled and reopened is told as reopened, whatever it was told at before; it is not an escalation, so the rise log is unchanged
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f-1", From: findings.StatusPatched, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain})
	want(3, 2, 1, 1)
	pub(notify.EventUrgencyRaised, rise("f-1", 2, 1, step(time.Hour)))
	want(3, 2, 1, 1)
}

// The summary of a first load records each finding at its layer, so a later rise to that layer is not told again and a rise above it is.
func TestFirstRunSummaryIsTheMemoryOfWhatWasTold(t *testing.T) {
	dir := &liveFindings{}
	dir.at("f-1", 2, qnap)
	dir.at("f-2", 3, qnap)
	dir.at("f-5", 5, qnap)
	e, pub := noticeEnv(t, dir)
	pub(notify.EventFirstRun, findings.FirstRunEvent{Key: "install", At: e.clock.Now().UTC().Format(time.RFC3339Nano), Findings: 3, Devices: 1, Layer: 2,
		FindingIDs: []string{"f-1", "f-2", "f-5"}, CVEList: []string{"CVE-2026-100"}})
	got := queued(e)
	if len(got) != 1 || fmt.Sprint(got[0].FindingIDs) != "[f-1 f-2]" || fmt.Sprint(got[0].FindingLayers) != "[2 3]" || got[0].Event != notify.NoticeFirstRun {
		t.Fatalf("summary = %+v", got)
	}
	at := e.clock.Now()
	pub(notify.EventUrgencyRaised, rise("f-1", 3, 2, at)) // told in the summary at 2
	pub(notify.EventUrgencyRaised, rise("f-2", 4, 3, at))
	if n := len(queued(e)); n != 1 {
		t.Fatalf("a rise to the layer the summary told: %d notices", n)
	}
	dir.at("f-2", 2, qnap)
	pub(notify.EventUrgencyRaised, rise("f-2", 3, 2, at))
	if n := len(queued(e)); n != 2 {
		t.Fatalf("a rise above it was not told: %d notices", n)
	}
	// a second summary lists only what the first did not tell
	pub(notify.EventFirstRun, findings.FirstRunEvent{Key: "install", At: e.clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), Findings: 2, Devices: 1, Layer: 2,
		FindingIDs: []string{"f-1", "f-2"}})
	if n := len(queued(e)); n != 2 {
		t.Fatalf("a summary of findings all told already was sent: %d notices", n)
	}
}

// The incident kind is an open vocabulary: a kind notify does not name is stored, listed and counted.
func TestIncidentKindIsOpen(t *testing.T) {
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	in := notify.IncidentInput{Kind: "ioc_hit", Source: "10.0.0.9", Target: "evil.example", Title: "A device reached a known-bad name", Severity: notify.High, Link: "/logs"}
	if _, created, err := e.svc.OpenIncident(e.ctx(), in); err != nil || !created {
		t.Fatalf("a new kind: created %v, %v", created, err)
	}
	counts, err := e.svc.KindCounts(e.ctx(), e.clock.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range counts {
		if c.Incidents > 0 {
			names = append(names, string(c.Kind))
		}
	}
	sort.Strings(names)
	if fmt.Sprint(names) != "[ioc_hit]" || len(counts) != len(notify.IncidentKinds)+1 {
		t.Fatalf("counts = %+v", counts)
	}
	for _, bad := range []notify.IncidentKind{"", "Has Space", "UPPER", notify.IncidentKind(strings.Repeat("a", 41)), "vuln"} {
		in.Kind = bad
		if _, _, err := e.svc.OpenIncident(e.ctx(), in); err == nil {
			t.Errorf("accepted kind %q", bad)
		}
	}
	if !notify.IncidentIntrusion.Valid() {
		t.Error("intrusion is a kind")
	}
}

// ---- count test: a fixture pass of the match and urgency passes ----

// fixturePass replays what the match pass and two urgency passes publish for eight findings, with redeliveries and a finding that drops
// and rises again, and counts what notify makes of it: the notices, the repeats (a finding told again at the layer it was told at or a
// less urgent one), the notices for layer 5 and the rises told for a finding that was handled by then.
func fixturePass(t *testing.T) (notices, repeats, layerFive, handled int) {
	t.Helper()
	dir := &liveFindings{}
	e, pub := noticeEnv(t, dir)
	t1, t2 := e.clock.Now().Add(time.Hour), e.clock.Now().Add(2*time.Hour)
	created := func(id string) {
		pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, AssetID: "a-1", CVE: "CVE-2026-100", Severity: findings.SeverityHigh})
	}
	for id, layer := range map[string]int{"f1": 2, "f2": 3, "f3": 5, "f4": 4, "f5": 2, "f6": 3, "f8": 3} {
		dir.at(id, layer, qnap)
		created(id)
	}
	created("f4") // the bus delivers it twice
	// the first urgency pass: f1 and f6 rise, f2 is rated again at the layer it started at
	dir.at("f1", 1, qnap)
	pub(notify.EventUrgencyRaised, rise("f1", 2, 1, t1))
	dir.at("f6", 2, qnap)
	pub(notify.EventUrgencyRaised, rise("f6", 3, 2, t1))
	pub(notify.EventUrgencyRaised, rise("f2", 4, 3, t1))
	// a person handles f8; Vedette reopens f5
	dir.handle("f8")
	pub(notify.EventFindingStatusChanged, findings.StatusChangedEvent{FindingID: "f5", From: findings.StatusPatched, To: findings.StatusSuspected, Reason: findings.ReasonMatchesAgain})
	// the second pass: the same rises again stamped later, f6 dropped to 3 and rose to 2 again, f8's rise arrives after it was handled
	pub(notify.EventUrgencyRaised, rise("f1", 2, 1, t2))
	dir.at("f6", 3, qnap)
	dir.at("f6", 2, qnap)
	pub(notify.EventUrgencyRaised, rise("f6", 3, 2, t2))
	pub(notify.EventUrgencyRaised, rise("f2", 4, 3, t2))
	pub(notify.EventUrgencyRaised, rise("f8", 3, 2, t2))
	told := map[string]int{}
	for _, n := range queued(e) {
		notices++
		id := n.FindingIDs[0]
		if n.Layer >= 5 {
			layerFive++
		}
		if f, _, _ := dir.Finding(e.ctx(), id); !f.Open && strings.Contains(n.ID, "urgency") { // a rise told after the person handled it
			handled++
		}
		if strings.Contains(n.ID, "-reopened-") { // a reopening is its own event, not a repeat of an escalation
			continue
		}
		if was, ok := told[id]; ok && n.Layer >= was {
			repeats++
		}
		if was, ok := told[id]; !ok || n.Layer < was {
			told[id] = n.Layer
		}
	}
	return notices, repeats, layerFive, handled
}

func TestCountNoticesOfAFixturePass(t *testing.T) {
	notices, repeats, layerFive, handled := fixturePass(t)
	t.Logf("notices %d, repeats %d, layer 5 %d, handled %d", notices, repeats, layerFive, handled)
	// f1: created, then under attack; f2: created; f3: none (layer 5); f4: created once; f5: created and reopened; f6: created, then
	// exploited; f8: created (it was open then), no rise once handled
	if notices != 9 || repeats != 0 || layerFive != 0 || handled != 0 {
		t.Fatalf("notices %d (want 9), repeats %d, layer 5 %d, rises told for handled findings %d", notices, repeats, layerFive, handled)
	}
}

// The summary tells what is left of the event's findings, not the event's counts: handled, layer 5 and already-told findings are not in its
// title, severity, worst layer or CVE list.
func TestFirstRunSummaryCountsTheKeptFindings(t *testing.T) {
	dir := &liveFindings{}
	other := qnap
	other.CVE = "CVE-2026-200"
	dir.at("f-1", 4, qnap)
	dir.at("f-2", 1, other)
	dir.handle("f-2")
	dir.at("f-5", 5, other)
	e, pub := noticeEnv(t, dir)
	pub(notify.EventFirstRun, findings.FirstRunEvent{Key: "install", At: e.clock.Now().UTC().Format(time.RFC3339Nano), Findings: 3, Devices: 3, Layer: 1,
		FindingIDs: []string{"f-1", "f-2", "f-5"}, CVEList: []string{"CVE-2026-100", "CVE-2026-200"}})
	got := queued(e)
	if len(got) != 1 {
		t.Fatalf("summaries = %+v", got)
	}
	n := got[0]
	if n.Title != "Patch first: 1 urgent finding on 1 device" || n.Layer != 4 || n.Severity != notify.Medium || fmt.Sprint(n.CVEs) != "[CVE-2026-100]" {
		t.Fatalf("title %q layer %d severity %q CVEs %v", n.Title, n.Layer, n.Severity, n.CVEs)
	}
}
