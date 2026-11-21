package findings

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// The rule of each layer, one case per edge.
func TestUrgency_TheRuleOfEachLayer(t *testing.T) {
	t.Parallel()
	now := t0
	critical := &CVSS{Score: 9.8, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	sig := func(kind string, q bool) Signal {
		return Signal{Kind: kind, Source: "src", FirstSeen: now.Add(-24 * time.Hour), Qualifies: q}
	}
	edge := Target{AssetID: "a-1", Class: productid.ClassFirewall, Affected: true}
	for _, c := range []struct {
		name    string
		facts   CVEFacts
		target  Target
		attacks []Attack
		want    int
	}{
		{"nothing", CVEFacts{}, edge, nil, UrgencyUpdate},
		{"an attack at the device", CVEFacts{}, Target{AssetID: "a-1"}, []Attack{{CVE: "CVE-1", AssetID: "a-1", LastSeen: now.Add(-time.Hour)}}, UrgencyUnderAttack},
		{"an attack elsewhere while affected", CVEFacts{}, edge, []Attack{{CVE: "CVE-1", AssetID: "a-9", LastSeen: now.Add(-time.Hour)}}, UrgencyUnderAttack},
		{"an attack elsewhere, not affected", CVEFacts{}, Target{AssetID: "a-1"}, []Attack{{CVE: "CVE-1", AssetID: "a-9", LastSeen: now.Add(-time.Hour)}}, UrgencyUpdate},
		{"an attack older than the window", CVEFacts{}, edge, []Attack{{CVE: "CVE-1", AssetID: "a-1", LastSeen: now.Add(-AttackWindow - time.Hour)}}, UrgencyUpdate},
		{"an attack on another CVE", CVEFacts{}, edge, []Attack{{CVE: "CVE-2", AssetID: "a-1", LastSeen: now}}, UrgencyUpdate},
		{"exploited", CVEFacts{Signals: []Signal{sig(SignalExploited, true)}}, edge, nil, UrgencyExploited},
		{"exploited, not qualifying", CVEFacts{Signals: []Signal{sig(SignalExploited, false)}}, Target{}, nil, UrgencyUpdate},
		{"public exploit", CVEFacts{Signals: []Signal{sig(SignalPublicExploit, true)}}, Target{}, nil, UrgencyPublicExploit},
		{"public exploit, few stars", CVEFacts{Signals: []Signal{sig(SignalPublicExploit, false)}}, Target{}, nil, UrgencyUpdate},
		{"an unknown kind", CVEFacts{Signals: []Signal{sig("ids_rule", true)}}, Target{}, nil, UrgencyUpdate},
		{"both: the most urgent", CVEFacts{Signals: []Signal{sig(SignalPublicExploit, true), sig(SignalExploited, true)}}, Target{}, nil, UrgencyExploited},
		{"critical on an edge product", CVEFacts{CVSS: critical}, edge, nil, UrgencyCriticalEdge},
		{"critical on a NAS product", CVEFacts{CVSS: critical}, Target{Class: productid.ClassNAS}, nil, UrgencyCriticalEdge},
		{"critical on a switch", CVEFacts{CVSS: critical}, Target{Class: productid.ClassNetwork}, nil, UrgencyUpdate},
		{"critical on a product of no class", CVEFacts{CVSS: critical}, Target{}, nil, UrgencyUpdate},
		{"not automatable", CVEFacts{CVSS: critical, Automatable: "no"}, edge, nil, UrgencyUpdate},
		{"automatable not given", CVEFacts{CVSS: critical, Automatable: ""}, edge, nil, UrgencyCriticalEdge},
		{"below 9", CVEFacts{CVSS: &CVSS{Score: 8.9, Version: "3.1", Vector: critical.Vector}}, edge, nil, UrgencyUpdate},
		{"local vector", CVEFacts{CVSS: &CVSS{Score: 9.3, Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}, edge, nil, UrgencyUpdate},
		{"needs a login", CVEFacts{CVSS: &CVSS{Score: 9.1, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"}}, edge, nil, UrgencyUpdate},
		{"CVSS 4.0", CVEFacts{CVSS: &CVSS{Score: 9.3, Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}, edge, nil, UrgencyCriticalEdge},
		{"CVSS 2.0 with no authentication", CVEFacts{CVSS: &CVSS{Score: 10, Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}}, edge, nil, UrgencyCriticalEdge},
		{"CVSS 2.0 with authentication", CVEFacts{CVSS: &CVSS{Score: 9, Version: "2.0", Vector: "AV:N/AC:L/Au:S/C:C/I:C/A:C"}}, edge, nil, UrgencyUpdate},
	} {
		if got := Urgency("CVE-1", c.facts, c.target, c.attacks, now); got.Layer != c.want {
			t.Errorf("%s: layer %d, want %d (%+v)", c.name, got.Layer, c.want, got)
		}
	}
}

// How a rise is told (Tell, the one rule of both passes): an attack is news; what a first load brought, inside its window, is a line
// of that load's summary; a reason first seen after its load is news, also inside the window; else a recent reason or a recent finding
// is news, and anything older is old news.
func TestUrgency_Tell(t *testing.T) {
	t.Parallel()
	recent, old := t0.Add(-24*time.Hour), t0.Add(-30*24*time.Hour)
	oldFinding, newFinding := Finding{FirstSeen: old}, Finding{FirstSeen: t0}
	reason := func(layer int, since time.Time) Reason {
		return Reason{Layer: layer, Source: "metasploit", Since: since}
	}
	loaded := func(at time.Time) Reason {
		return Reason{Layer: UrgencyPublicExploit, Source: "nuclei-templates", Since: at, FirstLoad: true, LoadedAt: at}
	}
	rating := func(layer int, rs ...Reason) Rating { return Rating{Layer: layer, Reasons: rs} }
	installed := Loads{Install: t0.Add(-2 * time.Hour)}                     // the box was installed two hours ago (t0 is 10:00)
	catalogue := Loads{Catalogue: t0.Add(-time.Hour)}                       // the catalogue first loaded an hour ago
	pub3 := rating(UrgencyPublicExploit, reason(UrgencyPublicExploit, old)) // a public exploit from before the install
	for _, c := range []struct {
		name  string
		f     Finding
		r     Rating
		loads Loads
		want  Telling
		key   string
	}{
		{"recent reason", oldFinding, rating(UrgencyPublicExploit, reason(UrgencyPublicExploit, recent)), Loads{}, TellNews, ""},
		{"old reason, old finding", oldFinding, pub3, Loads{}, TellBacklog, ""},
		{"old reason, new finding", newFinding, pub3, Loads{}, TellNews, ""},
		{"the newest reason of the layer counts", oldFinding, rating(UrgencyExploited, reason(UrgencyExploited, old), reason(UrgencyExploited, recent)), Loads{}, TellNews, ""},
		{"a reason of a lower layer does not", oldFinding, rating(UrgencyExploited, reason(UrgencyExploited, old), reason(UrgencyPublicExploit, recent)), Loads{}, TellBacklog, ""},
		{"no date", oldFinding, rating(UrgencyCriticalEdge, Reason{Layer: UrgencyCriticalEdge, Source: "nas"}), Loads{}, TellBacklog, ""},
		{"an attack", oldFinding, rating(UrgencyUnderAttack, reason(UrgencyUnderAttack, old)), installed, TellNews, ""},
		{"install: a reason from before it", newFinding, pub3, installed, TellFirstRun, "install"},
		{"install: a reason dated after it", newFinding, rating(UrgencyExploited, reason(UrgencyExploited, t0.Add(-time.Hour))), installed, TellNews, ""},
		{"install: a list entry of the install day", newFinding, rating(UrgencyExploited, reason(UrgencyExploited, t0.Truncate(24*time.Hour))), installed, TellNews, ""},
		{"after the install window", newFinding, pub3, Loads{Install: t0.Add(-FirstRunWindow - time.Hour)}, TellNews, ""},
		{"a source's first load", oldFinding, rating(UrgencyPublicExploit, loaded(t0.Add(-time.Hour))), Loads{}, TellFirstRun, "nuclei-templates-20261109"},
		{"a first load and a newer claim", oldFinding, rating(UrgencyPublicExploit, loaded(t0.Add(-time.Hour)), reason(UrgencyPublicExploit, t0)), Loads{}, TellNews, ""},
		{"a first load long ago, a new finding", newFinding, rating(UrgencyPublicExploit, loaded(old)), Loads{}, TellNews, ""},
		{"a first load long ago, an old finding", oldFinding, rating(UrgencyPublicExploit, loaded(old)), Loads{}, TellBacklog, ""},
		{"the catalogue's first load made it", newFinding, pub3, catalogue, TellFirstRun, "catalogue-20261109"},
		{"the catalogue's first load, a reason after it", newFinding, rating(UrgencyExploited, reason(UrgencyExploited, t0)), catalogue, TellNews, ""},
		{"the catalogue's first load, an older finding", Finding{FirstSeen: t0.Add(-10 * 24 * time.Hour)}, pub3, catalogue, TellBacklog, ""},
	} {
		if got, key := Tell(c.f, c.r, t0, c.loads); got != c.want || key != c.key {
			t.Errorf("%s: %v %q, want %v %q", c.name, got, key, c.want, c.key)
		}
	}
}

type sampleFixture struct {
	Now     time.Time `json:"now"`
	Samples []struct {
		CVE         string    `json:"cve"`
		FixKey      string    `json:"fix_key"`
		CVSS        *CVSS     `json:"cvss"`
		Automatable string    `json:"automatable"`
		Published   time.Time `json:"published"`
		Signals     []struct {
			Kind      string    `json:"kind"`
			Source    string    `json:"source"`
			FirstSeen time.Time `json:"first_seen"`
			Qualifies bool      `json:"qualifies"`
			URL       string    `json:"url"`
		} `json:"signals"`
		Want        int    `json:"want"`
		WantReasons []int  `json:"want_reasons"`
		WantSince   string `json:"want_since"`
		WantSource  string `json:"want_source"`
		WithoutCISA int    `json:"without_cisa"`
	} `json:"samples"`
}

// The four sample CVEs of the measurement get their layers on the frozen signals of 19 Nov 2026: the Synology flaw is exploited in the
// wild (CISA, 18 Nov) with "critical on an edge device since 19 Mar 2025" among its reasons, and critical on an edge device without
// the CISA row; the FortiOS flaw is exploited (Rapid7, 19 Nov) though on no list; the NGINX and Java flaws have a public exploit (18 and
// 17 Nov).
func TestUrgency_TheFourSampleCVEs(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("testdata/urgency-samples.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx sampleFixture
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Samples) != 4 {
		t.Fatalf("%d samples, want 4", len(fx.Samples))
	}
	for _, s := range fx.Samples {
		facts := CVEFacts{CVSS: s.CVSS, Automatable: s.Automatable, Published: s.Published}
		for _, g := range s.Signals {
			facts.Signals = append(facts.Signals, Signal{Kind: g.Kind, Source: g.Source, FirstSeen: g.FirstSeen, Qualifies: g.Qualifies, URL: g.URL})
		}
		f := Finding{AssetID: "a-1", CVE: s.CVE, FixKey: s.FixKey, Detected: true}
		r := Urgency(s.CVE, facts, TargetOf(f, Device{}), nil, fx.Now)
		var layers []int
		for _, x := range r.Reasons {
			layers = append(layers, x.Layer)
		}
		if r.Layer != s.Want || !slices.Equal(layers, s.WantReasons) || r.Since.Format(time.DateOnly) != s.WantSince || r.Reasons[0].Source != s.WantSource {
			t.Errorf("%s: %d %v since %s by %s, want %d %v since %s by %s", s.CVE, r.Layer, layers, r.Since.Format(time.DateOnly), r.Reasons[0].Source,
				s.Want, s.WantReasons, s.WantSince, s.WantSource)
		}
		for _, x := range r.Reasons {
			if x.Layer == UrgencyCriticalEdge && x.Since.Format(time.DateOnly) != "2025-03-19" {
				t.Errorf("%s: critical on an edge device since %s, want 2025-03-19", s.CVE, x.Since.Format(time.DateOnly))
			}
		}
		if s.WithoutCISA != 0 {
			facts.Signals = slices.DeleteFunc(slices.Clone(facts.Signals), func(g Signal) bool { return g.Source == "cisa-kev" })
			if r := Urgency(s.CVE, facts, TargetOf(f, Device{}), nil, fx.Now); r.Layer != s.WithoutCISA {
				t.Errorf("%s without the CISA row: layer %d, want %d", s.CVE, r.Layer, s.WithoutCISA)
			}
		}
	}
}

// markedPub records whether each event was published under the Backlog mark.
type markedPub struct {
	mu     sync.Mutex
	events []markedEvent
}

type markedEvent struct {
	name    string
	payload any
	backlog bool
}

type backlogKey struct{}

func (p *markedPub) Publish(ctx context.Context, name string, payload any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, markedEvent{name, payload, ctx.Value(backlogKey{}) != nil})
	return nil
}

func (p *markedPub) take() []markedEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.events
	p.events = nil
	return out
}

// announced is the ids of the findings whose rise was told (findings.finding.urgency_raised), split by the Backlog mark, and the
// first-run summaries.
func (p *markedPub) announced() (news, backlog []string) {
	news, backlog, _ = p.told()
	return news, backlog
}

func (p *markedPub) told() (news, backlog []string, summaries []FirstRunEvent) {
	for _, e := range p.take() {
		switch c := e.payload.(type) {
		case UrgencyRaisedEvent:
			if e.backlog {
				backlog = append(backlog, c.FindingID)
			} else {
				news = append(news, c.FindingID)
			}
		case FirstRunEvent:
			summaries = append(summaries, c)
		}
	}
	return news, backlog, summaries
}

// urgencyEnv is a FortiGate with one catalogue CVE on no list and the urgency pass wired to facts the test sets.
type urgencyEnv struct {
	*env
	pub     *markedPub
	mu      sync.Mutex
	facts   map[string]CVEFacts
	attacks []Attack
}

const offList = "CVE-2026-100001"

func newUrgencyEnv(t *testing.T) *urgencyEnv {
	t.Helper()
	e := &urgencyEnv{env: newEnv(t), pub: &markedPub{}, facts: map[string]CVEFacts{}}
	e.inv.match = map[string]Asset{"a-1": fortigate()}
	e.inv.assets["a-1"] = AssetView{ID: "a-1", Name: "fw01", IP: "192.0.2.1", Kind: "firewall"}
	e.feeds.vulns = []Vuln{catalogueOnly(offList, "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9")}
	e.feeds.kev = map[string]KevInfo{}
	e.svc.cfg.Publisher = e.pub
	e.svc.cfg.Backlog = func(ctx context.Context) context.Context { return context.WithValue(ctx, backlogKey{}, true) }
	e.svc.cfg.Urgency = UrgencySources{
		Facts: func(_ context.Context, cves []string) (map[string]CVEFacts, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			out := map[string]CVEFacts{}
			for _, c := range cves {
				if f, ok := e.facts[c]; ok {
					out[c] = f
				}
			}
			return out, nil
		},
		Attacks: func(context.Context, time.Time) ([]Attack, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			return slices.Clone(e.attacks), nil
		},
	}
	return e
}

func (e *urgencyEnv) setSignals(cve string, gs ...Signal) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.facts[cve] = CVEFacts{Signals: gs}
}

func (e *urgencyEnv) finding(cve string) Finding {
	e.t.Helper()
	fs, err := e.svc.Findings(e.t.Context(), "a-1")
	if err != nil {
		e.t.Fatal(err)
	}
	for _, f := range fs {
		if f.CVE == cve {
			return f
		}
	}
	e.t.Fatalf("no finding of %s", cve)
	return Finding{}
}

func (e *urgencyEnv) rate() UrgencyResult {
	e.t.Helper()
	r, err := e.svc.RateUrgency(e.t.Context(), "")
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *urgencyEnv) urgencyEvents(id string) []int {
	e.t.Helper()
	evs, err := e.svc.Events(e.t.Context(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []int
	for _, ev := range evs {
		if ev.Kind == EvUrgencyChanged {
			out = append(out, ev.Detail.Layer)
		}
	}
	return out
}

// reconciled is the env after a first match pass, its one off-list finding at layer 5 and eight days old (so an old reason is old news).
func (e *urgencyEnv) reconciled() Finding {
	e.t.Helper()
	if _, err := e.svc.Reconcile(e.t.Context()); err != nil {
		e.t.Fatal(err)
	}
	e.advance(8 * 24 * time.Hour)
	e.pub.take()
	f := e.finding(offList)
	if f.Urgency != UrgencyUpdate {
		e.t.Fatalf("start urgency %d", f.Urgency)
	}
	return f
}

func (e *urgencyEnv) attack(at time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attacks = []Attack{{CVE: offList, AssetID: "a-1", FirstSeen: at, LastSeen: at, AlertID: "al-1"}}
}

// Every rise of an open finding into a more urgent layer of 1–4 is told once, each its own alert: 5→3 on a public exploit, 3→2 when it is
// exploited, 2→1 when an attack hits it; a drop is never told; a rise after a drop is told again; a pass that changes nothing writes
// nothing. Each change is one urgency_changed event.
func TestRateUrgency_EveryRiseIsToldOnce(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	f := e.reconciled()
	if r := e.rate(); r.Raised != 0 || r.Lowered != 0 {
		t.Fatalf("no signal yet: %+v", r)
	}
	now := *e.clock
	msf := Signal{Kind: SignalPublicExploit, Source: "metasploit", FirstSeen: now.Add(-48 * time.Hour), Qualifies: true}
	r7 := Signal{Kind: SignalExploited, Source: "rapid7-blog", FirstSeen: now.Add(-time.Hour), Qualifies: true}
	var ats []string
	step := func(name string, want int, told bool, change func()) {
		t.Helper()
		e.advance(time.Hour)
		change()
		e.rate()
		if g := e.finding(offList); g.Urgency != want {
			t.Fatalf("%s: urgency %d, want %d", name, g.Urgency, want)
		}
		var news []string
		for _, ev := range e.pub.take() {
			if c, ok := ev.payload.(UrgencyRaisedEvent); ok && !ev.backlog {
				news = append(news, c.FindingID)
				ats = append(ats, c.At)
				if c.To != want {
					t.Errorf("%s: told a rise to %d, want %d", name, c.To, want)
				}
			}
		}
		if told && !slices.Equal(news, []string{f.ID}) || !told && len(news) != 0 {
			t.Fatalf("%s: told %v, want told %v", name, news, told)
		}
	}
	step("public exploit", UrgencyPublicExploit, true, func() { e.setSignals(offList, msf) })
	step("unchanged", UrgencyPublicExploit, false, func() {})
	step("exploited", UrgencyExploited, true, func() { e.setSignals(offList, msf, r7) })
	step("attacked", UrgencyUnderAttack, true, func() { e.attack(*e.clock) })
	step("attack over", UrgencyExploited, false, func() { e.attack(e.clock.Add(-AttackWindow - time.Hour)) })
	step("signals gone", UrgencyUpdate, false, func() { e.setSignals(offList) })
	step("public exploit again", UrgencyPublicExploit, true, func() { e.setSignals(offList, msf) })
	if len(slices.Compact(slices.Clone(ats))) != len(ats) {
		t.Fatalf("two rises share an id: %v", ats)
	}
	if got := e.urgencyEvents(f.ID); !slices.Equal(got, []int{3, 2, 1, 2, 5, 3}) {
		t.Fatalf("urgency events %v", got)
	}
}

// An old reason on an old finding is old news: counted under the Backlog mark, never sent; the same reason on a finding the match
// pass made this week is news (a late range or a new device makes it new to the customer).
func TestRateUrgency_OldNewsAndNewFindings(t *testing.T) {
	t.Parallel()
	old := Signal{Kind: SignalExploited, Source: "rapid7-blog", FirstSeen: t0.Add(-60 * 24 * time.Hour), Qualifies: true}
	e := newUrgencyEnv(t)
	f := e.reconciled()
	e.setSignals(offList, old)
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 {
		t.Fatalf("old finding: %+v", r)
	}
	if news, backlog := e.pub.announced(); len(news) != 0 || !slices.Equal(backlog, []string{f.ID}) {
		t.Fatalf("old finding: told %v, backlog %v; want it under the Backlog mark only", news, backlog)
	}
	e = newUrgencyEnv(t)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.setSignals(offList, old)
	if r := e.rate(); r.Raised != 1 || r.Announced != 1 {
		t.Fatalf("new finding: %+v", r)
	}
}

// What a source's first load raises goes into one first-run summary (no alert each); so does what the box's own first run raises.
func TestRateUrgency_TheFirstRunIsOneSummary(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	f := e.reconciled()
	now := *e.clock
	e.setSignals(offList, Signal{Kind: SignalPublicExploit, Source: "nuclei-templates", FirstSeen: now, Qualifies: true, FirstLoad: true, LoadedAt: now})
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 || r.FirstRun != 1 {
		t.Fatalf("first load: %+v", r)
	}
	news, backlog, sums := e.pub.told()
	if len(news) != 0 || !slices.Equal(backlog, []string{f.ID}) || len(sums) != 1 || sums[0].Findings != 1 || sums[0].Devices != 1 || !slices.Equal(sums[0].FindingIDs, []string{f.ID}) ||
		sums[0].Key != "nuclei-templates-"+now.Format("20060102") || sums[0].Layer != UrgencyPublicExploit {
		t.Fatalf("first load: told %v %v, summaries %+v", news, backlog, sums)
	}

	e = newUrgencyEnv(t)
	e.reconciled()
	install := e.clock.Add(-time.Hour)
	e.svc.cfg.Urgency.Loads = func(context.Context) (Loads, error) { return Loads{Install: install}, nil }
	e.setSignals(offList, Signal{Kind: SignalExploited, Source: "rapid7-blog", FirstSeen: install.AddDate(0, -2, 0), Qualifies: true})
	e.rate()
	if news, _, sums := e.pub.told(); len(news) != 0 || len(sums) != 1 || sums[0].Key != "install" {
		t.Fatalf("the box's first run: told %v, summaries %+v", news, sums)
	}
}

// A handled finding stores its layer and is never told.
func TestRateUrgency_AHandledFindingIsSilent(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	f := e.reconciled()
	if _, _, err := e.svc.Handle(t.Context(), []string{f.ID}, ResolutionFalsePositive, "Not this build.", time.Time{}, "it@example.com"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.setSignals(offList, Signal{Kind: SignalExploited, Source: "rapid7-blog", FirstSeen: *e.clock, Qualifies: true})
	e.attack(*e.clock)
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 {
		t.Fatalf("handled: %+v", r)
	}
	if news, backlog, sums := e.pub.told(); len(news)+len(backlog)+len(sums) != 0 {
		t.Fatalf("a handled finding was told %v %v %v", news, backlog, sums)
	}
	if g := e.finding(offList); g.Urgency != UrgencyUnderAttack || g.Open() {
		t.Fatalf("handled finding: %+v", g)
	}
}

// A finding a device's own match write creates is rated at once, and entering a layer is news even on an old signal (a new finding).
func TestRateUrgency_ANewMatchOnADeviceIsNews(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	e.setSignals(offList, Signal{Kind: SignalPublicExploit, Source: "exploit-db", FirstSeen: t0.Add(-400 * 24 * time.Hour), Qualifies: true})
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	f := e.finding(offList)
	if f.Urgency != UrgencyPublicExploit {
		t.Fatalf("urgency %d, want %d", f.Urgency, UrgencyPublicExploit)
	}
	if news, backlog := e.pub.announced(); !slices.Equal(news, []string{f.ID}) || len(backlog) != 0 {
		t.Fatalf("announced %v, backlog %v", news, backlog)
	}
	if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
		t.Fatal(err)
	}
	if news, backlog := e.pub.announced(); len(news)+len(backlog) != 0 {
		t.Fatalf("the next write announced again %v %v", news, backlog)
	}
}

// A CVE that joins an exploited list while its finding is at layer 3 is one alert of the rise (3→2), told by the one rule whichever
// pass sees the join first: the match pass (whose own urgency pass follows) or the hourly urgency pass; inside the box's first-run
// window too (the listing is dated after the install).
func TestRateUrgency_AJoinFromLayerThreeIsToldOnceInEitherOrder(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ urgencyFirst, firstRun bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		urgencyFirst := c.urgencyFirst
		e := newUrgencyEnv(t)
		f := e.reconciled()
		if c.firstRun { // the box was installed two hours ago: CISA listing the CVE today is news all the same
			install := e.clock.Add(-2 * time.Hour)
			e.svc.cfg.Urgency.Loads = func(context.Context) (Loads, error) { return Loads{Install: install}, nil }
		}
		msf := Signal{Kind: SignalPublicExploit, Source: "metasploit", FirstSeen: e.clock.Add(-48 * time.Hour), Qualifies: true}
		e.setSignals(offList, msf)
		e.rate()
		e.pub.take()
		e.advance(time.Hour)
		v := e.feeds.vulns[0]
		v.Vendor, v.Product, v.DateAdded = "Fortinet", "FortiOS", *e.clock
		e.feeds.vulns = []Vuln{v}
		e.feeds.kev[offList] = KevInfo{Vendor: "Fortinet", Product: "FortiOS"}
		e.setSignals(offList, msf, Signal{Kind: SignalExploited, Source: "cisa-kev", FirstSeen: e.clock.Truncate(24 * time.Hour), Qualifies: true})
		if urgencyFirst {
			e.rate()
		}
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		e.rate()
		var rises []UrgencyRaisedEvent
		for _, ev := range e.pub.take() {
			if c, ok := ev.payload.(UrgencyRaisedEvent); ok {
				if ev.backlog {
					t.Errorf("urgency first %v: the join went under the Backlog mark", urgencyFirst)
				}
				rises = append(rises, c)
			}
		}
		if len(rises) != 1 || rises[0].FindingID != f.ID || rises[0].From != UrgencyPublicExploit || rises[0].To != UrgencyExploited {
			t.Fatalf("urgency first %v: rises %+v, want one 3→2", urgencyFirst, rises)
		}
	}
}

// A fresh box: what its first look brings (a reason from before the install) is one summary, but a reason first seen after the install is
// news, also inside the window: a researcher's claim dated today, CISA listing the CVE on the first day (either pass first), a device
// added the first day whose finding carries a claim dated after the install.
func TestRateUrgency_TheFirstRunWindowKeepsTheNews(t *testing.T) {
	t.Parallel()
	before := func(e *urgencyEnv) time.Time { return e.clock.AddDate(0, -2, 0) }
	for _, c := range []struct {
		name   string
		signal func(e *urgencyEnv) Signal
		news   bool
	}{
		{"a claim from before the install", func(e *urgencyEnv) Signal {
			return Signal{Kind: SignalPublicExploit, Source: "metasploit", FirstSeen: before(e), Qualifies: true}
		}, false},
		{"a researcher's claim dated today", func(e *urgencyEnv) Signal {
			return Signal{Kind: SignalExploited, Source: "rapid7-blog", FirstSeen: e.clock.Add(-time.Hour), Qualifies: true}
		}, true},
		{"CISA lists it on the first day", func(e *urgencyEnv) Signal {
			return Signal{Kind: SignalExploited, Source: "cisa-kev", FirstSeen: e.clock.Truncate(24 * time.Hour), Qualifies: true}
		}, true},
	} {
		for _, onDevice := range []bool{false, true} { // the hourly pass, or a device added the first day (its own match write)
			e := newUrgencyEnv(t)
			install := e.clock.Add(-2 * time.Hour)
			e.svc.cfg.Urgency.Loads = func(context.Context) (Loads, error) { return Loads{Install: install}, nil }
			e.setSignals(offList, c.signal(e))
			if onDevice {
				if _, err := e.svc.OnMatchChanged(t.Context(), "a-1"); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := e.svc.Reconcile(t.Context()); err != nil {
					t.Fatal(err)
				}
				e.rate()
			}
			news, backlog, sums := e.pub.told()
			told := len(news) == 1 && len(backlog) == 0 && len(sums) == 0
			folded := len(news) == 0 && len(backlog) == 1 && len(sums) == 1 && sums[0].Key == "install"
			if c.news && !told || !c.news && !folded {
				t.Errorf("%s (device write %v): news %v, backlog %v, summaries %+v", c.name, onDevice, news, backlog, sums)
			}
		}
	}
}

// A CVE on an exploited list rates exploited, the layer the match pass starts it at: the two passes never pull a finding up and down.
func TestRateUrgency_AListedCVEDoesNotFlap(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	listed := catalogueOnly("CVE-2026-100005", "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.8")
	listed.Vendor, listed.Product = "Fortinet", "FortiOS"
	e.feeds.vulns = append(e.feeds.vulns, listed)
	e.feeds.kev["CVE-2026-100005"] = KevInfo{Vendor: "Fortinet", Product: "FortiOS"}
	e.setSignals("CVE-2026-100005", Signal{Kind: SignalExploited, Source: "cisa-kev", FirstSeen: t0.Add(-400 * 24 * time.Hour), Qualifies: true})
	for range 3 {
		if _, err := e.svc.Reconcile(t.Context()); err != nil {
			t.Fatal(err)
		}
		e.rate()
		e.advance(time.Hour)
	}
	f := e.finding("CVE-2026-100005")
	if f.Urgency != UrgencyExploited || len(e.urgencyEvents(f.ID)) != 0 {
		t.Fatalf("listed finding %+v, urgency events %v", f, e.urgencyEvents(f.ID))
	}
}

// cancelOnRise publishes into a markedPub and cancels a context at the first rise it sees: the pass's next write then fails.
type cancelOnRise struct {
	*markedPub
	cancel context.CancelFunc
}

func (p cancelOnRise) Publish(ctx context.Context, name string, payload any) error {
	if name == EventUrgencyRaised {
		p.cancel()
	}
	return p.markedPub.Publish(ctx, name, payload)
}

// Each write's first-run summary goes out as soon as that write commits: when a later write of the same pass fails, the rises the earlier
// one stored are told all the same (never stored and untold).
func TestRateUrgency_ASummaryIsSentWithItsWrite(t *testing.T) { //nolint:paralleltest // it sets the size of a write
	was := urgencyChunk
	urgencyChunk = 1
	t.Cleanup(func() { urgencyChunk = was })
	const second = "CVE-2026-100002"
	e := newUrgencyEnv(t)
	e.feeds.vulns = append(e.feeds.vulns, catalogueOnly(second, "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*", "7.2.0", "7.2.9"))
	e.reconciled()
	now := *e.clock
	loaded := Signal{Kind: SignalPublicExploit, Source: "nuclei-templates", FirstSeen: now, Qualifies: true, FirstLoad: true, LoadedAt: now}
	e.setSignals(offList, loaded)
	e.setSignals(second, loaded)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	e.svc.cfg.Publisher = cancelOnRise{e.pub, cancel}
	if _, err := e.svc.RateUrgency(ctx, ""); err == nil {
		t.Fatal("the second write did not fail")
	}
	_, backlog, sums := e.pub.told()
	if len(backlog) != 1 || len(sums) != 1 || sums[0].Findings != 1 || !slices.Equal(sums[0].FindingIDs, backlog) {
		t.Fatalf("rises %v, summaries %+v: the stored rise must be in a summary", backlog, sums)
	}
}

// A safe check that confirms a finding is saved and answered even when the urgency pass after it fails: the scan keeps its link to the
// finding, and the hourly pass rates it later.
func TestConfirmFromScan_AFailedUrgencyPassKeepsTheRecord(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	e.svc.cfg.Urgency.Facts = func(context.Context, []string) (map[string]CVEFacts, error) {
		return nil, errors.New("feeds unreadable")
	}
	rec, err := e.svc.ConfirmFromScan(t.Context(), "a-1", offList, Evidence{Summary: "hit", Template: "t", CheckedAt: t0})
	if err != nil || rec.ID == "" || rec.CVE != offList || !rec.Confirmed() {
		t.Fatalf("record %+v, error %v", rec, err)
	}
	if f := e.finding(offList); f.ID != rec.ID {
		t.Fatalf("stored %s, answered %s", f.ID, rec.ID)
	}
}
