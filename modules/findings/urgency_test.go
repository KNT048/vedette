package findings

import (
	"context"
	"encoding/json"
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
		{"critical on an edge device", CVEFacts{CVSS: critical}, Target{DeviceKind: "nas"}, nil, UrgencyCriticalEdge},
		{"critical on a switch", CVEFacts{CVSS: critical}, Target{Class: productid.ClassNetwork, DeviceKind: "switch"}, nil, UrgencyUpdate},
		{"critical on a PC", CVEFacts{CVSS: critical}, Target{DeviceKind: "pc"}, nil, UrgencyUpdate},
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

// A rise is news when its source dated it recently and it did not come with the first load of its source; an attack always is.
func TestUrgency_News(t *testing.T) {
	t.Parallel()
	recent, old := t0.Add(-24*time.Hour), t0.Add(-30*24*time.Hour)
	for _, c := range []struct {
		name string
		r    Rating
		want bool
	}{
		{"recent", Rating{Layer: UrgencyPublicExploit, Since: recent}, true},
		{"old", Rating{Layer: UrgencyPublicExploit, Since: old}, false},
		{"first load", Rating{Layer: UrgencyPublicExploit, Since: recent, FirstLoad: true}, false},
		{"no date", Rating{Layer: UrgencyExploited}, false},
		{"attack", Rating{Layer: UrgencyUnderAttack, Since: old}, true},
		{"update", Rating{Layer: UrgencyUpdate, Since: recent}, false},
	} {
		if got := c.r.News(t0); got != c.want {
			t.Errorf("%s: news %v, want %v", c.name, got, c.want)
		}
	}
}

type sampleFixture struct {
	Now     time.Time `json:"now"`
	Samples []struct {
		CVE         string    `json:"cve"`
		FixKey      string    `json:"fix_key"`
		DeviceKind  string    `json:"device_kind"`
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
		r := Urgency(s.CVE, facts, TargetOf(f, Device{Kind: s.DeviceKind}), nil, fx.Now)
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
			if r := Urgency(s.CVE, facts, TargetOf(f, Device{Kind: s.DeviceKind}), nil, fx.Now); r.Layer != s.WithoutCISA {
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

// announced is the ids of the findings announced (findings.finding.created), split by the Backlog mark.
func (p *markedPub) announced() (news, backlog []string) {
	for _, e := range p.take() {
		if c, ok := e.payload.(CreatedEvent); ok && e.name == EventCreated {
			if e.backlog {
				backlog = append(backlog, c.FindingID)
			} else {
				news = append(news, c.FindingID)
			}
		}
	}
	return news, backlog
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
		Devices: func(_ context.Context, ids []string) (map[string]Device, error) {
			return map[string]Device{"a-1": {Kind: "firewall"}}, nil
		},
		Attacks: func(_ context.Context, since time.Time) ([]Attack, error) {
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
	r, err := e.svc.RateUrgency(e.t.Context(), "", nil)
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

// The pass raises and lowers: a recent public exploit raises an off-list finding to layer 3 and announces it once as news; the signal
// going away lowers it to 5 silently; an old signal raises it under the Backlog mark (counted, never sent); every change is one
// urgency_changed event and a pass that changes nothing writes nothing.
func TestRateUrgency_RaisesAndLowers(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	f := e.finding(offList)
	e.pub.take()
	if f.Urgency != UrgencyUpdate {
		t.Fatalf("start urgency %d", f.Urgency)
	}
	if r := e.rate(); r.Raised != 0 || r.Lowered != 0 {
		t.Fatalf("no signal yet: %+v", r)
	}
	e.setSignals(offList, Signal{Kind: SignalPublicExploit, Source: "metasploit", FirstSeen: t0.Add(-48 * time.Hour), Qualifies: true})
	if r := e.rate(); r.Raised != 1 || r.Announced != 1 {
		t.Fatalf("recent public exploit: %+v", r)
	}
	if g := e.finding(offList); g.Urgency != UrgencyPublicExploit || !g.UrgencyAt.Equal(t0) {
		t.Fatalf("after the rise: %+v", g)
	}
	if news, backlog := e.pub.announced(); !slices.Equal(news, []string{f.ID}) || len(backlog) != 0 {
		t.Fatalf("announced %v, backlog %v; want the finding once as news", news, backlog)
	}
	if r := e.rate(); r.Raised+r.Lowered != 0 {
		t.Fatalf("a second pass changed %+v", r)
	}
	e.advance(time.Hour)
	e.setSignals(offList)
	if r := e.rate(); r.Lowered != 1 {
		t.Fatalf("signal gone: %+v", r)
	}
	if news, backlog := e.pub.announced(); len(news)+len(backlog) != 0 {
		t.Fatalf("a lowering announced %v %v", news, backlog)
	}
	e.advance(time.Hour)
	e.setSignals(offList, Signal{Kind: SignalExploited, Source: "rapid7", FirstSeen: t0.Add(-60 * 24 * time.Hour), Qualifies: true})
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 {
		t.Fatalf("old signal: %+v", r)
	}
	if news, backlog := e.pub.announced(); len(news) != 0 || !slices.Equal(backlog, []string{f.ID}) {
		t.Fatalf("old signal announced %v, backlog %v; want it under the Backlog mark only", news, backlog)
	}
	if got := e.urgencyEvents(f.ID); !slices.Equal(got, []int{UrgencyPublicExploit, UrgencyUpdate, UrgencyExploited}) {
		t.Fatalf("urgency events %v", got)
	}
}

// A signal that came with the first load of its source raises silently (the first-run rule), however recent its date.
func TestRateUrgency_TheFirstLoadIsSilent(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.setSignals(offList, Signal{Kind: SignalPublicExploit, Source: "nuclei-templates", FirstSeen: t0, Qualifies: true, FirstLoad: true})
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 {
		t.Fatalf("first load: %+v", r)
	}
	if news, _ := e.pub.announced(); len(news) != 0 {
		t.Fatalf("first load announced %v", news)
	}
}

// A handled finding stores its layer and stays silent; an attack here raises an open one to layer 1 and is always news.
func TestRateUrgency_HandledIsSilentAndAnAttackIsNews(t *testing.T) {
	t.Parallel()
	e := newUrgencyEnv(t)
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	f := e.finding(offList)
	if _, _, err := e.svc.Handle(t.Context(), []string{f.ID}, ResolutionFalsePositive, "Not this build.", time.Time{}, "it@example.com"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.setSignals(offList, Signal{Kind: SignalExploited, Source: "rapid7", FirstSeen: t0, Qualifies: true})
	if r := e.rate(); r.Raised != 1 || r.Announced != 0 {
		t.Fatalf("handled: %+v", r)
	}
	if news, backlog := e.pub.announced(); len(news)+len(backlog) != 0 {
		t.Fatalf("a handled finding announced %v %v", news, backlog)
	}
	if g := e.finding(offList); g.Urgency != UrgencyExploited || g.Open() {
		t.Fatalf("handled finding: %+v", g)
	}
	if _, err := e.svc.Reopen(t.Context(), f.ID, "Seen again.", "it@example.com"); err != nil {
		t.Fatal(err)
	}
	e.pub.take()
	e.mu.Lock()
	e.attacks = []Attack{{CVE: offList, AssetID: "a-1", FirstSeen: t0.Add(-time.Hour), LastSeen: t0, AlertID: "al-1"}}
	e.mu.Unlock()
	if r := e.rate(); r.Raised != 1 {
		t.Fatalf("attack: %+v", r)
	}
	if g := e.finding(offList); g.Urgency != UrgencyUnderAttack {
		t.Fatalf("attacked finding: %+v", g)
	}
}

// A finding a device's own match write creates is rated at once, and entering a layer is news even on an old signal (a new match on
// the device), as a new exploited-list match is.
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
