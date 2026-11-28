package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// Urgency says how much a finding matters now, in five layers (fnd_finding.urgency), most urgent first. One function decides it
// (Urgency) from what the box holds: the signals feeds keeps of the CVE (feeds_signal and the exploited lists), the CVE's CVSS and
// CISA's SSVC, the class of the software the flaw is on, and the attacks this network's intrusion alerts saw. Only the urgency pass
// (RateUrgency) stores it; the match pass gives a new finding the layer of its exploited-list entry until then.

// The urgency layers.
const (
	UrgencyUnderAttack   = 1 // an intrusion alert on this network named the CVE in the last AttackWindow, at this device or while it is affected
	UrgencyExploited     = 2 // attackers use the flaw: an exploited list, or a vendor or researcher says so
	UrgencyPublicExploit = 3 // working exploit code is public
	UrgencyCriticalEdge  = 4 // critical, over the network with no login, on a device class attackers target first
	UrgencyUpdate        = 5 // a known flaw, no sign of exploitation yet
)

// AttackWindow is how recent an intrusion alert naming a CVE must be for the finding to be under attack here.
const AttackWindow = 14 * 24 * time.Hour

// The kinds of signal (feeds_signal.kind) that raise a finding.
const (
	SignalExploited     = "exploited"
	SignalPublicExploit = "public_exploit"
)

// criticalScore is the CVSS base score from which a flaw on an edge device is layer 4.
const criticalScore = 9.0

// Signal is one reason a CVE is urgent as feeds holds it (a feeds_signal row): which source says it, of which kind, since when.
type Signal struct {
	Kind, Source string
	FirstSeen    time.Time // when the source says it, else when the box first saw it
	Qualifies    bool      // the row passes the quality rule of its kind; a row that does not only keeps its first sighting
	URL          string
	// FirstLoad: the row came with the first load of its source on this box (its source's first good pull, which ended at LoadedAt).
	// Its date says nothing about when the box learned it: a rise it causes soon after that load goes into the first-run summary.
	FirstLoad bool
	LoadedAt  time.Time
}

// CVEFacts is what the box holds about one CVE that its urgency reads.
type CVEFacts struct {
	Signals []Signal
	CVSS    *CVSS // the score feeds picks (feeds.PickCVSS); nil when none
	// Automatable is CISA's SSVC "automatable" decision point ("yes", "no"; "" when not given).
	Automatable string
	Published   time.Time // zero when not known
}

// Target is the device and software line a finding is on, as its urgency reads them.
type Target struct {
	AssetID  string
	Class    productid.Class // the class of the software's product (core/productid)
	Affected bool            // the current data detects the flaw on the device
	// Internet: the device is reachable from the Internet (exposure), seen at InternetSeen. A line of the reasons, never a layer.
	Internet     bool
	InternetSeen time.Time
}

// Attack is one CVE an intrusion alert on this network named, aimed at an address (the device that had it, "" when none did).
type Attack struct {
	CVE       string
	AssetID   string
	FirstSeen time.Time
	LastSeen  time.Time
	AlertID   string
}

// Reason is one layer that applies to a finding, with its source and date ("Exploited in the wild: Rapid7, 19 Nov").
type Reason struct {
	Layer  int
	Source string    // a feeds source id ("cisa-kev", "rapid7-blog"), "ids" for an attack, the product's class for layer 4
	Since  time.Time // the source's date (the attack's last event for layer 1, the CVE's publication for layer 4)
	URL    string    // the source's link, the alert id for an attack; "" when none
	// FirstLoad and LoadedAt: the reason came with the first load of its source, which ended then (Signal).
	FirstLoad bool
	LoadedAt  time.Time
}

// Rating is the urgency of a finding with every reason that applies, the most urgent first.
type Rating struct {
	Layer   int
	Reasons []Reason
	// Since is when the finding's layer began to apply: the earliest reason of that layer (the latest attack for layer 1).
	Since        time.Time
	Internet     bool
	InternetSeen time.Time
}

// FirstRunWindow is how long after a first load (of the box itself, of a signal source, of the catalogue) the rises of what that load
// brought go into one first-run summary instead of one alert each: the box's own first discovery runs as long.
const FirstRunWindow = 36 * time.Hour

// Loads are the first loads a rise may come from (zero when unknown or not yet).
type Loads struct {
	Install   time.Time // the box's own first run (its install)
	Catalogue time.Time // the end of the catalogue's first load (CVE ranges: a device's findings of old flaws appear then)
}

// Telling is how a rise of an open finding into a more urgent layer of 1–4 is told.
type Telling int

// The ways a rise is told.
const (
	TellNews     Telling = iota + 1 // one alert (findings.finding.urgency_raised)
	TellFirstRun                    // one line of a first-run summary (findings.urgency.first_run), no alert of its own
	TellBacklog                     // counted, silent (under the Backlog mark): old news the list shows
)

// Tell is the one rule of how a rise of open finding f to rating r is told at now; every pass that tells a rise asks it. T is the date of
// the newest reason of the new layer (an attack's last event, a signal's date, a CVE's publication for layer 4):
//   - an attack here is news;
//   - a rise that a first load brought, inside FirstRunWindow after that load, is a line of that load's summary: T before the day of
//     the box's install (key "install"); a reason that came with its source's first load (key: the source and the load's day); a
//     finding the catalogue's first load made, with T before that load's day (key: "catalogue" and the day). A reason first seen
//     after its load is news, also inside the window;
//   - else it is news when T or the finding itself is within RecentKEV (a late range or a device added later makes a new finding of
//     an old flaw: news);
//   - else it is old news: counted, silent.
func Tell(f Finding, r Rating, now time.Time, loads Loads) (Telling, string) {
	if r.Layer == UrgencyUnderAttack {
		return TellNews, ""
	}
	var newest Reason
	for _, x := range r.Reasons {
		if x.Layer == r.Layer && (newest.Layer == 0 || x.Since.After(newest.Since)) {
			newest = x
		}
	}
	t := newest.Since
	inWindow := func(load time.Time) bool {
		return !load.IsZero() && !now.Before(load) && now.Sub(load) <= FirstRunWindow
	}
	day := func(load time.Time) time.Time { return load.UTC().Truncate(24 * time.Hour) }
	switch {
	case inWindow(loads.Install) && t.Before(day(loads.Install)):
		return TellFirstRun, "install"
	case newest.FirstLoad && inWindow(newest.LoadedAt):
		return TellFirstRun, newest.Source + "-" + newest.LoadedAt.UTC().Format("20060102")
	case inWindow(loads.Catalogue) && t.Before(day(loads.Catalogue)) && !f.FirstSeen.Before(day(loads.Catalogue).Add(-24*time.Hour)):
		return TellFirstRun, "catalogue-" + loads.Catalogue.UTC().Format("20060102")
	}
	latest := t
	if f.FirstSeen.After(latest) {
		latest = f.FirstSeen
	}
	if !latest.IsZero() && now.Sub(latest) <= RecentKEV {
		return TellNews, ""
	}
	return TellBacklog, ""
}

// Urgency is the one function that rates a finding: the most urgent layer whose rule holds.
//   - 1 under attack here: an intrusion alert in the last AttackWindow named the CVE, aimed at this device, or at any address while
//     the device is affected, and the flaw can be exploited over the network (not AV:L or AV:P: NeedsLocalAccess).
//   - 2 exploited in the wild: a qualifying signal of kind exploited (an exploited list's entry is one).
//   - 3 public exploit available: a qualifying signal of kind public_exploit.
//   - 4 critical on an edge device: CVSS of 9 or more, attack over the network, no privileges, SSVC automatable not "no", on a product
//     of a class attackers target first (EdgeClass).
//   - 5 update recommended: every other finding.
//
// attacks may hold other CVEs' attacks: only c's count. now bounds the attack window.
func Urgency(cve string, c CVEFacts, t Target, attacks []Attack, now time.Time) Rating {
	var rs []Reason
	wire := !NeedsLocalAccess(c.CVSS)
	for _, a := range attacks {
		if !wire || a.CVE != cve || now.Sub(a.LastSeen) > AttackWindow || a.LastSeen.After(now) {
			continue
		}
		if a.AssetID == t.AssetID && t.AssetID != "" || t.Affected {
			rs = append(rs, Reason{Layer: UrgencyUnderAttack, Source: "ids", Since: a.LastSeen, URL: a.AlertID})
		}
	}
	for _, g := range c.Signals {
		if !g.Qualifies {
			continue
		}
		switch g.Kind {
		case SignalExploited:
			rs = append(rs, Reason{Layer: UrgencyExploited, Source: g.Source, Since: g.FirstSeen, URL: g.URL, FirstLoad: g.FirstLoad, LoadedAt: g.LoadedAt})
		case SignalPublicExploit:
			rs = append(rs, Reason{Layer: UrgencyPublicExploit, Source: g.Source, Since: g.FirstSeen, URL: g.URL, FirstLoad: g.FirstLoad, LoadedAt: g.LoadedAt})
		}
	}
	if criticalEdge(c, t) {
		rs = append(rs, Reason{Layer: UrgencyCriticalEdge, Source: string(t.Class), Since: c.Published})
	}
	slices.SortStableFunc(rs, func(a, b Reason) int {
		if a.Layer == UrgencyUnderAttack && b.Layer == UrgencyUnderAttack {
			return b.Since.Compare(a.Since) // the latest attack first
		}
		return cmp.Or(cmp.Compare(a.Layer, b.Layer), a.Since.Compare(b.Since), strings.Compare(a.Source, b.Source))
	})
	r := Rating{Layer: UrgencyUpdate, Reasons: rs, Internet: t.Internet, InternetSeen: t.InternetSeen}
	if len(rs) > 0 {
		r.Layer, r.Since = rs[0].Layer, rs[0].Since
	}
	return r
}

// criticalEdge is the rule of layer 4.
func criticalEdge(c CVEFacts, t Target) bool {
	if c.CVSS == nil || c.CVSS.Score < criticalScore || strings.EqualFold(c.Automatable, "no") {
		return false
	}
	if !EdgeClass(t.Class) {
		return false
	}
	return networkNoLogin(c.CVSS.Vector)
}

// networkNoLogin says whether a CVSS vector is an attack over the network that needs no privileges: AV:N and PR:N (3.x, 4.0), AV:N
// and Au:N (2.0).
func networkNoLogin(vector string) bool {
	m := vectorMetrics(vector)
	if m["AV"] != "N" {
		return false
	}
	if strings.HasPrefix(vector, "CVSS:") {
		return m["PR"] == "N"
	}
	return m["Au"] == "N"
}

// EdgeClass says whether a product class is one attackers target first: a product at the edge of a network or one that manages it
// (firewall, VPN, mail, file transfer, remote access, backup, an internet router, NAS, hypervisor, a management console). A switch or
// access point inside the network (ClassNetwork) is not.
func EdgeClass(c productid.Class) bool {
	return c != productid.ClassNone && c != productid.ClassNetwork && c.Valid()
}

// ClassOf is the class of the product a finding is on (ProductOf).
func ClassOf(f Finding) productid.Class {
	p, _ := ProductOf(f)
	return p.Class
}

// ProductOf is the catalogue's product a finding is on, read from its fix key (the line's product key leads it); false when the
// catalogue does not know it.
func ProductOf(f Finding) (productid.Product, bool) {
	v, rest, _ := strings.Cut(f.FixKey, "|")
	p, _, _ := strings.Cut(rest, "|")
	return productOfKey(v + "|" + p)
}

// productOfKey is the catalogue's product of a line's product key ("vmware|esxi"); false when the catalogue does not know it.
func productOfKey(key string) (productid.Product, bool) {
	v, p, _ := strings.Cut(key, "|")
	if pr, ok := productid.ByKey(key); ok {
		return pr, true
	}
	if pr, ok := productid.ByKEV(key); ok {
		return pr, true
	}
	return productid.ResolveStored(v, p, "", "")
}

// listed says the entry is on an exploited list (the catalogue's other CVEs have no list vendor and product).
func (v Vuln) listed() bool { return v.Vendor != "" || v.Product != "" }

// StartUrgency is the urgency a finding of v starts with until the urgency pass rates it: exploited when v is an exploited list's
// entry, update recommended otherwise. The one rule of what a new match is worth telling, with Announced.
func (v Vuln) StartUrgency() int {
	if v.listed() {
		return UrgencyExploited
	}
	return UrgencyUpdate
}

// The status codes of the urgency layers (the status model: the first five codes), for the readers that name a finding's urgency.
const (
	CodeUnderAttack       = "under_attack"
	CodeExploited         = "exploited"
	CodePublicExploit     = "public_exploit"
	CodeCriticalEdge      = "critical_edge"
	CodeUpdateRecommended = "update_recommended"
)

// LayerCode is the status code of an urgency layer; a value outside 1..5 reads as update recommended.
func LayerCode(layer int) string {
	switch layer {
	case UrgencyUnderAttack:
		return CodeUnderAttack
	case UrgencyExploited:
		return CodeExploited
	case UrgencyPublicExploit:
		return CodePublicExploit
	case UrgencyCriticalEdge:
		return CodeCriticalEdge
	}
	return CodeUpdateRecommended
}

// ExploitedLayer says whether an urgency layer means the CVE is exploited: under attack here, or exploited in the wild (1 or 2); 0 (not
// rated) and 3 to 5 are not. The one cutoff of "exploited": a finding's (Finding.Exploited), an alert's (notify reads it through
// FindingInfo.Exploited) and an exposure issue's (cmd/vedette exploitedCVEs) all ask it.
func ExploitedLayer(layer int) bool { return layer >= UrgencyUnderAttack && layer <= UrgencyExploited }

// Exploited says whether the finding's CVE is exploited: under attack here, or exploited in the wild (urgency 1 or 2). Every reader
// that calls a finding exploited, counts exploited findings or names an exploited list asks this, never "is it a finding".
func (f Finding) Exploited() bool { return ExploitedLayer(f.Urgency) }

// ---- the urgency pass ----

// UrgencySources are what the urgency pass reads besides the findings. A nil Facts: the pass does not run (the layers the match pass
// starts findings with stay).
type UrgencySources struct {
	// Facts returns what the box holds of these CVEs (feeds: signals of the feeds that are on, CVSS, SSVC, publication); a CVE it holds
	// nothing of is absent.
	Facts func(ctx context.Context, cves []string) (map[string]CVEFacts, error)
	// Devices returns the Internet exposure of these devices (exposure); an unknown one is absent. nil: none known. A line of the reasons
	// only, never a layer, so nothing reads it until the reasons are shown.
	Devices func(ctx context.Context, ids []string) (map[string]Device, error)
	// Attacks returns the CVEs this network's intrusion alerts named since a time (ids). nil: no intrusion detection, layer 1 never applies.
	Attacks func(ctx context.Context, since time.Time) ([]Attack, error)
	// Loads returns the first loads a rise may come from (the box's install, the catalogue's first load). nil: none known.
	Loads func(ctx context.Context) (Loads, error)
	// Names returns the signal sources' names by id (feeds), for the reasons a finding's view lists. nil: reasons of signals are left
	// out (a source is never shown by its id).
	Names SourceNames
}

// Device is what the urgency of a device's findings reads of the device.
type Device struct {
	Internet     bool // reachable from the Internet (exposure)
	InternetSeen time.Time
}

// TargetOf is the target of a finding on device d: the class of the line's product (ClassOf), the device's exposure, and whether the
// data detects the flaw now.
func TargetOf(f Finding, d Device) Target {
	return Target{AssetID: f.AssetID, Class: ClassOf(f), Affected: f.Detected, Internet: d.Internet, InternetSeen: d.InternetSeen}
}

// rates says whether the urgency pass runs (its ports are wired): then it alone rates and tells a rise of an existing finding, and the
// match pass only gives a new finding its start layer. Without it the match pass raises a finding whose CVE joined a list itself.
func (s *Service) rates() bool { return s.cfg.Urgency.Facts != nil }

// UrgencyEvery is the pause between two runs of the urgency pass (it also runs when the module starts, and for a device after each of
// its match writes).
const UrgencyEvery = time.Hour

// UrgencyJob is the name of the urgency pass's job (core_job_run.job): the selfcheck recomputes the layers as of its last run.
const UrgencyJob = "urgency"

// UrgencyResult says what one urgency pass did.
type UrgencyResult struct {
	Rated, Raised, Lowered int
	Announced              int // rises of open findings told as news (one alert each)
	FirstRun               int // rises of open findings listed in a first-run summary
}

// urgencyChunk bounds the findings one write of the pass changes, so the writer is never held for long (a variable for the tests).
var urgencyChunk = 500

// raised says whether a step raised an open finding into a more urgent layer of 1–4: the one kind of urgency change people are told
// about (a drop, a rise of a handled finding and a change to 5 never are). A new finding is told by its creation instead.
func raised(before, after Finding) bool {
	return before.State != "" && after.Open() && Announced(after) && after.Urgency < before.Urgency
}

// raisedEvent is the bus event of a rise.
func raisedEvent(before, after Finding, sev Severity) UrgencyRaisedEvent {
	return UrgencyRaisedEvent{FindingID: after.ID, AssetID: after.AssetID, CVE: after.CVE, Severity: sev, Basis: record(after, nil, sev).Basis,
		From: before.Urgency, To: after.Urgency, At: after.UrgencyAt.UTC().Format(time.RFC3339Nano)}
}

// RateUrgency rates the findings of one device (every device when assetID is "") with Urgency and stores each layer that changed
// through Transition (urgency_changed), raising and lowering. A drop is never told; a handled finding is never told. Every rise of an
// open finding into a more urgent layer of 1–4 is told once (Tell): as news (findings.finding.urgency_raised), as a line of the
// first-run summary (findings.urgency.first_run, one event per summary and pass), or as old news under the Backlog mark. Each finding is
// read again inside its write and rated on that row.
//
// A device a person ignored is silent: its findings are not rated, so nothing about it is told (no alert, no response rule, no
// planner work) and their stored layer stays as it was when the device was ignored. Stop ignoring rates the device again
// (inventory sends inventory.asset.updated with match, so OnMatchChanged matches and rates it): a rise that happened meanwhile is told
// then, by the same Tell rule as any rise (news while its reason is recent, else counted under the Backlog mark).
func (s *Service) RateUrgency(ctx context.Context, assetID string) (UrgencyResult, error) {
	var res UrgencyResult
	if !s.rates() {
		return res, nil
	}
	fs, err := findingsOf(ctx, s.cfg.DB.Reader(), assetID)
	if err != nil || len(fs) == 0 {
		return res, err
	}
	ignored, err := s.ignoredDevices(ctx)
	if err != nil {
		return res, fmt.Errorf("findings: urgency: %w", err) // never rate without knowing which devices are silent
	}
	fs = slices.DeleteFunc(fs, func(f Finding) bool { return ignored[f.AssetID] })
	if len(fs) == 0 {
		return res, nil
	}
	now := s.now().UTC()
	in, err := s.urgencyInputs(ctx, fs, now)
	if err != nil {
		return res, err
	}
	var plain, backlog []string
	for _, f := range fs {
		res.Rated++
		r := in.rate(f, now)
		if r.Layer == f.Urgency {
			continue
		}
		if t, _ := Tell(f, r, now, in.loads); r.Layer < f.Urgency && t != TellNews { // a summary's line or old news: no alert of its own
			backlog = append(backlog, f.ID)
		} else {
			plain = append(plain, f.ID)
		}
	}
	apply := func(wctx context.Context, ids []string, marked bool) error {
		for chunk := range slices.Chunk(ids, urgencyChunk) {
			// the first-run summaries of this write go out as soon as it commits: a later write that fails leaves none of its rises untold
			var summaries map[string]*FirstRunEvent
			var devices map[string]map[string]bool
			if err := s.write(wctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
				summaries, devices = map[string]*FirstRunEvent{}, map[string]map[string]bool{}
				silent := map[string]bool{} // by device: ignored, asked inside the write
				for _, id := range chunk {
					f, err := loadFinding(ctx, tx, id)
					if errors.Is(err, ErrNotFound) {
						continue // the device went away meanwhile
					} else if err != nil {
						return err
					}
					ig, asked := silent[f.AssetID]
					if !asked {
						if ig, err = s.cfg.Inventory.IsIgnored(ctx, f.AssetID); err != nil {
							return fmt.Errorf("findings: urgency: reading whether the device is ignored: %w", err)
						}
						silent[f.AssetID] = ig
					}
					if ig {
						continue // a person ignored the device after the pass read the list
					}
					r := in.rate(f, now)
					if r.Layer == f.Urgency {
						continue
					}
					g, _, err := s.step(ctx, tx, f, false, Trigger{Kind: TrUrgency, At: now, Layer: r.Layer}, emit)
					if err != nil {
						return fmt.Errorf("findings: urgency of %s on %s: %w", f.CVE, f.AssetID, err)
					}
					if g.Urgency < f.Urgency {
						res.Raised++
					} else {
						res.Lowered++
					}
					if !raised(f, g) {
						continue
					}
					band := SeverityMedium
					if c := in.facts[f.CVE].CVSS; c != nil {
						band = bandOf(*c)
					}
					// Every rise is one urgency_raised (the response rules, the SIEM export and To review act on it); only news is an alert
					// of its own: the others go out under the Backlog mark, which notify only counts.
					emit(EventUrgencyRaised, raisedEvent(f, g, band))
					t, key := Tell(g, r, now, in.loads)
					switch {
					case !marked:
						res.Announced++
					case t == TellFirstRun:
						res.FirstRun++
						sum := summaries[key]
						if sum == nil {
							sum = &FirstRunEvent{Key: key, At: now.Format(time.RFC3339Nano)}
							summaries[key], devices[key] = sum, map[string]bool{}
						}
						sum.add(g, devices[key])
					}
				}
				return nil
			}); err != nil {
				return err
			}
			s.publishFirstRun(ctx, summaries)
		}
		return nil
	}
	if err := apply(ctx, plain, false); err != nil {
		return res, err
	}
	bctx := ctx
	if s.cfg.Backlog != nil {
		bctx = s.cfg.Backlog(ctx)
	}
	if err := apply(bctx, backlog, true); err != nil {
		return res, err
	}
	return res, nil
}

// add counts one finding into a first-run summary.
func (e *FirstRunEvent) add(f Finding, devices map[string]bool) {
	e.Findings++
	if !devices[f.AssetID] {
		devices[f.AssetID] = true
		e.Devices++
	}
	if !slices.Contains(e.CVEList, f.CVE) && len(e.CVEList) < MaxBackfillListed {
		e.CVEList = append(e.CVEList, f.CVE)
	}
	if len(e.FindingIDs) < MaxBackfillListed {
		e.FindingIDs = append(e.FindingIDs, f.ID)
	}
	if e.Layer == 0 || f.Urgency < e.Layer {
		e.Layer = f.Urgency
	}
	if f.Exploited() {
		e.Exploited++
	}
}

// publishFirstRun sends the first-run summaries of one write, one event each, after it committed.
func (s *Service) publishFirstRun(ctx context.Context, sums map[string]*FirstRunEvent) {
	if s.cfg.Publisher == nil || len(sums) == 0 {
		return
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	for _, key := range slices.Sorted(maps.Keys(sums)) {
		if err := s.cfg.Publisher.Publish(pctx, EventFirstRun, *sums[key]); err != nil {
			s.cfg.Log.ErrorContext(pctx, "publishing a findings event failed", "event", EventFirstRun, "error", err)
		}
	}
}

// urgencyInputs is what one pass rates findings with, read once.
type urgencyInputs struct {
	facts   map[string]CVEFacts
	devices map[string]Device
	attacks map[string][]Attack // by CVE
	loads   Loads
}

func (in urgencyInputs) rate(f Finding, now time.Time) Rating {
	return Urgency(f.CVE, in.facts[f.CVE], TargetOf(f, in.devices[f.AssetID]), in.attacks[f.CVE], now)
}

func (s *Service) urgencyInputs(ctx context.Context, fs []Finding, now time.Time) (urgencyInputs, error) {
	var in urgencyInputs
	cves, assets := make([]string, 0, len(fs)), make([]string, 0, 8)
	for _, f := range fs {
		cves, assets = append(cves, f.CVE), append(assets, f.AssetID)
	}
	slices.Sort(cves)
	slices.Sort(assets)
	var err error
	if in.facts, err = s.cfg.Urgency.Facts(ctx, slices.Compact(cves)); err != nil {
		return in, fmt.Errorf("findings: urgency: reading the CVEs' signals: %w", err)
	}
	if s.cfg.Urgency.Devices != nil {
		if in.devices, err = s.cfg.Urgency.Devices(ctx, slices.Compact(assets)); err != nil {
			return in, fmt.Errorf("findings: urgency: reading the devices: %w", err)
		}
	}
	if s.cfg.Urgency.Attacks != nil {
		as, err := s.cfg.Urgency.Attacks(ctx, now.Add(-AttackWindow))
		if err != nil {
			return in, fmt.Errorf("findings: urgency: reading the attacks: %w", err)
		}
		in.attacks = AttacksByCVE(as)
	}
	if s.cfg.Urgency.Loads != nil {
		if in.loads, err = s.cfg.Urgency.Loads(ctx); err != nil {
			return in, fmt.Errorf("findings: urgency: reading the first-run window: %w", err)
		}
	}
	return in, nil
}

// AttacksByCVE groups attacks by their CVE, so a pass reads each finding's own.
func AttacksByCVE(as []Attack) map[string][]Attack {
	out := map[string][]Attack{}
	for _, a := range as {
		out[a.CVE] = append(out[a.CVE], a)
	}
	return out
}

// NeedsLocalAccess says whether the flaw can only be exploited with local or physical access (AV:L or AV:P in CVSS 2.0, 3.x and 4.0).
// An intrusion alert is traffic seen on the network: it may carry such an exploit (a file, a download) but cannot be its exploitation,
// so it never makes the finding under attack here. A missing score is not local.
func NeedsLocalAccess(c *CVSS) bool {
	if c == nil {
		return false
	}
	av := vectorMetrics(c.Vector)["AV"]
	return av == "L" || av == "P"
}

// vectorMetrics splits a CVSS vector into its metrics ("AV" → "N"); the version prefix of 3.x and 4.0 is one more entry.
func vectorMetrics(vector string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
	return m
}
