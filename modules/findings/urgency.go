package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/productid"
)

// Urgency says how much a finding matters now, in five layers (fnd_finding.urgency), most urgent first. One function decides it
// (Urgency) from what the box holds: the signals feeds keeps of the CVE (feeds_signal and the exploited lists), the CVE's CVSS and
// CISA's SSVC, the class of the device and of the software the flaw is on, and the attacks this network's intrusion alerts saw. Only
// the urgency pass (RateUrgency) stores it; the match pass gives a new finding the layer of its exploited-list entry until then.

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
	// FirstLoad: the row came with the first load of its source on this box (every row of a source's first pull). Its date says
	// nothing about when the box learned it, so a rise it causes is never news (the first-run rule).
	FirstLoad bool
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
	AssetID string
	// Class is the class of the software's product (core/productid); DeviceKind the device's type in inventory.
	Class      productid.Class
	DeviceKind string
	Affected   bool // the current data detects the flaw on the device
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

// Reason is one layer that applies to a finding, with its source and date ("Exploited in the wild: rapid7, 19 Nov").
type Reason struct {
	Layer  int
	Source string    // a feeds source id ("cisa-kev", "rapid7"), "ids" for an attack, the product's class for layer 4
	Since  time.Time // the source's date (the attack's last event for layer 1, the CVE's publication for layer 4)
	URL    string    // the source's link, the alert id for an attack; "" when none
	// FirstLoad: the reason came with the first load of its source (Signal.FirstLoad).
	FirstLoad bool
}

// Rating is the urgency of a finding with every reason that applies, the most urgent first.
type Rating struct {
	Layer   int
	Reasons []Reason
	// Since is when the finding's layer began to apply: the earliest reason of that layer (the latest attack for layer 1).
	Since time.Time
	// FirstLoad: that reason came with the first load of its source.
	FirstLoad    bool
	Internet     bool
	InternetSeen time.Time
}

// News says whether a rise into the rating's layer is news to tell people about at now: an attack here always is; a signal is when
// its source dated it within RecentKEV and it did not come with the first load of its source (the first-run rule: what a box learns
// from its first full load is listed, never sent one alert each). Layer 4 dates from the CVE's publication.
func (r Rating) News(now time.Time) bool {
	switch {
	case r.Layer == UrgencyUnderAttack:
		return true
	case r.Layer >= UrgencyUpdate || r.FirstLoad || r.Since.IsZero():
		return false
	}
	return now.Sub(r.Since) <= RecentKEV
}

// Urgency is the one function that rates a finding (SPEC's table of the four layers): the most urgent layer whose rule holds.
//   - 1 under attack here: an intrusion alert in the last AttackWindow named the CVE, aimed at this device, or at any address while
//     the device is affected.
//   - 2 exploited in the wild: a qualifying signal of kind exploited (an exploited list's entry is one).
//   - 3 public exploit available: a qualifying signal of kind public_exploit.
//   - 4 critical on an edge device: CVSS of 9 or more, attack over the network, no privileges, SSVC automatable not "no", on a product
//     or device of a class attackers target first (EdgeClass, EdgeDevice).
//   - 5 update recommended: every other finding.
//
// attacks may hold other CVEs' attacks: only c's count. now bounds the attack window.
func Urgency(cve string, c CVEFacts, t Target, attacks []Attack, now time.Time) Rating {
	var rs []Reason
	for _, a := range attacks {
		if a.CVE != cve || now.Sub(a.LastSeen) > AttackWindow || a.LastSeen.After(now) {
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
			rs = append(rs, Reason{Layer: UrgencyExploited, Source: g.Source, Since: g.FirstSeen, URL: g.URL, FirstLoad: g.FirstLoad})
		case SignalPublicExploit:
			rs = append(rs, Reason{Layer: UrgencyPublicExploit, Source: g.Source, Since: g.FirstSeen, URL: g.URL, FirstLoad: g.FirstLoad})
		}
	}
	if criticalEdge(c, t) {
		src := string(t.Class)
		if !EdgeClass(t.Class) {
			src = t.DeviceKind
		}
		rs = append(rs, Reason{Layer: UrgencyCriticalEdge, Source: src, Since: c.Published})
	}
	slices.SortStableFunc(rs, func(a, b Reason) int {
		if a.Layer == UrgencyUnderAttack && b.Layer == UrgencyUnderAttack {
			return b.Since.Compare(a.Since) // the latest attack first
		}
		return cmp.Or(cmp.Compare(a.Layer, b.Layer), a.Since.Compare(b.Since), strings.Compare(a.Source, b.Source))
	})
	r := Rating{Layer: UrgencyUpdate, Reasons: rs, Internet: t.Internet, InternetSeen: t.InternetSeen}
	if len(rs) > 0 {
		r.Layer, r.Since, r.FirstLoad = rs[0].Layer, rs[0].Since, rs[0].FirstLoad
	}
	return r
}

// criticalEdge is the rule of layer 4.
func criticalEdge(c CVEFacts, t Target) bool {
	if c.CVSS == nil || c.CVSS.Score < criticalScore || strings.EqualFold(c.Automatable, "no") {
		return false
	}
	if !EdgeClass(t.Class) && !EdgeDevice(t.DeviceKind) {
		return false
	}
	return networkNoLogin(c.CVSS.Vector)
}

// networkNoLogin says whether a CVSS vector is an attack over the network that needs no privileges: AV:N and PR:N (3.x, 4.0), AV:N
// and Au:N (2.0).
func networkNoLogin(vector string) bool {
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			m[k] = v
		}
	}
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

// edgeDevices are the device types (inventory's kind) of devices at the edge of a network or that manage it.
var edgeDevices = map[string]bool{
	"firewall": true, "vpn_gateway": true, "router": true, "modem": true, "sd_wan": true, "load_balancer": true, "proxy": true,
	"nas": true, "san": true, "backup_appliance": true, "backup_server": true, "hypervisor": true, "bmc": true, "mail_server": true,
	"network_controller": true, "wireless_controller": true,
}

// EdgeDevice says whether a device type is one attackers target first (edgeDevices).
func EdgeDevice(kind string) bool { return edgeDevices[kind] }

// ClassOf is the class of the product a finding is on, read from its fix key (the line's product key leads it).
func ClassOf(f Finding) productid.Class {
	v, rest, _ := strings.Cut(f.FixKey, "|")
	p, _, _ := strings.Cut(rest, "|")
	key := v + "|" + p
	if pr, ok := productid.ByKey(key); ok {
		return pr.Class
	}
	if pr, ok := productid.ByKEV(key); ok {
		return pr.Class
	}
	if pr, ok := productid.ResolveStored(v, p, "", ""); ok {
		return pr.Class
	}
	return productid.ClassNone
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

// Exploited says whether the finding's CVE is exploited: under attack here, or exploited in the wild (urgency 1 or 2). Every reader
// that calls a finding exploited, counts exploited findings or names an exploited list asks this, never "is it a finding".
func (f Finding) Exploited() bool {
	return f.Urgency >= UrgencyUnderAttack && f.Urgency <= UrgencyExploited
}

// ---- the urgency pass ----

// UrgencySources are what the urgency pass reads besides the findings. A nil Facts: the pass does not run (the layers the match pass
// starts findings with stay).
type UrgencySources struct {
	// Facts returns what the box holds of these CVEs (feeds: signals, CVSS, SSVC, publication); a CVE it holds nothing of is absent.
	Facts func(ctx context.Context, cves []string) (map[string]CVEFacts, error)
	// Devices returns the type and the Internet exposure of these devices (inventory, exposure); an unknown one is absent. nil: none known.
	Devices func(ctx context.Context, ids []string) (map[string]Device, error)
	// Attacks returns the CVEs this network's intrusion alerts named since a time (ids). nil: no intrusion detection, layer 1 never applies.
	Attacks func(ctx context.Context, since time.Time) ([]Attack, error)
}

// Device is what the urgency of a device's findings reads of the device.
type Device struct {
	Kind         string // inventory's device type
	Internet     bool   // reachable from the Internet (exposure)
	InternetSeen time.Time
}

// TargetOf is the target of a finding on device d: the class of the line's product (ClassOf), the device's type and exposure, and
// whether the data detects the flaw now.
func TargetOf(f Finding, d Device) Target {
	return Target{AssetID: f.AssetID, Class: ClassOf(f), DeviceKind: d.Kind, Affected: f.Detected, Internet: d.Internet, InternetSeen: d.InternetSeen}
}

// UrgencyEvery is the pause between two runs of the urgency pass (it also runs when the module starts, and for a device after each of
// its match writes).
const UrgencyEvery = time.Hour

// UrgencyJob is the name of the urgency pass's job (core_job_run.job): the selfcheck recomputes the layers as of its last run.
const UrgencyJob = "urgency"

// UrgencyResult says what one urgency pass did.
type UrgencyResult struct {
	Rated, Raised, Lowered int
	Announced              int // open findings that entered layers 1–4 and were announced as news
}

// urgencyChunk bounds the findings one write of the pass changes, so the writer is never held for long.
const urgencyChunk = 500

// RateUrgency rates the findings of one device (every device when assetID is "") with Urgency and stores each layer that changed
// through Transition (urgency_changed), raising and lowering. A lowering is never told. An open finding that enters layers 1–4 is
// announced once, the way the match pass announces a new exploited match (findings.finding.created): as news when Rating.News holds or
// the finding is one of fresh (created by the match write that runs this pass), else under the Backlog mark (counted, silent). A handled
// finding stores its layer and stays silent. Each finding is read again inside its write and rated on that row.
func (s *Service) RateUrgency(ctx context.Context, assetID string, fresh map[string]bool) (UrgencyResult, error) {
	var res UrgencyResult
	src := s.cfg.Urgency
	if src.Facts == nil {
		return res, nil
	}
	fs, err := findingsOf(ctx, s.cfg.DB.Reader(), assetID)
	if err != nil || len(fs) == 0 {
		return res, err
	}
	now := s.now().UTC()
	in, err := s.urgencyInputs(ctx, fs, now)
	if err != nil {
		return res, err
	}
	var news, backlog []string
	for _, f := range fs {
		res.Rated++
		r := in.rate(f, now)
		if r.Layer == f.Urgency {
			continue
		}
		if r.News(now) || fresh[f.ID] {
			news = append(news, f.ID)
		} else {
			backlog = append(backlog, f.ID)
		}
	}
	apply := func(wctx context.Context, ids []string, asNews bool) error {
		for chunk := range slices.Chunk(ids, urgencyChunk) {
			if err := s.write(wctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
				for _, id := range chunk {
					f, err := loadFinding(ctx, tx, id)
					if errors.Is(err, ErrNotFound) {
						continue // the device went away meanwhile
					} else if err != nil {
						return err
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
					if g.Open() && !Announced(f) && Announced(g) { // entered layers 1–4: one notice, as a new exploited match
						band := SeverityMedium
						if c := in.facts[f.CVE].CVSS; c != nil {
							band = bandOf(*c)
						}
						emit(EventCreated, CreatedEvent{FindingID: g.ID, AssetID: g.AssetID, CVE: g.CVE, Severity: band, Basis: record(g, nil, band).Basis})
						if asNews {
							res.Announced++
						}
					}
				}
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := apply(ctx, news, true); err != nil {
		return res, err
	}
	bctx, asNews := ctx, s.cfg.Backlog == nil // without a Backlog hook nothing can be marked, so nothing is held back
	if s.cfg.Backlog != nil {
		bctx = s.cfg.Backlog(ctx)
	}
	return res, apply(bctx, backlog, asNews)
}

// urgencyInputs is what one pass rates findings with, read once.
type urgencyInputs struct {
	facts   map[string]CVEFacts
	devices map[string]Device
	attacks []Attack
}

func (in urgencyInputs) rate(f Finding, now time.Time) Rating {
	return Urgency(f.CVE, in.facts[f.CVE], TargetOf(f, in.devices[f.AssetID]), in.attacks, now)
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
		if in.attacks, err = s.cfg.Urgency.Attacks(ctx, now.Add(-AttackWindow)); err != nil {
			return in, fmt.Errorf("findings: urgency: reading the attacks: %w", err)
		}
	}
	return in, nil
}
