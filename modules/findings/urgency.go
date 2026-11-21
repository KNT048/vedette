package findings

import (
	"cmp"
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
