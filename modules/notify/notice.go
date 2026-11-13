package notify

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/modules/notify/channel"
)

// Notice kinds that travel through Publish.
const (
	KindVuln     = "vuln"
	KindIncident = "incident"
)

// Notice is one thing to tell people about. A vulnerability notice (S-ALERT-1)
// carries the devices the finding matched; an incident (D-52) does not.
type Notice struct {
	ID       string
	Kind     string // KindVuln or KindIncident
	Severity Severity
	Product  string   // vulnerability: grouping key, e.g. "QNAP Photo Station"
	CVEs     []string // vulnerability
	// FindingIDs are the findings this notice is about (vulnerability); they let the finding page list who was told.
	FindingIDs []string
	Devices    []string // names of the matched devices (vulnerability: at least one)
	Title      string   // one plain sentence
	What       string   // what happened and how urgent
	Action     string   // what to do first
	Link       string   // absolute URL of the finding or incident in Vedette
	At         time.Time

	// IncidentKind (incidents) and DeviceIDs (parallel to Devices, when the ids are known) only feed the structured
	// fields of the webhook payload (kind, devices[]); the text channels do not use them.
	IncidentKind string
	DeviceIDs    []string
}

// Sendable implements INV-2: a vulnerability notice needs at least one matched
// device with a name (FORBID-1); blank names do not count. Other kinds are
// always sendable. Group, GroupHeld and Batch.Message enforce it themselves.
func (n Notice) Sendable() bool {
	if n.Kind != KindVuln {
		return true
	}
	for _, d := range n.Devices {
		if strings.TrimSpace(d) != "" {
			return true
		}
	}
	return false
}

// SplitSendable separates the notices that may be sent from the count of
// vulnerability notices dropped for matching no device (HistoryResponse.suppressed).
func SplitSendable(ns []Notice) (send []Notice, suppressed int) {
	for _, n := range ns {
		if n.Sendable() {
			send = append(send, n)
		} else {
			suppressed++
		}
	}
	return send, suppressed
}

// Grouping is the batching rule (contract.ts Grouping).
type Grouping struct {
	Enabled   bool `json:"enabled"`
	WindowMin int  `json:"window_min"` // 15, 60 or 240
}

// ErrBadGrouping means the batching rule is malformed.
var ErrBadGrouping = errors.New("notify: invalid grouping window")

// Validate checks that the window is one of the allowed values.
func (g Grouping) Validate() error {
	if g.WindowMin != 15 && g.WindowMin != 60 && g.WindowMin != 240 {
		return fmt.Errorf("%w: %d (use 15, 60 or 240 minutes)", ErrBadGrouping, g.WindowMin)
	}
	return nil
}

// Batch is a set of notices that go out as one message on one channel. Build it
// with Group or GroupHeld: they filter by the channel's min_severity and by
// sendability, and Message refuses a batch that was not built that way.
type Batch struct {
	Notices []Notice
	min     Severity // the channel's min_severity; the zero value passes nothing
	link    string   // a digest of several products: the findings list (digest)
}

// ErrUnsendable means a batch holds a notice that must not go to its channel (FORBID-1, INV-4).
var ErrUnsendable = errors.New("notify: batch holds a notice that must not be sent")

// held is the window used when quiet hours end: everything held for one product goes out together.
const held = 366 * 24 * time.Hour

// Group implements INV-3 for one channel (floor is its min_severity). Notices
// that are not sendable (FORBID-1) or below floor (INV-4) are dropped first, so
// a low notice can never ride in a batch to a high-only channel. Then, with
// grouping enabled, vulnerability notices for the same product whose time is
// within WindowMin of the first notice of the batch become one batch;
// everything else is a batch of its own. A critical notice is never grouped: it
// is always its own batch, due at its own time (D-62, INV-6). Batches come out
// in the order of their first notice. An invalid window groups nothing.
func Group(ns []Notice, g Grouping, floor Severity) []Batch {
	if !g.Enabled || g.Validate() != nil {
		return group(ns, 0, floor)
	}
	return group(ns, time.Duration(g.WindowMin)*time.Minute, floor)
}

// GroupHeld groups the notices kept during quiet hours (D-57 item 8): one batch
// per product, whatever the window setting, so people get one message when the
// window ends rather than one per notice. Same filtering as Group; a critical
// notice still stays a batch of its own.
func GroupHeld(ns []Notice, floor Severity) []Batch { return group(ns, held, floor) }

func group(ns []Notice, window time.Duration, floor Severity) []Batch {
	sorted := make([]Notice, 0, len(ns))
	for _, n := range ns {
		if n.Sendable() && MeetsMin(n.Severity, floor) {
			sorted = append(sorted, n)
		}
	}
	slices.SortStableFunc(sorted, func(a, b Notice) int { return a.At.Compare(b.At) })
	var out []Batch
	open := map[string]int{} // product key -> index in out of the batch still accepting notices
	for _, n := range sorted {
		key := strings.ToLower(strings.TrimSpace(n.Product))
		if window > 0 && n.Kind == KindVuln && key != "" && n.Severity != Critical {
			if i, ok := open[key]; ok && n.At.Sub(out[i].Notices[0].At) <= window {
				out[i].Notices = append(out[i].Notices, n)
				continue
			}
			open[key] = len(out)
		}
		out = append(out, Batch{Notices: []Notice{n}, min: floor})
	}
	return out
}

// digest merges the vulnerability batches a channel sends in one run into one message (D-483, W1-19): the first matching after a
// product is added makes a burst of findings, often critical (never grouped by window, D-62), and one message each floods the chat
// and runs into the provider's rate limit. Nothing waits longer for this: only batches already due now are merged. Critical notices
// come first. Incident batches stay their own message. link is the findings list, the link of a digest of several products.
func digest(release []Batch, link string) []Batch {
	at := -1
	var notices []Notice
	var out []Batch
	for _, b := range release {
		if b.Notices[0].Kind != KindVuln {
			out = append(out, b)
			continue
		}
		if at < 0 {
			at = len(out)
			out = append(out, b)
		}
		notices = append(notices, b.Notices...)
	}
	if at < 0 || len(notices) == len(out[at].Notices) {
		return release // one vulnerability batch or none: nothing to merge
	}
	slices.SortStableFunc(notices, func(a, b Notice) int {
		if (a.Severity == Critical) != (b.Severity == Critical) {
			if a.Severity == Critical {
				return -1
			}
			return 1
		}
		return a.At.Compare(b.At)
	})
	out[at] = Batch{Notices: notices, min: out[at].min, link: link}
	return out
}

// Listed is the notices the message of the batch names one by one, in its order: at most channel.MaxItems (the message counts the
// rest in "and N more"). A chat channel may send fewer lines whole (channel.Listed); only the lines sent count as told (W1-11).
func (b Batch) Listed() []Notice {
	return b.Notices[:min(len(b.Notices), channel.MaxItems)]
}

// Told is the notices a message of the batch on channel t actually names (D-483): one notice is the message itself; of several, the
// ones whose line t sends whole (channel.Listed of msg, the message of the batch).
func (b Batch) Told(t channel.Type, msg channel.Message) []Notice {
	l := b.Listed()
	if len(b.Notices) == 1 {
		return l
	}
	return l[:min(len(l), channel.Listed(t, msg))]
}

// DueAt is when a batch opened by its first notice must be sent at the latest
// under the grouping rule: the first notice time plus the window. A critical or
// non-vulnerability notice is due at its own time. Callers compare it with the
// 60-minute bound of INV-6.
func (b Batch) DueAt(g Grouping) time.Time {
	first := b.Notices[0]
	if !g.Enabled || g.Validate() != nil || first.Kind != KindVuln || first.Severity == Critical {
		return first.At
	}
	return first.At.Add(time.Duration(g.WindowMin) * time.Minute)
}

// Severity is the highest severity in the batch.
func (b Batch) Severity() Severity {
	best := Info
	for _, n := range b.Notices {
		if n.Severity.rank() > best.rank() {
			best = n.Severity
		}
	}
	return best
}

const maxBatchDevices = 5

// Message renders the batch as one channel.Message (what, urgency, what to do
// first, link; S-ALERT-1). A single notice is passed through; several notices of
// one product become "N vulnerabilities in <product> ...", with one detail line
// per notice. Strings stay unescaped: each adapter escapes for its own target.
// It returns ErrUnsendable for an empty batch, a notice that is not sendable
// or below the channel's min_severity, or a batch not built by Group.
func (b Batch) Message() (channel.Message, error) {
	if len(b.Notices) == 0 {
		return channel.Message{}, ErrUnsendable
	}
	for _, n := range b.Notices {
		if !n.Sendable() || !MeetsMin(n.Severity, b.min) {
			return channel.Message{}, ErrUnsendable
		}
	}
	first := b.Notices[0]
	if len(b.Notices) == 1 {
		m := channel.Message{ID: first.ID, Kind: first.Kind, IncidentKind: first.IncidentKind, Severity: string(first.Severity), Title: first.Title, Device: joinDevices(first.Devices),
			Devices: deviceRefs(first.Devices, first.DeviceIDs), What: first.What, Action: first.Action, Link: first.Link}
		if first.Kind == KindVuln {
			m.Items = slices.Clone(first.CVEs)
		}
		return m, nil
	}
	var devices, items, products []string
	perProduct := map[string]int{}
	for _, n := range b.Notices {
		for _, d := range n.Devices {
			if strings.TrimSpace(d) != "" && !slices.Contains(devices, d) {
				devices = append(devices, d)
			}
		}
		p := strings.TrimSpace(n.Product)
		if perProduct[p]++; perProduct[p] == 1 {
			products = append(products, p)
		}
	}
	mixed := len(products) > 1
	listed := b.Listed()
	for _, n := range listed {
		line := strings.Join(dedupe(n.CVEs), ", ")
		if line == "" {
			line = n.Title
		}
		if mixed && strings.TrimSpace(n.Product) != "" {
			line = strings.TrimSpace(n.Product) + ": " + line
		}
		if d := joinDevices(n.Devices); d != "" {
			line += " on " + d
		}
		items = append(items, line)
	}
	more := len(b.Notices) - len(listed)
	if mixed { // a digest of a burst across products (D-483)
		var names []string
		for _, p := range products {
			c := perProduct[p]
			if p == "" {
				p = "other products"
			}
			names = append(names, fmt.Sprintf("%s (%d)", p, c))
		}
		link := b.link
		if link == "" {
			link = first.Link
		}
		return channel.Message{
			ID: first.ID, Kind: first.Kind, Severity: string(b.Severity()),
			Title:  fmt.Sprintf("%d exploited vulnerabilities match your devices", len(b.Notices)),
			Device: joinDevices(devices), Devices: deviceRefs(devices, nil),
			What:   fmt.Sprintf("%d vulnerabilities that attackers are using match devices in your network: %s.", len(b.Notices), strings.Join(names, ", ")),
			Action: "Open the findings in Vedette and start with the critical ones.", Items: items, More: more, Link: link,
		}, nil
	}
	return channel.Message{
		ID: first.ID, Kind: first.Kind, Severity: string(b.Severity()),
		Title:  fmt.Sprintf("%s: %d vulnerabilities are being exploited", first.Product, len(b.Notices)),
		Device: joinDevices(devices), Devices: deviceRefs(devices, nil),
		What:   fmt.Sprintf("%d vulnerabilities in %s are being exploited and match your devices.", len(b.Notices), first.Product),
		Action: first.Action, Items: items, More: more, Link: first.Link,
	}, nil
}

// deviceRefs pairs device names with their ids (ids may be missing).
func deviceRefs(names, ids []string) []channel.DeviceRef {
	var out []channel.DeviceRef
	for i, n := range names {
		if strings.TrimSpace(n) == "" {
			continue
		}
		r := channel.DeviceRef{Name: n}
		if i < len(ids) {
			r.ID = ids[i]
		}
		out = append(out, r)
	}
	return out
}

func joinDevices(all []string) string {
	var ds []string
	for _, d := range all {
		if strings.TrimSpace(d) != "" {
			ds = append(ds, d)
		}
	}
	if len(ds) > maxBatchDevices {
		return strings.Join(ds[:maxBatchDevices], ", ") + fmt.Sprintf(" and %d more", len(ds)-maxBatchDevices)
	}
	return strings.Join(ds, ", ")
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
