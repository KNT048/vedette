package notify

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kiennt048/vedette/modules/notify/channel"
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
	Devices  []string // names of the matched devices (vulnerability: at least one)
	Title    string   // one plain sentence
	What     string   // what happened and how urgent
	Action   string   // what to do first
	Link     string   // absolute URL of the finding or incident in Vedette
	At       time.Time
}

// Sendable implements INV-2: a vulnerability notice without a matched device is
// never sent (FORBID-1). Other kinds are always sendable.
func (n Notice) Sendable() bool { return n.Kind != KindVuln || len(n.Devices) > 0 }

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
	Enabled   bool
	WindowMin int // 15, 60 or 240
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

// Batch is a set of notices that go out as one message.
type Batch struct{ Notices []Notice }

// held is the window used when quiet hours end: everything held for one product goes out together.
const held = 366 * 24 * time.Hour

// Group implements INV-3. With grouping enabled, vulnerability notices for the
// same product whose time is within WindowMin of the first notice of the batch
// become one batch; everything else is a batch of its own. Batches come out in
// the order of their first notice. An invalid window groups nothing.
func Group(ns []Notice, g Grouping) []Batch {
	if !g.Enabled || g.Validate() != nil {
		return group(ns, 0)
	}
	return group(ns, time.Duration(g.WindowMin)*time.Minute)
}

// GroupHeld groups the notices kept during quiet hours (D-57 item 8): one batch
// per product, whatever the window setting, so people get one message when the
// window ends rather than one per notice.
func GroupHeld(ns []Notice) []Batch { return group(ns, held) }

func group(ns []Notice, window time.Duration) []Batch {
	sorted := slices.Clone(ns)
	slices.SortStableFunc(sorted, func(a, b Notice) int { return a.At.Compare(b.At) })
	var out []Batch
	open := map[string]int{} // product key -> index in out of the batch still accepting notices
	for _, n := range sorted {
		key := strings.ToLower(strings.TrimSpace(n.Product))
		if window > 0 && n.Kind == KindVuln && key != "" {
			if i, ok := open[key]; ok && n.At.Sub(out[i].Notices[0].At) <= window {
				out[i].Notices = append(out[i].Notices, n)
				continue
			}
			open[key] = len(out)
		}
		out = append(out, Batch{Notices: []Notice{n}})
	}
	return out
}

// DueAt is when a batch opened by its first notice must be sent at the latest
// under the grouping rule: the first notice time plus the window. Callers
// compare it with the 60-minute bound of INV-6.
func (b Batch) DueAt(g Grouping) time.Time {
	first := b.Notices[0].At
	if !g.Enabled || g.Validate() != nil || b.Notices[0].Kind != KindVuln {
		return first
	}
	return first.Add(time.Duration(g.WindowMin) * time.Minute)
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
func (b Batch) Message() channel.Message {
	first := b.Notices[0]
	if len(b.Notices) == 1 {
		m := channel.Message{ID: first.ID, Kind: first.Kind, Severity: string(first.Severity), Title: first.Title, Device: joinDevices(first.Devices),
			What: first.What, Action: first.Action, Link: first.Link}
		if first.Kind == KindVuln {
			m.Items = slices.Clone(first.CVEs)
		}
		return m
	}
	var devices, items []string
	for _, n := range b.Notices {
		for _, d := range n.Devices {
			if !slices.Contains(devices, d) {
				devices = append(devices, d)
			}
		}
		cves := dedupe(n.CVEs)
		line := strings.Join(cves, ", ")
		if line == "" {
			line = n.Title
		}
		if len(n.Devices) > 0 {
			line += " on " + joinDevices(n.Devices)
		}
		items = append(items, line)
	}
	return channel.Message{
		ID: first.ID, Kind: first.Kind, Severity: string(b.Severity()),
		Title:  fmt.Sprintf("%s: %d vulnerabilities are being exploited", first.Product, len(b.Notices)),
		Device: joinDevices(devices),
		What:   fmt.Sprintf("%d vulnerabilities in %s are being exploited and match your devices.", len(b.Notices), first.Product),
		Action: first.Action, Items: items, Link: first.Link,
	}
}

func joinDevices(ds []string) string {
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
