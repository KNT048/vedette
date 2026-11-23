package findings

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// ServiceConfig is what NewService needs; Publisher and Clock may be nil.
type ServiceConfig struct {
	DB        *store.DB
	Audit     *audit.Log
	Publisher Publisher // nil: no events
	Inventory Inventory
	Feeds     Feeds
	Log       *slog.Logger
	Clock     func() time.Time // nil: time.Now
	Zone      orgtime.Source   // the organization's time zone, the days of instants the API sends are in it (orgtime); nil: UTC
	// Backlog marks the context of work whose findings are backlog, not news: Reconcile writes findings of KEV entries
	// older than RecentKEV under it, and the binary makes the bus carry it to notify (backlog is silent).
	// nil: nothing is marked. findings does not know notify; the binary supplies notify.WithBaseline.
	Backlog func(ctx context.Context) context.Context
	// HaveSince maps the id of each device "I have this" on Home declared (feeds, S-FEED-2) to the product the customer
	// answered and the CISA date from which that version-less product is matched on that device (INV-11). Only
	// that one device is scoped, never the same product on other devices. nil: no such scope.
	HaveSince func(ctx context.Context) (map[string]Have, error)
	// Applied reports which of the findings have a mitigation item a person marked applied (mitigation's log): such a
	// finding counts as decided when a merge must keep one of two findings of a CVE. It reads through tx, the merge's own
	// transaction, so a merge sees what the same write changed before it. nil: none has.
	Applied func(ctx context.Context, tx *sql.Tx, findingIDs []string) (map[string]bool, error)
	// Lifecycle holds the other modules' parts of a device merge (core/lifecycle): when a merge folds two findings of one line into one,
	// their FindingFolded moves the rows they keep by finding id (mitigation, response) before the folded finding is deleted. nil: none.
	Lifecycle *lifecycle.Hooks
	// SafeCheck says whether a safe vulnerability check exists for a CVE: the binary answers from the template pack the scan
	// itself plans with (scan Pack.ForCVE), never the nuclei-templates feed flag, which is off on an offline box and lists
	// templates the pack does not ship. The Feeds port's KevInfo.HasTemplate is the same answer. nil: Vuln.HasTemplate as given.
	SafeCheck func(cve string) bool
	// Urgency is what the urgency pass rates findings with (UrgencySources); a nil Facts: the pass does not run.
	Urgency UrgencySources
}

// Have is the scope of one device declared by "I have this" (INV-11): its software of KEV key Key that has no version
// matches only the CISA entries added on or after Since.
type Have struct {
	Key   string
	Since time.Time
}

// Service owns fnd_finding, fnd_finding_event and fnd_question. Every change of a finding goes through Transition and runs in one
// transaction with its events and its core_audit row (SYS-3); bus events go out after the commit.
type Service struct {
	// rematched counts the writes whose device read differently inside the write than when its match was computed (the match was
	// computed again): a measure that a device read twice compares equal, so the hourly pass stays on its fast path.
	rematched atomic.Int64
	cfg       ServiceConfig
	now       func() time.Time
	gen       atomic.Uint64 // counts committed writes: GET /findings/overview drops its kept answer when it moves (overview.go)
	stamps    stamps        // each device's match stamp of its last full match (matchstamp.go)
}

// NewService returns the service. DB, Audit, Inventory, Feeds and Log are required.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Inventory == nil || cfg.Feeds == nil || cfg.Log == nil {
		return nil, fmt.Errorf("findings: creating service: DB, Audit, Inventory, Feeds and Log are required")
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Service{cfg: cfg, now: now}, nil
}

// publishTimeout bounds the delivery of the events of one committed change.
const publishTimeout = 5 * time.Second

// eventWriteTimeout bounds how long a handler of an incoming event (OnMatchChanged) waits for the one writer. The bus gives a
// handler 5 s, but a long write elsewhere (the first KEV pull) holds the writer longer, and an event that failed at "store: begin:
// context deadline exceeded" is not delivered again. So these handlers run on their own deadline, cut loose from the bus's (a caller
// that really goes away, on shutdown, is still cut at this bound).
const eventWriteTimeout = time.Minute

func eventContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), eventWriteTimeout)
}

type event struct {
	name    string
	payload any
}

// write runs fn in a write transaction, then publishes the events fn collected.
func (s *Service) write(ctx context.Context, fn func(tx *sql.Tx, now time.Time, emit func(name string, payload any)) error) error {
	var events []event
	err := s.cfg.DB.Write(ctx, func(tx *sql.Tx) error {
		events = events[:0]
		return fn(tx, s.now().UTC().Truncate(time.Millisecond), func(name string, payload any) { events = append(events, event{name, payload}) })
	})
	if err != nil {
		return err
	}
	s.gen.Add(1)
	if s.cfg.Publisher == nil {
		return nil
	}
	// The change is committed: the events go out even if the caller has hung up, within a short deadline.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	for _, e := range events {
		if err := s.cfg.Publisher.Publish(pctx, e.name, e.payload); err != nil {
			s.cfg.Log.ErrorContext(pctx, "publishing a findings event failed", "event", e.name, "error", err)
		}
	}
	return nil
}

// step runs one trigger on one finding inside tx: Transition, the row and its events, an audit row for what a person or Vedette
// decided, and the bus events of the older read model. isNew says f has no row yet.
func (s *Service) step(ctx context.Context, tx *sql.Tx, f Finding, isNew bool, t Trigger, emit func(string, any)) (Finding, []Event, error) {
	g, evs, err := apply(ctx, tx, f, isNew, t)
	if err != nil || len(evs) == 0 {
		return g, evs, err
	}
	for _, e := range evs {
		action, detail := auditOf(g, e)
		if action == "" {
			continue
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: e.Actor, Action: action, Target: g.ID, Detail: detail}); err != nil {
			return f, nil, err
		}
	}
	if isNew {
		return g, evs, nil // the caller announces a new finding (CreatedEvent)
	}
	if e, ok := legacyEvent(f, g, evs); ok && Announced(g) && !raised(f, g) { // a rise: one notice, the caller's
		emit(EventStatusChanged, e)
	}
	return g, evs, nil
}

// auditOf is the audit row of one event: what a person did, and what Vedette decided by itself about the handling. "" for the
// rest (urgency, fix, detection edges: the finding's own history holds them).
func auditOf(f Finding, e Event) (action, detail string) {
	d := e.Detail
	switch e.Kind {
	case EvCreated:
		return "findings.created", f.CVE + ", basis " + string(f.Basis)
	case EvHandled:
		detail = f.CVE + ": " + string(d.Resolution) + " via " + string(d.Via)
		if d.FromVersion != "" {
			detail += " (" + d.FromVersion + " → " + d.ToVersion + ")"
		}
		if d.AcceptedUntil != "" {
			detail += " until " + d.AcceptedUntil
		}
		if d.Note != "" {
			detail += ": " + d.Note
		}
		return "findings.status", detail
	case EvReopened:
		detail = f.CVE + ": reopened (" + d.Why + ")"
		if d.Note != "" {
			detail += ": " + d.Note
		}
		return "findings.status", detail
	case EvAcceptanceExpire:
		return "findings.status", f.CVE + ": risk acceptance by " + d.From + " until " + d.AcceptedUntil + " expired"
	case EvConfirmed:
		if e.Actor != SystemUser {
			return "findings.confirm", f.CVE + ": confirmed by " + e.Actor + ": " + d.Note
		}
	case EvUnconfirmed:
		if e.Actor != SystemUser {
			return "findings.unconfirm", f.CVE + ": confirmation undone by " + e.Actor
		}
	}
	return "", ""
}

// Get returns one finding in the older read model, or an error wrapping ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	f, err := loadFinding(ctx, s.cfg.DB.Reader(), id)
	if err != nil {
		return Record{}, err
	}
	recs, err := s.records(ctx, s.cfg.DB.Reader(), []Finding{f}, "f.id = ?", id)
	if err != nil {
		return Record{}, err
	}
	return recs[0], nil
}

// List returns the findings of one device, or of every device when assetID is empty, newest first, in the older read model.
func (s *Service) List(ctx context.Context, assetID string) ([]Record, error) {
	q := s.cfg.DB.Reader()
	fs, err := findingsOf(ctx, q, assetID)
	if err != nil {
		return nil, err
	}
	return s.records(ctx, q, fs, "(?1 = '' OR f.asset_id = ?1)", assetID)
}

// Finding returns one finding, or an error wrapping ErrNotFound.
func (s *Service) Finding(ctx context.Context, id string) (Finding, error) {
	return loadFinding(ctx, s.cfg.DB.Reader(), id)
}

// Findings returns the findings of one device, or of every device when assetID is "", newest first.
func (s *Service) Findings(ctx context.Context, assetID string) ([]Finding, error) {
	return findingsOf(ctx, s.cfg.DB.Reader(), assetID)
}

// Events returns the history of one finding, oldest first.
func (s *Service) Events(ctx context.Context, id string) ([]Event, error) {
	m, err := eventsOf(ctx, s.cfg.DB.Reader(), "f.id = ?", id)
	return m[id], err
}

// Questions returns the questions of one device, or of every device when assetID is "".
func (s *Service) Questions(ctx context.Context, assetID string) ([]Question, error) {
	return questionsOf(ctx, s.cfg.DB.Reader(), assetID)
}

// records projects findings into the older read model, with their events (selected by where on fnd_finding f) and the CVSS band.
func (s *Service) records(ctx context.Context, q querier, fs []Finding, where string, args ...any) ([]Record, error) {
	if len(fs) == 0 {
		return nil, nil
	}
	evs, err := eventsOf(ctx, q, where, args...)
	if err != nil {
		return nil, err
	}
	cves := make([]string, 0, len(fs))
	for _, f := range fs {
		cves = append(cves, f.CVE)
	}
	slices.Sort(cves)
	scores, err := s.cfg.Feeds.CVSS(ctx, slices.Compact(cves))
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: reading the CVSS scores", "error", err)
		scores = nil
	}
	out := make([]Record, len(fs))
	for i, f := range fs {
		var band Severity
		if c, ok := scores[f.CVE]; ok {
			band = bandOf(c)
		}
		out[i] = record(f, evs[f.ID], band)
	}
	return out, nil
}

// ignoredDevices is the set of devices a person ignored: their findings stay as they are, and every reader of open findings leaves
// them out (an attribute of the device, never a change of its findings).
func (s *Service) ignoredDevices(ctx context.Context) (map[string]bool, error) {
	ids, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the ignored devices: %w", err)
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// CountByAsset returns how many findings each device has, every state included: the number inventory shows as findings_count, which
// is also what deleting the device deletes (DeviceDeleted). One grouped read; a device with none is absent.
func (s *Service) CountByAsset(ctx context.Context) (map[string]int, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT asset_id, count(*) FROM fnd_finding GROUP BY asset_id`)
	if err != nil {
		return nil, fmt.Errorf("findings: count by asset: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("findings: count by asset: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// UpsertResult says what one match write did.
type UpsertResult struct {
	Created []string // ids of the findings created
	Touched int      // findings detected again (open or handled)
	// Closed counts the findings Vedette handled because the data no longer detects them (patched or corrected).
	Closed int
	// Reopened counts the findings that opened again (detected again after Vedette closed them, or still detected after a person
	// marked them patched).
	Reopened int
	// Questions counts the questions the device has after the write.
	Questions int
}

// OnMatchChanged handles inventory.match.changed: it reads the device and the exploited list and matches them (PRE-1). An unknown
// device is ErrUnknownAsset.
func (s *Service) OnMatchChanged(ctx context.Context, assetID string) (UpsertResult, error) {
	ctx, cancel := eventContext(ctx)
	defer cancel()
	a, ok, err := s.cfg.Inventory.MatchInput(ctx, assetID)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("findings: reading the device to match: %w", err)
	}
	if !ok {
		return UpsertResult{}, fmt.Errorf("findings: matching device %q: %w", assetID, ErrUnknownAsset)
	}
	pinned, err := s.pinnedCVEs(ctx, assetID)
	if err != nil {
		return UpsertResult{}, err
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope([]Asset{a}, pinned))
	if err != nil {
		return UpsertResult{}, fmt.Errorf("findings: reading the catalogue: %w", err)
	}
	set := newMatchSet(vulns)
	dev := set.forDevice(a)
	a.winList = dev
	res, err := s.upsert(ctx, a, dev, cveSet(vulns), nil, true)
	if err != nil {
		return res, err
	}
	// The device's findings are rated at once: one this write created enters its layer as news (a new finding is recent).
	if _, err := s.RateUrgency(ctx, assetID); err != nil {
		return res, err
	}
	return res, nil
}

// UpsertFromMatch matches the device's software against vulns and writes the result through Transition (applyMatch): a detected
// (CVE, software line) is created or detected again, a finding of a CVE of vulns that is no longer detected goes away the way the
// data says (patched with credit, or corrected), and the device's questions are rewritten.
func (s *Service) UpsertFromMatch(ctx context.Context, a Asset, vulns []Vuln) (UpsertResult, error) {
	return s.upsert(ctx, a, vulns, cveSet(vulns), nil, false)
}

// upsert is UpsertFromMatch. whole, when not nil, is the match of the whole exploited list, whose questions the device's become
// instead of the ones this vulns list gives: Reconcile writes the backlog and the recent entries in two writes, each of which
// replaces them.
func (s *Service) upsert(ctx context.Context, a Asset, vulns []Vuln, judged map[string]bool, whole *MatchResult, reread bool) (UpsertResult, error) {
	return s.upsertPart(ctx, a, vulns, judged, whole, reread, nil)
}

// partMatch is the device's readings of the whole list (devMatch) and the entries of it a write compares (vulns of upsertPart).
type partMatch struct {
	dm  *devMatch
	idx []int
	// Set by the write: wrote (it ran: the device was neither ignored nor gone), changed (the device read differently inside it, so
	// its match was computed again for the newer reading) and rows (the device's findings and questions as the write left them).
	wrote, changed bool
	rows           deviceRows
}

// match is MatchAsset(a, vulns, have, now) for the part, from the readings already made (the part's vulns are dm's entries idx and
// the device is dm's).
func (p *partMatch) match(have map[string]bool) MatchResult {
	idx := p.idx
	if idx == nil {
		idx = []int{} // an empty part matches nothing (result reads nil as the whole list)
	}
	return p.dm.result(idx, have)
}

// upsertPart is upsert; pre, when not nil, holds the readings the device's match of vulns is assembled from instead of matching again
// (the match pass reads every entry once for its two writes and its questions). The device read again inside the write (reread) is
// matched afresh when it changed.
func (s *Service) upsertPart(ctx context.Context, a Asset, vulns []Vuln, judged map[string]bool, whole *MatchResult, reread bool, pre *partMatch) (UpsertResult, error) {
	var since map[string]Have
	if s.cfg.HaveSince != nil {
		var err error
		if since, err = s.cfg.HaveSince(ctx); err != nil {
			return UpsertResult{}, fmt.Errorf("findings: reading the products answered on Home: %w", err)
		}
	}
	haveOf := func(fs []Finding) map[string]bool {
		out := make(map[string]bool, len(fs))
		for _, f := range fs {
			out[f.CVE] = true
		}
		return out
	}
	// The match is computed before the write, against the findings the device has now, so the writer is held only for the writing;
	// a finding created meanwhile (a safe check) makes the write compute it again.
	before, err := findingsOf(ctx, s.cfg.DB.Reader(), a.ID)
	if err != nil {
		return UpsertResult{}, err
	}
	haveBefore := haveOf(before)
	var matched MatchResult
	if pre != nil {
		matched = pre.match(haveBefore)
	} else {
		matched = MatchAsset(a, vulns, haveBefore, s.now())
	}
	var res UpsertResult
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		res = UpsertResult{}
		// A match read before a person ignored the device writes nothing; asked inside the write.
		if ig, err := s.cfg.Inventory.IsIgnored(ctx, a.ID); err != nil {
			return fmt.Errorf("findings: reading whether the device is ignored: %w", err)
		} else if ig {
			return nil
		}
		// The device as the inventory holds it now: no inventory write can commit while this write runs, so a reading that arrived
		// after the match was computed (a device that reported its update meanwhile) is matched here, never overwritten by an older one.
		changed := false
		if reread {
			fresh, ok, err := s.cfg.Inventory.MatchInput(ctx, a.ID)
			if err != nil {
				return fmt.Errorf("findings: reading the device: %w", err)
			}
			if !ok {
				return nil // deleted (or ignored) since the match was computed
			}
			fresh.winList = a.winList
			if changed = !reflect.DeepEqual(fresh, a); changed {
				a = fresh // its entries stay the ones read for the older reading: a product it did not run waits for the next pass
			}
		}
		// findings on a line inventory gave to another device go with it, before the device's findings are read (followline.go)
		if err := s.followLines(ctx, tx, a); err != nil {
			return err
		}
		existing, err := findingsOf(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		have := haveOf(existing)
		switch {
		case !changed && !maps.Equal(have, haveBefore) && pre != nil:
			matched = pre.match(have)
		case changed || !maps.Equal(have, haveBefore):
			matched = MatchAsset(a, vulns, have, now)
		}
		if changed {
			s.rematched.Add(1)
			// the entries were chosen for the older reading: only the CVEs this write compares are judged (a CVE another device
			// brought into the set never closes a finding this reading may make), and the questions are those of the whole match
			mine := cveSet(vulns)
			judged = maps.Clone(judged)
			maps.DeleteFunc(judged, func(c string, _ bool) bool { return !mine[c] })
			if whole != nil {
				w := MatchAsset(a, a.winList, nil, now)
				whole = &w
			}
		}
		m := haveScope(a, vulns, matched, since, have, now)
		qm := m
		if whole != nil {
			qm = *whole
		}
		r, err := s.applyMatch(ctx, tx, a, vulns, judged, m, qm, existing, now, emit)
		res = r
		if err != nil || pre == nil {
			return err
		}
		rows, err := readDeviceRows(ctx, tx, a.ID)
		pre.wrote, pre.changed, pre.rows = err == nil, changed, rows
		return err
	})
	if err != nil {
		return UpsertResult{}, err
	}
	return res, nil
}

// haveScope drops the matches that "I have this" on Home does not cover (INV-11). On the one device "I have this"
// declared, a software row with no version and the answered KEV key is matched only against CISA entries added on or
// after the scope's date: older entries are not the customer's to handle unless they type the version, and then the
// version decides. Every other device, and every other row of that device, is matched as usual. An entry with no known
// date is kept. The matcher itself is unchanged; this is the customer's own scope.
//
// The matcher gives a version-less row no finding per CVE (only the "add the version" item). "I have this" is the
// customer asking to be alerted about this product without a version, so on the declared device the entries of the
// answered key from the scope's date on (or with no date) become product findings (medium) again; the older ones stay
// in the item only.
func haveScope(a Asset, vulns []Vuln, m MatchResult, since map[string]Have, have map[string]bool, now time.Time) MatchResult {
	h, ok := since[a.ID]
	if !ok {
		return m
	}
	key := productid.NormalizeKey(h.Key)
	scoped := map[string]Software{} // software rows under the scope
	for _, sw := range a.Software {
		if strings.TrimSpace(sw.Version) != "" {
			continue
		}
		for _, k := range sw.KevKeys {
			if productid.NormalizeKey(k) == key {
				scoped[sw.ID] = sw
			}
		}
	}
	if len(scoped) == 0 {
		return m
	}
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		byCVE[v.CVE] = v
	}
	inScope := func(sw, cve string) bool {
		_, ok := scoped[sw]
		d := byCVE[cve].DateAdded
		return ok && (d.IsZero() || !d.Before(h.Since))
	}
	keep := func(ms []Match) []Match {
		out := ms[:0:0]
		for _, x := range ms {
			if _, ok := scoped[x.SoftwareID]; ok && !inScope(x.SoftwareID, x.CVE) {
				continue
			}
			out = append(out, x)
		}
		return out
	}
	out := MatchResult{New: keep(m.New), Existing: keep(m.Existing), NeedVersion: m.NeedVersion, NotAffected: m.NotAffected, Unlisted: m.Unlisted, Retired: m.Retired, Aged: m.Aged,
		Unchecked: m.Unchecked, Asked: m.Asked}
	taken := map[string]bool{}
	for _, x := range append(append([]Match{}, out.New...), out.Existing...) {
		taken[x.CVE] = true
	}
	// A scoped version-less row whose CVE no version could decide is name-only; the customer asked to be
	// told about it, so it is listed like the "add the version" ones below, and not closed
	var asked []VersionNeeded
	for _, x := range m.NameOnly {
		if _, ok := scoped[x.SoftwareID]; ok && inScope(x.SoftwareID, x.CVE) && !taken[x.CVE] {
			asked = append(asked, VersionNeeded{SoftwareID: x.SoftwareID, CVEs: []string{x.CVE}})
			continue
		}
		out.NameOnly = append(out.NameOnly, x)
	}
	for _, x := range slices.Concat(m.Aged, out.NameOnly) { // dropped on another row of the same product; not re-added here (#803)
		taken[x.CVE] = true
	}
	name := clean(a.Name)
	for _, n := range slices.Concat(m.NeedVersion, asked) {
		for _, cve := range n.CVEs {
			if taken[cve] || !inScope(n.SoftwareID, cve) {
				continue
			}
			taken[cve] = true
			sw := clean(scoped[n.SoftwareID].Display)
			x := Match{CVE: cve, SoftwareID: n.SoftwareID, SoftwareDisplay: sw, Basis: BasisProduct, Confidence: ConfProduct, Severity: SeverityMedium,
				Evidence: Evidence{CheckedAt: now, Summary: fmt.Sprintf("%s runs %s, version not given. You asked on Home to be told about this product, so this new exploited entry is listed; add the version to check it.", name, sw)}}
			if have[cve] {
				out.Existing = append(out.Existing, x)
			} else {
				out.New = append(out.New, x)
			}
		}
	}
	return out
}

// ConfirmFromScan records a positive safe check for a CVE on a device (PRE-2). The check is about the software line the CVE is on
// (scanLine: the line the matcher reads the entry on, when the device has one): that line's finding is detected with basis scan,
// verified scan, at the version the line reads now; a finding on no line takes the line; a device with no such line gets a finding on
// no line. The scan's evidence is checked and truncated like any untrusted reply. It returns the finding in the older read model.
func (s *Service) ConfirmFromScan(ctx context.Context, assetID, cve string, ev Evidence) (Record, error) {
	if !ValidCVE(cve) {
		return Record{}, fmt.Errorf("findings: confirming from scan: %w", ErrInvalidCVE)
	}
	if ev.Template == "" || len(ev.Template) > maxTemplate || !isText(ev.Template, ev.Summary, ev.Request, ev.Response) {
		return Record{}, fmt.Errorf("findings: confirming from scan: %w", ErrInvalidEvidence)
	}
	ev.Summary, ev.Request, ev.Response = truncate(ev.Summary), truncate(ev.Request), truncate(ev.Response)
	line, version, productKey, err := s.scanLine(ctx, assetID, cve)
	if err != nil {
		return Record{}, err
	}
	urgency := UrgencyUpdate
	if kev, err := s.cfg.Feeds.KevInfo(ctx, []string{cve}); err != nil {
		return Record{}, fmt.Errorf("findings: reading the exploited lists: %w", err)
	} else if _, ok := kev[cve]; ok {
		urgency = UrgencyExploited
	}
	var id string
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		// A scan that started before a person ignored the device confirms nothing on it
		if ig, err := s.cfg.Inventory.IsIgnored(ctx, assetID); err != nil {
			return fmt.Errorf("findings: reading whether the device is ignored: %w", err)
		} else if ig {
			return nil
		}
		if ev.CheckedAt.IsZero() {
			ev.CheckedAt = now
		}
		fs, err := queryFindings(ctx, tx, `asset_id = ? AND cve = ?`, assetID, cve)
		if err != nil {
			return err
		}
		var onLine, noLine *Finding
		for i := range fs {
			switch fs[i].SoftwareID {
			case line:
				onLine = &fs[i]
			case "":
				noLine = &fs[i]
			}
		}
		var f Finding
		isNew := false
		switch {
		case onLine != nil && noLine != nil && line != "":
			if f, err = s.absorbNoLine(ctx, tx, *noLine, *onLine); err != nil {
				return err
			}
		case onLine != nil:
			f = *onLine
		case noLine != nil:
			f = *noLine // it takes the line, when there is one (TrDetected)
		case line == "" && len(fs) > 0:
			f = fs[0] // the matcher names no line for the CVE: the finding the device has
		default:
			known, err := s.cfg.Inventory.Assets(ctx, []string{assetID})
			if err != nil {
				return fmt.Errorf("findings: reading the device: %w", err)
			}
			if _, ok := known[assetID]; !ok {
				return fmt.Errorf("findings: confirming from scan on device %q: %w", assetID, ErrUnknownAsset)
			}
			f, isNew = Finding{ID: store.NewID("f"), AssetID: assetID, CVE: cve}, true
		}
		e := ev
		d := Detection{SoftwareID: line, Basis: DetectScan, Verified: VerifiedScan, RangeOrigin: RangeScan, MatchedVersion: version,
			Evidence: &e, ReadAt: ev.CheckedAt, Urgency: urgency}
		if !isNew {
			d.RangeOrigin = f.RangeOrigin
			if s.rates() {
				d.Urgency = 0 // the urgency pass that follows rates and tells a rise
			}
		} else {
			d.ProductKey = productKey
		}
		g, _, err := s.step(ctx, tx, f, isNew, Trigger{Kind: TrDetected, At: now, Detection: d}, emit)
		if err != nil {
			return err
		}
		switch {
		case isNew && Announced(g):
			emit(EventCreated, CreatedEvent{FindingID: g.ID, AssetID: g.AssetID, CVE: g.CVE, Severity: SeverityHigh, Basis: BasisScan})
		case !isNew && raised(f, g): // its CVE joined an exploited list since it was made: one alert of the rise
			emit(EventUrgencyRaised, raisedEvent(f, g, SeverityHigh))
		}
		id = g.ID
		return nil
	})
	if err != nil {
		return Record{}, err
	}
	if id == "" {
		return Record{}, nil
	}
	if _, err := s.RateUrgency(ctx, assetID); err != nil { // the check is saved: its record is the answer; the hourly pass rates it
		s.cfg.Log.WarnContext(ctx, "findings: rating urgency after a safe check failed", "device", assetID, "error", err)
	}
	return s.Get(ctx, id)
}

// scanLine is the software line of the device a safe check of the CVE is about: the line the matcher reads the entry on (a match,
// a proof, or a row it could not decide), with the version it matches on now (the package release when the line has one) and its
// product. "" when the device has none, or the entry is not on the exploited list.
func (s *Service) scanLine(ctx context.Context, assetID, cve string) (line, version, product string, err error) {
	a, m, ok, err := s.matchOne(ctx, assetID, cve)
	if err != nil || !ok {
		return "", "", "", err
	}
	var ids []string
	for _, x := range slices.Concat(m.New, m.Existing) {
		ids = append(ids, x.SoftwareID)
		for _, l := range x.Lines {
			ids = append(ids, l.SoftwareID)
		}
	}
	for _, x := range slices.Concat(m.NotAffected, m.NameOnly, m.Aged, m.Unlisted, m.Asked) {
		ids = append(ids, x.SoftwareID)
	}
	for _, n := range m.NeedVersion {
		ids = append(ids, n.SoftwareID)
	}
	lines := deviceLines(a)
	for _, id := range ids {
		if l, ok := lines[storedLine(id)]; ok && storedLine(id) != "" {
			v := l.reading.Version
			if l.reading.Pkg != "" {
				v = l.reading.Pkg
			}
			return l.sw.ID, v, productKey(l.sw), nil
		}
	}
	return "", "", "", nil
}

// matchOne matches the device against one entry of the exploited list, as if the device had a finding of it (so a proof names its
// line too); a Windows build's month is read from the whole list. ok is false when the device is gone or ignored, or the entry is
// not on the list.
func (s *Service) matchOne(ctx context.Context, assetID, cve string) (Asset, MatchResult, bool, error) {
	a, ok, err := s.cfg.Inventory.MatchInput(ctx, assetID)
	if err != nil {
		return Asset{}, MatchResult{}, false, fmt.Errorf("findings: reading the device: %w", err)
	}
	if !ok {
		return Asset{}, MatchResult{}, false, nil
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope([]Asset{a}, []string{cve}))
	if err != nil {
		return Asset{}, MatchResult{}, false, fmt.Errorf("findings: reading the catalogue: %w", err)
	}
	dev := newMatchSet(vulns).forDevice(a)
	i := slices.IndexFunc(dev, func(v Vuln) bool { return v.CVE == cve })
	if i < 0 {
		return Asset{}, MatchResult{}, false, nil
	}
	a.winList = dev
	return a, MatchAsset(a, dev[i:i+1], map[string]bool{cve: true}, s.now()), true, nil
}

// Handle marks findings of one device handled by a person, with one note (POST /findings/handle): all of ids must be findings of one
// device (else ErrManyDevices). A finding that already has this handling is skipped. One event and one audit row per finding, all
// or nothing.
func (s *Service) Handle(ctx context.Context, ids []string, res Resolution, note string, until time.Time, user string) (handled, skipped int, err error) {
	if err := ValidUser(user); err != nil {
		return 0, 0, err
	}
	uniq := uniqueIDs(ids)
	if len(uniq) == 0 || len(uniq) > MaxBulk {
		return 0, 0, ErrTooMany
	}
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		handled, skipped = 0, 0
		device := ""
		for _, id := range uniq {
			f, err := loadFinding(ctx, tx, id)
			if err != nil {
				return err
			}
			if device != "" && f.AssetID != device {
				return ErrManyDevices
			}
			device = f.AssetID
			_, evs, err := s.step(ctx, tx, f, false, Trigger{Kind: TrHandle, At: now, Actor: user, Resolution: res, Note: note, Until: until}, emit)
			if err != nil {
				return err
			}
			if len(evs) == 0 {
				skipped++
				continue
			}
			handled++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return handled, skipped, nil
}

// Reopen opens a handled finding again on a person's word (their handling was a mistake).
func (s *Service) Reopen(ctx context.Context, id, note, user string) (Finding, error) {
	return s.personStep(ctx, id, Trigger{Kind: TrReopen, Actor: user, Note: note})
}

// Verify confirms a finding that is not confirmed yet on a person's word; the note says what makes them sure. No bus event: a
// person's own click sends no notice and starts no response.
func (s *Service) Verify(ctx context.Context, id, note, user string) (Finding, error) {
	return s.personStep(ctx, id, Trigger{Kind: TrVerify, Actor: user, Note: note})
}

// Unverify takes back a person's own confirmation.
func (s *Service) Unverify(ctx context.Context, id, user string) (Finding, error) {
	return s.personStep(ctx, id, Trigger{Kind: TrUnverify, Actor: user})
}

// personStep runs a person's trigger on one finding in a write of its own.
func (s *Service) personStep(ctx context.Context, id string, t Trigger) (Finding, error) {
	if err := ValidUser(t.Actor); err != nil {
		return Finding{}, err
	}
	var out Finding
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		f, err := loadFinding(ctx, tx, id)
		if err != nil {
			return err
		}
		t.At = now
		quiet := func(string, any) {}
		if t.Kind == TrReopen {
			quiet = emit
		}
		out, _, err = s.step(ctx, tx, f, false, t, quiet)
		return err
	})
	return out, err
}

// MaxBulk is how many findings one handle request may touch: a filtered list of a few hundred findings fits, and the one write
// transaction stays short.
const MaxBulk = 500

// ErrTooMany is a bulk change that names more than MaxBulk findings, or none (the API's 400 invalid).
var ErrTooMany = &APIError{"invalid", 400, fmt.Sprintf("Select between 1 and %d findings.", MaxBulk)}

// ErrManyDevices is a handle request whose findings are on more than one device: handling always applies to one device.
var ErrManyDevices = &APIError{"many_devices", 400, "Handle the findings of one device at a time."}

func uniqueIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
