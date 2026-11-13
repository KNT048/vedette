package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
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
	// Backlog marks the context of work whose findings are backlog, not news: Reconcile writes findings of KEV entries
	// older than RecentKEV under it, and the binary makes the bus carry it to notify (D-78: backlog is silent).
	// nil: nothing is marked. findings does not know notify; the binary supplies notify.WithBaseline.
	Backlog func(ctx context.Context) context.Context
	// HaveSince maps the id of each device "I have this" on Home declared (feeds, S-FEED-2) to the product the customer
	// answered and the CISA date from which that version-less product is matched on that device (INV-11, D-484). Only
	// that one device is scoped, never the same product on other devices. nil: no such scope.
	HaveSince func(ctx context.Context) (map[string]Have, error)
}

// Have is the scope of one device declared by "I have this" (INV-11): its software of KEV key Key that has no version
// matches only the CISA entries added on or after Since.
type Have struct {
	Key   string
	Since time.Time
}

// Service owns fnd_finding and fnd_finding_history. Every mutation runs in one transaction with its
// history rows and its core_audit row (SYS-3); events go out after the commit.
type Service struct {
	cfg ServiceConfig
	now func() time.Time
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

// eventWriteTimeout bounds how long a handler of an incoming event (OnMatchChanged, OnAssetDeleted) waits for the one
// writer. The bus gives a handler 5 s, but a long write elsewhere (the first KEV pull) holds the writer longer, and an
// event that failed at "store: begin: context deadline exceeded" is not delivered again: the finding would never be
// created, or the findings of a deleted device would stay. So these handlers run on their own deadline, cut loose from
// the bus's (a caller that really goes away, on shutdown, is still cut at this bound).
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

// Get returns one finding, or an error wrapping ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (Record, error) {
	return loadByID(ctx, s.cfg.DB.Reader(), id)
}

// CountByAsset returns how many findings each asset has, every status included: the number inventory shows as findings_count, which
// is also what deleting the device deletes (OnAssetDeleted). One grouped read; an asset with none is absent.
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

// List returns the findings of one asset, or of every asset when assetID is empty, newest first.
func (s *Service) List(ctx context.Context, assetID string) ([]Record, error) {
	return listRecords(ctx, s.cfg.DB.Reader(), assetID)
}

// UpsertResult says what an upsert did.
type UpsertResult struct {
	Created []string // ids of the findings created
	Touched int      // findings that already existed (open or closed) and only had last_seen refreshed
}

// OnMatchChanged handles inventory.match.changed: it reads the device and the exploited list and
// matches them (PRE-1). An unknown device is ErrUnknownAsset.
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
	vulns, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("findings: reading the exploited list: %w", err)
	}
	return s.UpsertFromMatch(ctx, a, vulns)
}

// UpsertFromMatch matches the device's software against vulns and writes the result (INV-6, POST-1):
// a new pair becomes a suspected finding with its "created" history row and a
// findings.finding.created event; a pair that already exists, open or closed, is never created again
// or reopened: it only gets last_seen refreshed and, if open, a stronger basis (product to version).
// The matcher only adds, never removes.
func (s *Service) UpsertFromMatch(ctx context.Context, a Asset, vulns []Vuln) (UpsertResult, error) {
	var since map[string]Have
	if s.cfg.HaveSince != nil {
		var err error
		if since, err = s.cfg.HaveSince(ctx); err != nil {
			return UpsertResult{}, fmt.Errorf("findings: reading the products answered on Home: %w", err)
		}
	}
	var res UpsertResult
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		res = UpsertResult{}
		have, err := cvesOfAsset(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		m := haveScope(a, vulns, MatchAsset(a, vulns, haveSet(have), now), since)
		for _, nm := range m.New {
			f, h := NewFinding(nm, now)
			if err := f.Validate(); err != nil {
				return fmt.Errorf("findings: new finding for %s: %w", nm.CVE, err)
			}
			r := Record{ID: store.NewID("f"), AssetID: a.ID, CVE: nm.CVE, Finding: f, FirstSeen: now, LastSeen: now}
			if err := insertRecord(ctx, tx, r); err != nil {
				return err
			}
			if err := insertHistory(ctx, tx, r.ID, h); err != nil {
				return err
			}
			if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.created", Target: r.ID,
				Detail: fmt.Sprintf("%s on %s, basis %s, %s", r.CVE, r.AssetID, r.Basis, r.Severity)}); err != nil {
				return err
			}
			emit(EventCreated, CreatedEvent{FindingID: r.ID, AssetID: r.AssetID, CVE: r.CVE, Severity: r.Severity, Basis: r.Basis})
			res.Created = append(res.Created, r.ID)
		}
		for _, em := range m.Existing {
			r, err := loadByPair(ctx, tx, a.ID, em.CVE)
			if err != nil {
				return err
			}
			before := r.Finding
			r.Finding = r.ApplyMatch(em)
			r.LastSeen = now
			if err := r.Validate(); err != nil {
				return fmt.Errorf("findings: finding %s after a repeated match: %w", r.ID, err)
			}
			if err := updateRecord(ctx, tx, r); err != nil {
				return err
			}
			if r.Basis != before.Basis {
				if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.basis_raised", Target: r.ID,
					Detail: fmt.Sprintf("%s: %s to %s", r.CVE, before.Basis, r.Basis)}); err != nil {
					return err
				}
			}
			if n := len(r.History); n > 0 && r.History[n-1].Action == "no_longer_matches" { // matches again: the newest line must not say otherwise
				if err := insertHistory(ctx, tx, r.ID, HistoryEntry{TS: now, User: SystemUser, Action: "matches_again", Note: "The device matches this entry again."}); err != nil {
					return err
				}
				if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.matches_again", Target: r.ID, Detail: r.CVE}); err != nil {
					return err
				}
			}
			res.Touched++
		}
		return s.noteNoLongerMatching(ctx, tx, a.ID, vulns, m, now)
	})
	if err != nil {
		return UpsertResult{}, err
	}
	return res, nil
}

// haveScope drops the matches that "I have this" on Home does not cover (INV-11, D-484). On the one device "I have this"
// declared, a software row with no version and the answered KEV key is matched only against CISA entries added on or
// after the scope's date: older entries are not the customer's to handle unless they type the version, and then the
// version decides. Every other device, and every other row of that device, is matched as usual. An entry with no known
// date is kept. The matcher itself is unchanged; this is the customer's own scope.
func haveScope(a Asset, vulns []Vuln, m MatchResult, since map[string]Have) MatchResult {
	h, ok := since[a.ID]
	if !ok {
		return m
	}
	key := NormalizeKevKey(h.Key)
	scoped := map[string]bool{} // software ids under the scope
	for _, sw := range a.Software {
		if strings.TrimSpace(sw.Version) != "" {
			continue
		}
		for _, k := range sw.KevKeys {
			if NormalizeKevKey(k) == key {
				scoped[sw.ID] = true
			}
		}
	}
	if len(scoped) == 0 {
		return m
	}
	added := make(map[string]time.Time, len(vulns))
	for _, v := range vulns {
		added[v.CVE] = v.DateAdded
	}
	keep := func(ms []Match) []Match {
		out := ms[:0:0]
		for _, x := range ms {
			if d := added[x.CVE]; scoped[x.SoftwareID] && !d.IsZero() && d.Before(h.Since) {
				continue
			}
			out = append(out, x)
		}
		return out
	}
	return MatchResult{New: keep(m.New), Existing: keep(m.Existing)}
}

// noteNoLongerMatching records, once, that a suspected finding (basis version or product) is no longer produced by the
// matcher although its CVE is in the list that was matched: the device's software changed, or CISA changed the vendor or
// product of the entry (D-439). Nothing closes (FORBID-2): a person reads the history row and closes it. A CVE that is not
// in vulns says nothing (a partial list never judges a pair), and a finding the scan confirmed (basis scan) is not judged by
// the version matcher.
func (s *Service) noteNoLongerMatching(ctx context.Context, tx *sql.Tx, assetID string, vulns []Vuln, m MatchResult, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT cve FROM fnd_finding WHERE asset_id = ? AND status = 'suspected'`, assetID)
	if err != nil {
		return fmt.Errorf("findings: reading suspected findings: %w", err)
	}
	var open []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return fmt.Errorf("findings: reading suspected findings: %w", err)
		}
		open = append(open, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("findings: reading suspected findings: %w", err)
	}
	if len(open) == 0 {
		return nil
	}
	listed := make(map[string]bool, len(vulns))
	for _, v := range vulns {
		listed[v.CVE] = true
	}
	matched := make(map[string]bool, len(m.New)+len(m.Existing))
	for _, x := range m.New {
		matched[x.CVE] = true
	}
	for _, x := range m.Existing {
		matched[x.CVE] = true
	}
	for _, cve := range open {
		if !listed[cve] || matched[cve] {
			continue
		}
		r, err := loadByPair(ctx, tx, assetID, cve)
		if err != nil {
			return err
		}
		if n := len(r.History); n > 0 && r.History[n-1].Action == "no_longer_matches" {
			continue // said already
		}
		h := HistoryEntry{TS: now, User: SystemUser, Action: "no_longer_matches",
			Note: "The device no longer matches this entry (its software changed, or CISA changed the entry's vendor or product). Close it yourself if it does not apply."}
		if err := insertHistory(ctx, tx, r.ID, h); err != nil {
			return err
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.no_longer_matches", Target: r.ID, Detail: cve}); err != nil {
			return err
		}
	}
	return nil
}

// ConfirmFromScan records a positive scan result for a pair (PRE-2, POST-2). The finding must exist
// (scan targets come from findings). The change, its history row and the audit row are one
// transaction; findings.finding.status_changed goes out when the library says a person has to know.
func (s *Service) ConfirmFromScan(ctx context.Context, assetID, cve string, ev Evidence) (Record, error) {
	if !ValidCVE(cve) {
		return Record{}, fmt.Errorf("findings: confirming from scan: %w", ErrInvalidCVE)
	}
	var out Record
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if err != nil {
			return err
		}
		if ev.CheckedAt.IsZero() {
			ev.CheckedAt = now
		}
		was := r.Status
		o, err := r.ConfirmFromScan(ev, now)
		if err != nil {
			return err
		}
		if len(o.History) == 0 && !o.Notify {
			out = r // the same match was already recorded: nothing changes
			return nil
		}
		r.Finding = o.Finding
		r.LastSeen = now
		if err := r.Validate(); err != nil {
			return fmt.Errorf("findings: finding %s after a scan: %w", r.ID, err)
		}
		if err := updateRecord(ctx, tx, r); err != nil {
			return err
		}
		for _, h := range o.History {
			if err := insertHistory(ctx, tx, r.ID, h); err != nil {
				return err
			}
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.scan_confirmed", Target: r.ID,
			Detail: fmt.Sprintf("%s: %s to %s, template %s", r.CVE, was, r.Status, ev.Template)}); err != nil {
			return err
		}
		if o.Notify {
			emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status})
		}
		out, err = loadByID(ctx, tx, r.ID)
		return err
	})
	return out, err
}

// RescanClear records that a rescan no longer matches (history row rescan_clear). The status never
// changes: nothing closes without a person (FORBID-2).
func (s *Service) RescanClear(ctx context.Context, assetID, cve string) error {
	if !ValidCVE(cve) {
		return fmt.Errorf("findings: recording a clear rescan: %w", ErrInvalidCVE)
	}
	return s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if err != nil {
			return err
		}
		if err := insertHistory(ctx, tx, r.ID, ScanClear(now)); err != nil {
			return err
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.rescan_clear", Target: r.ID, Detail: r.CVE})
	})
}

// SetStatus applies a person's action (INV-3). user is the actor's email. On any error nothing is
// written. The checks run in the order the API reports them (library Finding.Apply).
func (s *Service) SetStatus(ctx context.Context, id string, action Action, note, user string) (Record, error) {
	if err := ValidUser(user); err != nil {
		return Record{}, err
	}
	var out Record
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		r, err := applyStatus(ctx, s.cfg.Audit, tx, id, action, note, user, now, emit)
		out = r
		return err
	})
	return out, err
}

// MaxBulk is how many findings one bulk status change may touch (INV-10): a filtered list of a few hundred findings
// fits, and the one write transaction stays short.
const MaxBulk = 500

// ErrTooMany is a bulk change that names more than MaxBulk findings, or none (the API's 400 invalid).
var ErrTooMany = &APIError{"invalid", 400, fmt.Sprintf("Select between 1 and %d findings.", MaxBulk)}

// SetStatusMany applies one action with one note to the open findings among ids (INV-10): every open finding gets its
// own history row, its own core_audit row and its own status_changed event, exactly as SetStatus would give it, all in
// one transaction. A finding that is already closed (patched, mitigated, false positive, not relevant) is counted in
// skipped and left as it is: a bulk change never overwrites a reason someone wrote. All or nothing: an unknown id or a
// refused action writes nothing. reopen is not a bulk action. A duplicate id counts once.
func (s *Service) SetStatusMany(ctx context.Context, ids []string, action Action, note, user string) (changed, skipped int, err error) {
	if err := ValidUser(user); err != nil {
		return 0, 0, err
	}
	if action == ActionReopen {
		return 0, 0, fmt.Errorf("findings: bulk %q: %w", action, ErrBadAction)
	}
	seen := make(map[string]bool, len(ids))
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}
	if len(uniq) == 0 || len(uniq) > MaxBulk {
		return 0, 0, ErrTooMany
	}
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		changed, skipped = 0, 0
		for _, id := range uniq {
			r, err := loadByID(ctx, tx, id)
			if err != nil {
				return err
			}
			if !r.Status.Open() {
				skipped++
				continue
			}
			if _, err := applyStatus(ctx, s.cfg.Audit, tx, id, action, note, user, now, emit); err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	return changed, skipped, nil
}

// applyStatus is one person's action on one finding inside tx: the change, its history row, its audit row and, when the
// status changed, its event.
func applyStatus(ctx context.Context, log *audit.Log, tx *sql.Tx, id string, action Action, note, user string, now time.Time, emit func(string, any)) (Record, error) {
	r, err := loadByID(ctx, tx, id)
	if err != nil {
		return Record{}, err
	}
	was := r.Status
	f, h, err := r.Apply(action, note, user, now)
	if err != nil {
		return Record{}, err
	}
	r.Finding = f
	if err := f.Validate(); err != nil {
		return Record{}, fmt.Errorf("findings: finding %s after %s: %w", r.ID, action, err)
	}
	if err := updateRecord(ctx, tx, r); err != nil {
		return Record{}, err
	}
	if err := insertHistory(ctx, tx, r.ID, h); err != nil {
		return Record{}, err
	}
	detail := fmt.Sprintf("%s: %s", r.CVE, action)
	if h.Note != "" {
		detail += ": " + h.Note
	}
	if err := log.Append(ctx, tx, audit.Entry{User: user, Action: "findings.status", Target: r.ID, Detail: detail}); err != nil {
		return Record{}, err
	}
	if was != r.Status {
		emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status})
	}
	return loadByID(ctx, tx, r.ID)
}

// OnAssetDeleted handles inventory.asset.deleted: the device's findings, their history and, through
// the foreign keys of mitigation, their applied log and AI results go with it (INV-7). It returns
// how many findings were removed.
func (s *Service) OnAssetDeleted(ctx context.Context, assetID string) (int, error) {
	ctx, cancel := eventContext(ctx)
	defer cancel()
	return s.deleteAsset(ctx, assetID)
}

// deleteAsset removes the findings of a device under the caller's context (Reconcile keeps its own cancellation).
func (s *Service) deleteAsset(ctx context.Context, assetID string) (int, error) {
	var n int64
	err := s.write(ctx, func(tx *sql.Tx, _ time.Time, _ func(string, any)) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM fnd_finding WHERE asset_id = ?`, assetID)
		if err != nil {
			return fmt.Errorf("findings: deleting findings of device: %w", err)
		}
		if n, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("findings: deleting findings of device: %w", err)
		}
		if n == 0 {
			return nil
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.deleted_with_asset", Target: assetID,
			Detail: fmt.Sprintf("%d findings removed with the device", n)})
	})
	return int(n), err
}

func cvesOfAsset(ctx context.Context, q querier, assetID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `SELECT cve FROM fnd_finding WHERE asset_id = ?`, assetID)
	if err != nil {
		return nil, fmt.Errorf("findings: reading existing findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("findings: reading existing findings: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func haveSet(cves []string) map[string]bool {
	m := make(map[string]bool, len(cves))
	for _, c := range cves {
		m[c] = true
	}
	return m
}
