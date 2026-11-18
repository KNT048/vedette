package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/orgtime"
)

// ReconcileEvery is the pause between two reconcile runs (the job also runs once when the module starts).
const ReconcileEvery = time.Hour

// RecentKEV is how recent a KEV entry must be for a finding that Reconcile creates to be announced. Reconcile can
// create thousands of findings at once when the baseline events of the first CISA pull were lost; an entry CISA added
// within this window is real news a lost new_kev event should still announce, anything older is backlog and, like the baseline,
// silent. An entry with no known date is backlog.
const RecentKEV = 7 * 24 * time.Hour

// ReconcileResult says what a reconcile run did.
type ReconcileResult struct {
	Devices int // devices matched
	Created int // findings created that an event had not created
	Closed  int // findings Vedette closed by itself: version proved outside every range
	Retired int // old product findings of settled "Multiple Products" entries NVD's list leaves out, closed
	Aged    int // product findings of KEV CVEs published over 12 months ago, closed
	// NameOnly: product findings with no version evidence, closed and listed under "Could not be checked"
	NameOnly int
	Orphans  int // findings removed because their device no longer exists
	Expired  int // risk acceptances whose day passed, reopened (INV-13)
	// IgnoreHealed counts the findings a lost inventory.asset.ignored or .unignored left behind: open
	// findings of an ignored device closed, findings Ignore closed on a watched device reopened.
	IgnoreHealed int
}

// Reconcile heals what a lost event left behind (the bus is best-effort, findings owns the catch-up). It does the
// work of OnMatchChanged for every device and the work of OnAssetDeleted for every device that findings still has
// findings for but inventory no longer has. It reads only through Inventory and Feeds, writes one device per transaction
// (the writer is never held for the run), honours ctx between devices, and is idempotent: a pair that exists is only
// touched (its last_seen moves), so it publishes findings.finding.created only for findings it creates. Those are
// written under ServiceConfig.Backlog unless their KEV entry is recent (RecentKEV), so a lost baseline is not announced
// finding by finding. A device list that cannot be read is an error before anything is removed: a short list is never
// taken for "these devices are gone". An error on one device is logged and the run goes on (the orphan pass included);
// the errors come back together at the end. First of all it reopens the risk acceptances whose day has passed
// (INV-13), whatever inventory and feeds say.
func (s *Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	if err := ctx.Err(); err != nil {
		return res, err
	}
	var failed []error
	n, err := s.expireAcceptances(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile could not reopen expired risk acceptances", "error", err)
		failed = append(failed, err)
	}
	res.Expired = n
	if err := s.reclassifyPatched(ctx); err != nil { // once: earlier closures after an update become patched, no notice
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile could not mark earlier closures after an update as patched", "error", err)
		failed = append(failed, err)
	}
	ids, err := s.cfg.Inventory.AssetIDs(ctx)
	if err != nil {
		return res, errors.Join(append(failed, fmt.Errorf("findings: reconcile: listing devices: %w", err))...)
	}
	// review r2 N1 of #945: without the ignored list the watched devices are still matched and the orphan pass still runs (each orphan's
	// second look, Assets, still finds an ignored device, so it is never taken for a deleted one; review r1 L2 of #948); only closing an
	// ignored device's open findings waits for the next pass
	ignored, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile could not read the ignored devices; it matches the watched devices and leaves the ignored ones for the next pass", "error", err)
		failed = append(failed, fmt.Errorf("findings: reconcile: listing ignored devices: %w", err))
	}
	vulns, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return res, errors.Join(append(failed, fmt.Errorf("findings: reconcile: reading the exploited list: %w", err))...)
	}
	backlog, recent := s.splitByNews(vulns)
	skip := func(id string, err error) error { // a device that failed is logged and skipped; a cancelled run stops
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile skipped a device", "device", id, "error", err)
		failed = append(failed, fmt.Errorf("device %q: %w", id, err))
		return nil
	}
	live := make(map[string]bool, len(ids)+len(ignored))
	// An ignored device is not gone (its findings are never orphans, review r1 L10 of #945), and the work of a lost
	// inventory.asset.ignored is done here: its open findings close (review r1 M2).
	for _, id := range ignored {
		live[id] = true
		if err := ctx.Err(); err != nil {
			return res, err
		}
		n, err := s.healIgnored(ctx, id, true)
		if err != nil {
			if err := skip(id, err); err != nil {
				return res, err
			}
			continue
		}
		res.IgnoreHealed += n
	}
	for _, id := range ids {
		live[id] = true
		if err := ctx.Err(); err != nil {
			return res, err
		}
		// a lost inventory.asset.unignored: the findings Ignore closed on a device watched again reopen before it is matched
		if n, err := s.healIgnored(ctx, id, false); err != nil {
			if err := skip(id, err); err != nil {
				return res, err
			}
		} else {
			res.IgnoreHealed += n
		}
		if len(vulns) == 0 {
			continue // no exploited list loaded yet: nothing can match
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		a, ok, err := s.cfg.Inventory.MatchInput(ctx, id)
		if err != nil {
			if err := skip(id, fmt.Errorf("reading the device: %w", err)); err != nil {
				return res, err
			}
			continue
		}
		if !ok {
			continue // deleted since the list was read; it is in live, so the orphan pass leaves it and the next run removes its findings
		}
		up, err := s.upsertSplit(ctx, a, backlog, recent)
		if err != nil {
			if err := skip(id, err); err != nil {
				return res, err
			}
			continue
		}
		res.Devices++
		res.Created += len(up.Created)
		res.Closed += up.Closed
		res.Retired += up.Retired
		res.Aged += up.Aged
		res.NameOnly += up.NameOnly
	}
	orphans, err := s.orphanAssets(ctx, live)
	if err != nil {
		return res, errors.Join(append(failed, err)...)
	}
	for _, id := range orphans {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		known, err := s.cfg.Inventory.Assets(ctx, []string{id}) // a second look: a device created (or ignored) after the lists were read is not an orphan
		if err != nil {
			if err := skip(id, fmt.Errorf("checking the device: %w", err)); err != nil {
				return res, err
			}
			continue
		}
		if _, ok := known[id]; ok {
			continue
		}
		n, err := s.deleteWithin(ctx, id)
		if err != nil {
			if err := skip(id, err); err != nil {
				return res, err
			}
			continue
		}
		res.Orphans += n
	}
	// The first pass with the exploited list loaded ends the first pass after the device-version rule arrived, whatever failed: its
	// summary tells what it recorded, and a device that failed it tells its confirmations one by one later (a device that fails every
	// pass must not keep the marker and silence every later confirmation). A box with no finding yet drops the marker even before the
	// list is loaded, so a fresh install never sends the "already open" summary.
	if err := s.finishBackfill(ctx, len(vulns) > 0); err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile could not send the summary of the findings the device's version confirmed", "error", err)
		failed = append(failed, err)
	}
	// One line per run, so a box's log shows the pass ran and what it changed (the job's own line is debug).
	s.cfg.Log.InfoContext(ctx, "findings: reconcile pass done", "devices", res.Devices, "created", res.Created,
		"closed_not_affected", res.Closed, "closed_multiple_products", res.Retired, "closed_older_than_12_months", res.Aged, "closed_no_version_evidence", res.NameOnly, "removed_with_device", res.Orphans, "risk_acceptances_expired", res.Expired, "ignore_healed", res.IgnoreHealed)
	return res, errors.Join(failed...)
}

// expireAcceptances reopens, in one write, every risk_accepted finding whose acceptance has ended (AcceptanceEnds,
// INV-13): Finding.ExpireAcceptance, its history row by the system user, an audit row findings.status and the
// status_changed event with reason ReasonRiskExpired. A row that cannot be read or reopened whole is reopened on its
// status alone (expireRaw); one that cannot be even so is logged with its id and skipped; the others still reopen. It
// returns how many it reopened. A finding of a device a person ignored keeps its acceptance until the device is watched
// again: no alert about a device nobody watches.
func (s *Service) expireAcceptances(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	unwatched := s.unwatchedAccepted(ctx)
	n := 0
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		n = 0
		// accepted_until < the latest day that has ended everywhere; ExpireAcceptance decides with AcceptanceEnds.
		rows, err := tx.QueryContext(ctx, `SELECT id, asset_id FROM fnd_finding WHERE status = 'risk_accepted' AND accepted_until < ? ORDER BY id`, dayOf(now).Format(time.DateOnly))
		if err != nil {
			return fmt.Errorf("findings: reading expired risk acceptances: %w", err)
		}
		var ids []string
		for rows.Next() {
			var id, asset string
			if err := rows.Scan(&id, &asset); err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading expired risk acceptances: %w", err)
			}
			if !unwatched[asset] {
				ids = append(ids, id)
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("findings: reading expired risk acceptances: %w", err)
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			r, err := loadByID(ctx, tx, id)
			if err == nil {
				by, until := r.ResolvedBy, r.AcceptedUntil
				f, h, ok := r.ExpireAcceptance(now)
				if !ok {
					continue
				}
				before := r.Finding
				r.Finding = f
				if err = s.expireOne(ctx, tx, r, h, until); err == nil {
					emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: before.Status, To: r.Status, Reason: ReasonRiskExpired,
						AcceptedBy: by, AcceptedUntil: until.Format(time.DateOnly)})
					n++
					continue
				}
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// The row cannot be read or written back whole: end the acceptance on the columns it needs, or it stays
			// accepted past its day and is skipped every hour.
			ev, ok, rawErr := s.expireRaw(ctx, tx, id, now)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if rawErr != nil {
				s.cfg.Log.WarnContext(ctx, "findings: a risk acceptance could not be ended; skipped", "finding", id, "error", errors.Join(err, rawErr))
				continue
			}
			if !ok { // its day has not ended everywhere yet
				continue
			}
			s.cfg.Log.WarnContext(ctx, "findings: a risk acceptance ended on its status alone; the rest of the finding could not be read", "finding", id, "error", err)
			emit(EventStatusChanged, ev)
			n++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// unwatchedAccepted is the set of devices a person ignored: their risk acceptances wait until the device is watched again.
// One read; when it fails the acceptances expire as usual (an alert too many, never one lost; review r1 L10 of #945).
func (s *Service) unwatchedAccepted(ctx context.Context) map[string]bool {
	ids, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		s.cfg.Log.WarnContext(ctx, "findings: the ignored devices could not be read; their risk acceptances expire as usual", "error", err)
		return nil
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// healIgnored does the work of a lost inventory.asset.ignored (ignored: close the open findings of an ignored device) or
// .unignored (reopen on a watched device the findings Ignore closed). A read first, so the hourly pass
// writes only for a device that needs it; the write checks the device's state again (forAssetFindings).
func (s *Service) healIgnored(ctx context.Context, id string, ignored bool) (int, error) {
	q := `SELECT 1 FROM fnd_finding WHERE asset_id = ? AND status IN ('suspected', 'confirmed') LIMIT 1`
	args := []any{id}
	if !ignored {
		q = `SELECT 1 FROM fnd_finding WHERE asset_id = ? AND status = 'not_relevant' AND resolved_by = ? AND resolution_reason IS NULL AND substr(resolution_note, 1, ?) = ? LIMIT 1`
		args = append(args, SystemUser, len(IgnoredNote), IgnoredNote)
	}
	var one int
	err := s.cfg.DB.Reader().QueryRowContext(ctx, q, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("findings: reading the findings of a device: %w", err)
	}
	wctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	if ignored {
		return s.OnAssetIgnored(wctx, id, "")
	}
	return s.OnAssetUnignored(wctx, id, "")
}

// expireOne writes one expiry under a savepoint, so a row that fails leaves nothing half written and the pass goes on.
func (s *Service) expireOne(ctx context.Context, tx *sql.Tx, r Record, h HistoryEntry, until time.Time) (err error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT fnd_expire`); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_, _ = tx.ExecContext(context.WithoutCancel(ctx), `ROLLBACK TO fnd_expire`)
		}
		_, _ = tx.ExecContext(context.WithoutCancel(ctx), `RELEASE fnd_expire`)
	}()
	if err := r.Validate(); err != nil {
		return fmt.Errorf("findings: finding %s after its risk acceptance expired: %w", r.ID, err)
	}
	if err := updateRecord(ctx, tx, r); err != nil {
		return err
	}
	if err := insertHistory(ctx, tx, r.ID, h); err != nil {
		return err
	}
	return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.status", Target: r.ID,
		Detail: r.CVE + ": risk acceptance expired (until " + until.Format(time.DateOnly) + "), reopened as " + string(r.Status)})
}

// expireRaw ends the acceptance of a finding that cannot be read whole (loadByID) or written back through Record
// (expireOne). It reads only id, cve, basis, resolved_by and accepted_until, decides with
// AcceptanceEnds like ExpireAcceptance, and writes only status (confirmed for basis scan, else suspected), the closing
// fields and accepted_until, plus the same history, audit and event; the broken column stays as it was, no worse. The
// table's CHECKs refuse a write that would make the row invalid (confirmed without evidence): that, or a day that is not
// a date, is an error and the row is only logged. ok is false when the day has not ended yet.
func (s *Service) expireRaw(ctx context.Context, tx *sql.Tx, id string, now time.Time) (ev StatusChangedEvent, ok bool, err error) {
	var cve, basis, day string
	var by sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT cve, basis, resolved_by, accepted_until FROM fnd_finding WHERE id = ? AND status = 'risk_accepted'`, id).
		Scan(&cve, &basis, &by, &day); err != nil {
		return ev, false, err
	}
	until, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return ev, false, fmt.Errorf("accepted_until: %w", err)
	}
	if now.Before(AcceptanceEnds(until)) {
		return ev, false, nil
	}
	to := StatusSuspected
	if b := Basis(basis); b == BasisScan || b == BasisPerson {
		to = StatusConfirmed
	}
	if _, err := tx.ExecContext(ctx, `SAVEPOINT fnd_expire_raw`); err != nil {
		return ev, false, err
	}
	defer func() {
		if err != nil {
			_, _ = tx.ExecContext(context.WithoutCancel(ctx), `ROLLBACK TO fnd_expire_raw`)
		}
		_, _ = tx.ExecContext(context.WithoutCancel(ctx), `RELEASE fnd_expire_raw`)
	}()
	if _, err = tx.ExecContext(ctx, `UPDATE fnd_finding SET status = ?, resolved_by = NULL, resolved_at = NULL, resolution_note = NULL,
		resolution_reason = NULL, accepted_until = NULL WHERE id = ? AND status = 'risk_accepted'`, string(to), id); err != nil {
		return ev, false, err
	}
	note := "Risk acceptance expired (accepted by " + by.String + " until " + orgtime.CalendarDay(until) + ")."
	if err = insertHistory(ctx, tx, id, HistoryEntry{TS: now, User: SystemUser, Action: "reopened", Note: note}); err != nil {
		return ev, false, err
	}
	if err = s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.status", Target: id,
		Detail: cve + ": risk acceptance expired (until " + day + "), reopened as " + string(to) + "; the rest of this finding could not be read"}); err != nil {
		return ev, false, err
	}
	return StatusChangedEvent{FindingID: id, From: StatusRiskAccepted, To: to, Reason: ReasonRiskExpired, AcceptedBy: by.String, AcceptedUntil: day}, true, nil
}

// splitByNews separates the entries whose findings are announced (added to KEV within RecentKEV) from the backlog.
// Without a Backlog hook everything is "recent": nothing can be marked, so nothing is held back.
func (s *Service) splitByNews(vulns []Vuln) (backlog, recent []Vuln) {
	if s.cfg.Backlog == nil {
		return nil, vulns
	}
	cut := s.now().Add(-RecentKEV)
	for _, v := range vulns {
		if v.DateAdded.IsZero() || v.DateAdded.Before(cut) {
			backlog = append(backlog, v)
		} else {
			recent = append(recent, v)
		}
	}
	return backlog, recent
}

// upsertSplit matches one device against both lists, one write each, the backlog under the Backlog mark. It returns what
// both writes did together. Both writes store the "add the version" items of the two lists together: the items are one
// per software for the whole exploited list, and each write replaces them.
func (s *Service) upsertSplit(ctx context.Context, a Asset, backlog, recent []Vuln) (UpsertResult, error) {
	var sum UpsertResult
	a.winList = slices.Concat(backlog, recent)      // A Windows build's month is read from the whole list in both writes
	whole := MatchAsset(a, a.winList, nil, s.now()) // its NeedVersion and Unchecked: which findings exist does not change them
	add := func(wctx context.Context, vulns []Vuln) error {
		if len(vulns) == 0 {
			return nil
		}
		r, err := s.upsertWithin(wctx, a, vulns, &whole)
		sum.Created = append(sum.Created, r.Created...)
		sum.Closed += r.Closed
		sum.Retired += r.Retired
		sum.Aged += r.Aged
		sum.NameOnly += r.NameOnly
		return err
	}
	if len(backlog) > 0 {
		if err := add(s.cfg.Backlog(ctx), backlog); err != nil {
			return sum, err
		}
	}
	return sum, add(ctx, recent)
}

func (s *Service) upsertWithin(ctx context.Context, a Asset, vulns []Vuln, whole *MatchResult) (UpsertResult, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.upsert(ctx, a, vulns, whole)
}

func (s *Service) deleteWithin(ctx context.Context, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.deleteAsset(ctx, id)
}

// orphanAssets lists the devices that have findings, "add the version" items or unchecked rows but are not in live, in id order.
func (s *Service) orphanAssets(ctx context.Context, live map[string]bool) ([]string, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT asset_id FROM fnd_finding UNION SELECT asset_id FROM fnd_version_needed UNION SELECT asset_id FROM fnd_unchecked UNION SELECT asset_id FROM fnd_unchecked_seen ORDER BY asset_id`)
	if err != nil {
		return nil, fmt.Errorf("findings: reconcile: reading the devices with findings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("findings: reconcile: reading the devices with findings: %w", err)
		}
		if !live[id] {
			out = append(out, id)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: reconcile: reading the devices with findings: %w", err)
	}
	return out, nil
}

// Jobs returns the jobs of the module (core runs one only while the module is on): reconcile runs when the module
// starts, then every ReconcileEvery; plan when the module starts, then every PlanEvery.
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: "findings", Name: "reconcile", Every: ReconcileEvery, Run: func(ctx context.Context) error {
		_, err := svc.Reconcile(ctx)
		return err
	}}, {Module: "findings", Name: "plan", Every: PlanEvery, Run: func(ctx context.Context) error {
		return svc.RefreshPlan(ctx)
	}}}
}
