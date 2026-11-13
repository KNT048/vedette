package findings

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// ReconcileEvery is the pause between two reconcile runs (the job also runs once when the module starts).
const ReconcileEvery = time.Hour

// RecentKEV is how recent a KEV entry must be for a finding that Reconcile creates to be announced. Reconcile can
// create thousands of findings at once when the baseline events of the first CISA pull were lost; an entry CISA added
// within this window is real news a lost new_kev event should still announce, anything older is backlog and, as in D-78,
// silent. An entry with no known date is backlog.
const RecentKEV = 7 * 24 * time.Hour

// ReconcileResult says what a reconcile run did.
type ReconcileResult struct {
	Devices int // devices matched
	Created int // findings created that an event had not created
	Closed  int // findings Vedette closed by itself: version proved outside every range (D-530)
	Retired int // old product findings of settled "Multiple Products" entries NVD's list leaves out, closed (D-506)
	Orphans int // findings removed because their device no longer exists
}

// Reconcile heals what a lost event left behind (D-144: the bus is best-effort, findings owns the catch-up). It does the
// work of OnMatchChanged for every device and the work of OnAssetDeleted for every device that findings still has
// findings for but inventory no longer has. It reads only through Inventory and Feeds, writes one device per transaction
// (the writer is never held for the run), honours ctx between devices, and is idempotent: a pair that exists is only
// touched (its last_seen moves), so it publishes findings.finding.created only for findings it creates. Those are
// written under ServiceConfig.Backlog unless their KEV entry is recent (RecentKEV), so a lost baseline is not announced
// finding by finding. A device list that cannot be read is an error before anything is removed: a short list is never
// taken for "these devices are gone". An error on one device is logged and the run goes on (the orphan pass included);
// the errors come back together at the end.
func (s *Service) Reconcile(ctx context.Context) (ReconcileResult, error) {
	var res ReconcileResult
	if err := ctx.Err(); err != nil {
		return res, err
	}
	ids, err := s.cfg.Inventory.AssetIDs(ctx)
	if err != nil {
		return res, fmt.Errorf("findings: reconcile: listing devices: %w", err)
	}
	vulns, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return res, fmt.Errorf("findings: reconcile: reading the exploited list: %w", err)
	}
	backlog, recent := s.splitByNews(vulns)
	var failed []error
	skip := func(id string, err error) error { // a device that failed is logged and skipped; a cancelled run stops
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile skipped a device", "device", id, "error", err)
		failed = append(failed, fmt.Errorf("device %q: %w", id, err))
		return nil
	}
	live := make(map[string]bool, len(ids))
	for _, id := range ids {
		live[id] = true
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
	}
	orphans, err := s.orphanAssets(ctx, live)
	if err != nil {
		return res, errors.Join(append(failed, err)...)
	}
	for _, id := range orphans {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		known, err := s.cfg.Inventory.Assets(ctx, []string{id}) // a second look: a device created after the list was read is not an orphan
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
	// One line per run, so a box's log shows the pass ran and what it changed (walk 3: the job's own line is debug).
	s.cfg.Log.InfoContext(ctx, "findings: reconcile pass done", "devices", res.Devices, "created", res.Created,
		"closed_not_affected", res.Closed, "closed_multiple_products", res.Retired, "removed_with_device", res.Orphans)
	return res, errors.Join(failed...)
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
// per software for the whole exploited list (D-500), and each write replaces them (W6-1).
func (s *Service) upsertSplit(ctx context.Context, a Asset, backlog, recent []Vuln) (UpsertResult, error) {
	var sum UpsertResult
	need := MatchAsset(a, slices.Concat(backlog, recent), nil, s.now()).NeedVersion // which findings exist does not change them
	if need == nil {
		need = []VersionNeeded{} // not nil: the device has no item, so a write must clear the ones it had
	}
	add := func(wctx context.Context, vulns []Vuln) error {
		if len(vulns) == 0 {
			return nil
		}
		r, err := s.upsertWithin(wctx, a, vulns, need)
		sum.Created = append(sum.Created, r.Created...)
		sum.Closed += r.Closed
		sum.Retired += r.Retired
		return err
	}
	if len(backlog) > 0 {
		if err := add(s.cfg.Backlog(ctx), backlog); err != nil {
			return sum, err
		}
	}
	return sum, add(ctx, recent)
}

func (s *Service) upsertWithin(ctx context.Context, a Asset, vulns []Vuln, need []VersionNeeded) (UpsertResult, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.upsert(ctx, a, vulns, need)
}

func (s *Service) deleteWithin(ctx context.Context, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.deleteAsset(ctx, id)
}

// orphanAssets lists the devices that have findings or "add the version" items but are not in live, in id order.
func (s *Service) orphanAssets(ctx context.Context, live map[string]bool) ([]string, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT asset_id FROM fnd_finding UNION SELECT asset_id FROM fnd_version_needed ORDER BY asset_id`)
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
// starts, then every ReconcileEvery.
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: "findings", Name: "reconcile", Every: ReconcileEvery, Run: func(ctx context.Context) error {
		_, err := svc.Reconcile(ctx)
		return err
	}}}
}
