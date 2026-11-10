package findings

import (
	"context"
	"fmt"
	"time"

	"github.com/knt048/vedette/core/jobs"
)

// ReconcileEvery is the pause between two reconcile runs (the job also runs once when the module starts).
const ReconcileEvery = time.Hour

// ReconcileResult says what a reconcile run did.
type ReconcileResult struct {
	Devices int // devices matched
	Created int // findings created that an event had not created
	Orphans int // findings removed because their device no longer exists
}

// Reconcile heals what a lost event left behind (D-144: the bus is best-effort, findings owns the catch-up). It does the
// work of OnMatchChanged for every device and the work of OnAssetDeleted for every device that findings still has
// findings for but inventory no longer has. It reads only through Inventory and Feeds, writes one device per transaction
// (the writer is never held for the whole run), honours ctx between devices, and is idempotent: a pair that exists is
// only touched, so it publishes findings.finding.created only for findings it creates. A device list that cannot be read
// is an error before anything is removed: a short list is never taken for "these devices are gone".
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
			return res, fmt.Errorf("findings: reconcile: reading device %q: %w", id, err)
		}
		if !ok {
			continue // deleted since the list was read: the orphan pass below sees it
		}
		up, err := s.upsertWithin(ctx, a, vulns)
		if err != nil {
			return res, err
		}
		res.Devices++
		res.Created += len(up.Created)
	}
	orphans, err := s.orphanAssets(ctx, live)
	if err != nil {
		return res, err
	}
	for _, id := range orphans {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		known, err := s.cfg.Inventory.Assets(ctx, []string{id}) // a second look: a device created after the list was read is not an orphan
		if err != nil {
			return res, fmt.Errorf("findings: reconcile: checking device %q: %w", id, err)
		}
		if _, ok := known[id]; ok {
			continue
		}
		n, err := s.deleteWithin(ctx, id)
		if err != nil {
			return res, err
		}
		res.Orphans += n
	}
	return res, nil
}

func (s *Service) upsertWithin(ctx context.Context, a Asset, vulns []Vuln) (UpsertResult, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.UpsertFromMatch(ctx, a, vulns)
}

func (s *Service) deleteWithin(ctx context.Context, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.deleteAsset(ctx, id)
}

// orphanAssets lists the devices that have findings but are not in live, in id order.
func (s *Service) orphanAssets(ctx context.Context, live map[string]bool) ([]string, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT DISTINCT asset_id FROM fnd_finding ORDER BY asset_id`)
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
