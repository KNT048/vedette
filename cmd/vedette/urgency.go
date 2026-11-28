package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	idsmodule "github.com/knt048/vedette/modules/ids"
	"github.com/knt048/vedette/modules/inventory"
)

// The ports of findings' urgency pass (findings.UrgencySources): what feeds holds of each CVE, the CVEs this network's intrusion alerts
// named, and the end of the box's own first-run window. The CVE facts and the attacks are read through a *sql.DB so the selfcheck
// recomputes the stored layers with the very same reads on its read-only handle. The devices' Internet exposure is a line of the reasons
// only, never a layer: it is not read until the reasons are shown.

// urgencySources wires the pass. The attacks are read only while the intrusion detection module is on. The CVE facts are read also
// while the feeds module is off: turning a module off keeps its data (modules.md) and stops its routes, jobs and pulls, which this
// read is none of. The stored signals stay the last word on a CVE, so the layers hold; reading nothing instead would lower every
// finding while feeds is off and tell every rise again when it comes back on.
func urgencySources(d *deps) findings.UrgencySources {
	q := d.DB.Reader()
	facts := feeds.NewUrgencyReader(q) // keeps what it reads of the sources until a feed pulls
	return findings.UrgencySources{
		Facts: func(ctx context.Context, cves []string) (map[string]findings.CVEFacts, error) {
			return urgencyFacts(ctx, facts, cves)
		},
		Attacks: func(ctx context.Context, since time.Time) ([]findings.Attack, error) {
			if d.Reg != nil && !d.Reg.Enabled(idsmodule.ModuleID) {
				return nil, nil
			}
			return urgencyAttacks(ctx, q, since)
		},
		Names: func(ctx context.Context) (map[string]string, error) { return feeds.ReadSourceNames(ctx, q) },
		Loads: func(ctx context.Context) (findings.Loads, error) {
			install, err := newNotify(d).FirstRunAt(ctx)
			if err != nil {
				return findings.Loads{}, err
			}
			catalogue, err := facts.CatalogueLoaded(ctx)
			return findings.Loads{Install: install, Catalogue: catalogue}, err
		},
	}
}

// urgencyKick runs the urgency pass when intrusion alerts arrive, one pass at a time: alerts that arrive while it runs make it run once
// more, so a burst of alerts costs at most two passes and the last alert is always rated.
type urgencyKick struct {
	mu             sync.Mutex
	running, again bool
}

func (k *urgencyKick) run(ctx context.Context, pass func(context.Context) error) error {
	k.mu.Lock()
	if k.running {
		k.again = true
		k.mu.Unlock()
		return nil
	}
	k.running = true
	k.mu.Unlock()
	for {
		err := pass(ctx)
		k.mu.Lock()
		if !k.again || err != nil {
			k.running, k.again = false, false
			k.mu.Unlock()
			return err
		}
		k.again = false
		k.mu.Unlock()
	}
}

// urgencyOnAlerts rates every finding again when the intrusion detection module stores alerts (ids.alert.detected): an attack on a CVE
// a device is affected by is "under attack here" now, not at the next hourly pass. The pass runs off the publisher's goroutine, on its
// own deadline, so the ids module is never held by it; alerts that arrive while it runs make it run once more.
func urgencyOnAlerts(d *deps) events.Handler {
	k := &urgencyKick{}
	return func(ctx context.Context, _ events.Event) error {
		if d.Findings == nil || d.Reg != nil && (!d.Reg.Enabled("findings") || !d.Reg.Enabled(idsmodule.ModuleID)) {
			return nil
		}
		base := context.WithoutCancel(ctx) // the pass outlives the publisher's call
		go func() {
			ctx, cancel := context.WithTimeout(base, time.Minute)
			defer cancel()
			if err := k.run(ctx, func(ctx context.Context) error { _, err := d.Findings.RateUrgency(ctx, ""); return err }); err != nil {
				d.Log.WarnContext(ctx, "findings: rating urgency after intrusion alerts failed", "error", err)
			}
		}()
		return nil
	}
}

// exploitedCVEs says which CVEs are exploited in the wild, by the rule a finding's alert follows: findings' Urgency over the facts feeds'
// urgency reader holds (an exploited list's entry, CISA KEV and VulnCheck KEV included, or a vendor's or researcher's exploited signal:
// layer 2). Exposure's alerts use it (exposure Config.Exploited), so one rule decides what alerts at once.
func exploitedCVEs(d deps) func(ctx context.Context, cves []string) (map[string]bool, error) {
	return func(ctx context.Context, cves []string) (map[string]bool, error) {
		out := map[string]bool{}
		if d.DB == nil || len(cves) == 0 {
			return out, nil
		}
		facts, err := urgencyFacts(ctx, feeds.NewUrgencyReader(d.DB.Reader()), cves)
		if err != nil {
			return nil, err
		}
		now := time.Now()
		if d.Clock != nil {
			now = d.Clock()
		}
		for _, c := range cves {
			out[c] = findings.ExploitedLayer(findings.Urgency(c, facts[c], findings.Target{}, nil, now).Layer)
		}
		return out, nil
	}
}

// urgencyFacts converts feeds' urgency facts of the CVEs into findings' (findings.CVEFacts).
func urgencyFacts(ctx context.Context, r *feeds.UrgencyReader, cves []string) (map[string]findings.CVEFacts, error) {
	got, err := r.Facts(ctx, cves)
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.CVEFacts, len(got))
	for cve, f := range got {
		c := findings.CVEFacts{Automatable: f.Automatable}
		for _, g := range f.Signals {
			c.Signals = append(c.Signals, findings.Signal{Kind: g.Kind, Source: g.Source, FirstSeen: g.FirstSeen, Qualifies: g.Qualifies, URL: g.URL,
				FirstLoad: g.FirstLoad, LoadedAt: g.LoadedAt})
		}
		if f.CVSS != nil {
			c.CVSS = &findings.CVSS{Score: f.CVSS.Score, Version: f.CVSS.Version, Source: f.CVSS.Source, Vector: f.CVSS.Vector}
		}
		if f.Published != nil {
			c.Published = *f.Published
		}
		out[cve] = c
	}
	return out, nil
}

// urgencyAttacks converts the intrusion alerts' attacked CVEs since a time into findings' attacks.
func urgencyAttacks(ctx context.Context, q *sql.DB, since time.Time) ([]findings.Attack, error) {
	as, err := idsmodule.ReadAttacked(ctx, q, since)
	if err != nil {
		return nil, err
	}
	out := make([]findings.Attack, len(as))
	for i, a := range as {
		out[i] = findings.Attack{CVE: a.CVE, AssetID: a.DstAssetID, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, AlertID: a.LastAlertID}
	}
	return out, nil
}

func init() {
	selfcheck.Register(selfcheck.Invariant{Name: "findings.urgency_recomputed", Count: urgencyMismatches})
}

// urgencyMismatches counts the findings whose stored urgency differs from findings.Urgency recomputed (data invariant: stored
// urgency equals Urgency(...)), plus one when the pass itself is not running: no successful urgency run, or the last one older than
// urgencyStale, while the findings module is on and holds findings (stored layers then go stale unseen).
//
// It recomputes as of the last successful run (core_job_run), so data that arrived after the pass does not count against it: signals
// stored after the run's start are left out, the attack window ends at its start, and a finding created after the run started or whose
// urgency changed after it ended (a device's own match write rates it at once) is not compared. With no successful run it recomputes
// every finding against the current facts. What it cannot rewind clears at the next pass: a signal deleted after the run, a proof of
// concept that started to qualify, a CVSS or SSVC change; right after a feeds pull the count may be non-zero for up to an hour.
func urgencyMismatches(ctx context.Context, db *sql.DB) (int64, error) {
	var on bool
	if err := db.QueryRowContext(ctx, `SELECT count(*) > 0 FROM core_module WHERE id = 'findings' AND enabled = 1`).Scan(&on); err != nil {
		return 0, err
	}
	var started, finished string
	err := db.QueryRowContext(ctx, `SELECT started_at, finished_at FROM core_job_run WHERE module = 'findings' AND job = ? AND status = 'ok'
		ORDER BY finished_at DESC LIMIT 1`, findings.UrgencyJob).Scan(&started, &finished)
	ran := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	now := time.Now().UTC()
	at, upTo := now, store.FormatTS(now)
	if ran {
		if at, err = time.Parse(time.RFC3339Nano, started); err != nil {
			return 0, fmt.Errorf("reading the last urgency pass: %w", err)
		}
		upTo = finished
	}
	var n int64
	if on && (!ran || now.Sub(at) > urgencyStale) {
		var held bool
		if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM fnd_finding)`).Scan(&held); err != nil {
			return 0, err
		}
		if held {
			n++ // the pass is not running: the stored layers go stale unseen
		}
	}
	fs, err := storedUrgencies(ctx, db, store.FormatTS(at), upTo)
	if err != nil || len(fs) == 0 {
		return n, err
	}
	cves := make([]string, 0, len(fs))
	for _, f := range fs {
		cves = append(cves, f.CVE)
	}
	slices.Sort(cves)
	facts, err := urgencyFacts(ctx, feeds.NewUrgencyReader(db), slices.Compact(cves))
	if err != nil {
		return 0, err
	}
	stored, err := signalsStoredAfter(ctx, db, store.FormatTS(at))
	if err != nil {
		return 0, err
	}
	for cve, c := range facts { // as of the pass: the signals it could read
		c.Signals = slices.DeleteFunc(c.Signals, func(g findings.Signal) bool { return stored[cve+"|"+g.Kind+"|"+g.Source] })
		facts[cve] = c
	}
	var attacks []findings.Attack
	var idsOn bool
	if err := db.QueryRowContext(ctx, `SELECT count(*) > 0 FROM core_module WHERE id = ? AND enabled = 1`, idsmodule.ModuleID).Scan(&idsOn); err != nil {
		return 0, err
	}
	if idsOn {
		if attacks, err = urgencyAttacks(ctx, db, at.Add(-findings.AttackWindow)); err != nil {
			return 0, err
		}
		attacks = slices.DeleteFunc(attacks, func(a findings.Attack) bool { return a.FirstSeen.After(at) })
		for i := range attacks {
			if attacks[i].LastSeen.After(at) {
				attacks[i].LastSeen = at
			}
		}
	}
	byCVE := findings.AttacksByCVE(attacks)
	for _, f := range fs {
		if findings.Urgency(f.CVE, facts[f.CVE], findings.TargetOf(f, findings.Device{}), byCVE[f.CVE], at).Layer != f.Urgency {
			n++
		}
	}
	return n, nil
}

// urgencyStale is how old the last successful urgency pass may be before the selfcheck counts the pass as not running.
const urgencyStale = 2 * findings.UrgencyEvery

// storedUrgencies reads the findings the selfcheck compares: first seen by from, urgency last changed by upTo, of devices nobody ignored
// (the pass leaves an ignored device's layers as they were until a person stops ignoring it, findings.RateUrgency).
func storedUrgencies(ctx context.Context, db *sql.DB, from, upTo string) ([]findings.Finding, error) {
	ignored, err := inventory.ReadIgnoredIDs(ctx, db)
	if err != nil {
		return nil, err
	}
	ig, _ := json.Marshal(append([]string{}, ignored...))
	rows, err := db.QueryContext(ctx, `SELECT id, asset_id, cve, fix_key, detected, urgency FROM fnd_finding WHERE first_seen <= ? AND urgency_at <= ?
		AND asset_id NOT IN (SELECT value FROM json_each(?))`, from, upTo, string(ig))
	if err != nil {
		return nil, err
	}
	var fs []findings.Finding
	for rows.Next() {
		var f findings.Finding
		if err := rows.Scan(&f.ID, &f.AssetID, &f.CVE, &f.FixKey, &f.Detected, &f.Urgency); err != nil {
			_ = rows.Close()
			return nil, err
		}
		fs = append(fs, f)
	}
	return fs, errors.Join(rows.Err(), rows.Close())
}

// signalsStoredAfter is the signal rows (cve|kind|source) stored after a time.
func signalsStoredAfter(ctx context.Context, db *sql.DB, at string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT cve, kind, source FROM feeds_signal WHERE stored_at > ?`, at)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for rows.Next() {
		var c, k, s string
		if err := rows.Scan(&c, &k, &s); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out[c+"|"+k+"|"+s] = true
	}
	return out, errors.Join(rows.Err(), rows.Close())
}
