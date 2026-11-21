package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/selfcheck"
	"github.com/knt048/vedette/core/store"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	idsmodule "github.com/knt048/vedette/modules/ids"
)

// The ports of findings' urgency pass (findings.UrgencySources): what feeds holds of each CVE, the devices' types and exposure, and the
// CVEs this network's intrusion alerts named. The CVE facts and the attacks are read through a *sql.DB so the selfcheck recomputes the
// stored layers with the very same reads on its read-only handle.

// urgencySources wires the pass. The attacks are read only while the intrusion detection module is on.
func urgencySources(d *deps) findings.UrgencySources {
	q := d.DB.Reader()
	src := findings.UrgencySources{
		Facts: func(ctx context.Context, cves []string) (map[string]findings.CVEFacts, error) {
			return urgencyFacts(ctx, q, cves)
		},
		Attacks: func(ctx context.Context, since time.Time) ([]findings.Attack, error) {
			if d.Reg != nil && !d.Reg.Enabled(idsmodule.ModuleID) {
				return nil, nil
			}
			return urgencyAttacks(ctx, q, since)
		},
	}
	if d.Inventory != nil {
		src.Devices = func(ctx context.Context, ids []string) (map[string]findings.Device, error) {
			refs, err := d.Inventory.DeviceRefs(ctx, ids)
			if err != nil {
				return nil, err
			}
			out := make(map[string]findings.Device, len(refs))
			for id, r := range refs {
				out[id] = findings.Device{Kind: r.Kind}
			}
			gw, at := urgencyGateway(ctx, d)
			if dev, ok := out[gw]; ok && gw != "" {
				dev.Internet, dev.InternetSeen = true, at
				out[gw] = dev
			}
			return out, nil
		}
	}
	return src
}

// urgencyGateway is the device that is the network's default gateway (it holds the address the Internet reaches), read now; "" when
// the box has no host component or no device has the gateway's address. A failed read is no exposure, never an error of the pass.
func urgencyGateway(ctx context.Context, d *deps) (string, time.Time) {
	if d.HostSocket == "" || d.Inventory == nil {
		return "", time.Time{}
	}
	g := exposureGateway{state: hostclient.New(d.HostSocket), inv: d.Inventory, fnd: d.Findings}
	dev, err := g.Gateway(ctx)
	if err != nil {
		return "", time.Time{}
	}
	return dev.DeviceID, clockOf(d)
}

// urgencyFacts converts feeds' urgency facts of the CVEs into findings' (findings.CVEFacts).
func urgencyFacts(ctx context.Context, q *sql.DB, cves []string) (map[string]findings.CVEFacts, error) {
	got, err := feeds.ReadUrgencyFacts(ctx, q, cves)
	if err != nil {
		return nil, err
	}
	out := make(map[string]findings.CVEFacts, len(got))
	for cve, f := range got {
		c := findings.CVEFacts{Automatable: f.Automatable}
		for _, g := range f.Signals {
			c.Signals = append(c.Signals, findings.Signal{Kind: g.Kind, Source: g.Source, FirstSeen: g.FirstSeen, Qualifies: g.Qualifies, URL: g.URL, FirstLoad: g.FirstLoad})
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
// urgency equals Urgency(...)). It recomputes as of the last finished urgency pass (core_job_run), so data that arrived after the pass
// does not count against it: signals stored after the pass's start are left out, the attack window ends at its start, and a finding
// created after the pass started or whose urgency changed after it ended (a device's own match write rates it at once) is not
// compared. No pass yet: nothing to compare.
func urgencyMismatches(ctx context.Context, db *sql.DB) (int64, error) {
	var started, finished string
	err := db.QueryRowContext(ctx, `SELECT started_at, finished_at FROM core_job_run WHERE module = 'findings' AND job = ? AND status = 'ok'
		ORDER BY finished_at DESC LIMIT 1`, findings.UrgencyJob).Scan(&started, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	at, err := time.Parse(time.RFC3339Nano, started)
	if err != nil {
		return 0, fmt.Errorf("reading the last urgency pass: %w", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT id, asset_id, cve, fix_key, detected, urgency FROM fnd_finding WHERE first_seen <= ? AND urgency_at <= ?`, started, finished)
	if err != nil {
		return 0, err
	}
	var fs []findings.Finding
	var cves, assets []string
	for rows.Next() {
		var f findings.Finding
		if err := rows.Scan(&f.ID, &f.AssetID, &f.CVE, &f.FixKey, &f.Detected, &f.Urgency); err != nil {
			_ = rows.Close()
			return 0, err
		}
		fs, cves, assets = append(fs, f), append(cves, f.CVE), append(assets, f.AssetID)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return 0, err
	}
	if len(fs) == 0 {
		return 0, nil
	}
	slices.Sort(cves)
	facts, err := urgencyFacts(ctx, db, slices.Compact(cves))
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
	slices.Sort(assets)
	kinds := map[string]findings.Device{}
	for chunk := range slices.Chunk(slices.Compact(assets), 500) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return 0, err
		}
		krows, err := db.QueryContext(ctx, `SELECT id, kind FROM inv_asset WHERE id IN (SELECT value FROM json_each(?))`, string(part))
		if err != nil {
			return 0, err
		}
		for krows.Next() {
			var id, kind string
			if err := krows.Scan(&id, &kind); err != nil {
				_ = krows.Close()
				return 0, err
			}
			kinds[id] = findings.Device{Kind: kind}
		}
		if err := errors.Join(krows.Err(), krows.Close()); err != nil {
			return 0, err
		}
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
	var n int64
	for _, f := range fs {
		if findings.Urgency(f.CVE, facts[f.CVE], findings.TargetOf(f, kinds[f.AssetID]), attacks, at).Layer != f.Urgency {
			n++
		}
	}
	return n, nil
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
