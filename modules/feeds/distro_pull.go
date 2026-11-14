package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// distroFetchTimeout bounds one download and parse of a distribution file (D-516): the VEX archive took 47 s to unpack
// and read on a desktop CPU on 2026-11-14, the whole pull stays inside pullBudget.
const distroFetchTimeout = 9 * time.Minute

// errDistroWaits: the CISA list is not on the box yet, so a distribution file would keep nothing. Nothing is recorded,
// the feed stays due and pulls at the next tick after the list (like ErrBoxAddrsUnknown).
var errDistroWaits = errors.New("feeds: the distribution feeds wait for the CISA list")

// errDistroNoDevice: no device needs this distribution feed (D-570, LEAN). Nothing is fetched or recorded, the stored rows
// stay, and the feed stays due, so it pulls at the next tick after such a device appears.
var errDistroNoDevice = errors.New("feeds: no device needs this distribution feed")

// distroOfFeed is the distribution each distribution feed answers for.
var distroOfFeed = map[string]string{ubuntuOSVFeedID: DistroUbuntu, ubuntuVEXFeedID: DistroUbuntu, debianTrackerFeedID: DistroDebian}

// distroNeeded says whether some device needs the distribution of feed id, and remembers the answer for the Feeds page.
// No lister, the inventory module off, or a read error: pull as before, since a missed fix costs more than a download.
// ponytail: asks the inventory on each tick while a distribution feed is due (every PullEvery while no device needs it);
// upgrade: an inventory event that says a device's OS changed.
func (s *Service) distroNeeded(ctx context.Context, id string) bool {
	need := true
	if l, ok := s.Inventory.(DistroLister); ok && (s.Modules == nil || s.Modules.Enabled("inventory")) {
		if got, err := l.Distros(ctx); err != nil {
			s.Log.WarnContext(ctx, "reading the distributions of the devices failed; pulling the feed anyway", "feed", id, "error", err)
		} else {
			need = got[distroOfFeed[id]]
		}
	}
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.distroIdle == nil {
		s.distroIdle = map[string]bool{}
	}
	s.distroIdle[id] = !need
	return need
}

// distroNote is the Feeds page line of a distribution feed no device needs; "" when it is pulled.
func (s *Service) distroNote(id string) string {
	s.idleMu.Lock()
	idle := s.distroIdle[id]
	s.idleMu.Unlock()
	if !idle {
		return ""
	}
	if distroOfFeed[id] == DistroDebian {
		return "Not pulled: no Debian device yet. Vedette pulls it on the next check after an agent reports the packages of a Debian device."
	}
	return "Not pulled: no Ubuntu device yet. Vedette pulls it on the next check after an agent reports the packages of an Ubuntu device."
}

var distroParsers = map[Decoder]func(io.Reader, map[string]bool) (DistroResult, error){
	DecoderUbuntuOSV:     ParseUbuntuOSV,
	DecoderUbuntuVEX:     ParseUbuntuVEX,
	DecoderDebianTracker: ParseDebianTracker,
}

// buildDistro pulls one distribution file as a stream (D-516), conditional on the validators of the last good pull, and
// keeps the rows of the CVEs of the CISA list (the only CVEs findings matches). A pull that keeps no row fails, so the
// stored rows are never replaced with nothing. A file that did not change (304) keeps the rows: a CVE CISA added since
// gets its rows when the file changes, at most a day later.
func (s *Service) buildDistro(ctx context.Context, src sourceRow, p pullPlan, dec Decoder) (pullPlan, error) {
	cves, err := s.st.kevCVEs(ctx)
	if err != nil {
		return p, err
	}
	if len(cves) == 0 {
		return p, errDistroWaits
	}
	if !s.distroNeeded(ctx, src.ID) {
		return p, errDistroNoDevice
	}
	want := make(map[string]bool, len(cves))
	for _, c := range cves {
		want[c] = true
	}
	parse := distroParsers[dec]
	var res DistroResult
	req := Request{URL: src.URL, MaxBytes: distroMaxBytes, Stream: func(r io.Reader) error {
		var err error
		res, err = parse(r, want)
		return err
	}}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	ctx, cancel := context.WithTimeout(ctx, distroFetchTimeout)
	defer cancel()
	resp, err := s.Fetcher.Fetch(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	if err := accepted(res.Stats); err != nil {
		return p, err
	}
	p.out = outcome{OK: true, ETag: resp.ETag, LastModif: resp.LastModified}
	p.out.fill(res.Stats, len(res.Rows))
	p.distro, p.hasDistro = res.Rows, true
	return p, nil
}

// distroFeeds are the feeds whose rows DistroFixes reads.
var distroFeeds = map[string]bool{ubuntuOSVFeedID: true, ubuntuVEXFeedID: true, debianTrackerFeedID: true}

// distroCVEs lists the CVEs a distribution feed has rows for, sorted.
func distroCVEs(ctx context.Context, tx *sql.Tx, sourceID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT cve FROM feeds_distro_fix WHERE source_id = ? ORDER BY cve`, sourceID)
	if err != nil {
		return nil, fmt.Errorf("feeds: distro: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("feeds: distro: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type distroKey struct{ distro, release, pkg, cve string }

type distroVal struct {
	status, fixed string
	pro           bool
}

// applyDistro replaces the rows of one distribution feed. changed lists the CVEs whose rows differ (added, removed or
// changed), for the rematch of their devices; first is true when the feed had no row before (its first fill is the
// baseline of D-78: findings it closes or raises send no alert).
func applyDistro(ctx context.Context, tx *sql.Tx, sourceID string, rows []DistroFix) (changed []string, first bool, err error) {
	old := map[distroKey]distroVal{}
	q, err := tx.QueryContext(ctx, `SELECT distro, release, package, cve, status, COALESCE(fixed_version, ''), pro FROM feeds_distro_fix WHERE source_id = ?`, sourceID)
	if err != nil {
		return nil, false, fmt.Errorf("feeds: distro: %w", err)
	}
	for q.Next() {
		var k distroKey
		var v distroVal
		if err := q.Scan(&k.distro, &k.release, &k.pkg, &k.cve, &v.status, &v.fixed, &v.pro); err != nil {
			_ = q.Close()
			return nil, false, fmt.Errorf("feeds: distro: %w", err)
		}
		old[k] = v
	}
	if err := errors.Join(q.Err(), q.Close()); err != nil {
		return nil, false, fmt.Errorf("feeds: distro: %w", err)
	}
	cves := map[string]bool{}
	seen := map[distroKey]bool{}
	if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_distro_fix WHERE source_id = ?`, sourceID); err != nil {
		return nil, false, fmt.Errorf("feeds: distro: %w", err)
	}
	for _, r := range rows {
		k := distroKey{r.Distro, r.Release, r.Package, r.CVE}
		if seen[k] { // the parsers give one row per key; a second is dropped rather than failing the pull
			continue
		}
		seen[k] = true
		v := distroVal{r.Status, r.Fixed, r.Pro}
		if was, ok := old[k]; !ok || was != v {
			cves[r.CVE] = true
		}
		var fixed any
		if r.Status == DistroFixed {
			fixed = r.Fixed
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_distro_fix (source_id, distro, release, package, cve, status, fixed_version, pro) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sourceID, r.Distro, r.Release, r.Package, r.CVE, r.Status, fixed, r.Pro); err != nil {
			return nil, false, fmt.Errorf("feeds: distro: %w", err)
		}
	}
	for k := range old {
		if !seen[k] {
			cves[k.cve] = true
		}
	}
	for c := range cves {
		changed = append(changed, c)
	}
	slices.Sort(changed)
	return changed, len(old) == 0 && len(rows) > 0, nil
}

// DistroFixes returns what the distributions say about the CVEs of the CISA list, by CVE, from the distribution feeds
// that are on (D-516): a feed an admin turned off is not used, its rows stay until it is on again.
func (s *Store) DistroFixes(ctx context.Context) (map[string][]DistroFix, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT d.distro, d.release, d.package, d.cve, d.status, COALESCE(d.fixed_version, ''), d.pro
FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id WHERE s.enabled = 1 ORDER BY d.cve, d.distro, d.release, d.package, d.source_id`)
	if err != nil {
		return nil, fmt.Errorf("feeds: read distro: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]DistroFix{}
	for rows.Next() {
		var f DistroFix
		if err := rows.Scan(&f.Distro, &f.Release, &f.Package, &f.CVE, &f.Status, &f.Fixed, &f.Pro); err != nil {
			return nil, fmt.Errorf("feeds: read distro: %w", err)
		}
		out[f.CVE] = append(out[f.CVE], f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("feeds: read distro: %w", err)
	}
	return out, nil
}
