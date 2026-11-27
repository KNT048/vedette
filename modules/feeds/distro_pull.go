package feeds

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"time"
)

// distroFetchTimeout bounds one download and parse of a distribution file: the VEX archive took 47 s to unpack
// and read on a desktop CPU on 2026-11-14, the whole pull stays inside pullBudget.
const distroFetchTimeout = 9 * time.Minute

// errDistroWaits: the CISA list is not on the box yet, so a distribution file would keep nothing. Nothing is recorded,
// the feed stays due and pulls at the next tick after the list (like ErrBoxAddrsUnknown).
var errDistroWaits = errors.New("feeds: the distribution feeds wait for the CISA list")

// errDistroNoDevice: no device needs this distribution feed (LEAN). Nothing is fetched or recorded, the stored rows
// stay, and the feed stays due, so it pulls at the next tick after such a device appears. A feed that never filled is pulled
// once whatever the inventory says, so the first device of that distribution is judged on its rows, not NVD's upstream
// ranges (no false alerts while the pull runs; review H1).
var errDistroNoDevice = errors.New("feeds: no device needs this distribution feed")

// distroOfFeed is the distribution each distribution feed answers for.
var distroOfFeed = map[string]string{ubuntuOSVFeedID: DistroUbuntu, ubuntuVEXFeedID: DistroUbuntu, debianTrackerFeedID: DistroDebian, alpineOSVFeedID: DistroAlpine}

// distroNeeds says whether some device needs the distribution of feed id, with the source packages those devices run as the
// security data names them. No lister, the inventory module off, or a read error: pull as before (a missed fix
// costs more than a download), with no package known, so the pull keeps no tier row (DistroWant). Except alpine-osv: it is fetched only when the inventory says a device states Alpine, never on a guess (PRIVACY flow 1 says "never").
// ponytail: asks the inventory on each tick while a distribution feed is due (every PullEvery while no device needs it);
// upgrade: an inventory event that says a device's OS changed.
func (s *Service) distroNeeds(ctx context.Context, id string) (need bool, pkgs map[string]bool) {
	unknown := id != alpineOSVFeedID // what an unknown inventory means: pull, except alpine-osv
	l, ok := s.Inventory.(DistroLister)
	if !ok || !s.inventoryOn() {
		return unknown, nil
	}
	got, err := l.Distros(ctx)
	if err != nil {
		s.Log.WarnContext(ctx, "reading the distributions of the devices failed", "feed", id, "pull", unknown, "error", err)
		return unknown, nil
	}
	pkgs, need = got[distroOfFeed[id]]
	return need, pkgs
}

// setDistroIdle remembers whether the last check found no device for feed id, for the Feeds page.
func (s *Service) setDistroIdle(id string, idle bool) {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if s.distroIdle == nil {
		s.distroIdle = map[string]bool{}
	}
	s.distroIdle[id] = idle
}

// distroBehindFloor is the shortest time between a feed's last good pull and a pull for a new package:
// a churny fleet, or an agent that reports a different made-up source name each time, costs at most four whole-file
// downloads a day per feed, and a device's new package waits at most this long instead of the feed's daily interval.
const distroBehindFloor = 6 * time.Hour

// distroKeep is the sorted list of the packages a pull keeps tier rows for: only names a Debian or Alpine source package can have
// (the inventory's names come from agents: untrusted); nil for none.
func distroKeep(pkgs map[string]bool) []string {
	var out []string
	for p := range pkgs {
		if debPackageRE.MatchString(p) || apkPackageRE.MatchString(p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return out
}

// distroBehind says whether a device runs a package the stored tier rows of feed id were not kept for (a new device, a
// new package, the first check after the upgrade that added tier rows) and the last good pull is distroBehindFloor old: RunPull
// then pulls the feed now, not a day after its last pull. A package that left (a removal, a deleted device) never counts: the
// stored rows are a superset. Never for ubuntu-vex (no tier rows), nor while nvd-recent has no tier CVE; a read error says no
// (the daily pull stays). ponytail: asks the inventory on each check for each such feed; upgrade: an inventory event when a
// package appears.
func (s *Service) distroBehind(ctx context.Context, src sourceRow) bool {
	if src.ID == ubuntuVEXFeedID || src.LastSuccess == nil || s.now().Sub(*src.LastSuccess) < distroBehindFloor {
		return false
	}
	need, pkgs := s.distroNeeds(ctx, src.ID)
	if !need || len(pkgs) == 0 {
		return false
	}
	has, err := s.st.hasTierCVEs(ctx, s.now())
	if err != nil || !has {
		return false
	}
	kept, err := s.st.distroKept(ctx, src.ID)
	return err == nil && !covers(kept, distroKeep(pkgs))
}

// covers says whether every name of want is in kept (both sorted).
func covers(kept, want []string) bool {
	for _, p := range want {
		if _, ok := slices.BinarySearch(kept, p); !ok {
			return false
		}
	}
	return true
}

// distroKept is the sorted list of packages feed id's stored tier rows were kept for, nil for none (no pull with tier rows yet).
func (s *Store) distroKept(ctx context.Context, id string) ([]string, error) {
	var raw sql.NullString
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT distro_packages FROM feeds_source WHERE id = ?`, id).Scan(&raw); err != nil {
		return nil, fmt.Errorf("feeds: distro packages: %w", err)
	}
	if !raw.Valid {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, nil // the CHECK keeps this from happening; unreadable = none kept, the next pull rewrites it
	}
	slices.Sort(out)
	return out, nil
}

// distroNote is the Feeds page line of a distribution feed no device needs; "" when it is pulled.
func (s *Service) distroNote(id string) string {
	s.idleMu.Lock()
	idle := s.distroIdle[id]
	s.idleMu.Unlock()
	if !idle {
		return ""
	}
	switch distroOfFeed[id] {
	case DistroDebian:
		return "Not updated: no Debian device now. Vedette updates it on the next check after an agent reports the packages of a Debian device."
	case DistroAlpine: // never fetched until then
		return "Not updated: no Alpine Linux device now. Vedette fetches it on the next check after a device's agent or SNMP answer, or a person, says it runs Alpine Linux."
	}
	return "Not updated: no Ubuntu device now. Vedette updates it on the next check after an agent reports the packages of an Ubuntu device."
}

var distroParsers = map[Decoder]func(io.Reader, DistroWant) (DistroResult, error){
	DecoderUbuntuOSV:     ParseUbuntuOSV,
	DecoderUbuntuVEX:     ParseUbuntuVEX,
	DecoderDebianTracker: ParseDebianTracker,
	DecoderAlpineOSV:     ParseAlpineOSV,
}

// buildDistro pulls one distribution file as a stream, conditional on the validators of the last good pull, and
// keeps the rows of the CVEs of the CISA list (the only CVEs findings matches) and, for ubuntu-osv and debian-tracker, the
// fixed rows of the tier CVEs for the source packages the devices run (DistroWant: "Updates to plan"). A pull that
// keeps no row fails, so the stored rows are never replaced with nothing. A file that did not change (304) keeps the rows: a
// CVE CISA added since gets its rows when the file changes, at most a day later. The validators are sent only when the stored
// rows were kept for every package needed now (distro_packages): a device's new package needs the whole file once.
func (s *Service) buildDistro(ctx context.Context, src sourceRow, p pullPlan, dec Decoder) (pullPlan, error) {
	cves, err := s.st.kevCVEs(ctx)
	if err != nil {
		return p, err
	}
	if len(cves) == 0 {
		return p, errDistroWaits
	}
	need, pkgs := s.distroNeeds(ctx, src.ID)
	// a feed that never filled is pulled whatever the inventory says (review H1), except alpine-osv: without its rows findings
	// asks or keeps the finding (no Alpine word is no proof either way), so a box with no Alpine device never contacts OSV.dev
	if src.LastSuccess != nil || src.ID == alpineOSVFeedID {
		s.setDistroIdle(src.ID, !need)
		if !need {
			return p, errDistroNoDevice
		}
	}
	want := DistroWant{KEV: make(map[string]bool, len(cves))}
	for _, c := range cves {
		want.KEV[c] = true
	}
	// ubuntu-vex keeps only "not affected", which never makes a plan item for Ubuntu (Ubuntu's own OSV data lists every release it
	// tracks, so a CVE it does not list for a package is no item): its tier rows would cost 561,161 rows and 485 MB of peak RSS for
	// nothing (2026-11-15). alpine-osv keeps the tier rows of the apk source packages the Alpine devices run, like the others.
	if dec != DecoderUbuntuVEX && len(pkgs) > 0 {
		if want.Tier, err = s.st.tierCVEs(ctx, s.now()); err != nil {
			return p, err
		}
		want.Packages = pkgs
	}
	var keep []string // the packages the tier rows are kept for, stored with them
	if len(want.Tier) > 0 {
		keep = distroKeep(want.Packages)
		want.Packages = make(map[string]bool, len(keep))
		for _, k := range keep {
			want.Packages[k] = true
		}
	}
	kept, err := s.st.distroKept(ctx, src.ID)
	if err != nil {
		return p, err
	}
	parse := distroParsers[dec]
	var res DistroResult
	maxBytes := int64(distroMaxBytes)
	if dec == DecoderAlpineOSV {
		maxBytes = alpineMaxBytes
	}
	req := Request{URL: src.URL, MaxBytes: maxBytes, Stream: func(r io.Reader) error {
		var err error
		res, err = parse(r, want)
		return err
	}}
	// a 304 keeps the stored rows: only when they were kept for every package needed now (a removed package needs nothing)
	if src.Status == "ok" && (len(keep) == 0 || kept != nil && covers(kept, keep)) {
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
	p.distro, p.hasDistro, p.distroKEV, p.distroKeep = res.Rows, true, want.KEV, keep
	var ms runtime.MemStats // The heap with the parsed rows still held, logged to measure peak memory (once a day a feed)
	runtime.ReadMemStats(&ms)
	s.Log.InfoContext(ctx, "feeds: distribution pull parsed", "feed", src.ID, "rows", len(res.Rows), "tier_cves", len(want.Tier), "packages", len(want.Packages), "heap_mb", ms.HeapInuse>>20)
	return p, nil
}

// distroFeeds are the feeds whose rows DistroFixes reads.
var distroFeeds = map[string]bool{ubuntuOSVFeedID: true, ubuntuVEXFeedID: true, debianTrackerFeedID: true, alpineOSVFeedID: true}

// distroCVEs lists the CVEs of the CISA list a distribution feed has rows for, sorted: the findings it may change (its tier rows
// decide no finding).
func distroCVEs(ctx context.Context, tx *sql.Tx, sourceID string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT cve FROM feeds_distro_fix WHERE source_id = ? AND cve IN (SELECT cve FROM feeds_kev WHERE list = 'cisa') ORDER BY cve`, sourceID)
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
// baseline: findings it closes or raises send no alert).
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
// that are on: a feed an admin turned off is not used, its rows stay until it is on again. The tier rows are
// not read here: the KEV matcher sees exactly the rows it saw before them.
func (s *Store) DistroFixes(ctx context.Context) (map[string][]DistroFix, error) {
	return s.distroFixes(ctx, "")
}

// DistroLoading lists the distributions one of whose feeds is on but holds no row while a first pull can still come: never
// completed, not yet failed DistroGiveUpFailures times in a row, and the CISA list it waits for on the box or still coming
// (kevCanArrive). findings then keeps an Alpine CVE of the platform list a question ("not loaded yet") instead of letting NVD decide; a
// feed that is off is not loading (its distribution falls back to NVD), and one with rows from an earlier good pull decides with them.
func (s *Store) DistroLoading(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM feeds_source s WHERE s.enabled = 1 AND s.builtin = 1 AND s.id IN ('alpine-osv', 'debian-tracker', 'ubuntu-osv', 'ubuntu-vex')
AND NOT EXISTS (SELECT 1 FROM feeds_distro_fix d WHERE d.source_id = s.id) AND s.last_success IS NULL AND s.failures < ? AND `+kevCanArrive, DistroGiveUpFailures, DistroGiveUpFailures)
	if err != nil {
		return nil, fmt.Errorf("feeds: distro loading: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("feeds: distro loading: %w", err)
		}
		out[distroOfFeed[id]] = true
	}
	return out, rows.Err()
}

// DistroOn lists the distributions ("ubuntu", "debian") whose security data decides their own packages: one of their feeds is on and
// has rows or a completed pull, or is loading (DistroLoading). findings judges a package such a distribution built by its word alone; a
// distribution whose feeds are off, or were given up after failing, falls back to NVD's ranges.
func (s *Store) DistroOn(ctx context.Context) (map[string]bool, error) {
	out, err := s.DistroLoading(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM feeds_source s WHERE s.enabled = 1 AND s.builtin = 1 AND s.id IN ('debian-tracker', 'ubuntu-osv', 'ubuntu-vex')
AND (s.last_success IS NOT NULL OR EXISTS (SELECT 1 FROM feeds_distro_fix d WHERE d.source_id = s.id))`)
	if err != nil {
		return nil, fmt.Errorf("feeds: distro on: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("feeds: distro on: %w", err)
		}
		out[distroOfFeed[id]] = true
	}
	delete(out, DistroAlpine) // Alpine's packages keep the platform list's rule (findings platformCheck)
	return out, rows.Err()
}

// kevCanArrive is true while the CISA list the distribution feeds wait for (errDistroWaits) is on the box or can still come: its
// feed is on and has either rows or not yet failed DistroGiveUpFailures times in a row with none completed. A distribution feed
// that waits on a list that cannot come (turned off, blocked) records nothing, so without this it would be loading for good.
// It takes one argument: DistroGiveUpFailures.
const kevCanArrive = `(EXISTS (SELECT 1 FROM feeds_kev WHERE list = 'cisa') OR EXISTS (SELECT 1 FROM feeds_source k WHERE k.id = 'cisa-kev'
AND k.enabled = 1 AND k.last_success IS NULL AND k.failures < ?))`

// DistroGiveUpFailures is how many pulls in a row may fail, with none ever completed, before the plan stops waiting for a
// distribution feed (KEVStaleChecks: the same count of checks after which the exploited list is called stale).
const DistroGiveUpFailures = KEVStaleChecks

// DistroPlanLoading lists the distributions the plan still waits for: a feed the plan reads (alpine-osv, debian-tracker, ubuntu-osv;
// ubuntu-vex is not read by the plan) is on, has never completed a pull and has not failed DistroGiveUpFailures times in a row. A pull
// that completed is loaded even if it stored no row; a feed that keeps failing is given up, so the plan falls back to "Check <distro>'s
// security updates" for its devices instead of leaving them unchecked for good.
func (s *Store) DistroPlanLoading(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM feeds_source WHERE enabled = 1 AND builtin = 1 AND id IN ('alpine-osv', 'debian-tracker', 'ubuntu-osv')
AND last_success IS NULL AND failures < ? AND `+kevCanArrive, DistroGiveUpFailures, DistroGiveUpFailures)
	if err != nil {
		return nil, fmt.Errorf("feeds: distro plan loading: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("feeds: distro plan loading: %w", err)
		}
		out[distroOfFeed[id]] = true
	}
	return out, rows.Err()
}

// DistroFixesOf is DistroFixes of one CVE (the CVE page's platform check); nil when none.
func (s *Store) DistroFixesOf(ctx context.Context, cve string) ([]DistroFix, error) {
	out, err := s.distroFixes(ctx, cve)
	return out[cve], err
}

// DistroFixesFor is DistroFixes for these CVEs, on an exploited list or not: what the distributions say about the catalogue CVEs the
// match pass compares.
func (s *Store) DistroFixesFor(ctx context.Context, cves []string) (map[string][]DistroFix, error) {
	out := map[string][]DistroFix{}
	for chunk := range slices.Chunk(cves, 400) {
		part, err := json.Marshal(chunk)
		if err != nil {
			return nil, fmt.Errorf("feeds: read distro: %w", err)
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT d.distro, d.release, d.package, d.cve, d.status, COALESCE(d.fixed_version, ''), d.pro
FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id WHERE s.enabled = 1
AND (d.status IN ('fixed', 'not_affected') OR d.status = 'open' AND d.cve IN (SELECT cve FROM feeds_kev WHERE list = 'cisa'))
AND d.cve IN (SELECT value FROM json_each(?)) ORDER BY d.cve, d.distro, d.release, d.package, d.source_id`, string(part))
		if err != nil {
			return nil, fmt.Errorf("feeds: read distro: %w", err)
		}
		for rows.Next() {
			var f DistroFix
			if err := rows.Scan(&f.Distro, &f.Release, &f.Package, &f.CVE, &f.Status, &f.Fixed, &f.Pro); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("feeds: read distro: %w", err)
			}
			out[f.CVE] = append(out[f.CVE], f)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("feeds: read distro: %w", err)
		}
	}
	return out, nil
}

// DistroPackage is a source package of one release as the distributions' security data names it ("ubuntu", "24.04", "openssl").
// Release "" asks for every release of the distribution.
type DistroPackage struct{ Distro, Release, Package string }

// DistroCVEs returns the CVEs the enabled distribution feeds say something about (fixed or not affected) for these packages: a CVE a
// distribution has fixed in a package reaches the match pass before NVD names the upstream product. Sorted.
func (s *Store) DistroCVEs(ctx context.Context, pkgs []DistroPackage) ([]string, error) {
	cves := map[string]bool{}
	for chunk := range slices.Chunk(pkgs, 400) {
		triples := make([][3]string, len(chunk))
		for i, p := range chunk {
			triples[i] = [3]string{p.Distro, p.Release, p.Package}
		}
		part, err := json.Marshal(triples)
		if err != nil {
			return nil, fmt.Errorf("feeds: distribution CVEs: %w", err)
		}
		got, err := stringSet(ctx, s.db.Reader(), `SELECT DISTINCT d.cve FROM json_each(?) j
JOIN feeds_distro_fix d ON d.distro = json_extract(j.value, '$[0]') AND d.package = json_extract(j.value, '$[2]')
  AND (json_extract(j.value, '$[1]') = '' OR d.release = json_extract(j.value, '$[1]'))
JOIN feeds_source s ON s.id = d.source_id WHERE s.enabled = 1 AND d.status IN ('fixed', 'not_affected')`, string(part))
		if err != nil {
			return nil, err
		}
		for c := range got {
			cves[c] = true
		}
	}
	return slices.Sorted(mapsKeys(cves)), nil
}

// distroFixes reads DistroFixes, of one CVE when cve is not "".
func (s *Store) distroFixes(ctx context.Context, cve string) (map[string][]DistroFix, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT d.distro, d.release, d.package, d.cve, d.status, COALESCE(d.fixed_version, ''), d.pro
FROM feeds_distro_fix d JOIN feeds_source s ON s.id = d.source_id WHERE s.enabled = 1 AND d.status IN ('fixed', 'not_affected', 'open') AND d.cve IN (SELECT cve FROM feeds_kev WHERE list = 'cisa')
AND (? = '' OR d.cve = ?) ORDER BY d.cve, d.distro, d.release, d.package, d.source_id`, cve, cve)
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
