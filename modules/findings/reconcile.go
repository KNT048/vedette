package findings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
)

// ReconcileEvery is the pause between two reconcile runs (the job also runs once when the module starts).
const ReconcileEvery = time.Hour

// RecentKEV is how recent a KEV entry must be for a finding that Reconcile creates to be announced. Reconcile can
// create thousands of findings at once when the baseline events of the first CISA pull were lost; an entry CISA added
// within this window is real news a lost new_kev event should still announce, anything older is backlog and, like the baseline,
// silent. An entry with no known date is backlog.
const RecentKEV = 7 * 24 * time.Hour

// lineKey is a finding's identity on its device: the CVE and the software line ("" for none).
func lineKey(cve, softwareID string) string { return cve + "\x1f" + softwareID }

// storedLine is the software id a match's row is stored under: "" for a row the inventory has no line for (the network OS a device
// states without one).
func storedLine(id string) string {
	if strings.HasPrefix(id, "os:") {
		return ""
	}
	return id
}

// applyMatch writes one match of device a against vulns through Transition, in tx:
//   - every match (and every other line the entry matches, Match.Lines) is detected on its (CVE, software line): created, or
//     detected again;
//   - every finding of the device that was detected until now, whose CVE is in vulns and that this match no longer detects, goes
//     away the way the data says (goneVia): a scan's proof is left to the scans unless its software line is gone;
//   - the device's questions become those of qm (the match of the whole list).
func (s *Service) applyMatch(ctx context.Context, tx *sql.Tx, a Asset, vulns []Vuln, judged map[string]bool, m, qm MatchResult, existing []Finding, now time.Time, emit func(string, any)) (UpsertResult, error) {
	var res UpsertResult
	byKey := make(map[string]Finding, len(existing))
	for _, f := range existing {
		byKey[lineKey(f.CVE, f.SoftwareID)] = f
	}
	lines := deviceLines(a)
	byCVE := make(map[string]Vuln, len(vulns))
	for _, v := range vulns {
		if _, ok := byCVE[v.CVE]; !ok { // the first, as the matcher reads it
			byCVE[v.CVE] = v
		}
	}
	seen := map[string]bool{}
	for _, list := range [][]Match{m.New, m.Existing} {
		for _, best := range list {
			for _, x := range append([]Match{best}, best.Lines...) {
				k := lineKey(x.CVE, storedLine(x.SoftwareID))
				if seen[k] {
					continue
				}
				seen[k] = true
				f, ok := byKey[k]
				if line := storedLine(x.SoftwareID); line != "" {
					// a finding on no line (a safe check's hit, or the OS a device stated without a line) takes the line the CVE is now
					// found on, rather than one closing and another opening for the same flaw; beside a finding of that line, the two fold
					if g, held := byKey[lineKey(x.CVE, "")]; held && !seen[lineKey(x.CVE, "")] {
						seen[lineKey(x.CVE, "")] = true
						delete(byKey, lineKey(x.CVE, ""))
						if !ok {
							f, ok = g, true // Transition gives it the line (TrDetected)
						} else {
							kept, err := s.absorbNoLine(ctx, tx, g, f)
							if err != nil {
								return res, err
							}
							f = kept
						}
					}
				}
				if !ok {
					f = Finding{ID: store.NewID("f"), AssetID: a.ID, CVE: x.CVE}
				}
				d := detectionOf(x, lines)
				if v, known := byCVE[x.CVE]; known {
					resolve(&d, a, lines, v)
				}
				if ok && s.rates() {
					d.Urgency = 0 // the urgency pass that follows rates and tells an existing finding's rise (Tell), not the match
				}
				g, evs, err := s.step(ctx, tx, f, !ok, Trigger{Kind: TrDetected, At: now, Detection: d}, emit)
				if err != nil {
					return res, fmt.Errorf("findings: %s on %s: %w", x.CVE, a.ID, err)
				}
				switch {
				case !ok:
					res.Created = append(res.Created, g.ID)
					if Announced(g) {
						emit(EventCreated, CreatedEvent{FindingID: g.ID, AssetID: g.AssetID, CVE: g.CVE, Severity: x.Severity, Basis: x.Basis})
					}
				default:
					res.Touched++
					if raised(f, g) { // a more urgent layer (its CVE joined an exploited list): one alert of the rise
						emit(EventUrgencyRaised, raisedEvent(f, g, x.Severity))
					}
					if slices.ContainsFunc(evs, func(e Event) bool { return e.Kind == EvReopened }) {
						res.Reopened++
					}
				}
			}
		}
	}
	proofs := map[string]Match{}
	for _, p := range m.NotAffected {
		proofs[p.CVE] = p
	}
	for _, f := range existing {
		if seen[lineKey(f.CVE, f.SoftwareID)] || !judged[f.CVE] || !f.Detected {
			continue
		}
		via, from, to, by := goneVia(a, lines, f, proofs) // a safe check's proof holds against data alone (Transition)
		_, evs, err := s.step(ctx, tx, f, false, Trigger{Kind: TrGone, At: now, Via: via, FromVersion: from, ToVersion: to, Actor: by}, emit)
		if err != nil {
			return res, fmt.Errorf("findings: %s on %s: %w", f.CVE, a.ID, err)
		}
		if slices.ContainsFunc(evs, func(e Event) bool { return e.Kind == EvHandled }) {
			res.Closed++
		}
	}
	if err := replaceQuestions(ctx, tx, a.ID, questionsOfMatch(qm), now); err != nil {
		return res, err
	}
	n, err := countQuestions(ctx, tx, a.ID)
	if err != nil {
		return res, err
	}
	res.Questions = n
	return res, nil
}

// line is a software line of a device as the match reads it now: its effective reading.
type line struct {
	sw      Software
	reading *Reading
}

// deviceLines is the effective reading of each software line of a, by id (the first row of an id is its effective reading; the
// others are readings the resolver keeps for matching), plus the network OS the device states without a line.
func deviceLines(a Asset) map[string]line {
	out := map[string]line{}
	for _, s := range a.Software {
		if _, ok := out[s.ID]; ok || s.ID == "" {
			continue
		}
		out[s.ID] = line{sw: s, reading: readingOf(s, newSWInfo(s, a.OS))}
	}
	if os, _, ok := deviceOS(a); ok {
		out[""] = line{sw: os, reading: readingOf(os, newSWInfo(os, ""))}
	}
	return out
}

// detectionOf is the detection of one match.
func detectionOf(x Match, lines map[string]line) Detection {
	ev := x.Evidence
	d := Detection{SoftwareID: storedLine(x.SoftwareID), Evidence: &ev, Urgency: UrgencyUpdate, RangeOrigin: RangeNVD}
	l, ok := lines[d.SoftwareID]
	if ok {
		d.ProductKey = productKey(l.sw)
	}
	src, pkg := "", ""
	if r := ev.Read; r != nil {
		d.MatchedVersion, d.ReadAt, src, pkg = r.Version, r.At, r.Source, r.Pkg
	} else if ok {
		d.MatchedVersion, d.ReadAt, src, pkg = l.reading.Version, l.sw.SeenAt, l.sw.Source, l.reading.Pkg
	}
	if src == "" && ok {
		src = l.sw.Source
	}
	switch {
	case x.Basis == BasisScan:
		d.Basis, d.Verified, d.RangeOrigin = DetectScan, VerifiedScan, RangeScan
	case pkg != "": // the match compared a distribution's package release, whoever read it
		d.Basis, d.RangeOrigin, d.MatchedVersion = DetectPackage, RangeDistro, pkg
	case src == "manual":
		d.Basis = DetectStatement
	case src == "agent" || src == SourceSNMP:
		d.Basis = DetectDeviceVersion
	default:
		d.Basis = DetectBannerVersion
	}
	if d.Verified == "" {
		d.Verified = VerifiedNo
		if ev.deviceStated() {
			d.Verified = VerifiedDevice
		}
	}
	return d
}

// resolve completes a version detection with what the match pass decides from the CVE's data: the origin of the ranges it compared
// and the fix of the line (FixOf, the one resolver). A safe check's detection keeps its own origin; a detection on no line has no fix
// to read (the fix the finding had stays).
func resolve(d *Detection, a Asset, lines map[string]line, v Vuln) {
	d.Urgency = v.StartUrgency()
	if d.Basis != DetectScan && d.Basis != DetectPackage {
		d.RangeOrigin = v.rangeOrigin()
	}
	l, ok := lines[d.SoftwareID]
	if !ok {
		return
	}
	d.Fix = FixOf(a, l.sw, v)
	if d.Basis != DetectScan && d.Basis != DetectPackage {
		if r, ok := schemeJudge(a, l.sw, newSWInfo(l.sw, a.OS), v); ok && r.origin != "" { // the vendor's rows decided it
			d.RangeOrigin = r.origin
		}
	}
	if d.ProductKey == "" {
		d.ProductKey = "unknown"
	}
}

// goneVia says how a finding the match no longer detects went away, from what the device reads now:
//   - its software line is gone: software_removed; a person said it is not installed: not_installed (by that person);
//   - the line reads a newer release than the one matched: version_moved (from, to), unless the reading is a person's correction of
//     what a source reads (a wrong version corrected, nothing changed on the device): data_corrected;
//   - the distribution's fixed package release proves it: distro_fixed;
//   - anything else (range data changed, an answer about the platform): data_corrected.
func goneVia(a Asset, lines map[string]line, f Finding, proofs map[string]Match) (via Via, from, to, by string) {
	l, ok := lines[f.SoftwareID]
	if !ok {
		for _, ni := range a.NotInstalled {
			if ni.ID == f.SoftwareID && f.SoftwareID != "" {
				return ViaNotInstalled, "", "", ni.MarkedBy
			}
		}
		if f.SoftwareID != "" {
			return ViaSoftwareRemoved, "", "", ""
		}
		return ViaDataCorrected, "", "", ""
	}
	cur := l.reading.Version
	if l.reading.Pkg != "" { // a line with a package release is matched on it (detectionOf, scanLine): whatever the basis
		cur = l.reading.Pkg
	}
	if moved(f.MatchedVersion, cur) {
		if l.sw.Source == "manual" && l.sw.ReportedSource != "" {
			return ViaDataCorrected, "", "", "" // a person corrected what a source reads
		}
		return ViaVersionMoved, f.MatchedVersion, cur, ""
	}
	if p, ok := proofs[f.CVE]; ok && p.pkgFixed {
		return ViaDistroFixed, "", "", ""
	}
	return ViaDataCorrected, "", "", ""
}

// moved reports whether cur is a newer release than was: both known, ordered, and not the same release written more or less
// precisely ("10.2" and "10.2p1").
func moved(was, cur string) bool {
	was, cur = strings.TrimSpace(was), strings.TrimSpace(cur)
	if was == "" || cur == "" || was == cur || sameRelease(was, cur) {
		return false
	}
	for _, cmp := range []func(a, b string) (int, bool){debCompare, apkCompare, CompareVersions} {
		if o, ok := cmp(cur, was); ok {
			return o > 0
		}
	}
	return false
}

// sameRelease reports whether one version is the other with more detail after it ("10.2" and "10.2p1 Ubuntu-3").
func sameRelease(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	if !strings.HasPrefix(b, a) {
		return false
	}
	next := b[len(a)]
	return next < '0' || next > '9'
}

// questionsOfMatch is the device's questions as a match gives them: one version_needed per software line that has no version Vedette
// can read, and one per (line, CVE) Vedette could not check.
func questionsOfMatch(m MatchResult) []Question {
	var out []Question
	for _, n := range m.NeedVersion {
		if len(n.CVEs) == 0 {
			continue
		}
		out = append(out, Question{SoftwareID: storedLine(n.SoftwareID), Kind: QuestionVersionNeeded, Cves: len(n.CVEs),
			Detail: QuestionDetail{Software: n.Software, Version: n.Version, CVEList: n.CVEs}})
	}
	for _, u := range m.Unchecked {
		kind := QuestionNoRangeData
		switch u.Reason {
		case UncheckedNotComparable:
			kind = QuestionNotComparable
		case UncheckedPlatformUnknown:
			kind = QuestionPlatform
		case UncheckedPackageUnknown:
			kind = QuestionPackageRelease
		}
		out = append(out, Question{SoftwareID: storedLine(u.SoftwareID), CVE: u.CVE, Kind: kind, Cves: 1,
			Detail: QuestionDetail{Software: u.Software, Version: u.Version, Source: u.Source, Reason: string(u.Reason), NVDPending: u.NVDPending, Choice: u.Answer}})
	}
	return out
}

func countQuestions(ctx context.Context, q querier, assetID string) (int, error) {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT count(*) FROM fnd_question WHERE asset_id = ?`, assetID).Scan(&n); err != nil {
		return 0, fmt.Errorf("findings: counting questions: %w", err)
	}
	return n, nil
}

// ReconcileResult says what a reconcile run did.
type ReconcileResult struct {
	Devices  int // devices matched
	Created  int // findings created that an event had not created
	Closed   int // findings Vedette handled because the data no longer detects them
	Reopened int // findings that opened again
	Orphans  int // devices whose findings were removed because the device no longer exists
	Expired  int // accepted risks whose last day passed
}

// Reconcile heals what a lost event left behind (the bus is best-effort, findings owns the catch-up): it lets time pass for every
// accepted risk (TrTick), then does the work of OnMatchChanged for every device, and removes what findings keeps for a device the
// inventory no longer has. It reads only through Inventory and Feeds, writes one device per transaction (the writer is never held
// for the run), honours ctx between devices, and is idempotent. Findings it creates are written under ServiceConfig.Backlog unless
// their KEV entry is recent (RecentKEV), so a lost baseline is not announced finding by finding. A device list that cannot be read
// is an error before anything is removed. An error on one device is logged and the run goes on; the errors come back together.
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
	ids, err := s.cfg.Inventory.AssetIDs(ctx)
	if err != nil {
		return res, errors.Join(append(failed, fmt.Errorf("findings: reconcile: listing devices: %w", err))...)
	}
	ignored, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile could not read the ignored devices; it matches the watched devices", "error", err)
		failed = append(failed, fmt.Errorf("findings: reconcile: listing ignored devices: %w", err))
	}
	skip := func(id string, err error) error { // a device that failed is logged and skipped; a cancelled run stops
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.cfg.Log.WarnContext(ctx, "findings reconcile skipped a device", "device", id, "error", err)
		failed = append(failed, fmt.Errorf("device %q: %w", id, err))
		return nil
	}
	live := make(map[string]bool, len(ids)+len(ignored))
	for _, id := range ignored { // an ignored device is not gone: its findings stay as they are
		live[id] = true
	}
	assets := make([]Asset, 0, len(ids))
	for _, id := range ids {
		live[id] = true
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
		if ok { // else deleted (or ignored) since the list was read
			assets = append(assets, a)
		}
	}
	pinned, err := s.pinnedCVEs(ctx, "")
	if err != nil {
		return res, errors.Join(append(failed, fmt.Errorf("findings: reconcile: %w", err))...)
	}
	vulns, err := s.cfg.Feeds.MatchSet(ctx, NewMatchScope(assets, pinned))
	if err != nil {
		return res, errors.Join(append(failed, fmt.Errorf("findings: reconcile: reading the catalogue: %w", err))...)
	}
	set := newMatchSet(vulns)
	for _, a := range assets {
		if len(vulns) == 0 {
			break // no catalogue loaded yet: nothing can match
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		up, err := s.upsertSplit(ctx, a, set)
		if err != nil {
			if err := skip(a.ID, err); err != nil {
				return res, err
			}
			continue
		}
		res.Devices++
		res.Created += len(up.Created)
		res.Closed += up.Closed
		res.Reopened += up.Reopened
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
		if _, err := s.deleteWithin(ctx, id); err != nil {
			if err := skip(id, err); err != nil {
				return res, err
			}
			continue
		}
		res.Orphans++
	}
	// The layers at once: a CVE that joined a list in this pass is told now, by the one rule (Tell)
	if _, err := s.RateUrgency(ctx, ""); err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		failed = append(failed, fmt.Errorf("findings: reconcile: rating urgency: %w", err))
	}
	// One line per run, so a box's log shows the pass ran and what it changed (the job's own line is debug).
	s.cfg.Log.InfoContext(ctx, "findings: reconcile pass done", "devices", res.Devices, "created", res.Created, "handled_by_vedette", res.Closed,
		"reopened", res.Reopened, "devices_removed", res.Orphans, "risk_acceptances_expired", res.Expired)
	return res, errors.Join(failed...)
}

// expireAcceptances lets time pass for every accepted risk whose last day is over (TrTick), in one write: it opens again while the
// data still detects it. A finding of a device a person ignored keeps its acceptance until the device is watched again: no alert
// about a device nobody watches. It returns how many changed.
func (s *Service) expireAcceptances(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	unwatched := map[string]bool{}
	if ids, err := s.cfg.Inventory.IgnoredIDs(ctx); err == nil {
		for _, id := range ids {
			unwatched[id] = true
		}
	}
	n := 0
	err := s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		n = 0
		fs, err := queryFindings(ctx, tx, `state = 'handled' AND resolution = 'accepted' AND accepted_until < ?`, dayOf(now).Format(time.DateOnly))
		if err != nil {
			return err
		}
		for _, f := range fs {
			if unwatched[f.AssetID] {
				continue
			}
			_, evs, err := s.step(ctx, tx, f, false, Trigger{Kind: TrTick, At: now}, emit)
			if err != nil {
				return err
			}
			if len(evs) > 0 {
				n++
			}
		}
		return nil
	})
	return n, err
}

// splitIdx separates the entries whose findings are announced (added to an exploited list within RecentKEV) from the backlog: an
// older entry, and a catalogue CVE on no list, whose findings are written silently (the urgency pass says what is urgent).
// Without a Backlog hook everything is "recent": nothing can be marked, so nothing is held back.
// It returns indexes into vulns; backlog is nil without a Backlog hook.
func (s *Service) splitIdx(vulns []Vuln) (backlog, recent []int) {
	if s.cfg.Backlog == nil {
		recent = make([]int, len(vulns))
		for i := range vulns {
			recent[i] = i
		}
		return nil, recent
	}
	cut := s.now().Add(-RecentKEV)
	for i, v := range vulns {
		if v.DateAdded.IsZero() || v.DateAdded.Before(cut) {
			backlog = append(backlog, i)
		} else {
			recent = append(recent, i)
		}
	}
	return backlog, recent
}

// pick is the entries idx of vulns, in order; nil for none.
func pick(vulns []Vuln, idx []int) []Vuln {
	if len(idx) == 0 {
		return nil
	}
	out := make([]Vuln, len(idx))
	for k, i := range idx {
		out[k] = vulns[i]
	}
	return out
}

// judgedParts is, for the whole set of one pass, the CVEs of its backlog and of its recent entries (splitIdx): each write of a
// device judges the findings of its part's CVEs. Read once per pass, not once per device.
func (s *Service) judgedParts(set *matchSet) (backlog, recent map[string]bool) {
	set.splitOnce.Do(func() {
		cves := func(idx []int) map[string]bool {
			out := make(map[string]bool, len(idx))
			for _, i := range idx {
				out[set.vulns[i].CVE] = true
			}
			return out
		}
		b, r := s.splitIdx(set.vulns)
		if b != nil {
			set.backlog = cves(b)
		}
		set.recent = cves(r)
	})
	return set.backlog, set.recent
}

// cveSet is the CVEs of vulns.
func cveSet(vulns []Vuln) map[string]bool {
	out := make(map[string]bool, len(vulns))
	for _, v := range vulns {
		out[v.CVE] = true
	}
	return out
}

// upsertSplit matches one device against the entries of set that can concern it, in two writes, the backlog under the Backlog mark.
// Each write judges every finding of the device whose CVE is in its part of the whole set (a CVE the device no longer runs a product
// of is gone), and both store the questions of the whole match (each write replaces them).
func (s *Service) upsertSplit(ctx context.Context, a Asset, set *matchSet) (UpsertResult, error) {
	var sum UpsertResult
	dev := set.forDevice(a)
	a.winList = dev // A Windows build's month is read from the device's whole list in both writes
	// The device's rows are read once and each entry once: the whole match (its questions: which findings exist does not change them)
	// and each write's match of its part are assembled from the same readings (devMatch).
	dm := newDevMatch(a, dev, s.now())
	whole := dm.result(nil, nil)
	allBacklog, allRecent := s.judgedParts(set)
	backlog, recent := s.splitIdx(dev)
	add := func(wctx context.Context, part []int, judged map[string]bool) error {
		if len(judged) == 0 {
			return nil
		}
		wctx, cancel := context.WithTimeout(wctx, eventWriteTimeout)
		defer cancel()
		r, err := s.upsertPart(wctx, a, pick(dev, part), judged, &whole, true, &partMatch{dm: dm, idx: part})
		sum.Created = append(sum.Created, r.Created...)
		sum.Touched += r.Touched
		sum.Closed += r.Closed
		sum.Reopened += r.Reopened
		sum.Questions = r.Questions
		return err
	}
	if len(allBacklog) > 0 {
		if err := add(s.cfg.Backlog(ctx), backlog, allBacklog); err != nil {
			return sum, err
		}
	}
	return sum, add(ctx, recent, allRecent)
}

func (s *Service) deleteWithin(ctx context.Context, id string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, eventWriteTimeout)
	defer cancel()
	return s.deleteAsset(ctx, id)
}

// orphanAssets lists the devices that have findings or questions but are not in live, in id order.
func (s *Service) orphanAssets(ctx context.Context, live map[string]bool) ([]string, error) {
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT asset_id FROM fnd_finding UNION SELECT asset_id FROM fnd_question ORDER BY asset_id`)
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
// starts, then every ReconcileEvery; plan when the module starts, then every PlanEvery; urgency (UrgencyJob) when the module starts,
// then every UrgencyEvery.
func Jobs(svc *Service) []jobs.Job {
	return []jobs.Job{{Module: "findings", Name: "reconcile", Every: ReconcileEvery, Run: func(ctx context.Context) error {
		_, err := svc.Reconcile(ctx)
		return err
	}}, {Module: "findings", Name: "plan", Every: PlanEvery, Run: func(ctx context.Context) error {
		return svc.RefreshPlan(ctx)
	}}, {Module: "findings", Name: UrgencyJob, Every: UrgencyEvery, Run: func(ctx context.Context) error {
		r, err := svc.RateUrgency(ctx, "")
		svc.cfg.Log.InfoContext(ctx, "findings: urgency pass done", "rated", r.Rated, "raised", r.Raised, "lowered", r.Lowered, "announced", r.Announced)
		return err
	}}}
}
