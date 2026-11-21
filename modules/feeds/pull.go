package feeds

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/winrel"
)

// Pull schedule.
const (
	// PullEvery is how often the pull job looks for feeds that are due. Each feed keeps its own interval and
	// back-off (State); this only bounds how late a due pull can start, so INV-9 (interval + 60 min) holds.
	PullEvery = 5 * time.Minute
	// pullBudget bounds one whole pull (an EPSS pull makes up to dozens of requests).
	pullBudget = 10 * time.Minute
)

// ErrFeedDisabled is returned by Fetch for a feed that is turned off (INV-8, FORBID-3).
var ErrFeedDisabled = errors.New("feeds: the feed is turned off")

// Jobs returns the pull job of the module for the scheduler. The scheduler runs it only while the module is on.
func (s *Service) Jobs() []jobs.Job {
	return []jobs.Job{{Module: "feeds", Name: "pull", Every: PullEvery, Run: s.RunPull}}
}

// RunPull is one tick of the pull job: every enabled feed that is due (INV-8, INV-9: State.Due with the feed's
// interval and its back-off after errors; nvd-recent with an unfinished pull, and a feed whose stored data this code reads again
// (INV-32), only its back-off) is pulled in turn,
// vulnerabilities first. A failed pull is recorded on
// the feed and never fails the job; only a cancelled context or a database failure does.
func (s *Service) RunPull(ctx context.Context) error {
	now := s.now()
	rows, err := s.sources(ctx)
	if err != nil {
		return err
	}
	pulled := false
	var kevPulled *sourceRow
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		if pulled { // an earlier pull of this tick may have filled it (EPSS after the CISA list); a tick that pulled nothing reads no row twice
			if cur, err := s.st.source(ctx, r.ID); err == nil {
				r = cur
			}
		}
		due := r.state().Due(now, r.IntervalHours)
		if r.ID == recentFeedID && r.Enabled { // An unfinished fill or walk goes on now, not a day after the last success
			owed, err := s.st.recentOwed(ctx, r.URL)
			if err != nil { // the plain schedule this tick, as the re-read above falls back
				s.Log.ErrorContext(ctx, "reading where the NVD pull of the catalogue stands failed", "error", err)
			} else if owed {
				st := r.state()
				st.LastSuccess = time.Time{} // only the back-off after failures holds it back
				due = st.Due(now, r.IntervalHours)
			}
		}
		if r.ID == cveOrgFeedID && r.Enabled && r.Failures == 0 { // The whole list is loading: it goes on at the next check
			if owed, err := s.st.recordsOwed(ctx, r.URL); err != nil {
				s.Log.ErrorContext(ctx, "reading where the CVE records stand failed", "error", err)
			} else if owed {
				due = true
			}
		}
		if at, paused := s.nvdResumeAt(); paused && r.ID == nvdFeedID {
			due = !now.Before(at) // a paused NVD pull goes on when it said it would
		}
		if r.ID == recentFeedID && now.Before(s.recentResumeAt()) {
			due = false // nvd-recent waits out NVD's busy answer as its progress line says (review r2 #6 of #802)
		}
		if !due && r.Enabled && distroFeeds[r.ID] && r.Failures == 0 && !s.busy(r.ID) && s.distroBehind(ctx, r) {
			due = true // A device runs a package its tier rows were not kept for (6 h floor); a failing feed keeps its back-off
		}
		if !r.Enabled || !due || s.busy(r.ID) { // busy: a "Fetch now" is pulling it; never a second pull
			continue
		}
		pulled = true
		row, err := s.pull(ctx, r.ID, "") // pull brings the EPSS scores after a CISA list load
		if r.ID == kevFeedID && err == nil {
			kevPulled = &row // Only the job's own checks count toward the run of both-failed checks
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, ErrFeedDisabled) || errors.Is(err, ErrNotFound) { // changed since the list was read
			continue
		}
		if err != nil { // a database failure: the feed's own error state could not be written either
			s.Log.ErrorContext(ctx, "pulling a feed failed", "feed", r.ID, "error", err)
			continue
		}
	}
	if err := s.watchKEV(ctx, kevPulled); err != nil && ctx.Err() == nil { // After the pulls, so a box that was off pulls before it judges
		s.Log.ErrorContext(ctx, "the stale watch of the CISA list failed", "error", err)
	}
	if err := s.reconcileDevices(ctx); err != nil && ctx.Err() == nil {
		s.Log.ErrorContext(ctx, "adding the devices of \"I have it\" failed", "error", err)
	}
	if err := s.maintain(ctx, now); err != nil && ctx.Err() == nil { // a stop in the middle of it is a shutdown, not a failure
		s.Log.ErrorContext(ctx, "pruning feed data failed", "error", err)
	}
	return nil
}

// Fetch pulls one feed now (PRE-1: the feed is on; its address passes INV-2 inside the fetcher). A failed pull is
// recorded on the feed (status error) and is not an error here; ErrFeedDisabled and ErrNotFound are.
func (s *Service) Fetch(ctx context.Context, feedID string) error {
	_, err := s.pull(ctx, feedID, "")
	return err
}

// pullPlan is what a pull learned and has to write in one transaction (INV-3: nothing is written for a rejected pull).
type pullPlan struct {
	out outcome

	vulns        []Vuln
	replaceVulns bool
	hasVulns     bool

	templates    []Template
	hasTemplates bool

	nvd    []NVDRecord // nvd-kev: the records of the exploited-list selector, written into the catalogue
	hasNVD bool

	// kevRanges are the exploited-list CVEs whose ranges a pull of nvd-recent or cve-org changed (they write as they go), kevRangesFirst
	// whether none of them had an answer before the pull.
	kevRanges      []string
	kevRangesFirst bool

	iocs    []iocInput
	hasIOCs bool

	distro     []DistroFix     // ubuntu-osv, ubuntu-vex, debian-tracker, alpine-osv: the feed's rows, replaced whole
	distroKEV  map[string]bool // the CISA list's CVEs: only their changed rows are news for findings
	distroKeep []string        // the packages the tier rows were kept for (distroKeep); nil: no tier row
	hasDistro  bool

	epssAll    []EPSSAllScore // epss-all: every CVE's score, written in chunks (applyEPSSAll)
	hasEPSSAll bool
	epssDay    string // epss-all: FIRST's day of the scores (YYYY-MM-DD), "" when the file does not say

	winRel    []winrel.Release // windows-releases: the releases Microsoft's pages list, replaced whole
	winRelUpd []winrel.Update  // windows-releases: the monthly updates of the pages read, replaced per release
	hasWinRel bool

	signals    []publicSignal // metasploit, exploit-db, poc-in-github: the index's CVEs, replaced whole (applyPublicSignals)
	hasSignals bool

	vendor    vendorRead // msrc, cisco-psirt, fortinet-psirt: the vendor's exploitation claims (applyVendorClaims)
	hasVendor bool
	vendorMem *advisoryMemory // cisco-psirt, fortinet-psirt: what the box read of each advisory, kept once the claims are written
}

func (s *Service) get(ctx context.Context, req Request) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()
	return s.Fetcher.Fetch(ctx, req)
}

func (s *Service) authFor(ctx context.Context, src sourceRow) (Auth, error) {
	a := Auth{Type: src.Auth}
	if src.Auth == AuthNone || src.Auth == "" {
		return a, nil
	}
	if src.HeaderName != nil {
		a.HeaderName = *src.HeaderName
	}
	if src.Username != nil {
		a.Username = *src.Username
	}
	if src.SecretID == nil {
		return Auth{}, fail(ErrInvalidAuth, "The feed has no secret saved. Edit the feed and enter it again.")
	}
	plain, err := s.Secrets.Open(ctx, s.DB.Reader(), *src.SecretID, secretPurpose)
	if err != nil {
		s.Log.ErrorContext(ctx, "opening a feed secret failed", "feed", src.ID, "error", err)
		return Auth{}, fail(ErrInvalidAuth, "The saved secret could not be read. Edit the feed and enter it again.")
	}
	sec, err := NewSecret(string(plain))
	if err != nil {
		return Auth{}, err
	}
	a.Secret = sec
	return a, nil
}

// userError is the sentence stored on a feed after a failed pull and shown in Settings -> Feeds: what
// went wrong, without addresses (they may carry a token) or internals.
func userError(err error, rawURL string) string {
	host := ""
	if u, perr := url.Parse(rawURL); perr == nil {
		host = u.Hostname()
	}
	var (
		fe  *Error
		se  *StatusError
		dns *net.DNSError
	)
	switch {
	case errors.As(err, &fe):
		return fe.Detail
	case errors.As(err, &se):
		return fmt.Sprintf("The source answered HTTP %d.", se.Code)
	case errors.Is(err, ErrBoxAddrsUnknown):
		return "Vedette does not know its own addresses yet, so it did not connect. It will try again at the next pull."
	case errors.Is(err, ErrOwnAddress):
		return ownText
	case errors.Is(err, ErrBlockedAddress):
		return blockedText
	case errors.Is(err, context.DeadlineExceeded):
		return "The source did not answer in time."
	case errors.As(err, &dns):
		return fmt.Sprintf("Could not resolve %s. Check the address.", host)
	}
	return fmt.Sprintf("Could not reach %s.", host)
}

// accepted turns a parse with no accepted row into an error, so a pull never replaces data with nothing.
func accepted(st Stats) error {
	if st.Accepted > 0 {
		return nil
	}
	if st.Rejected > 0 && len(st.Reasons) > 0 {
		return fail(ErrBadSample, "All %s rows were rejected: %s.", grouped(st.Rejected), mostOften(st.Reasons[0]))
	}
	return fail(ErrBadSample, "The feed returned no records.")
}

// note is the status line of an ok pull that dropped rows: the counts as the GUI writes numbers (fmtNumber,
// en-GB), the most common reason with one row of it as a sample (mostOften, INV-3) and why that is fine.
func note(st Stats) string {
	if st.Rejected == 0 {
		return ""
	}
	m := fmt.Sprintf("%s of %s rows were rejected.", grouped(st.Rejected), grouped(st.Accepted+st.Rejected))
	if len(st.Reasons) > 0 {
		m += fmt.Sprintf(" Most often: %s.", mostOften(st.Reasons[0]))
	}
	return m + " A few bad lines in a public list are normal; they are skipped."
}

// mostOften is a reason for the status line: its first row with the value shown (quoteVal: at most 40 UTF-16 units,
// unprintable runes as spaces, quoted), so the admin sees what was rejected; the masked template when
// there is no example ("other").
func mostOften(r Reason) string {
	if r.Example != "" {
		return r.Example
	}
	return r.Reason
}

// grouped writes n with a comma every three digits (185987 -> "185,987").
func grouped(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// build runs one pull of src against the network and the parsers and returns what to write. An error is the
// failure of the pull (its text goes through userError).
func (s *Service) build(ctx context.Context, src sourceRow) (pullPlan, error) {
	var p pullPlan
	dec, builtin := DecoderParser, Source{}
	if src.Builtin {
		b, ok := BuiltinByID(src.ID)
		if !ok {
			return p, fail(ErrBadConfig, "This built-in feed is no longer part of Vedette.")
		}
		dec, builtin = b.Decoder, b
	}
	switch dec {
	case DecoderNVD:
		return s.buildNVD(ctx, src, p)
	case DecoderCVEOrg:
		return s.buildCVERecords(ctx, src, p)
	case DecoderVulnCheck:
		return s.buildVulnCheck(ctx, src, p)
	case DecoderUbuntuOSV, DecoderUbuntuVEX, DecoderDebianTracker, DecoderAlpineOSV:
		return s.buildDistro(ctx, src, p, dec)
	case DecoderEPSSAll:
		return s.buildEPSSAll(ctx, src, p)
	case DecoderNVDRecent:
		return s.buildRecent(ctx, src, p)
	case DecoderWinRel:
		return s.buildWinRel(ctx, src, p)
	case DecoderMetasploit, DecoderExploitDB, DecoderPoCGitHub:
		return s.buildPublicExploit(ctx, src, p, dec)
	case DecoderMSRC:
		return s.buildMSRC(ctx, src, p)
	case DecoderCisco:
		return s.buildCisco(ctx, src, p)
	case DecoderFortinet:
		return s.buildFortinet(ctx, src, p)
	}
	auth, err := s.authFor(ctx, src)
	if err != nil {
		return p, err
	}
	if src.ID == kevFeedID && src.URL == s.kevPrimary() { // Both copies of the CISA list, every check
		return s.buildKEVBoth(ctx, src, p)
	}
	// Conditional only after a good pull: a list pulled every hour stays cheap with a 304.
	req := Request{URL: src.URL, Auth: auth}
	if src.Status == "ok" {
		req.ETag, req.LastModified = orEmpty(src.ETag), orEmpty(src.LastModified)
	}
	resp, err := s.get(ctx, req)
	if err != nil {
		return p, err
	}
	if resp.NotModified {
		p.out = outcome{OK: true, NotModified: true, ETag: req.ETag, LastModif: req.LastModified}
		return p, nil
	}
	p.out = outcome{OK: true, Bytes: len(resp.Body), ETag: resp.ETag, LastModif: resp.LastModified}
	switch dec {
	case DecoderKEV:
		cat, err := ParseKEV(resp.Body)
		if err != nil {
			return p, err
		}
		if err := accepted(cat.Stats); err != nil {
			return p, err
		}
		p.vulns, p.hasVulns = cat.Vulns, true
		p.out.fill(cat.Stats, cat.Accepted)
		p.out.CatalogVersion, p.out.CatalogReleased = cat.Version, cat.ReleasedAt
	case DecoderNuclei:
		n, err := ParseNucleiCVEs(resp.Body)
		if err != nil {
			return p, err
		}
		if err := accepted(n.Stats); err != nil {
			return p, err
		}
		// a cut or substituted index must not take the public-exploit signal from the CVEs it no longer names: the retention rule would
		// then drop thousands of older CVEs, which come back only slowly once the index is whole again. The yardstick is the last good
		// pull from this address (feeds_source.records: cleared by a new address or by turning the feed off and on), and an index at or
		// above nucleiFloor is always taken.
		if n, held := len(n.Templates), src.Records; held != nil && *held >= nucleiShrinkFloor && 2*n < *held && n < nucleiFloor {
			return p, fail(ErrBadSample, "The nuclei index lists %s CVEs, fewer than half of the %s of the last good index; Vedette kept the templates it had. To take this index anyway, turn the feed off and on again.", grouped(n), grouped(*held))
		}
		p.templates, p.hasTemplates = n.Templates, true
		p.out.fill(n.Stats, len(n.Templates))
	default: // DecoderParser: the built-in IOC lists and every custom feed
		var res Result
		if src.Builtin {
			res, err = ParseSource(ctx, builtin, resp.Body)
		} else {
			res, err = ParseFeed(ctx, resp.Body, src.Kind, *src.Parser)
		}
		if err != nil {
			return p, err
		}
		st := res.Stats
		var vulns []Vuln
		if src.Kind == KindVulnerabilities {
			var long int
			if vulns, long = vulnsOf(res.Records); long > 0 { // fail-closed: such a row is rejected with its reason
				st.Accepted -= long
				st.Rejected += long
				st.Reasons = append(slices.Clone(st.Reasons), Reason{Reason: "vendor or product: longer than 200 characters", Count: long})
			}
		}
		if err := accepted(st); err != nil {
			return p, err
		}
		p.out.fill(st, st.Accepted)
		if src.Kind == KindVulnerabilities {
			p.vulns, p.hasVulns, p.replaceVulns = vulns, true, true
		} else {
			p.iocs, p.hasIOCs = iocsOf(res.Records), true
		}
	}
	return p, nil
}

func (o *outcome) fill(st Stats, records int) {
	o.Accepted, o.Rejected, o.Reasons, o.Records, o.Note = st.Accepted, st.Rejected, st.Reasons, records, note(st)
}

// vulnsOf maps the records of a custom vulnerability feed (fields cve, vendor, product, date, description, link).
// A feed that gives no vendor or product is filed under "Unknown"; a vendor or product over 200 characters (or a
// key over 500) is not stored and is counted in tooLong, so the key CHECKs can never fail.
func vulnsOf(recs []Record) (out []Vuln, tooLong int) {
	out = make([]Vuln, 0, len(recs))
	for _, r := range recs {
		v := Vuln{CVE: str(r["cve"]), Vendor: str(r["vendor"]), Product: str(r["product"]), Description: str(r["description"]), DateAdded: str(r["date"]), Links: []string{}}
		if utf8.RuneCountInString(v.Vendor) > maxVendorProduct || utf8.RuneCountInString(v.Product) > maxVendorProduct || utf8.RuneCountInString(v.Key()) > maxProductKey {
			tooLong++
			continue
		}
		if v.Vendor == "" {
			v.Vendor = "Unknown"
		}
		if v.Product == "" {
			v.Product = "Unknown"
		}
		v.Name = v.CVE
		if l := str(r["link"]); l != "" {
			v.Links = append(v.Links, l)
		}
		out = append(out, v)
	}
	return out, tooLong
}

func iocsOf(recs []Record) []iocInput {
	out := make([]iocInput, 0, len(recs))
	for _, r := range recs {
		in := iocInput{Kind: str(r["kind"]), Value: str(r["indicator"]), FirstSeen: str(r["first_seen"])}
		if c, ok := r["confidence"].(float64); ok {
			in.Confidence = &c
		}
		out = append(out, in)
	}
	return out
}

// errStoreFailed is the sentence stored on a feed when its result could not be written (a database problem).
const errStoreFailed = "The result could not be stored. Check the disk space and the box logs."

// pullOne runs one pull of one feed under the feed's lock and writes its result in one transaction (with a core_audit
// row when a person started it: actor is their email). It returns the feed as stored afterwards (not as shown: live) and how many CVEs
// of the CISA list were new. A pull whose feed was edited, turned off or deleted while it ran writes nothing (the
// row is re-read inside the transaction and its rev compared): deleted is ErrNotFound, the others return the feed
// as it is. A failed pull is recorded on the feed; if even that fails to store, a second short transaction records
// the failure. Only a context error, ErrNotFound, ErrFeedDisabled or a database that cannot record anything is an error.
func (s *Service) pullOne(ctx context.Context, id, actor string) (sourceRow, int, []events.Event, error) {
	if err := s.ready(ctx); err != nil {
		return sourceRow{}, 0, nil, err
	}
	release, joined, err := s.lockFeed(ctx, id)
	if err != nil {
		return sourceRow{}, 0, nil, err
	}
	if joined { // another pull of this feed ran while this one waited: its result is the answer, not a second pull
		row, err := s.st.source(ctx, id)
		return row, 0, nil, err
	}
	defer release()
	src, err := s.st.source(ctx, id)
	if err != nil {
		return sourceRow{}, 0, nil, err
	}
	if !src.Enabled {
		return sourceRow{}, 0, nil, ErrFeedDisabled
	}
	started := s.now()
	bctx, cancel := context.WithTimeout(ctx, pullBudget)
	p, perr := s.build(bctx, src)
	cancel()
	if perr != nil && ctx.Err() != nil {
		return sourceRow{}, 0, nil, ctx.Err() // cancelled (module turned off, shutdown): not a failure of the feed
	}
	if errors.Is(perr, ErrBoxAddrsUnknown) { // Not a failure of the feed: nothing is recorded, no back-off, the feed stays due
		if s.unknownLogged.CompareAndSwap(false, true) {
			s.Log.DebugContext(ctx, "feed pull waits: the box's own addresses are not known yet", "feed", src.ID)
		}
		return src, 0, nil, nil
	}
	if errors.Is(perr, errNVDPaused) { // The pages so far are kept and the pull goes on later; nothing is written
		return src, 0, nil, nil
	}
	if errors.Is(perr, errDistroWaits) || errors.Is(perr, errDistroNoDevice) { // No CISA list yet; no device needs it. Nothing to keep; the feed stays due
		return src, 0, nil, nil
	}
	if perr != nil {
		s.Log.WarnContext(ctx, "feed pull failed", "feed", src.ID, "name", src.Name, "error", perr) // the name too: an admin knows the feed by it
		p = pullPlan{out: outcome{Err: userError(perr, src.URL), Copies: p.out.Copies}}             // what each copy of the CISA list said is kept
	}
	p.out.Started, p.out.Finished = started, s.now()

	var (
		fresh          []VulnRow
		changed        []string
		added, removed int
		stale          bool
		baseline       bool // the CISA list filled an empty table: one baseline event, not one per CVE
		rangesChanged  []string
		rangesFirst    bool
	)
	pinned, err := s.pinned(ctx) // the catalogue keeps them, whatever an NVD pull brings
	if err != nil {
		return sourceRow{}, 0, nil, err
	}
	// the outcome row and the audit entry, in the pull's last transaction; the note is the pull's own (what the feed holds is
	// counted when the row is read: heldNow)
	finish := func(tx *sql.Tx, out outcome) error {
		if err := recordOutcome(ctx, tx, src.ID, out); err != nil {
			return err
		}
		if actor == "" {
			return nil
		}
		detail := fmt.Sprintf("%d records", out.Records)
		if !out.OK {
			detail = out.Err
		}
		return s.Audit.Append(ctx, tx, audit.Entry{User: actor, Action: "feeds.fetch", Target: src.Name, Detail: detail})
	}
	write := func(p pullPlan) error {
		fresh, changed, added, removed, stale, baseline, rangesChanged, rangesFirst = nil, nil, 0, 0, false, false, nil, false
		if p.hasIOCs { // a long list: chunks, not one transaction that holds the writer (applyIOCs)
			var err error
			added, removed, stale, err = applyIOCs(ctx, s.DB, p.out.Finished, src, p.iocs, s.afterChunk, func(tx *sql.Tx, _, _ int) error { return finish(tx, p.out) })
			return err
		}
		if p.hasEPSSAll { // 400,000 rows: chunks too (applyEPSSAll)
			var err error
			stale, err = applyEPSSAll(ctx, s.DB, p.out.Finished, src, p.epssAll, p.epssDay, func(tx *sql.Tx) error { return finish(tx, p.out) })
			return err
		}
		return s.DB.Write(ctx, func(tx *sql.Tx) error {
			cur, err := sourceTx(ctx, tx, src.ID)
			if err != nil {
				return err // ErrNotFound: deleted meanwhile
			}
			if cur.Rev != src.Rev || !cur.Enabled { // edited or switched off meanwhile: this result is about old settings
				stale = true
				return nil
			}
			switch {
			case p.hasVulns:
				var updated []string
				if isKEVSource(src.ID) {
					var have int
					if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM feeds_kev WHERE source_id = ?`, src.ID).Scan(&have); err != nil {
						return fmt.Errorf("feeds: count KEV rows: %w", err)
					}
					baseline = have == 0
					if src.ID == vulnCheckFeedID { // first fill = the first good pull since the key was saved, not "no rows" (they can all be CISA's now)
						baseline = cur.LastSuccess == nil
					}
				}
				if fresh, updated, err = applyVulns(ctx, tx, p.out.Finished, src.ID, p.vulns, p.replaceVulns); err != nil {
					return err
				}
				// the entries this pull announces as new (below, after the commit) are recorded with it
				if src.ID == kevFeedID && !baseline {
					if err := markAnnounced(ctx, tx, fresh, p.out.Finished); err != nil {
						return err
					}
				}
				changed = append(changed, updated...)
			case p.hasTemplates:
				if changed, err = applyTemplates(ctx, tx, p.out.Finished, p.templates); err != nil {
					return err
				}
			case p.hasNVD:
				before, err := kevNVDCountTx(ctx, tx)
				if err != nil {
					return err
				}
				rangesFirst = before == 0
				ret, err := retentionOf(ctx, tx, p.out.Finished, pinned)
				if err != nil {
					return err
				}
				w, err := writeNVDRecords(ctx, tx, p.nvd, ret, p.out.Finished)
				if err != nil {
					return err
				}
				rangesChanged = w.KEVChanged
				if p.out.Records, err = kevNVDCountTx(ctx, tx); err != nil { // the exploited CVEs NVD answered for, not only this (incremental) pull's
					return err
				}
			case p.hasDistro:
				if rangesChanged, rangesFirst, err = applyDistro(ctx, tx, src.ID, p.distro); err != nil {
					return err
				}
				// a tier CVE's rows change only "Updates to plan", which TierStamp reaches: findings rematches as before
				rangesChanged = slices.DeleteFunc(rangesChanged, func(c string) bool { return !p.distroKEV[c] })
				var kept any // the packages the rows were kept for, with the rows (distroBehind, covered of TierDistroRecords)
				if p.distroKeep != nil {
					b, err := json.Marshal(p.distroKeep)
					if err != nil {
						return fmt.Errorf("feeds: distro packages: %w", err)
					}
					kept = string(b)
				}
				if _, err = tx.ExecContext(ctx, `UPDATE feeds_source SET distro_packages = ? WHERE id = ?`, kept, src.ID); err != nil {
					return fmt.Errorf("feeds: distro print: %w", err)
				}
			case p.hasSignals:
				if err := applyPublicSignals(ctx, tx, p.out.Finished, src.ID, p.signals); err != nil {
					return err
				}
			case p.hasVendor:
				if p.out.Records, err = applyVendorClaims(ctx, tx, p.out.Finished, prevGood(src), src.ID, p.vendor); err != nil {
					return err
				}
			case p.hasWinRel: // findings matches the Windows entries again when the releases changed
				if rangesChanged, rangesFirst, err = applyWinRel(ctx, tx, p.winRel, p.winRelUpd); err != nil {
					return err
				}
			case len(p.kevRanges) > 0: // nvd-recent and cve-org stored as they went: the exploited-list CVEs whose ranges changed are news
				// (ranges of CVEs read for the first time are backlog; a new CISA entry still alerts by its own new_kev event)
				rangesChanged, rangesFirst = p.kevRanges, p.kevRangesFirst
			}
			return finish(tx, p.out)
		})
	}
	err = write(p)
	switch {
	case errors.Is(err, ErrNotFound):
		return sourceRow{}, 0, nil, ErrNotFound
	case err != nil && ctx.Err() != nil:
		return sourceRow{}, 0, nil, ctx.Err()
	case err != nil:
		// The data could not be stored: leave a trace on the feed (error text, back-off) in a small transaction
		// that touches nothing else, so Settings shows it and the job does not hit the source on every tick.
		s.Log.ErrorContext(ctx, "storing a pull failed", "feed", src.ID, "error", err)
		p = pullPlan{out: outcome{Err: errStoreFailed, Started: started, Finished: s.now()}}
		if err2 := write(p); err2 != nil {
			return sourceRow{}, 0, nil, fmt.Errorf("feeds: recording the failure of a pull: %w", errors.Join(err, err2))
		}
	}
	if p.hasWinRel && p.out.OK && !stale { // every good pull, before the event: findings reads the new releases (review r1 L1 of #951)
		if err := s.LearnWindowsReleases(ctx); err != nil {
			s.Log.ErrorContext(ctx, "reading the Windows releases failed", "error", err)
		}
	}
	if p.vendorMem != nil && p.out.OK && !stale {
		s.keepAdvisories(src.ID, p.vendorMem)
	}
	row, rerr := s.st.source(ctx, id)
	if stale || rerr != nil {
		return row, 0, nil, rerr
	}

	var evs []events.Event
	emit := func(name string, data any) { evs = append(evs, events.Event{Name: name, Data: data}) }
	kev := 0
	if isKEVSource(src.ID) { // only the CISA list and VulnCheck KEV make KEV events; a custom feed's CVEs are not KEV entries
		kev = len(fresh)
		if baseline {
			if kev > 0 {
				emit(EventSyncBaseline, SyncBaselineEvent{Source: src.ID, Count: kev})
			}
		} else {
			for _, v := range fresh {
				emit(EventNewKEV, NewKEVEvent{CVE: v.CVE, Vendor: v.Vendor, Product: v.Product, HasTemplate: v.HasTemplate, DateAdded: v.DateAdded})
			}
		}
	}
	if len(changed) > 0 && (isKEVSource(src.ID) || p.hasTemplates) {
		emit(EventVulnUpdated, VulnUpdatedEvent{CVEs: changed})
	}
	if added > 0 || removed > 0 {
		emit(EventIOCUpdated, IOCUpdatedEvent{FeedID: src.ID, Added: added, Removed: removed})
	}
	if len(rangesChanged) > 0 {
		slices.Sort(rangesChanged)
		emit(EventRangesUpdated, RangesUpdatedEvent{CVEs: rangesChanged, First: rangesFirst})
	}
	if !p.out.OK {
		emit(EventFetchFailed, FetchFailedEvent{FeedID: src.ID, Error: p.out.Err})
	}
	return row, kev, evs, nil
}

// pull is pullOne plus the rule that every load of the CISA list brings the NVD records and the CVE records of its new
// entries with it, whoever started it (the job or "Fetch now"): new CVEs get their versions now, not in a day. A feed
// that is off is left alone; NVD failing is its own feed's status, not the list's. (Every CVE's EPSS score is already on
// the box: epss-all holds them all.)
//
// The events of the CISA list (new_kev, baseline, updated) go out only after those pulls: the devices are matched
// once, against the new entry's NVD versions, so a ransomware CVE inside the range alerts as critical at once, and a
// device outside every range gets no alert at all. The events of the other pulls follow those of the list.
func (s *Service) pull(ctx context.Context, id, actor string) (sourceRow, error) {
	row, fresh, evs, err := s.pullOne(ctx, id, actor)
	if err == nil && isKEVSource(id) && row.Status == "ok" {
		deps := []string{nvdFeedID, cveOrgFeedID} // CVE.org after NVD: only what NVD left without ranges
		if id == vulnCheckFeedID {
			deps = []string{cveOrgFeedID} // VulnCheck's entries get the CNA's ranges at once; NVD's selector answers for the CISA list only
		}
		for _, dep := range deps {
			if s.busy(dep) {
				continue // already being pulled (a person's "Fetch now"): never a second pull of it
			}
			e, err := s.st.source(ctx, dep)
			if err != nil || !e.Enabled || (fresh == 0 && e.Records != nil && *e.Records > 0) {
				continue
			}
			// a paused NVD pull keeps the wait NVD asked for (busy, Retry-After): the list does not make it ask sooner (review LOW)
			if at, paused := s.nvdResumeAt(); dep == nvdFeedID && paused && s.now().Before(at) {
				continue
			}
			dctx := ctx
			if dep == cveOrgFeedID { // only the records of the new entries, by ID: no download holds the list's alerts back
				dctx = context.WithValue(ctx, urgentOnlyKey{}, true)
			}
			_, _, more, err := s.pullOne(dctx, dep, "")
			evs = append(evs, more...)
			if err != nil && ctx.Err() != nil {
				break
			}
		}
	}
	for _, e := range evs {
		s.publish(ctx, e.Name, e.Data)
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return row, err
}

// isTimeout is a pull that got no answer in time.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

// unreached says how the box failed to get to the server at all, as words that follow its name ("cisa.gov refused the connection");
// "" for any other failure.
func unreached(err error) string {
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns):
		return "did not resolve on this box"
	case errors.Is(err, ErrBlockedAddress), errors.Is(err, ErrBoxAddrsUnknown):
		return "resolved to an address Vedette does not connect to"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused the connection"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.ErrUnexpectedEOF):
		return "cut the connection"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "could not be reached from this box"
	}
	var cv *tls.CertificateVerificationError
	var rh tls.RecordHeaderError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &cv) || errors.As(err, &rh) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci) {
		return "failed the secure connection (TLS certificate or handshake)"
	}
	return ""
}

func (s *Service) kevPrimary() string {
	if s.KEVPrimary != "" {
		return s.KEVPrimary
	}
	b, _ := BuiltinByID("cisa-kev")
	return b.URL
}

func (s *Service) kevFallback() string {
	if s.KEVFallback != "" {
		return s.KEVFallback
	}
	return KEVMirrorURL
}

func orEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
