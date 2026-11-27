package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/knt048/vedette/core/store"
)

// The range origins of a finding a check of the CVE's advisories decided (fnd_finding.range_origin).
const (
	// RangeAdvisory: the box read the vendor's advisory and its ranges place the line's version inside one (decided by the box).
	RangeAdvisory = "advisory"
	// RangeAIConfirmed: a person confirmed the AI's proposal that the version is affected; the AI's quote and sources are the evidence.
	RangeAIConfirmed = "ai_confirmed"
)

// The ways a check decided (fnd_possible_check.decided_by) and its verdicts.
const (
	DecidedStructured = "structured"
	DecidedAdvisory   = "advisory"
	DecidedAI         = "ai"

	VerdictAffected    = "affected"
	VerdictNotAffected = "not_affected"
	VerdictUnsure      = "unsure"

	ConfidenceConfident = "confident"
	ConfidenceLikely    = "likely"
)

// Check is one row of fnd_possible_check.
type Check struct {
	Key        string
	CVE        string
	ID         CheckID
	DecidedBy  string
	Verdict    string
	Confidence string // "" unless the AI decided and proposed a verdict
	Reason     string
	Quote      string
	Sources    []CheckSource
	Undecided  *Undecided // why it stays undecided, for an audit; nil when decided
	Model      string
	Profile    string
	ActivityID string
	CheckedBy  string
	CheckedAt  time.Time
	RejectedBy string
	RejectedAt time.Time
	// Stale says the check was made on older evidence of the CVE record (checksFor): it applies until a check of the question's own
	// evidence replaces it.
	Stale bool
	// Reading is the AI's reading of the vendor's statement for the line this check shows (fnd_line_statement); nil for a check of
	// fnd_possible_check.
	Reading *LineStatement
}

// CheckSource is one page a check read (or tried to).
type CheckSource struct {
	URL    string `json:"url"`
	Title  string `json:"title,omitempty"`
	Status string `json:"status"` // ok, failed, skipped
	Note   string `json:"note,omitempty"`
	Cited  bool   `json:"cited,omitempty"` // the verdict's quote is from this page
}

// checkDetail is the JSON of fnd_possible_check.detail.
type checkDetail struct {
	Undecided *Undecided `json:"undecided,omitempty"`
}

// Proposal reports whether the check is an AI proposal still waiting for a person: decided by the AI, affected or not affected, not
// rejected.
func (c Check) Proposal() bool {
	return c.DecidedBy == DecidedAI && c.Verdict != VerdictUnsure && c.RejectedBy == ""
}

// Settled reports whether the box decided the CVE itself from the advisory (or its own data): applied without a person.
func (c Check) Settled() bool {
	return (c.DecidedBy == DecidedAdvisory || c.DecidedBy == DecidedStructured) && c.Verdict != VerdictUnsure
}

const checkColumns = `check_key, cve, product_key, line, version, evidence_hash, decided_by, verdict, ifnull(confidence, ''), reason, quote, sources, detail,
	ifnull(model, ''), ifnull(profile, ''), ifnull(activity_id, ''), checked_by, checked_at, ifnull(rejected_by, ''), ifnull(rejected_at, '')`

func scanCheck(sc scanner) (Check, error) {
	var c Check
	var sources, detail, at, rejAt string
	if err := sc.Scan(&c.Key, &c.CVE, &c.ID.Product, &c.ID.Line, &c.ID.Version, &c.ID.Evidence, &c.DecidedBy, &c.Verdict, &c.Confidence, &c.Reason, &c.Quote,
		&sources, &detail, &c.Model, &c.Profile, &c.ActivityID, &c.CheckedBy, &at, &c.RejectedBy, &rejAt); err != nil {
		return Check{}, err
	}
	if err := json.Unmarshal([]byte(sources), &c.Sources); err != nil {
		return Check{}, fmt.Errorf("findings: reading a check: %w", err)
	}
	var d checkDetail
	if err := json.Unmarshal([]byte(detail), &d); err != nil {
		return Check{}, fmt.Errorf("findings: reading a check: %w", err)
	}
	c.Undecided = d.Undecided
	var err error
	if c.CheckedAt, err = parseTS(at); err != nil {
		return Check{}, err
	}
	if rejAt != "" {
		if c.RejectedAt, err = parseTS(rejAt); err != nil {
			return Check{}, err
		}
	}
	return c, nil
}

// checksOf reads the checks stored under keys, by key.
func checksOf(ctx context.Context, q querier, keys []string) (map[string]Check, error) {
	out := map[string]Check{}
	if len(keys) == 0 {
		return out, nil
	}
	b, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT `+checkColumns+` FROM fnd_possible_check WHERE check_key IN (SELECT value FROM json_each(?))`, string(b))
	if err != nil {
		return nil, fmt.Errorf("findings: reading checks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading checks: %w", err)
		}
		out[c.Key] = c
	}
	return out, rows.Err()
}

// checksFor is the check that applies to each question with a check identity, by the question's key: the check of its own evidence,
// else the last check of the same CVE, product, release line and release (version and stated build) made on older evidence of the CVE
// record, marked Stale. A change of the record alone never drops a verdict, in either direction: an advisory's finding stays detected
// and a proposal stays a proposal until a check of the new evidence replaces it.
func checksFor(ctx context.Context, q querier, qs []Question) (map[string]Check, error) {
	var keys []string
	for _, x := range qs {
		if x.CheckKey != "" {
			keys = append(keys, x.CheckKey)
		}
	}
	out, err := checksOf(ctx, q, keys)
	if err != nil {
		return nil, err
	}
	identity := func(cve, product, line, release string) string {
		return cve + "\x1f" + clipBytes(product, 300) + "\x1f" + clipBytes(line, 200) + "\x1f" + clipBytes(release, 200)
	}
	var cves []string
	for _, x := range qs {
		if _, ok := out[x.CheckKey]; !ok && x.CheckKey != "" && x.Detail.Check != nil && !slices.Contains(cves, x.CVE) {
			cves = append(cves, x.CVE)
		}
	}
	if len(cves) == 0 {
		return out, nil
	}
	b, err := json.Marshal(cves)
	if err != nil {
		return nil, err
	}
	rows, err := q.QueryContext(ctx, `SELECT `+checkColumns+` FROM fnd_possible_check WHERE cve IN (SELECT value FROM json_each(?))
		ORDER BY checked_at DESC, rowid DESC`, string(b))
	if err != nil {
		return nil, fmt.Errorf("findings: reading checks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	last := map[string]Check{}
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading checks: %w", err)
		}
		// the version column holds the release (CheckID.Release), so a check of another build never applies
		if k := identity(c.CVE, c.ID.Product, c.ID.Line, c.ID.Version); last[k].Key == "" {
			last[k] = c
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings: reading checks: %w", err)
	}
	for _, x := range qs {
		if _, ok := out[x.CheckKey]; ok || x.CheckKey == "" || x.Detail.Check == nil {
			continue
		}
		id := x.Detail.Check
		if c, ok := last[identity(x.CVE, id.Product, id.Line, id.Release())]; ok {
			c.Stale = true
			out[x.CheckKey] = c
		}
	}
	return out, nil
}

// insertCheck stores one check; a key already checked keeps its first check (a key is checked once).
func insertCheck(ctx context.Context, tx *sql.Tx, c Check) (bool, error) {
	if !checkKeyRE.MatchString(c.Key) {
		return false, fmt.Errorf("findings: bad check key %q", c.Key)
	}
	sources := c.Sources
	if sources == nil {
		sources = []CheckSource{}
	}
	sb, err := json.Marshal(sources)
	if err != nil {
		return false, err
	}
	db, err := json.Marshal(checkDetail{Undecided: c.Undecided})
	if err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO fnd_possible_check (check_key, cve, product_key, line, version, evidence_hash, decided_by, verdict, confidence,
		reason, quote, sources, detail, model, profile, activity_id, checked_by, checked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Key, c.CVE, clipBytes(c.ID.Product, 300), clipBytes(c.ID.Line, 200), clipBytes(c.ID.Release(), 200), c.ID.Evidence, c.DecidedBy, c.Verdict, nullString(c.Confidence),
		clipBytes(cleanOr(c.Reason, "No reason given."), 600), clipBytes(c.Quote, 400), string(sb), string(db), nullString(clipBytes(c.Model, 80)),
		nullString(clipBytes(c.Profile, 160)), nullString(c.ActivityID), c.CheckedBy, store.FormatTS(c.CheckedAt))
	if err != nil {
		return false, fmt.Errorf("findings: storing a check: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func cleanOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// lineDetection is the detection of CVE v on line sw of device a when a check, not the version ranges, decides that the version is
// affected: its basis and confirmation come from who stated the version (the device's agent or SNMP answer: confirmed by the device; the
// release it states over LLDP or a banner: not confirmed; a person's entry: that person's word), never from the check itself.
func lineDetection(a Asset, lines map[string]line, sw string, v Vuln, origin string, ev Evidence) (Detection, bool) {
	l, ok := lines[sw]
	if !ok || l.reading == nil || l.reading.Version == "" {
		return Detection{}, false
	}
	d := Detection{SoftwareID: sw, RangeOrigin: origin, MatchedVersion: l.reading.Version, ReadAt: l.sw.SeenAt, ProductKey: productKey(l.sw),
		Urgency: v.StartUrgency(), Verified: VerifiedNo}
	switch src := l.sw.Source; {
	case src == "manual":
		d.Basis, d.SetBy = DetectStatement, enteredBy(l.sw)
		if d.entryConfirms() {
			d.Verified = VerifiedPerson
		}
	case src == "agent" || src == SourceSNMP:
		d.Basis, d.Verified = DetectDeviceVersion, VerifiedDevice
		ev.Source = src
	case l.sw.stated:
		d.Basis = DetectDeviceVersion
	default:
		d.Basis = DetectBannerVersion
	}
	if d.ProductKey == "" {
		d.ProductKey = "unknown"
	}
	d.Fix = FixOf(a, l.sw, v)
	d.Evidence = &ev
	return d, true
}

// checkedDetections is what the checks of a device's questions decide in the match pass (the one writer of detection, M-2): a question
// the box settled from the vendor's advisory as affected is a finding (range origin advisory) and no longer a question, and so is one the
// AI's reading of the vendor's statement for the line places inside the affected releases (range origin ai_read); a finding a
// person confirmed from an AI proposal stays detected while the person's answer applies (range origin ai_confirmed). A check that says
// "not affected" leaves the question in place: the lists show it settled, with the reason, and a person can still answer it.
func (s *Service) checkedDetections(ctx context.Context, tx *sql.Tx, a Asset, lines map[string]line, byCVE map[string]Vuln, qs []Question,
	existing []Finding, now time.Time) (dets map[string]Detection, keep []Question, err error) {
	dets = map[string]Detection{}
	checks, err := checksFor(ctx, tx, qs)
	if err != nil {
		return nil, nil, err
	}
	readings, err := readingsFor(ctx, tx, qs)
	if err != nil {
		return nil, nil, err
	}
	old, err := questionsOf(ctx, tx, a.ID)
	if err != nil {
		return nil, nil, err
	}
	confirmed := map[string]bool{}
	for _, f := range existing {
		if f.RangeOrigin == RangeAIConfirmed {
			confirmed[lineKey(f.CVE, f.SoftwareID)] = true
		}
	}
	for _, q := range qs {
		v, known := byCVE[q.CVE]
		k := lineKey(q.CVE, q.SoftwareID)
		if !known || q.CVE == "" {
			keep = append(keep, q)
			continue
		}
		if was, ok := answeredFor(old, q.SoftwareID, q.CVE, q.Detail.Version); ok {
			if was.Answer == AnswerAffected && confirmed[k] {
				ev := Evidence{Summary: aiConfirmedNote(was, checks[q.CheckKey]), CheckedAt: now}
				if d, ok := lineDetection(a, lines, q.SoftwareID, v, RangeAIConfirmed, ev); ok {
					dets[k] = d
				}
			}
			keep = append(keep, q) // the person's answer holds (replaceQuestions keeps their row)
			continue
		}
		c, ok := checks[q.CheckKey]
		if ok && c.Settled() && c.Verdict == VerdictAffected {
			if d, ok := lineDetection(a, lines, q.SoftwareID, v, RangeAdvisory, Evidence{Summary: advisoryNote(a, q, c), CheckedAt: now}); ok {
				dets[k] = d
				continue // a finding now, no longer a question
			}
		}
		// the AI's reading of the vendor's statement for the line: affected opens the finding (a person can reject the reading)
		if r, ok := readings[q.CheckKey]; ok && r.applied != nil && q.Detail.Check != nil && (!c.Settled() || c.Stale) &&
			r.applied.verdictFor(*q.Detail.Check) == VerdictAffected {
			if d, ok := lineDetection(a, lines, q.SoftwareID, v, RangeAIRead, Evidence{Summary: aiReadNote(q, *r.applied), CheckedAt: now}); ok {
				d.Fix = r.applied.fix() // the fix the quote names, never one the AI only proposed
				dets[k] = d
				if r.due(*q.Detail.Check, now) {
					s.noteReadingDue(q) // the finding stands on it until a new reading replaces it
				}
				continue
			}
		}
		keep = append(keep, q)
	}
	return dets, keep, nil
}

// advisoryNote is the evidence of a finding the vendor's advisory decided: the release, the advisory's sentence and its page.
func advisoryNote(a Asset, q Question, c Check) string {
	url := ""
	for _, s := range c.Sources {
		if s.Cited {
			url = s.URL
		}
	}
	note := fmt.Sprintf("%s runs %s %s. The vendor's advisory lists it as affected by %s", clean(a.Name), clean(q.Detail.Software), clean(q.Detail.Version), q.CVE)
	if c.Quote != "" {
		note += ": \"" + oneLine(c.Quote, 300) + "\""
	}
	if url != "" {
		note += " (" + url + ")"
	}
	return clipBytes(note+suspectedClause, 1000)
}

// aiConfirmedNote is the evidence of a finding a person confirmed from an AI proposal.
func aiConfirmedNote(answer Question, c Check) string {
	note := fmt.Sprintf("%s confirmed an AI check of the CVE's advisories that %s %s is affected", cleanOr(answer.AnsweredBy, "A person"), clean(answer.Detail.Software),
		clean(answer.Detail.Version))
	if c.Quote != "" {
		note += ": \"" + oneLine(c.Quote, 300) + "\""
	}
	return clipBytes(note+".", 1000)
}
