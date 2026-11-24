package findings

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/store"
)

// Input is the Needs your input queue: what Vedette cannot settle without a person, in one list. Four kinds of item, each with its one
// action: a device nobody added that has open findings (Add device, Ignore), a watched device Vedette knows nothing to check by (say
// what runs there: its firmware, SNMP read access or an agent), an urgent finding (layers 1 to 4) not confirmed yet (Run the safe
// check, Confirm vulnerability, Not affected), and a question (fnd_question) not answered yet. Devices a person ignored are left out. An item leaves the moment it is answered or stops being true: the queue is read from the current rows, never stored.

// InputItemJS is one item of contract.ts InputItem (the fields of its kind are set, the others left out).
type InputItemJS struct {
	Kind     string            `json:"kind"`
	ID       string            `json:"id"`
	Device   deviceRefJS       `json:"device"`
	Status   any               `json:"status,omitempty"` // device_not_added: *DeviceStatus (null allowed); unconfirmed: the open status
	Findings int               `json:"findings,omitempty"`
	CVE      *string           `json:"cve,omitempty"`
	Software *softwareRefJS    `json:"software,omitempty"`
	Severity *cveSeverityJS    `json:"severity,omitempty"`
	Basis    string            `json:"basis,omitempty"`
	Check    *bool             `json:"safe_check,omitempty"`
	Question string            `json:"question,omitempty"`
	CVEs     int               `json:"cves,omitempty"`
	AskedAt  string            `json:"asked_at,omitempty"`
	URL      *string           `json:"url,omitempty"`
	Command  *string           `json:"command,omitempty"`
	Choices  []UncheckedAnswer `json:"choices,omitempty"`
	CVEList  []string          `json:"cve_list,omitempty"`
	Fixes    []string          `json:"fixes,omitempty"`
	Line     *string           `json:"line,omitempty"`
	Listed   *bool             `json:"versions_listed,omitempty"`

	nullables []string // the keys of this kind that are null when unset (encoded explicitly)
	rank      [3]int
	// terms are what a search also finds the item by beyond its own fields: for a device not added yet, the CVE ids and the
	// software names of its open findings (the card names neither, yet "OpenSSH" or a CVE must find the device that has it)
	terms []string
}

// MarshalJSON writes the item with the null fields its kind has.
func (it InputItemJS) MarshalJSON() ([]byte, error) {
	type plain InputItemJS
	b, err := json.Marshal(plain(it))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for _, k := range it.nullables {
		if _, ok := m[k]; !ok {
			m[k] = nil
		}
	}
	if it.Kind == "question" {
		for _, k := range []string{"choices", "cve_list", "fixes"} {
			if _, ok := m[k]; !ok {
				m[k] = []any{}
			}
		}
	}
	return json.Marshal(m)
}

// InputList is contract.ts InputList.
type InputList struct {
	Items []InputItemJS `json:"items"`
	Total int           `json:"total"`
}

// Input reads one page of the queue (of one device when device is set, of the items a search q finds when q is set): devices not
// added yet first, then devices Vedette cannot check, then unconfirmed findings by status, then questions by the CVEs waiting on them.
func (s *Service) Input(ctx context.Context, device, q string, p Page) (InputList, error) {
	q = strings.TrimSpace(q)
	var items []InputItemJS
	err := s.readTx(ctx, func(ctx context.Context) error {
		var err error
		items, err = s.inputItems(ctx, device, q != "")
		return err
	})
	if err != nil {
		return InputList{}, err
	}
	if q != "" {
		items = slices.DeleteFunc(items, func(it InputItemJS) bool { return !it.matches(q) })
	}
	lo, hi := p.cut(len(items))
	return InputList{Items: append([]InputItemJS{}, items[lo:hi]...), Total: len(items)}, nil
}

// matches is the search of the queue, the same as the other lists': the device's name or address, the software's name or the CVE id
// contains q (any case).
func (it InputItemJS) matches(q string) bool {
	low := strings.ToLower(q)
	has := func(v string) bool { return v != "" && strings.Contains(strings.ToLower(v), low) }
	if has(it.Device.Name) || it.Device.IP != nil && has(*it.Device.IP) {
		return true
	}
	if it.Software != nil && has(it.Software.Name) {
		return true
	}
	if it.CVE != nil && has(*it.CVE) {
		return true
	}
	return slices.ContainsFunc(it.terms, has)
}

// inputItems is the whole queue, in order. search says the caller filters it by search text: only then are the words a device not
// added yet is found by read (the CVE ids and software names of its open findings), since the card names neither.
func (s *Service) inputItems(ctx context.Context, device string, search bool) ([]InputItemJS, error) {
	rows, args, _, _, err := s.where(ctx, StateOpen, ListFilter{Device: device})
	if err != nil {
		return nil, err
	}
	q := s.rd(ctx)
	// devices not added yet with open findings: how many
	counts := map[string]int{}
	r, err := q.QueryContext(ctx, `SELECT asset_id, count(*) FROM fnd_finding WHERE `+rows+` GROUP BY asset_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: needs your input: %w", err)
	}
	for r.Next() {
		var id string
		var n int
		if err := r.Scan(&id, &n); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: needs your input: %w", err)
		}
		counts[id] = n
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: needs your input: %w", err)
	}
	unconfirmed, err := selectFindings(ctx, q, rows+` AND urgency < ? AND verified = 'no' ORDER BY urgency, cve, id`, append(args, UrgencyUpdate)...)
	if err != nil {
		return nil, err
	}
	qs, err := s.openQuestions(ctx, device)
	if err != nil {
		return nil, err
	}
	assets, lines := map[string]bool{}, map[string]bool{}
	for id := range counts {
		assets[id] = true
	}
	for _, x := range qs {
		assets[x.AssetID] = true
		if x.SoftwareID != "" {
			lines[x.SoftwareID] = true
		}
	}
	ref, err := s.refs(ctx, keys(assets), keys(lines), nil)
	if err != nil {
		return nil, err
	}
	var out []InputItemJS
	var notAdded []string
	for id := range counts {
		if a, ok := ref.assets[id]; ok && !a.Approved {
			notAdded = append(notAdded, id)
		}
	}
	var terms map[string][]string
	if search {
		if terms, err = s.notAddedTerms(ctx, rows, args, notAdded); err != nil {
			return nil, err
		}
	}
	statuses, err := s.deviceStatuses(ctx, notAdded)
	if err != nil {
		return nil, err
	}
	for _, id := range notAdded {
		st := statuses[id]
		out = append(out, InputItemJS{Kind: "device_not_added", ID: "device:" + id, Device: deviceRef(ref.device(id)), Status: st, Findings: counts[id],
			nullables: []string{"status"}, rank: [3]int{0, statusRank(st), -counts[id]}, terms: terms[id]})
	}
	vs, err := s.views(ctx, unconfirmed)
	if err != nil {
		return nil, err
	}
	for i, v := range vs {
		cve := v.Finding.CVE
		check := v.SafeCheck
		basis := v.Finding.Basis
		if !slices.Contains(knownBases, basis) {
			basis = DetectBannerVersion
		}
		out = append(out, InputItemJS{Kind: "unconfirmed", ID: v.Finding.ID, CVE: &cve, Device: deviceRef(v.Device), Software: softwareRef(v),
			Status: v.Status(), Severity: severityJS(v.Severity), Basis: string(basis), Check: &check,
			nullables: []string{"software", "severity"}, rank: [3]int{1, v.Finding.Urgency, i}})
	}
	var distro map[string][]DistroFix
	for i, x := range qs {
		if x.Kind == QuestionNothingToCheck {
			if a := ref.device(x.AssetID); a.Approved && !a.Box { // a device waiting to be added, or the box, is not asked about
				out = append(out, InputItemJS{Kind: "device_unchecked", ID: x.ID, Device: deviceRef(a), rank: [3]int{0, statusRank(nil) + 1, i}})
			}
			continue
		}
		listed := x.Detail.Listed
		it := InputItemJS{Kind: "question", ID: x.ID, Question: string(x.Kind), Device: deviceRef(ref.device(x.AssetID)), CVEs: max(x.Cves, 1),
			AskedAt: store.FormatTS(x.AskedAt), Choices: []UncheckedAnswer{}, CVEList: x.Detail.CVEList, Fixes: x.Detail.Fixes, Listed: &listed,
			nullables: []string{"software", "cve", "url", "command", "line"}, rank: [3]int{2, -x.Cves, i}}
		if x.Detail.Line != "" {
			line := x.Detail.Line
			it.Line = &line
		}
		if l, ok := ref.lines[x.SoftwareID]; ok && x.SoftwareID != "" {
			sw := &softwareRefJS{ID: l.ID, Name: cmp.Or(x.Detail.Software, l.Display)}
			if v := cmp.Or(x.Detail.Version, l.Version); v != "" {
				sw.Version = &v
			}
			it.Software = sw
		}
		if x.CVE != "" {
			cve := x.CVE
			it.CVE = &cve
			u := "https://nvd.nist.gov/vuln/detail/" + x.CVE
			it.URL = &u
		}
		if (x.Kind == QuestionPlatform || x.Kind == QuestionPackageRelease) && x.CVE != "" {
			if distro == nil {
				if distro, err = s.distroWords(ctx); err != nil {
					return nil, err
				}
			}
			reason := UncheckedPlatformUnknown
			if x.Kind == QuestionPackageRelease {
				reason = UncheckedPackageUnknown
			}
			if pq := platformQuestion(x.CVE, ref.device(x.AssetID).Name, reason, x.Detail.Choice, distro[x.CVE]); pq != nil {
				it.Command, it.Choices = pq.Command, pq.Answers
			}
		}
		out = append(out, it)
	}
	slices.SortStableFunc(out, func(a, b InputItemJS) int {
		return cmp.Or(cmp.Compare(a.rank[0], b.rank[0]), cmp.Compare(a.rank[1], b.rank[1]), cmp.Compare(a.rank[2], b.rank[2]),
			cmp.Compare(strings.ToLower(a.Device.Name), strings.ToLower(b.Device.Name)), cmp.Compare(a.ID, b.ID))
	})
	return out, nil
}

// notAddedTerms is, for each device not added yet, what a search also finds it by: the CVE ids and the software names of its open
// findings (rows and args select the open findings of the queue). One read of the findings and one of inventory for them all.
func (s *Service) notAddedTerms(ctx context.Context, rows string, args []any, notAdded []string) (map[string][]string, error) {
	if len(notAdded) == 0 {
		return nil, nil
	}
	ids, _ := json.Marshal(notAdded)
	r, err := s.rd(ctx).QueryContext(ctx, `SELECT asset_id, cve, ifnull(software_id, '') FROM fnd_finding WHERE `+rows+
		` AND asset_id IN (SELECT value FROM json_each(?))`, append(slices.Clone(args), string(ids))...)
	if err != nil {
		return nil, fmt.Errorf("findings: needs your input: %w", err)
	}
	type found struct{ asset, cve, line string }
	var open []found
	var lines []string
	for r.Next() {
		var x found
		if err := r.Scan(&x.asset, &x.cve, &x.line); err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("findings: needs your input: %w", err)
		}
		open = append(open, x)
		if x.line != "" {
			lines = append(lines, x.line)
		}
	}
	if err := errors.Join(r.Err(), r.Close()); err != nil {
		return nil, fmt.Errorf("findings: needs your input: %w", err)
	}
	names := map[string]Line{}
	if len(lines) > 0 {
		if names, err = s.cfg.Inventory.Lines(ctx, lines); err != nil {
			return nil, fmt.Errorf("findings: needs your input: reading software lines: %w", err)
		}
	}
	terms := map[string][]string{}
	for _, x := range open {
		terms[x.asset] = append(terms[x.asset], x.cve)
		if n := names[x.line].Display; n != "" {
			terms[x.asset] = append(terms[x.asset], n)
		}
	}
	return terms, nil
}

// openQuestions are the questions not answered yet, of devices nobody ignored (of one device when device is set), the most CVEs first.
func (s *Service) openQuestions(ctx context.Context, device string) ([]Question, error) {
	ignored, err := s.cfg.Inventory.IgnoredIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the ignored devices: %w", err)
	}
	ig, _ := json.Marshal(nonNilStrings(ignored))
	rows, err := s.rd(ctx).QueryContext(ctx, `SELECT `+questionColumns+` FROM fnd_question
		WHERE answer IS NULL AND asset_id NOT IN (SELECT value FROM json_each(?)) AND (?2 = '' OR asset_id = ?2)
		ORDER BY cves DESC, asked_at, id`, string(ig), device)
	if err != nil {
		return nil, fmt.Errorf("findings: reading questions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Question
	for rows.Next() {
		x, err := scanQuestion(rows)
		if err != nil {
			return nil, fmt.Errorf("findings: reading questions: %w", err)
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// distroWords is the distributions' word on the exploited-list CVEs, for the answers of a platform question.
func (s *Service) distroWords(ctx context.Context) (map[string][]DistroFix, error) {
	vs, err := s.cfg.Feeds.Vulns(ctx)
	if err != nil {
		return nil, fmt.Errorf("findings: reading the exploited list: %w", err)
	}
	out := map[string][]DistroFix{}
	for _, v := range vs {
		if len(v.Distro) > 0 {
			out[v.CVE] = v.Distro
		}
	}
	return out, nil
}

// ---- Handled ----

// HandledFilter is what the Handled list shows.
type HandledFilter struct {
	Q           string
	Resolutions []Resolution
	Device      string
	From, To    time.Time // zero: no bound
	// Corrections lists the findings Vedette closed itself because it corrected its own match (via data_corrected, by Vedette): a
	// match that was wrong, never a flaw someone handled. Left out by default, as the report leaves out what was not relevant, so a
	// correction of hundreds of rows (a kernel's package lines) does not bury the people's decisions; HandledList.Corrections counts them.
	Corrections bool
}

// HandledRowJS is contract.ts HandledRow.
type HandledRowJS struct {
	ID       string         `json:"id"`
	CVE      string         `json:"cve"`
	Device   deviceRefJS    `json:"device"`
	Software *softwareRefJS `json:"software"`
	Status   string         `json:"status"`
	Severity *cveSeverityJS `json:"severity"`
	Handled  *handledJS     `json:"handled"`
}

// HandledList is contract.ts HandledList.
type HandledList struct {
	Items       []HandledRowJS `json:"items"`
	Total       int            `json:"total"`
	Corrections int            `json:"corrections"`
}

// Handled reads one page of the handled findings of devices nobody ignored, the newest handling first.
func (s *Service) Handled(ctx context.Context, f HandledFilter, p Page) (HandledList, error) {
	var out HandledList
	err := s.readTx(ctx, func(ctx context.Context) error {
		var err error
		out, err = s.handled(ctx, f, p)
		return err
	})
	return out, err
}

func (s *Service) handled(ctx context.Context, f HandledFilter, p Page) (HandledList, error) {
	rows, args, cond, cargs, err := s.where(ctx, StateHandled, ListFilter{Device: f.Device, Q: f.Q})
	if err != nil {
		return HandledList{}, err
	}
	w := rows
	if cond != "" {
		w += " AND " + cond
		args = append(args, cargs...)
	}
	if len(f.Resolutions) > 0 {
		rs, _ := json.Marshal(f.Resolutions)
		w += ` AND resolution IN (SELECT value FROM json_each(?))`
		args = append(args, string(rs))
	}
	if !f.From.IsZero() {
		w, args = w+` AND resolved_at >= ?`, append(args, store.FormatTS(f.From))
	}
	if !f.To.IsZero() {
		w, args = w+` AND resolved_at <= ?`, append(args, store.FormatTS(f.To))
	}
	out := HandledList{Items: []HandledRowJS{}}
	correction := `(via = ? AND ifnull(resolved_by, '') = ?)`
	if err := s.rd(ctx).QueryRowContext(ctx, `SELECT count(*), ifnull(sum(CASE WHEN `+correction+` THEN 1 ELSE 0 END), 0) FROM fnd_finding WHERE `+w,
		append([]any{string(ViaDataCorrected), SystemUser}, args...)...).Scan(&out.Total, &out.Corrections); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return HandledList{}, fmt.Errorf("findings: counting handled findings: %w", err)
	}
	if !f.Corrections {
		out.Total -= out.Corrections
		w, args = w+` AND NOT `+correction, append(args, string(ViaDataCorrected), SystemUser)
	}
	fs, err := selectFindings(ctx, s.rd(ctx), w+` ORDER BY resolved_at DESC, id LIMIT ? OFFSET ?`, append(args, p.Limit, p.Offset)...)
	if err != nil {
		return HandledList{}, err
	}
	vs, err := s.views(ctx, fs)
	if err != nil {
		return HandledList{}, err
	}
	for _, v := range vs {
		out.Items = append(out.Items, HandledRowJS{ID: v.Finding.ID, CVE: v.Finding.CVE, Device: deviceRef(v.Device), Software: softwareRef(v),
			Status: v.Status(), Severity: severityJS(v.Severity), Handled: handledOf(v.Finding)})
	}
	return out, nil
}

// ---- answering a question ----

// The answers to a question (POST /findings/questions/{id}/answer).
const (
	AnswerAffected    = "affected"
	AnswerNotAffected = "not_affected"
)

// API errors of answering a question.
var (
	ErrNoQuestion  = &APIError{"not_found", 404, "No such question."}
	ErrAnswered    = &APIError{"already_answered", 409, "This question is answered already."}
	ErrSeveralCVEs = &APIError{"invalid", 400, "This question is about several CVEs: give the version on the software line instead."}
	ErrBadAnswer   = &APIError{"invalid", 400, "Answer affected or not affected."}
	// ErrNotAnswerable is an answer to "Vedette cannot check this device": it is answered by saying what runs there.
	ErrNotAnswerable = &APIError{"invalid", 400, "Tell Vedette what runs on this device instead: add its firmware, give SNMP read access or install an agent."}
	// ErrFixTooBig is a fix with more open findings on one device than one handle request may change.
	ErrFixTooBig        = &APIError{"invalid", 400, fmt.Sprintf("This fix has more than %d open findings on the device: tick the CVEs to handle, %d at a time.", MaxBulk, MaxBulk)}
	ErrAffectedNeedsWhy = &APIError{"confirm_note_required", 400, "Write what makes you sure (at least 3 characters) so the next person understands."}
)

// AnswerQuestion answers a question on a person's word. affected (one CVE only) records the finding of the question's CVE on its device
// and software line, confirmed by the person, and returns its id; not_affected closes the question. The question keeps the answer while
// it holds (the match pass keeps an answered row). One audit row, one history row for the finding.
func (s *Service) AnswerQuestion(ctx context.Context, id, answer, note, user string) (string, error) {
	if err := ValidUser(user); err != nil {
		return "", err
	}
	if answer != AnswerAffected && answer != AnswerNotAffected {
		return "", ErrBadAnswer
	}
	note, err := personNote(note, false)
	if err != nil {
		return "", err
	}
	if answer == AnswerAffected && jsLen(note) < MinReasonNote {
		return "", ErrAffectedNeedsWhy
	}
	var found string
	err = s.write(ctx, func(tx *sql.Tx, now time.Time, emit func(string, any)) error {
		found = ""
		x, err := scanQuestion(tx.QueryRowContext(ctx, `SELECT `+questionColumns+` FROM fnd_question WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNoQuestion
		}
		if err != nil {
			return fmt.Errorf("findings: reading a question: %w", err)
		}
		if x.Answer != "" {
			return ErrAnswered
		}
		if x.Kind == QuestionNothingToCheck {
			return ErrNotAnswerable
		}
		if answer == AnswerAffected {
			if x.CVE == "" {
				return ErrSeveralCVEs
			}
			if found, err = s.affectedByPerson(ctx, tx, x, note, user, now, emit); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE fnd_question SET answer = ?, answered_by = ?, answered_at = ? WHERE id = ?`,
			answer, user, store.FormatTS(now), x.ID); err != nil {
			return fmt.Errorf("findings: answering a question: %w", err)
		}
		detail := questionAuditDetail(x, "answered "+strings.ReplaceAll(answer, "_", " "))
		if note != "" {
			detail += ": " + note
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: user, Action: "findings.question_answered", Target: x.ID, Detail: detail})
	})
	if err != nil {
		return "", err
	}
	return found, nil
}

// affectedByPerson records the finding of question x confirmed by a person: the finding of its CVE on its line, created when there is
// none, then confirmed on the person's word (an open one already confirmed stays as it is).
func (s *Service) affectedByPerson(ctx context.Context, tx *sql.Tx, x Question, note, user string, now time.Time, emit func(string, any)) (string, error) {
	fs, err := queryFindings(ctx, tx, `asset_id = ? AND cve = ? AND ifnull(software_id, '') = ?`, x.AssetID, x.CVE, x.SoftwareID)
	if err != nil {
		return "", err
	}
	var f Finding
	if len(fs) == 1 {
		f = fs[0]
	} else {
		product := ""
		if x.SoftwareID != "" {
			ls, err := s.cfg.Inventory.Lines(ctx, []string{x.SoftwareID})
			if err != nil {
				return "", fmt.Errorf("findings: reading the software line: %w", err)
			}
			product = ls[x.SoftwareID].ProductKey
		}
		f = Finding{ID: store.NewID("f"), AssetID: x.AssetID, CVE: x.CVE}
		d := Detection{SoftwareID: x.SoftwareID, Basis: DetectPerson, Verified: VerifiedNo, RangeOrigin: RangePerson, MatchedVersion: x.Detail.Version,
			ProductKey: product, Fix: Fix{Kind: FixUnknown}}
		if f, _, err = s.step(ctx, tx, f, true, Trigger{Kind: TrDetected, At: now, Detection: d}, emit); err != nil {
			return "", err
		}
	}
	if f.Confirmed() {
		return f.ID, nil
	}
	if _, _, err := s.step(ctx, tx, f, false, Trigger{Kind: TrVerify, At: now, Actor: user, Note: note}, func(string, any) {}); err != nil {
		return "", err
	}
	return f.ID, nil
}
