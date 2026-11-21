package feeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Apple's exploitation claims. Apple states exploitation on its security release pages, whose terms forbid reading them with a
// program, and in the CVE records it publishes as a CNA: each record's description carries the same sentence ("Apple is aware of a
// report that this issue may have been exploited in an extremely sophisticated attack …"). The box already holds those descriptions
// (the CVE records and NVD feeds write them into the catalogue), so Apple's claims are read from there, one record per CVE: a sentence
// about "this issue" belongs to the record's own CVE only, so a claim can never land on the CVE of the next entry of a release page.
// Each claim is a feeds_signal row (kind exploited, source apple), dated by the CVE's publication, linked to its CVE record. The rows
// are reconciled with the catalogue after each write of descriptions (applyAppleClaims): a record that no longer says it loses its row.

// appleClaimSource is the source of Apple's claims (feeds_signal.source); appleSourceName is how it is shown.
const (
	appleClaimSource = "apple"
	appleSourceName  = "Apple (its CVE records)"
)

// appleForms: Apple's sentences in its CVE records, as written since 2021.
var appleForms = concatForms(
	forms(formClaim, false,
		`\(?apple is aware (?:of )?(?:a report|reports) that (?:this issue|these issues) (?:may have been|might have been|was|were|has been|have been) `+
			`(?:actively )?exploited(?P<o2> .{1,240})?`),
	forms(formNeutral, false,
		`\{cve\} (?:was|were) also issued in response to this report`),
)

// appleCandidatesSQL: the catalogue's descriptions that may hold Apple's sentence (a prefilter; the forms decide).
const appleCandidatesSQL = `SELECT cve, description, published FROM feeds_cve WHERE description LIKE '%Apple is aware%'`

// cveRecordPage is where a person reads a CVE record (the link of Apple's claims).
const cveRecordPage = "https://www.cve.org/CVERecord?id="

// appleClaimed says whether a description claims its own CVE is exploited, by Apple's forms.
func appleClaimed(ctx context.Context, cve, description string) (bool, error) {
	r := newClaimReader(appleForms, maxClaimText, nil)
	r.total = 1
	if err := r.read(ctx, description, []string{cve}, map[string]bool{cve: true}); err != nil {
		return false, err
	}
	return len(r.result()) == 1, nil
}

// appleNoteAdded notes, before a write replaces a CVE's description, whether the new one adds Apple's claim to a description the
// catalogue held without it: the claim came later than the CVE's publication. Only descriptions that hold Apple's words are looked at.
func appleNoteAdded(ctx context.Context, tx *sql.Tx, cve, description string, added map[string]bool) error {
	if !strings.Contains(description, "Apple is aware") {
		return nil
	}
	var prior sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT description FROM feeds_cve WHERE cve = ?`, cve).Scan(&prior)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("feeds: Apple claims: %w", err)
	case !prior.Valid || strings.TrimSpace(prior.String) == "":
		return nil
	}
	was, err := appleClaimed(ctx, cve, prior.String)
	if err != nil {
		return err
	}
	if now, err := appleClaimed(ctx, cve, description); err != nil || (now && !was) {
		added[cve] = true
		return err
	}
	return nil
}

// applyAppleClaims reconciles the rows of Apple's claims with the catalogue's descriptions: a CVE whose description claims it gets a
// row dated by its publication (now when it has none, one in the future, or when the claim was added to a description the catalogue
// held without it, added, more than claimSlack after the publication, as Cisco's and Fortinet's late claims); a row whose CVE's
// description no longer does goes. A row already held keeps its date.
func applyAppleClaims(ctx context.Context, tx *sql.Tx, now time.Time, added map[string]bool) error {
	held, err := stringSet(ctx, tx, `SELECT cve FROM feeds_signal WHERE source = '`+appleClaimSource+`' AND kind = '`+SignalExploited+`'`)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, appleCandidatesSQL)
	if err != nil {
		return fmt.Errorf("feeds: Apple claims: %w", err)
	}
	type cand struct {
		cve, description string
		published        sql.NullString
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.cve, &c.description, &c.published); err != nil {
			_ = rows.Close()
			return fmt.Errorf("feeds: Apple claims: %w", err)
		}
		cands = append(cands, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("feeds: Apple claims: %w", err)
	}
	stamp := store.FormatTS(now)
	claimed := map[string]bool{}
	for _, c := range cands {
		ok, err := appleClaimed(ctx, c.cve, c.description)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		claimed[c.cve] = true
		if held[c.cve] {
			continue
		}
		first := now
		if c.published.Valid {
			if t, err := parseTS(c.published.String); err == nil && !t.After(now) && (!added[c.cve] || !t.Before(now.Add(-claimSlack))) {
				first = t
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies, url) VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
			c.cve, SignalExploited, appleClaimSource, store.FormatTS(first), stamp, stamp, cveRecordPage+c.cve); err != nil {
			return fmt.Errorf("feeds: Apple claims: %w", err)
		}
	}
	for cve := range held {
		if claimed[cve] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM feeds_signal WHERE cve = ? AND kind = ? AND source = ?`, cve, SignalExploited, appleClaimSource); err != nil {
			return fmt.Errorf("feeds: Apple claims: %w", err)
		}
	}
	return nil
}
