package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/store"
)

// Corrections (INV-41): a person says what a device really runs where Vedette shows it. The device's OS is a manual
// observation, which wins the field over every sensor and agent (INV-1). A software line's version is the person's entry: a reading
// of source manual on that line (entries.go), which is the line until a source first seen after it reads a newer release (Resolve).
// What the sources read keeps being recorded, and the device page shows it next to the entry when they disagree. Clearing the entry
// deletes it, and the line is back to what its sources read. Every change is audited and in the line's history.

// liveSW is the SQL condition on a software line (alias s) that counts for matching and the "Do you have it?" lists: present (not
// removed, not marked not installed by a person), never an nmap OS guess the device does not use (hiddenGuess).
var liveSW = `(s.state = 'present' AND NOT ` + hiddenGuess + `)`

// notInstalledSW is the SQL condition on a software line (alias s) that a person said it is not installed (INV-41 (6)).
const notInstalledSW = `(s.state = 'not_installed')`

// pkgVersionRE is a distribution's full package version as a person copies it from the device: Debian's "1:9.6p1-3ubuntu13.14",
// Alpine's "10.2_p1-r1", RPM's "8.7p1-38.el9_4.4".
var pkgVersionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+~:-]{0,99}$`)

const badPkgVersion = "The package release is the full version the device's package manager shows, for example 10.2_p1-r1 or 1:9.6p1-3ubuntu13.14: letters, digits and . _ + ~ : -, up to 100 characters."

// osText checks the OS a person types: 1..200 characters (the inv_asset.os column), no < >, control or invisible characters.
func osText(s string) bool {
	return cleanText(s) && len([]rune(s)) <= 200 && !strings.ContainsAny(s, "<>")
}

const badOS = "The operating system is at most 200 characters and cannot contain < or >, control characters or invisible characters. Example: Alpine Linux 3.23."

// manualOS is the OS a person set on the device, when and who (the observation's evidence), ok false when none.
func manualOS(ctx context.Context, q querier, id string) (value, setAt, setBy string, ok bool, err error) {
	err = q.QueryRowContext(ctx, `SELECT value, seen_at, ifnull(evidence, '') FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual' AND NOT `+declaredObsSQL+` ORDER BY seen_at DESC, id DESC LIMIT 1`, id).Scan(&value, &setAt, &setBy)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", false, fmt.Errorf("inventory: read the corrected OS: %w", err)
	}
	return value, setAt, setBy, true, nil
}

// correctionDay is the day of a stored time in the findings history's words ("17 Nov 2026"), in the organization's zone loc; the
// stored text when it does not parse.
func correctionDay(at string, loc *time.Location) string {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return at
	}
	return orgtime.Day(t, loc)
}

// detectedOS is the OS the device's sources read, the person's left out: the value that would win without the correction.
func detectedOS(ctx context.Context, q querier, id string) (*Observed, error) {
	// The MACs too: an LLDP statement counts only on its vendor's card (INV-44, markStated).
	rows, err := q.QueryContext(ctx, `SELECT id, field, value, source, confidence, seen_at FROM inv_observation WHERE asset_id = ?
		AND ((field = 'os' AND source <> 'manual') OR field = 'mac')`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var list []obs
	for rows.Next() {
		var o obs
		if err := rows.Scan(&o.id, &o.field, &o.value, &o.source, &o.confidence, &o.seenAt); err != nil {
			return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
		}
		list = append(list, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read the detected OS: %w", err)
	}
	w, ok := winners(list)["os"]
	if !ok {
		return nil, nil
	}
	basis := osBasis(w.value, w.source, "") // a guess; the statement was decided against the MAC by winners
	if w.stated && w.source == "passive" {
		basis = basisStated
	}
	return &Observed{Value: w.value, Source: w.source, Confidence: w.confidence, SeenAt: w.seenAt, Basis: basis}, nil
}

// setOSTx sets (os != "") or clears (os == "") the person's OS of a device, in PatchDevice's transaction. changed is false when
// nothing changes (the same value again, or clearing a device with no correction): no audit row then.
func (s *Service) setOSTx(ctx context.Context, tx *sql.Tx, actor, id, name, os string) (changed bool, err error) {
	old, _, _, had, err := manualOS(ctx, tx, id)
	if err != nil {
		return false, err
	}
	if (os == "" && !had) || (had && old == os) {
		return false, nil
	}
	var shown sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT os FROM inv_asset WHERE id = ?`, id).Scan(&shown); err != nil {
		return false, fmt.Errorf("inventory: read device OS: %w", err)
	}
	// One correction per device: the previous one goes (a declared row's stored OS too: the person's OS decides now), so an older value set again cannot lose to a newer one.
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, id); err != nil {
		return false, fmt.Errorf("inventory: clear the corrected OS: %w", err)
	}
	if os != "" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, evidence) VALUES (?, ?, 'os', ?, 'manual', 1, ?, ?)`,
			store.NewID("o"), id, os, s.now(), nullStr(actor)); err != nil { // evidence: who set it, for the findings history
			return false, fmt.Errorf("inventory: record the corrected OS: %w", err)
		}
	}
	if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
		return false, err
	}
	if os == "" {
		var now sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT os FROM inv_asset WHERE id = ?`, id).Scan(&now); err != nil {
			return false, fmt.Errorf("inventory: read device OS: %w", err)
		}
		return true, s.auditTx(ctx, tx, actor, "inventory.clear_os", name, old+" → back to detected: "+cmp.Or(now.String, "unknown"))
	}
	return true, s.auditTx(ctx, tx, actor, "inventory.correct_os", name, cmp.Or(shown.String, "unknown")+" → "+os)
}

// OSCorrection is the OS a person set on a device (contract.ts OsCorrection), with what the sources read now.
type OSCorrection struct {
	Value string `json:"value"`
	SetAt string `json:"set_at"`
	// Detected is the OS the device's sources read without the correction (the value that would win), nil when none read one.
	Detected *Observed `json:"detected"`
	// Disagrees: the sources read another OS than the person's ("You set X on <date>; the last scan reads Y").
	Disagrees bool `json:"disagrees"`
}

func osCorrection(ctx context.Context, q querier, id string) (*OSCorrection, error) {
	v, at, _, ok, err := manualOS(ctx, q, id)
	if err != nil || !ok {
		return nil, err
	}
	det, err := detectedOS(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return &OSCorrection{Value: v, SetAt: at, Detected: det, Disagrees: det != nil && !sameOS(det.Value, v)}, nil
}

// sameOS says two OS texts do not contradict each other: equal without case, or one the other with more detail after a space (SNMP's
// "Alpine Linux" and a person's "Alpine Linux 3.23").
func sameOS(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	return a == b || strings.HasPrefix(a, b+" ") || strings.HasPrefix(b, a+" ")
}
