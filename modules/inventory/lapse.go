package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/knt048/vedette/core/apkver"
	"github.com/knt048/vedette/core/debver"
	"github.com/knt048/vedette/core/pkgrel"
)

// A person's correction of a version lapses when any source reads a newer release after the correction was set (INV-52): the
// person said what the device ran then, and a later reading of a newer release means it was updated since. A reading that was
// already there (a source repeating the version the person overrode, on every report) never lapses it, nor does an older or the
// same release (core/pkgrel), nor a pair of versions that cannot be ordered reliably: then the person's version stays.

var preReleaseRE = regexp.MustCompile(`(?i)(alpha|beta|rc|pre|dev|snapshot|nightly|git|svn)`)

// newerRelease reports whether the reading (version, package release) is a newer release than the person's. false when it is the
// same release, older, or when the two cannot be ordered: an empty version, a pre-release, another epoch or a text no version order reads.
func newerRelease(readV, readP, personV, personP string) bool {
	rel := func(v, p string) string {
		if strings.TrimSpace(p) != "" {
			return p
		}
		return v
	}
	r, p := rel(readV, readP), rel(personV, personP)
	if strings.TrimSpace(r) == "" || strings.TrimSpace(p) == "" {
		return false
	}
	// both are package releases of one upstream version (1:9.2p1-2+deb12u2, 1:9.2p1-2+deb12u4): the distribution's security update is
	// a newer release, so the full release is ordered
	if strings.TrimSpace(readP) != "" && strings.TrimSpace(personP) != "" && pkgrel.Upstream(readP) == pkgrel.Upstream(personP) && epochPart(readP) == epochPart(personP) {
		if a, ok := apkver.Parse(readP); ok {
			if b, ok := apkver.Parse(personP); ok { // Alpine: 10.2_p1-r1 < 10.2_p1-r3
				return apkver.Compare(a, b) > 0
			}
		}
		if !debver.Valid(readP) || !debver.Valid(personP) {
			return false
		}
		c, err := debver.Compare(readP, personP)
		return err == nil && c > 0
	}
	if pkgrel.Same(readV, readP, personV, personP) {
		return false
	}
	ur, up := pkgrel.Upstream(r), pkgrel.Upstream(p)
	if ur == "" || up == "" || preReleaseRE.MatchString(ur) || preReleaseRE.MatchString(up) || !debver.Valid(ur) || !debver.Valid(up) {
		return false
	}
	if er, ep := epochPart(r), epochPart(p); er != "" && ep != "" && er != ep {
		return false
	}
	c, err := debver.Compare(ur, up)
	return err == nil && c > 0
}

// pkgUpdate reports whether a reading and a correction both name a package release of one upstream version: the person stated the
// distribution's release, so a newer one read later is the distribution's update whatever the overridden reading was.
func pkgUpdate(r, c swFacts) bool {
	return strings.TrimSpace(r.pkg) != "" && strings.TrimSpace(c.pkg) != "" && pkgrel.Upstream(r.pkg) == pkgrel.Upstream(c.pkg)
}

func epochPart(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 {
		return v[:i]
	}
	return ""
}

// swFacts is a software row as the lapse rule reads it. setAt is when a person set a correction, or when a source first reported a
// reading ("" for a reading that predates the record of it: it counts as read before any correction).
type swFacts struct {
	id, display, vendor, product, cpe, version, pkg, source, setAt string
	overrode                                                       string // on a correction: the version of the reading it replaced ("" when none)
}

// lapsingReadings is the one rule for software, firmware and declared OS rows alike (INV-52): for each correction, the newest
// reading of the same software (the same vendor and product, or the same CPE application) that first appeared after the correction
// was set and reads a newer release than the person's and than the reading the person overrode (a row the source dropped and reads
// again, at the version the person said was wrong, is not an update). The result maps a correction's id to that reading; a
// correction nothing outgrew is not in it.
func lapsingReadings(corrections, readings []swFacts) map[string]swFacts {
	out := map[string]swFacts{}
	for _, c := range corrections {
		var newest *swFacts
		for i := range readings {
			r := &readings[i]
			same := strings.EqualFold(r.vendor, c.vendor) && strings.EqualFold(r.product, c.product) || cpeApp(r.cpe) != "" && cpeApp(r.cpe) == cpeApp(c.cpe)
			if !same || r.source == "manual" || r.setAt == "" || r.setAt <= c.setAt || !newerRelease(r.version, r.pkg, c.version, c.pkg) ||
				c.overrode != "" && !pkgUpdate(*r, c) && !newerRelease(r.version, r.pkg, c.overrode, "") {
				continue
			}
			if newest == nil || newerRelease(r.version, r.pkg, newest.version, newest.pkg) {
				newest = r
			}
		}
		if newest != nil {
			out[c.id] = *newest
		}
	}
	return out
}

// lapseCorrections ends the corrections of a device that a reading first seen after them has outgrown (INV-52): the correction row
// goes, the device is back to what its sources read, and the audit trail says "from the person's version to the newly read one"
// under the system actor. It reports whether any lapsed.
func (s *Service) lapseCorrections(ctx context.Context, tx *sql.Tx, assetID string) (bool, error) {
	read := func(where string) ([]swFacts, error) {
		//nolint:gosec // G202: where is one of two constant conditions below
		rows, err := tx.QueryContext(ctx, `SELECT s.id, s.display, s.vendor, s.product, ifnull(s.cpe, ''), ifnull(s.version, ''), ifnull(s.pkg_version, ''), s.source, CASE WHEN s.source = 'manual' THEN s.seen_at ELSE ifnull(s.first_seen, '') END, ifnull(s.corrects, '')
			FROM inv_software s WHERE s.asset_id = ? AND NOT `+hiddenGuess+` AND `+where+` ORDER BY s.seen_at, s.id`, assetID)
		if err != nil {
			return nil, fmt.Errorf("inventory: read software: %w", err)
		}
		defer func() { _ = rows.Close() }()
		var out []swFacts
		for rows.Next() {
			var x swFacts
			var corrects string
			if err := rows.Scan(&x.id, &x.display, &x.vendor, &x.product, &x.cpe, &x.version, &x.pkg, &x.source, &x.setAt, &corrects); err != nil {
				return nil, fmt.Errorf("inventory: read software: %w", err)
			}
			if corrects != "" {
				_, _, _, x.overrode = correctedFrom(corrects)
			}
			out = append(out, x)
		}
		return out, rows.Err()
	}
	corrections, err := read(`s.corrects IS NOT NULL AND s.not_installed = 0`)
	if err != nil || len(corrections) == 0 {
		return false, err
	}
	readings, err := read(`s.source <> 'manual' AND ifnull(s.first_seen, '') <> '' AND NOT ` + notInstalledSW)
	if err != nil {
		return false, err
	}
	lapsed := false
	for _, c := range corrections {
		newest, ok := lapsingReadings([]swFacts{c}, readings)[c.id]
		if !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software WHERE id = ?`, c.id); err != nil {
			return false, fmt.Errorf("inventory: lapse correction: %w", err)
		}
		lapsed = true
		if err := s.auditTx(ctx, tx, systemActor, "inventory.software_correction_lapsed", deviceName(ctx, tx, assetID)+": "+c.display,
			swText(c.display, c.version, c.pkg)+" → "+swText(newest.display, newest.version, newest.pkg)+" ("+newest.source+")"); err != nil {
			return false, err
		}
	}
	return lapsed, nil
}

var osVersionRE = regexp.MustCompile(`^\s*([^\d]*?)\s*(\d+(?:\.\d+)*)([^\d]*)$`)

// osSplit reads an OS text as its name and its version: "Alpine Linux 3.23" is ("alpine linux", "3.23"), "Ubuntu 24.04 LTS" is
// ("ubuntu", "24.04"). ok is false for a text with no name before one version number or with more digits after it ("Windows 10 22H2",
// "Linux 4.15 - 5.19"): it cannot be ordered reliably.
func osSplit(text string) (name, version string, ok bool) {
	m := osVersionRE.FindStringSubmatch(text)
	if m == nil || strings.TrimSpace(m[1]) == "" {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(m[1])), m[2], true
}

// sameOSName reports whether two OS texts name the same OS with a version each ("Alpine Linux 3.20", "Alpine Linux 3.23").
func sameOSName(a, b string) bool {
	an, _, ok1 := osSplit(a)
	bn, _, ok2 := osSplit(b)
	return ok1 && ok2 && an == bn
}

// osNewer reports whether an OS reading names a newer version of the same OS than the person's text, by the rule of newerRelease.
func osNewer(reading, person string) bool {
	rn, rv, ok1 := osSplit(reading)
	pn, pv, ok2 := osSplit(person)
	return ok1 && ok2 && rn == pn && newerRelease(rv, "", pv, "")
}

// lapseOS ends a person's corrected OS (INV-41) when a source reads a newer version of that OS than the person's text after the
// correction was set: the same rule as for software, with the history saying so. It reports whether the correction lapsed; the caller
// folds the observations again.
func (s *Service) lapseOS(ctx context.Context, tx *sql.Tx, assetID string) (bool, error) {
	person, setAt, _, ok, err := manualOS(ctx, tx, assetID)
	if err != nil || !ok {
		return false, err
	}
	// only what the device states about itself (its agent, its SNMP system description) lapses it: a scan or traffic fingerprint
	// is a guess and wobbles between versions from run to run
	rows, err := tx.QueryContext(ctx, `SELECT value, source, ifnull(first_seen, '') FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source IN ('agent', 'snmp')
		ORDER BY first_seen DESC, id`, assetID)
	if err != nil {
		return false, fmt.Errorf("inventory: read the detected OS: %w", err)
	}
	var newest, from string
	var before []string // the readings there when the person set it: the one they overrode is among them
	for rows.Next() {
		var v, src, first string
		if err := rows.Scan(&v, &src, &first); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("inventory: read the detected OS: %w", err)
		}
		if first == "" || first <= setAt {
			before = append(before, v)
			continue
		}
		if osNewer(v, person) && (newest == "" || osNewer(v, newest)) {
			newest, from = v, src
		}
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	for _, b := range before { // a reading the source dropped and reads again is not an update
		if newest != "" && !osNewer(newest, b) && sameOSName(newest, b) {
			newest = ""
		}
	}
	if newest == "" {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = 'manual'`, assetID); err != nil {
		return false, fmt.Errorf("inventory: lapse the corrected OS: %w", err)
	}
	return true, s.auditTx(ctx, tx, systemActor, "inventory.os_correction_lapsed", deviceName(ctx, tx, assetID), person+" → "+newest+" ("+from+")")
}
