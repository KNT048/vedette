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

// A person's version of a software line lapses when a source reads a newer release after the person set it (INV-52, Resolve rule
// 1): the person said what the device ran then, and a later reading of a newer release means it was updated since. A reading that was
// already there never lapses it, nor does an older or the same release (core/pkgrel), nor a pair of versions that cannot be ordered
// reliably: then the person's version stays. The device's OS follows the same rule (lapseOS).

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

func epochPart(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 {
		return v[:i]
	}
	return ""
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
