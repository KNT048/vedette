package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
)

// "Not installed" (INV-6c, inventory INV-41 (6)): a person says a software row a scan, SNMP or an agent reported is not on
// the device. Inventory leaves the row out of matching while that row stays reported and gives it in Asset.NotInstalled; the open
// findings only that row produces close here, in the same write as the match, with the person named. Clearing it, or the source
// reading another version (a new install), puts a row back in the match, and ReopenOnMatch reopens them.

// NotInstalledNote starts the note of a finding Vedette closed because a person said its software is not installed: with the reason
// not_affected_version (Vedette's own close) it reopens on the next match that produces it.
const NotInstalledNote = "Closed: a person said the software is not installed."

// ReasonNotInstalled and ReasonNotInstalledCleared are the StatusChangedEvent reasons of a close for "Not installed" and of the reopen
// after a person clears it: notify sends nothing for either (a person just acted on the device). A reopen because the source reads
// another version, a new install, keeps ReasonMatchesAgain and its notice.
const (
	ReasonNotInstalled        = "not_installed"
	ReasonNotInstalledCleared = "not_installed_cleared"
)

// notMark is why a CVE closes for "Not installed": the person's words ("op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026"),
// the identity of the row the mark covers (inventory's row key) and when the person made it.
type notMark struct {
	said, key string
	at        time.Time
}

// notInstalledCVEs is, per CVE, the mark of the rows a person said are not installed whose CVEs they would produce as a finding (or a
// closed or asked one) and that no row the match still reads produces (live: the match of the device without them). When several
// marked rows produce a CVE, the first names it and the newest mark's time counts. nil when there are none.
func notInstalledCVEs(a Asset, vulns []Vuln, have map[string]bool, live MatchResult, now time.Time) map[string]notMark {
	if len(a.NotInstalled) == 0 {
		return nil
	}
	marks := make(map[string]notMark, len(a.NotInstalled))
	for _, sw := range a.NotInstalled {
		marks[sw.ID] = notMark{said: sw.Correction, key: sw.Key, at: sw.MarkedAt}
	}
	gone := a
	gone.Software, gone.NotInstalled = a.NotInstalled, nil
	r := MatchAsset(gone, vulns, have, now)
	still := map[string]bool{}
	for _, list := range [][]Match{live.New, live.Existing} {
		for _, m := range list {
			still[m.CVE] = true
		}
	}
	out := map[string]notMark{}
	for _, list := range [][]Match{r.New, r.Existing, r.NameOnly, r.Asked, r.Aged} {
		for _, m := range list {
			mk, ok := marks[m.SoftwareID]
			if !ok || still[m.CVE] {
				continue
			}
			if done, seen := out[m.CVE]; seen {
				if mk.at.After(done.at) {
					done.at = mk.at
					out[m.CVE] = done
				}
				continue
			}
			out[m.CVE] = mk
		}
	}
	return out
}

// notInstalledNote is the close note: "Closed: a person said the software is not installed. op@example.com said OpenSSH 10.2 (nmap)
// is not installed on router-1 on 17 Nov 2026." (inventory gives "… is not installed on 17 Nov 2026"; the device's name goes before the
// day).
func notInstalledNote(said, device string) string {
	if said == "" {
		return NotInstalledNote
	}
	if i := strings.LastIndex(said, " is not installed on "); i >= 0 && device != "" {
		said = said[:i] + " is not installed on " + clean(device) + " (" + said[i+len(" is not installed on "):] + ")"
	}
	return clipNote(NotInstalledNote + " " + said + ".")
}

// closeNotInstalled closes the open suspected findings of the CVEs only software a person said is not installed produces (INV-6c):
// not_relevant by the system user with the reason not_affected_version, so the next match that produces the CVE again reopens it (the
// person cleared it, or a source reads it again); the note names the person, a history row, audit findings.auto_resolved and a
// status_changed event with ReasonNotInstalled (no notice). A finding a scan confirmed (basis scan) is direct evidence and stays open,
// like every closed one (a person's status stands). Like every other close by Vedette, it never closes a finding a person reopened
// after Vedette last closed it, or one whose risk a person accepted (an expired acceptance reopens it with a notice): those are
// returned in kept, CVE -> the sentence noteNoLongerMatching writes once.
func (s *Service) closeNotInstalled(ctx context.Context, tx *sql.Tx, assetID, device string, cves map[string]notMark, now time.Time, emit func(string, any)) (closed int, kept map[string]string, err error) {
	for _, cve := range slices.Sorted(maps.Keys(cves)) {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return closed, kept, err
		}
		mk := cves[cve]
		if (r.Status == StatusSuspected || r.ByDevice()) && keptAfter(r.History, mk.at) {
			if kept == nil {
				kept = map[string]string{}
			}
			kept[cve] = clipNote(mk.said + ". This finding stays open because a person reopened it or accepted its risk after that; close it yourself if the software is not there.")
			continue
		}
		was := r.Status
		f, h, ok := r.AutoResolve(notInstalledNote(mk.said, device), now)
		if !ok {
			continue
		}
		r.Finding = f
		if err := updateRecord(ctx, tx, r); err != nil {
			return closed, kept, err
		}
		if err := insertHistory(ctx, tx, r.ID, h); err != nil {
			return closed, kept, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO fnd_not_installed (finding_id, mark) VALUES (?, ?) ON CONFLICT (finding_id) DO UPDATE SET mark = excluded.mark`,
			r.ID, cmp.Or(mk.key, "?"+cve)); err != nil {
			return closed, kept, fmt.Errorf("findings: recording the not-installed mark: %w", err)
		}
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.auto_resolved", Target: r.ID,
			Detail: r.CVE + ": not installed (" + mk.said + ")"}); err != nil {
			return closed, kept, err
		}
		emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status, Reason: ReasonNotInstalled})
		closed++
	}
	return closed, kept, nil
}

// keptAfter reports whether a person reopened the finding, or accepted its risk, after the mark (at): that newer decision stands
// (INV-6c). One made before the mark does not: the mark is the person's newer word. A zero at (unknown) counts every such act.
func keptAfter(hist []HistoryEntry, at time.Time) bool {
	return slices.ContainsFunc(hist, func(h HistoryEntry) bool {
		return h.User != SystemUser && (h.Action == "reopened" || h.Action == string(StatusRiskAccepted)) && !h.TS.Before(at)
	})
}

// reopenReason is the StatusChangedEvent reason of a finding ReopenOnMatch reopens on the row softwareID, by what brought the row back.
// ReasonNotInstalledCleared (no notice) only when Vedette had closed it for "Not installed" and the row that matches again is the very
// reported row the mark covered (the same identity: source, vendor, product and version; its display may differ): the person cleared
// the mark. Anything else is new evidence, ReasonMatchesAgain with its notice: another source reports the product, the source reads
// another version, a person's own row, or a change of the exploited list brings in another row. The recorded mark goes with the close.
func reopenReason(ctx context.Context, tx *sql.Tx, a Asset, closed Record, softwareID string) (string, error) {
	if !strings.HasPrefix(closed.ResolutionNote, NotInstalledNote) {
		return ReasonMatchesAgain, nil
	}
	var mark string
	err := tx.QueryRowContext(ctx, `SELECT mark FROM fnd_not_installed WHERE finding_id = ?`, closed.ID).Scan(&mark)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("findings: reading the not-installed mark: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_not_installed WHERE finding_id = ?`, closed.ID); err != nil {
		return "", fmt.Errorf("findings: clearing the not-installed mark: %w", err)
	}
	for _, sw := range a.Software {
		if sw.ID == softwareID && sw.Source != "manual" && mark != "" && sw.Key == mark {
			return ReasonNotInstalledCleared, nil
		}
	}
	return ReasonMatchesAgain, nil
}
