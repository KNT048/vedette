package findings

import (
	"context"
	"database/sql"
	"errors"
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

// notInstalledCVEs is, per CVE, the person's words ("op said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026") for the CVEs that
// the rows a person said are not installed would produce as a finding (or a closed or asked one), and that no row the match still
// reads produces (live: the match of the device without them). nil when there are none.
func notInstalledCVEs(a Asset, vulns []Vuln, have map[string]bool, live MatchResult, now time.Time) map[string]string {
	if len(a.NotInstalled) == 0 {
		return nil
	}
	said := make(map[string]string, len(a.NotInstalled))
	for _, sw := range a.NotInstalled {
		said[sw.ID] = sw.Correction
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
	out := map[string]string{}
	for _, list := range [][]Match{r.New, r.Existing, r.NameOnly, r.Asked, r.Aged} {
		for _, m := range list {
			if note, ok := said[m.SoftwareID]; ok && !still[m.CVE] {
				if _, done := out[m.CVE]; !done {
					out[m.CVE] = note
				}
			}
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
func (s *Service) closeNotInstalled(ctx context.Context, tx *sql.Tx, assetID, device string, cves map[string]string, now time.Time, emit func(string, any)) (closed int, kept map[string]string, err error) {
	for _, cve := range slices.Sorted(maps.Keys(cves)) {
		r, err := loadByPair(ctx, tx, assetID, cve)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return closed, kept, err
		}
		if r.Status == StatusSuspected && (reopenedByPerson(r.History) || acceptedByPerson(r.History)) {
			if kept == nil {
				kept = map[string]string{}
			}
			kept[cve] = clipNote(cves[cve] + ". This finding stays open because a person reopened it or accepted its risk; close it yourself if the software is not there.")
			continue
		}
		was := r.Status
		f, h, ok := r.AutoResolve(notInstalledNote(cves[cve], device), now)
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
		if err := s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.auto_resolved", Target: r.ID,
			Detail: r.CVE + ": not installed (" + cves[cve] + ")"}); err != nil {
			return closed, kept, err
		}
		emit(EventStatusChanged, StatusChangedEvent{FindingID: r.ID, From: was, To: r.Status, Reason: ReasonNotInstalled})
		closed++
	}
	return closed, kept, nil
}

// acceptedByPerson reports whether a person ever accepted the finding's risk (its acceptance may have expired since).
func acceptedByPerson(hist []HistoryEntry) bool {
	return slices.ContainsFunc(hist, func(h HistoryEntry) bool { return h.User != SystemUser && h.Action == string(StatusRiskAccepted) })
}

// reopenReason is the StatusChangedEvent reason of a finding ReopenOnMatch reopens on the row softwareID, by what brought the row back.
// ReasonNotInstalledCleared (no notice) when Vedette had closed it for "Not installed" and a person's own act did: the row that matches
// again is the very row the person said was not installed (same name, version and source, as the close note names it: they cleared
// the mark), or a person's row (they now say what is installed). Anything else is a new reading, ReasonMatchesAgain with its notice:
// another source reports the product (an agent next to the scan), the source reads another version, or another row matches.
func reopenReason(a Asset, closed Finding, softwareID string) string {
	if !strings.HasPrefix(closed.ResolutionNote, NotInstalledNote) {
		return ReasonMatchesAgain
	}
	for _, sw := range a.Software {
		if sw.ID != softwareID {
			continue
		}
		if sw.Source == "manual" || strings.Contains(closed.ResolutionNote, " said "+strings.TrimSpace(sw.Display+" "+sw.Version)+" ("+sw.Source+") is not installed") {
			return ReasonNotInstalledCleared
		}
	}
	return ReasonMatchesAgain
}
