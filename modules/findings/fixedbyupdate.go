package findings

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/orgtime"
)

// Fixed by an update (INV-2, INV-27). A version match closes in one of two ways when a later match proves the version outside every
// affected range:
//   - patched (ReasonFixedByUpdate): the same software on the same device was read again, by the same reader or by the device itself,
//     at another version: the device got an update. History: "Fixed by an update: WinRAR 6.24 → 7.23.0 (agent, 17 Nov 2026)."
//   - not_relevant (ReasonNotAffectedVersion): the same version judged again with better data (an NVD range that changed, a
//     distribution's fix data), a guess (a banner, an OS guess) replaced by the device's own reading, or a person's correction.
// Tenable and Qualys mark a vulnerability no longer detected after a version change "Fixed"; "not affected" stays for "never was".

// deviceReader says the source is the device itself (its agent, its SNMP answer): two readings of these are both the device's word.
func deviceReader(src string) bool { return src == "agent" || src == SourceSNMP }

// readerName is how the history names a reader.
func readerName(src string) string {
	switch src {
	case SourceSNMP:
		return "SNMP"
	case "":
		return "reading"
	}
	return src
}

// Sentences of a version match written before Evidence.Read was kept (agentSummary, the SNMP confirmation): the version read is the
// last word of "<software> <version>".
var (
	agentReadRE = regexp.MustCompile(`^The agent on .+? reports (.+) installed\. That version is inside the range`)
	agentWinRE  = regexp.MustCompile(`^The agent on .+? reports (.+) build ([0-9][0-9.]*[0-9])[ .,]`)
	snmpReadRE  = regexp.MustCompile(`^Confirmed: .+? reports (.+) over SNMP;`)
)

// priorReading is the reading a version finding was matched on: its stored Evidence.Read, else what its sentence says (only the
// device's own readings are read from a sentence; any other is unknown). ok is false when it is not known.
func priorReading(r Record) (Reading, bool) {
	if r.Evidence == nil {
		return Reading{}, false
	}
	if r.Evidence.Read != nil && r.Evidence.Read.Version != "" {
		return *r.Evidence.Read, true
	}
	s := r.Evidence.Summary
	if m := agentWinRE.FindStringSubmatch(s); m != nil {
		return Reading{Software: strings.TrimSpace(m[1]), Source: "agent", Version: m[2]}, true
	}
	for _, x := range []struct {
		re  *regexp.Regexp
		src string
	}{{agentReadRE, "agent"}, {snmpReadRE, SourceSNMP}} {
		if m := x.re.FindStringSubmatch(s); m != nil {
			name, ver, ok := cutLastWord(m[1])
			if !ok {
				return Reading{}, false
			}
			return Reading{Software: name, Source: x.src, Version: ver}, true
		}
	}
	return Reading{}, false
}

func cutLastWord(s string) (head, last string, ok bool) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ' ')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:i]), s[i+1:], true
}

// buildNum drops the "10.0." of a Windows build, as the sentences write it.
func buildNum(v string) string { return strings.TrimPrefix(strings.TrimSpace(v), "10.0.") }

// readingsDiffer says the two readings name different releases: the package releases when both have one, else the versions.
func readingsDiffer(a, b Reading) (from, to string, differ bool) {
	if a.Pkg != "" && b.Pkg != "" {
		return a.Pkg, b.Pkg, a.Pkg != b.Pkg
	}
	from, to = buildNum(a.Version), buildNum(b.Version)
	return from, to, from != "" && to != "" && from != to
}

// matchedOnVersion says the finding rests on a version inside a range: basis version, or a person's confirm of one.
func matchedOnVersion(r Record) bool {
	return r.Basis == BasisVersion || r.Basis == BasisPerson && r.Evidence != nil && r.Evidence.Prior == BasisVersion
}

// updateReadings decides whether the move from prior to later is an update the device got: both readings are of the same reader, or
// both are the device's own; neither is a person's entry; the release differs. from and to are the releases to name.
func updateReadings(prior, later Reading) (from, to string, ok bool) {
	if prior.Source == "" || prior.Source == "manual" || later.Source == "" || later.Source == "manual" {
		return "", "", false
	}
	if prior.Source != later.Source && (!deviceReader(prior.Source) || !deviceReader(later.Source)) {
		return "", "", false // a guess replaced by the device's reading: the version was never the one matched
	}
	return readingsDiffer(prior, later)
}

// fixedNote is the history and resolution note of a finding fixed by an update: the move, then the matcher's proof (what range or
// which distribution's fix the new release is outside of, with the data's source), then that it reopens.
func fixedNote(software, from, to, reader string, at time.Time, loc *time.Location, proof string) string {
	when := ""
	if !at.IsZero() {
		when = ", " + orgtime.Day(at, loc)
	}
	if p := proofSentence(proof); p != "" {
		proof = " " + p
	} else {
		proof = ""
	}
	return fmt.Sprintf("%s %s %s → %s (%s%s).%s Vedette reopens it if a later reading is inside an affected range again.", FixedByUpdateNote, clean(software), clean(from), clean(to), readerName(reader), when, proof)
}

// proofSentence is the matcher's "Not affected: …" sentence without its lead and its closing sentence ("Vedette closed this by
// itself …"), with a capital first letter: "Version 7.23.0 of WinRAR is outside every version range NVD lists for CVE-2025-8088."
func proofSentence(s string) string {
	s = strings.TrimSpace(strings.TrimPrefix(s, "Not affected: "))
	if i := strings.Index(s, " Vedette closed this by itself"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// fixedByUpdate says whether proof p, which closes the open finding r, shows an update the device got (see the package rule above),
// with the note to close it with.
func fixedByUpdate(r Record, p Match, loc *time.Location) (string, bool) {
	if !r.Status.Open() || p.provedOn == "" || p.corrected || p.Evidence.Read == nil || !matchedOnVersion(r) {
		return "", false
	}
	prior, ok := priorReading(r)
	if !ok {
		return "", false
	}
	later := *p.Evidence.Read
	if r.SoftwareID != "" && p.SoftwareID != "" && r.SoftwareID != p.SoftwareID {
		return "", false // another software row (a second install of the same product, or another product)
	}
	from, to, ok := updateReadings(prior, later)
	if !ok {
		return "", false
	}
	return fixedNote(cmp.Or(later.Software, prior.Software, p.SoftwareDisplay), from, to, later.Source, later.At, loc, p.Evidence.Summary), true
}

// reclassifyPatched is the one-time pass over findings Vedette closed as not affected before the rule above existed (migration 0017's
// marker fnd_patched_backfill_pending): a closure by a version proof (the note "Not affected: version …", the version it proved in
// proved_version) of a finding matched on the device's own reading of another version becomes patched by an update, with a history
// line built from what is stored (the matched sentence, the proved version, the day it was closed). Its resolved_at stays the day of
// the closure. No event is sent (no alert burst): one audit row says how many. The marker is dropped after the pass.
func (s *Service) reclassifyPatched(ctx context.Context) error {
	loc := orgtime.At(ctx, s.cfg.Zone)
	return s.write(ctx, func(tx *sql.Tx, now time.Time, _ func(string, any)) error {
		var one int
		switch err := tx.QueryRowContext(ctx, `SELECT 1 FROM fnd_patched_backfill_pending`).Scan(&one); {
		case errors.Is(err, sql.ErrNoRows):
			return nil
		case err != nil:
			return fmt.Errorf("findings: reading the patched pass marker: %w", err)
		}
		rows, err := tx.QueryContext(ctx, `SELECT `+findingColumns+` FROM fnd_finding WHERE status = 'not_relevant' AND resolution_reason = 'not_affected_version'
			AND resolved_by = 'system' AND proved_version IS NOT NULL AND basis IN ('version', 'person') ORDER BY id`)
		if err != nil {
			return fmt.Errorf("findings: reading the closed findings: %w", err)
		}
		var list []Record
		for rows.Next() {
			r, err := scanRecord(rows)
			if err != nil {
				_ = rows.Close()
				return fmt.Errorf("findings: reading the closed findings: %w", err)
			}
			list = append(list, r)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return fmt.Errorf("findings: reading the closed findings: %w", err)
		}
		n := 0
		for _, r := range list {
			note, ok := relabelNote(r, loc)
			if !ok {
				continue
			}
			f, h, ok := r.RelabelFixed(note, now)
			if !ok {
				continue
			}
			r.Finding = f
			if err := updateRecord(ctx, tx, r); err != nil {
				return err
			}
			if err := insertHistory(ctx, tx, r.ID, h); err != nil {
				return err
			}
			n++
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM fnd_patched_backfill_pending`); err != nil {
			return fmt.Errorf("findings: ending the patched pass: %w", err)
		}
		if n == 0 {
			return nil
		}
		return s.cfg.Audit.Append(ctx, tx, audit.Entry{User: SystemUser, Action: "findings.patched_backfill", Target: "findings",
			Detail: fmt.Sprintf("%d findings closed as not affected after the device's version changed are now patched (fixed by an update); no notice sent", n)})
	})
}

// relabelNote is the "Fixed by an update" note of a finding closed before the rule, from what is stored: the reading it was matched on
// (priorReading) and the version the close proved (proved_version), read by the same reader (the effective row of a software is the
// strongest source's, inventory INV-50), on the day it was closed. ok is false when the closure is not of that kind: no version proof,
// a person's correction, a release that did not change, or a reading that cannot be told.
func relabelNote(r Record, loc *time.Location) (string, bool) {
	if !matchedOnVersion(r) || !strings.HasPrefix(r.ResolutionNote, "Not affected: version ") || strings.Contains(r.ResolutionNote, "person's correction") {
		return "", false
	}
	prior, ok := priorReading(r)
	if !ok || prior.Pkg != "" { // a package release was compared: the stored proved version may be the package's, not comparable
		return "", false
	}
	later := Reading{Software: prior.Software, Source: prior.Source, Version: r.ProvedVersion, At: r.ResolvedAt}
	from, to, ok := updateReadings(prior, later)
	if !ok {
		return "", false
	}
	return fixedNote(prior.Software, from, to, prior.Source, r.ResolvedAt, loc, r.ResolutionNote), true
}
