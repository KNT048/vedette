package feeds

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/versionscheme"
)

// dsmRecord is a Synology record that names DSM: with no version (its fixed releases in the description only) when ranges is empty.
func dsmRecord(cve, description string, ranges ...Range) (NVDRecord, CVERecord) {
	if len(ranges) == 0 {
		ranges = []Range{{CVE: cve, Origin: OriginCNA, Vendor: "synology", Product: "diskstationmanagerdsm", DefaultStatus: DefaultAffected}}
	}
	return NVDRecord{CVE: cve, Published: epoch0.AddDate(0, -1, 0), LastModified: epoch0, Status: "Received", Affected: []AffectedRow{}, Description: description},
		CVERecord{CVE: cve, State: RecordPublished, Description: description, Ranges: ranges}
}

// seedDSM writes the records into a new store.
func seedDSM(t *testing.T, records ...[2]string) *Store {
	t.Helper()
	s, db := newStore(t)
	var nvd []NVDRecord
	var recs []CVERecord
	for _, r := range records {
		n, c := dsmRecord(r[0], r[1])
		if r[0] == "CVE-2025-13392" { // the CNA states two lines as rows, and the line it leaves out in words
			c.Ranges = []Range{
				{CVE: r[0], Origin: OriginCNA, Vendor: "synology", Product: "diskstationmanagerdsm", StartIncl: "7.3.1", EndExcl: "7.3.1-86003-1", VersionType: "custom", DefaultStatus: DefaultUnknown},
				{CVE: r[0], Origin: OriginCNA, Vendor: "synology", Product: "diskstationmanagerdsm", StartIncl: "7.2.2", EndExcl: "7.2.2-72806-5", VersionType: "custom", DefaultStatus: DefaultUnknown},
			}
		}
		nvd, recs = append(nvd, n), append(recs, c)
	}
	write(t, db, func(tx *sql.Tx) error {
		if err := storeRecords(t.Context(), tx, nvd, epoch0); err != nil {
			return err
		}
		k, err := recordKeepOf(t.Context(), tx, epoch0, nil)
		if err != nil {
			return err
		}
		_, err = writeRecords(t.Context(), tx, recs, k, epoch0)
		return err
	})
	return s
}

// vendorWord is what the vendor's rows of cve say about a DSM release, read the way the matcher reads them: "" when they say nothing
// about its line (the generic comparison decides, a record row without a version stays a question), else "not affected" or
// "affected, fixed in <release>".
func vendorWord(t *testing.T, s *Store, cve, version string) string {
	t.Helper()
	rows, err := s.SchemeRangesOf(t.Context(), []string{cve})
	if err != nil {
		t.Fatal(err)
	}
	installed, ok := versionscheme.SynologyDSM.Installed(version, "")
	if !ok {
		t.Fatal(version)
	}
	var spans []versionscheme.Span
	for _, r := range rows {
		if _, sp, _, ok := RangeScheme(r); ok && r.CVE == cve {
			spans = append(spans, sp)
		}
	}
	line := func(v *versionscheme.Version) bool { return v != nil && slices.Equal(v.Line, installed.Line) }
	named, ownTrain := false, false
	for _, sp := range spans {
		older := sp.Start == nil && sp.End != nil && slices.Compare(installed.Line, sp.End.Line) < 0 // from the first release on
		named = named || line(sp.Start) || line(sp.End) || older
		ownTrain = ownTrain || sp.End != nil && !sp.End.LineStart && sp.End.Train == installed.Train
	}
	v := versionscheme.Judge(installed, spans)
	switch {
	case !named || v.State == versionscheme.NotComparable, v.State == versionscheme.NotAffected && !ownTrain:
		return ""
	case v.State == versionscheme.NotAffected:
		return "not affected"
	case v.Fix == nil:
		return "affected"
	}
	return "affected, fixed in " + v.Fix.Label
}

const (
	laterLinesOnly = "An incorrect authorization vulnerability in Synology DiskStation Manager (DSM) before 7.3.2-86009-5 and 7.4.1-90080-1 allows remote attackers to read specific files."
	sameBatch      = "A path traversal vulnerability in Synology DiskStation Manager (DSM) before 7.2.1-69057-13, 7.2.2-72806-10, 7.3.2-86009-5, and 7.4.1-90080-1 allows remote attackers to read or write arbitrary files."
	earlierBatch   = "A buffer overflow in Synology DiskStation Manager (DSM) before 7.1.1-42962-8 and 7.2.1-69057-2 and 7.2.2-72806 and Synology Unified Controller (DSMUC) before 3.1.4-23079 allows remote attackers to execute arbitrary code."
	statedNot      = "A missing authentication vulnerability in Synology DiskStation Manager (DSM) before 7.2.2-72806-5 and 7.3.1-86003-1 (7.2.1-69057 is not affected) allows remote attackers to bypass authentication."
	statedNotTwo   = "An improper limitation vulnerability in Synology DiskStation Manager (DSM) before 7.2.2-72806-5 and 7.3.1-86003-1 (7.1.1-42962 and 7.2.1-69057 are not affected) allows remote attackers to read files."
)

// A record naming only later DSM lines than the device's says nothing about the device's line: a question, never a finding, and
// never "not affected" because another record names a fix on that line (Synology fixes selected flaws only on a line past its
// support, so a fix there for one CVE does not say another CVE leaves the line alone). A line the record says outright is not
// affected is not; a named line is judged by its own fix.
func TestSchemeRangesOf_DSMLineTheRecordLeavesOut(t *testing.T) {
	t.Parallel()
	s := seedDSM(t, [2]string{"CVE-2026-124993", laterLinesOnly}, [2]string{"CVE-2026-76954", sameBatch}, [2]string{"CVE-2024-5401", earlierBatch},
		[2]string{"CVE-2025-13392", statedNot}, [2]string{"CVE-2025-15716", statedNotTwo})
	for _, c := range []struct {
		cve, ver, say string
	}{
		{"CVE-2026-124993", "7.2.1-69057-5", ""}, // a fix of 7.2.1 in the same batch is no word about this CVE
		{"CVE-2026-124993", "7.2.2-72806-3", ""},
		{"CVE-2026-124993", "7.1.1-42962-5", ""},
		{"CVE-2026-124993", "7.3.1-86003", ""},
		{"CVE-2026-124993", "7.3.2-86009-4", "affected, fixed in 7.3.2-86009 Update 5"},
		{"CVE-2026-76954", "7.2.1-69057-5", "affected, fixed in 7.2.1-69057 Update 13"}, // the fix of the device's own line
		{"CVE-2026-76954", "7.2.2-72806-3", "affected, fixed in 7.2.2-72806 Update 10"},
		{"CVE-2026-76954", "7.1.1-42962-5", ""},
		{"CVE-2024-5401", "7.2.1-69057-5", "not affected"},
		{"CVE-2025-13392", "7.2.1-69057-5", "not affected"}, // "(7.2.1-69057 is not affected)"
		{"CVE-2025-13392", "7.2.2-72806-3", "affected, fixed in 7.2.2-72806 Update 5"},
		{"CVE-2025-15716", "7.2.1-69057-5", "not affected"}, // "(7.1.1-42962 and 7.2.1-69057 are not affected)"
		{"CVE-2025-15716", "7.1.1-42962-5", "not affected"},
	} {
		if got := vendorWord(t, s, c.cve, c.ver); got != c.say {
			t.Errorf("%s on %s: %q, want %q", c.cve, c.ver, got, c.say)
		}
	}
}
