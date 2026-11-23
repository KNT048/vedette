package feeds

import (
	"slices"
	"testing"

	"github.com/knt048/vedette/core/versionscheme"
)

// DSM's ranges, whichever way they come: NVD writes Synology's notation (read in the DSM scheme beside the generic comparison), and a
// record that names "DiskStation Manager (DSM)" with no version states its fixed releases in its description. A record row without a
// version is never "every version" in a scheme: it stays the generic comparison's (a question), unless the description says more.
func TestDSMRanges(t *testing.T) {
	t.Parallel()
	installed, ok := versionscheme.SynologyDSM.Installed("7.2.1-69057-5", "")
	if !ok {
		t.Fatal("7.2.1-69057-5")
	}
	nvd := Range{CVE: "CVE-2024-10441", Origin: OriginNVD, Part: "o", Vendor: "synology", Product: "diskstation_manager",
		CPE: "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*", StartIncl: "7.2.1-69057", EndExcl: "7.2.1-69057-6"}
	_, sp, _, ok := RangeScheme(nvd)
	if !ok || versionscheme.Judge(installed, []versionscheme.Span{sp}).State != versionscheme.Affected {
		t.Fatalf("NVD's DSM row: ok %v", ok)
	}
	if !slices.Contains(nvdNotationCPEs(), "o:synology:diskstation_manager") || slices.Contains(nvdNotationCPEs(), "o:vmware:esxi") {
		t.Fatalf("NVD names read in a scheme: %v", nvdNotationCPEs())
	}
	silent := Range{CVE: "CVE-2026-4036", Origin: OriginCNA, Vendor: "synology", Product: "diskstationmanagerdsm", DefaultStatus: DefaultAffected}
	if _, _, _, ok := RangeScheme(silent); ok || recordSkipped(silent) {
		t.Fatalf("a record row with no version: read in the scheme %v, left out of the generic comparison %v", ok, recordSkipped(silent))
	}
	desc := "An improper neutralization of special elements used in an SQL command ('SQL injection') vulnerability in Sharing API in Synology " +
		"DiskStation Manager (DSM) before 7.2.1-69057-10, 7.2.2-72806-7 and 7.3.2-86009-2 allows remote authenticated users to obtain arbitrary sharing files."
	rows := describedRows(silent, desc, nil)
	var got []string
	for _, r := range rows {
		got = append(got, r.StartIncl+" < "+r.EndExcl)
		if r.Generic() || r.Fixed != r.EndExcl || r.DefaultStatus != DefaultUnaffected {
			t.Errorf("described row %+v", r)
		}
	}
	if want := []string{"7.2.1 < 7.2.1-69057-10", "7.2.2 < 7.2.2-72806-7", "7.3.2 < 7.3.2-86009-2"}; !slices.Equal(got, want) {
		t.Fatalf("described rows %v, want %v", got, want)
	}
	var spans []versionscheme.Span
	for _, r := range rows {
		_, sp, _, ok := RangeScheme(r)
		if !ok {
			t.Fatalf("described row %+v does not read", r)
		}
		spans = append(spans, sp)
	}
	if v := versionscheme.Judge(installed, spans); v.State != versionscheme.Affected || v.Fix == nil || v.Fix.Label != "7.2.1-69057 Update 10" {
		t.Fatalf("7.2.1-69057-5 against the description: %+v", v)
	}
	// a line older than every line the description names is left out unless the vendor still patches it: then an empty row of the
	// line says it is not affected (the row of each named line still starts at its line)
	later := "An incorrect authorization vulnerability in Synology DiskStation Manager (DSM) before 7.4.1-90080-1 and 7.3.2-86009-5 allows remote attackers to read specific files."
	line721, _ := versionscheme.SynologyDSM.Parse("7.2.1")
	line711, _ := versionscheme.SynologyDSM.Parse("7.1.1")
	line741, _ := versionscheme.SynologyDSM.Parse("7.4.1")
	got = nil
	for _, r := range describedRows(silent, later, []versionscheme.Version{line721, line711, line741}) {
		got = append(got, r.StartIncl+" < "+r.EndExcl)
	}
	if want := []string{"7.4.1 < 7.4.1-90080-1", "7.3.2 < 7.3.2-86009-5", "7.2.1 < 7.2.1", "7.1.1 < 7.1.1"}; !slices.Equal(got, want) {
		t.Fatalf("described rows %v, want %v", got, want)
	}
	// the list ends at the first word that is no release; another product's "before" is not this one's
	rows = describedRows(silent, "Synology BeeStation OS (BSM) before 1.1-65374 and Synology DiskStation Manager (DSM) before 7.2.1-69057-2 and 7.2.2-72806 and Synology Unified Controller (DSMUC) before 3.1.4-23079 allows remote attackers to execute arbitrary code.", nil)
	got = nil
	for _, r := range rows {
		got = append(got, r.EndExcl)
	}
	if want := []string{"7.2.1-69057-2", "7.2.2-72806"}; !slices.Equal(got, want) {
		t.Fatalf("described rows %v, want %v", got, want)
	}
	for _, d := range []string{"", "Synology DiskStation Manager (DSM) allows remote attackers to read files.", "Synology Photos before 1.7.0-0794 allows …"} {
		if rows := describedRows(silent, d, nil); len(rows) != 0 {
			t.Errorf("%q: %+v", d, rows)
		}
	}
}
