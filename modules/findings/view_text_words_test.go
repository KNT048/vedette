package findings

import (
	"strings"
	"testing"
)

// A Windows fix the data gives without a build reads as a whole sentence: the update's KB when it is known, else the latest
// cumulative update, never "brings the build to " with nothing after it.
func TestFixWords_WindowsUpdateWithoutABuild(t *testing.T) {
	for _, tc := range []struct{ version, ref, want string }{
		{"10.0.26100.4061", "KB5058411", "install the Windows update that brings the build to 10.0.26100.4061 (KB5058411)"},
		{"10.0.26100.4061", "", "install the Windows update that brings the build to 10.0.26100.4061"},
		{"", "KB5058411", "install the Windows update KB5058411"},
		{"", "", "install the latest Windows cumulative update on Windows 11"},
	} {
		if got := FixWords(Fix{Kind: FixOSUpdate, Version: tc.version, Ref: tc.ref}, "Windows 11", ""); got != tc.want {
			t.Errorf("FixWords(os_update, %q, %q) = %q, want %q", tc.version, tc.ref, got, tc.want)
		}
	}
	if got := FixWords(Fix{Kind: FixOSUpdate}, "", ""); got != "install the latest Windows cumulative update" {
		t.Errorf("without a product = %q", got)
	}
}

// The class: no fix kind leaves a gap where an unknown version, product or reference would go.
func TestFixWords_NoKindLeavesAGapForAMissingValue(t *testing.T) {
	for _, k := range knownFixKinds {
		for _, in := range [][4]string{{"", "", "", ""}, {"Windows 11", "", "", ""}, {"", "1.0", "", ""}, {"", "", "", "KB1"}, {"openssl", "3.0.1", "", ""}} {
			w := FixWords(Fix{Kind: k, Version: in[2], Ref: in[3]}, in[0], in[1])
			if w == "" {
				continue
			}
			if strings.Contains(w, "  ") || strings.HasSuffix(w, " ") || strings.Contains(w, " ()") || strings.Contains(w, " to (") ||
				strings.HasSuffix(w, " to") || strings.HasSuffix(w, " version") || strings.Contains(w, ", version (") {
				t.Errorf("FixWords(%s, %q) = %q: a gap where a value should be", k, in, w)
			}
		}
	}
}
