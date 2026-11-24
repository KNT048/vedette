package findings

import (
	"testing"

	"github.com/knt048/vedette/core/api/oas"
)

// The fix a reader lists for an open finding is its block's: nas01's CVE-2026-1001 needs 10.3 on its own, but By device and By fix
// list it under "update OpenSSH to 10.6" with the other two, so the report must say 10.6 too. Handled findings and those of an
// ignored device have none.
func TestListedFixes_TheBlockReleaseOfEachOpenFinding(t *testing.T) {
	e := modelEnv(t)
	got, err := e.svc.ListedFixes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	cards := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-nas", "viewer", "")
	block := cards.Items[0].Blocks[0].Fix
	for _, id := range []string{"f-n1", "f-n2", "f-n3"} {
		l, ok := got[id]
		if !ok || l.Fix.Version != "10.6" || l.Key != block.Key {
			t.Errorf("%s: listed %+v, want the block %s (10.6)", id, l, block.Key)
		}
	}
	for _, id := range []string{"f-h1", "f-h2", "f-i1"} {
		if l, ok := got[id]; ok {
			t.Errorf("%s (handled or on an ignored device) listed %+v", id, l)
		}
	}
	// Java 8 and Java 21 keep their own fixes: two lines of one product are two blocks
	if got["f-f2"].Fix.Version != "8u461" || got["f-f3"].Fix.Version != "21.0.8" {
		t.Errorf("java lines %+v %+v", got["f-f2"], got["f-f3"])
	}
}

// The listed fix of one finding is the one ListedFixes gives it: the release the lists name for its block.
func TestListedFix_OneFindingAsTheLists(t *testing.T) {
	t.Parallel()
	e := blockTargetWorld(t)
	all, err := e.svc.ListedFixes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("no open finding")
	}
	for id, want := range all {
		got, ok, err := e.svc.ListedFix(t.Context(), id)
		if err != nil || !ok || got != want {
			t.Errorf("%s: ListedFix %+v %v %v, want %+v", id, got, ok, err, want)
		}
	}
	if _, ok, err := e.svc.ListedFix(t.Context(), "no-such-finding"); ok || err != nil {
		t.Errorf("an unknown finding: ok %v, %v", ok, err)
	}
}
