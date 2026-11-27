package findings

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A bulk "patched" on findings the device's latest reading still shows is one answer for the whole selection: how many, a short list of
// their CVEs (five, then "and N more"), nothing written; the same request with confirm marks them all.
func TestHandle_BulkStillReportedIsOneShortConfirmation(t *testing.T) {
	t.Parallel()
	e := blockTargetWorld(t)
	ctx := t.Context()
	fs, err := e.svc.Findings(ctx, "web-01")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	cves := map[string]bool{}
	for _, f := range fs {
		if stillReported(f) {
			ids = append(ids, f.ID)
			cves[f.CVE] = true
		}
	}
	if len(cves) <= stillListMax {
		t.Fatalf("the fixture has %d still-reported CVEs on web-01, want more than %d", len(cves), stillListMax)
	}
	_, _, err = e.svc.Handle(ctx, ids, ResolutionPatched, "", time.Time{}, "ana@example.com")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "still_reported" {
		t.Fatalf("err = %v, want one still_reported answer", err)
	}
	if !strings.Contains(ae.Message, " and ") || !strings.Contains(ae.Message, " more") || strings.Count(ae.Message, "CVE-") != stillListMax {
		t.Errorf("message %q: want %d CVEs then \"and N more\"", ae.Message, stillListMax)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'web-01' AND state = 'handled'`); n != 0 {
		t.Errorf("%d findings handled by a refused request", n)
	}
	handled, _, err := e.svc.HandleConfirmed(ctx, ids, ResolutionPatched, "", time.Time{}, "ana@example.com")
	if err != nil || handled != len(ids) {
		t.Errorf("confirmed: handled %d of %d, %v", handled, len(ids), err)
	}
}
