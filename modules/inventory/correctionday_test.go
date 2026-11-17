package inventory

import (
	"testing"
	"time"
)

// The day of a correction in the findings history is the organization's day of the moment it was made, like the finding page's times.
func TestCorrectionDay_InTheOrganizationZone(t *testing.T) {
	hcm, err := time.LoadLocation("Asia/Ho_Chi_Minh")
	if err != nil {
		t.Fatal(err)
	}
	if got := correctionDay("2026-11-16T20:30:00.000Z", hcm); got != "17 Nov 2026" {
		t.Fatalf("correctionDay = %q", got)
	}
	if got := correctionDay("2026-11-16T20:30:00.000Z", nil); got != "16 Nov 2026" {
		t.Fatalf("no zone known: %q", got)
	}
}
