package inventory_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/inventory"
)

// A scope active discovery could not sweep within a week of its windows is refused when it is saved, with the numbers; one that
// needs several windows is taken (the sweep is one run over several nights). Without an estimate nothing is refused.
func TestSaveRefusesAScopeThatCannotBeSweptInAWeek(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	in := okSafety() // 21:00 to 04:00 on two days: 7 h windows, 2 a week
	in.LANRanges = []string{"10.20.0.0/16"}
	if _, err := e.saveSafety(in); err != nil { // no estimate yet: nothing is refused
		t.Fatal(err)
	}
	e.svc.SetScopeCost(func(_ context.Context, st inventory.Settings) inventory.ScopeCost {
		n := 1 << 8
		if strings.Contains(strings.Join(st.LANRanges, ","), "/16") {
			n = 1 << 16
		}
		pass := time.Duration(n*17/st.Active.Rate) * time.Second
		win := 7 * time.Hour
		return inventory.ScopeCost{Addresses: n, Pass: pass, Window: win, Windows: int((pass + win - 1) / win), WeekWindows: len(st.Active.Days)}
	})
	in.PacketsPerS = 10 // 65,536 addresses at 10 packets/s: about 31 h, 5 windows of 7 h; the week has 2
	_, err := e.saveSafety(in)
	var api *apierr.Error
	if !errors.As(err, &api) || api.Code != "scope_too_large" || !strings.Contains(api.Message, "65536 addresses") || !strings.Contains(api.Message, "a week has 2") {
		t.Fatalf("a /16 at 10 packets/s on two days: %v", err)
	}
	in.Days = []int{1, 2, 3, 4, 5, 6, 7} // seven windows a week: five are enough, over several nights
	if _, err := e.saveSafety(in); err != nil {
		t.Fatalf("the same scope with a window every day: %v", err)
	}
	in.Days, in.PacketsPerS = []int{1}, 10
	if _, err := e.saveSafety(in); err == nil {
		t.Fatal("one window a week took a scope that needs five")
	}
	// an added range is held to the same rule
	in.Days, in.LANRanges = []int{1}, []string{"10.40.0.0/24"}
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.addRange("admin@acme.example", "10.30.0.0/16", []string{"10.40.0.0/24"}, true); !errors.As(err, &api) || api.Code != "scope_too_large" {
		t.Fatalf("an added /16 that does not fit a week: %v", err)
	}
	// PUT /scans/config writes the window too: the same rule holds there
	in.LANRanges, in.Days = []string{"10.20.0.0/16"}, []int{1, 2, 3, 4, 5, 6, 7}
	if _, err := e.saveSafety(in); err != nil {
		t.Fatal(err)
	}
	err = e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		return e.svc.SaveChecks(e.ctx(), tx, "admin@acme.example", inventory.ChecksInput{Days: []int{1}, From: "21:00", To: "04:00", CheckRate: 8})
	})
	if !errors.As(err, &api) || api.Code != "scope_too_large" {
		t.Fatalf("a one-day window through PUT /scans/config: %v", err)
	}
}
