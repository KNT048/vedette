package ai_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/modules/ai"
)

// S-AI-8, D-430: the daily verify raises one incident when the chain is broken, and says nothing while it holds.
func TestVerifyJobAlertsOncePerBreak(t *testing.T) {
	a := newAPI(t)
	rows := a.threeCalls()
	var alerts []string
	svc, err := ai.New(a.ctx(), ai.Config{DB: a.db, Secrets: a.sec, Audit: audit.New(a.clock.Now), Log: slog.New(slog.DiscardHandler), Clock: a.clock.Now,
		Alert: func(_ context.Context, id, _, text string) error {
			alerts = append(alerts, id+"|"+text)
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	var verify func(context.Context) error
	for _, j := range svc.Jobs() {
		if j.Name == "activity-verify" {
			if j.Housekeeping {
				t.Fatal("the verify job calls out, so it is not housekeeping")
			}
			verify = j.Run
		}
	}
	if verify == nil {
		t.Fatal("no activity-verify job although Alert is wired")
	}
	if err := verify(a.ctx()); err != nil || len(alerts) != 0 {
		t.Fatalf("an intact chain: err %v, alerts %v", err, alerts)
	}
	if err := a.exec(`DROP TRIGGER ai_activity_no_update`); err != nil {
		t.Fatal(err)
	}
	if err := a.exec(`UPDATE ai_activity SET summary = 'edited' WHERE id = '` + rows[1].ID + `'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := verify(a.ctx()); err != nil {
			t.Fatal(err)
		}
		a.explain("CVE-2022-27593", 409, "blocked_by_hook") // another call adds a row after the break: still the same break
	}
	if len(alerts) != 1 || !strings.Contains(alerts[0], rows[1].ID) {
		t.Fatalf("alerts = %q, want one naming the first bad row", alerts)
	}
}
