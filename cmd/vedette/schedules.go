package main

import (
	"context"

	"github.com/knt048/vedette/core/schedule"
)

// newSchedules builds the box's schedule service (core/schedule). The modules register their schedules on it while they are
// built; serve starts it after the runs. Its scan window is the shared safety block of the inventory (Settings › Scanning),
// read at each look, so a schedule in the scan window starts only while it is open.
func newSchedules(d *deps) (*schedule.Service, error) {
	cfg := schedule.Config{DB: d.DB, Audit: d.Audit, Log: d.Log, Clock: d.Clock}
	if d.Reg != nil { // a due time of a module that is off is skipped
		cfg.Gate = d.Reg
	}
	cfg.ScanWindow = func(ctx context.Context) (schedule.Window, error) {
		if d.Inventory == nil { // a build without the inventory (tests): no window limits a start
			return schedule.Window{Days: []int{1, 2, 3, 4, 5, 6, 7}, From: "00:00", To: "00:00"}, nil
		}
		st, err := d.Inventory.Settings(ctx)
		if err != nil {
			return schedule.Window{}, err
		}
		return schedule.Window{Days: st.Active.Days, From: st.Active.From, To: st.Active.To}, nil
	}
	return schedule.New(cfg)
}
