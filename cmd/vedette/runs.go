package main

import corerun "github.com/knt048/vedette/core/run"

// newRuns builds the box's run manager (core/run). The modules register their kinds of run on it while they are built; serve
// starts it once they all are.
func newRuns(d *deps) (*corerun.Manager, error) {
	cfg := corerun.Config{DB: d.DB, Audit: d.Audit, Log: d.Log, Clock: d.Clock}
	if d.Reg != nil { // a run starts only while its module is on
		cfg.Gate = d.Reg
	}
	return corerun.New(cfg)
}
