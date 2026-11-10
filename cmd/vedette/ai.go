package main

import (
	"context"
	"time"

	"github.com/knt048/vedette/modules/ai"
)

// newAI builds the ai service once, in buildServices (deps.AI): the handlers share one router and one meter. It reads the box
// time zone from core's general settings once, at start (the meter's day boundary); a change of zone applies after a restart.
func newAI(d *deps) (*ai.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return ai.New(ctx, ai.Config{DB: d.DB, Secrets: d.Secrets, Audit: d.Audit, Log: d.Log, Clock: d.Clock, Zone: orgZone(d)})
}
