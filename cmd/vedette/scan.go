package main

import (
	"context"
	"fmt"
	"sync"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/inventory"
	"github.com/knt048/vedette/modules/scan"
)

var (
	scanMu       sync.Mutex
	scanServices = map[*store.DB]*scan.Service{}
)

// scanService builds the scan service once per database, so the handlers and (later) the jobs share it.
// ponytail: no Engine yet: the remote nuclei engine over the sensor protocol is slice S5 (D-125), so the
// scanner is "not available" (can_scan=false, 503 scanner_unavailable) and nothing is ever sent until then.
func scanService(d deps) *scan.Service {
	scanMu.Lock()
	defer scanMu.Unlock()
	if s := scanServices[d.DB]; s != nil {
		return s
	}
	svc, err := scan.NewService(scan.Config{DB: d.DB, Audit: d.Audit, Inventory: scanInventory{inv: d.Inventory}, Log: d.Log, Clock: d.Clock})
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	scanServices[d.DB] = svc
	return svc
}

// scanInventory is the inventory as the scan module sees it (scan.Inventory): read only (scan INV-11).
type scanInventory struct{ inv *inventory.Service }

func (s scanInventory) Scope(ctx context.Context) (scan.Scope, error) {
	if s.inv == nil {
		return scan.Scope{}, fmt.Errorf("vedette: scan: the inventory is not wired")
	}
	st, err := s.inv.Settings(ctx)
	if err != nil {
		return scan.Scope{}, err
	}
	sc := scan.Scope{Networks: st.LANRanges}
	if st.ScopeConfirmedAt != nil {
		sc.ConfirmedAt = *st.ScopeConfirmedAt
	}
	if st.ScopeConfirmedBy != nil {
		sc.ConfirmedBy = *st.ScopeConfirmedBy
	}
	return sc, nil
}
