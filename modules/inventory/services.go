package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// Bounds of a list of open ports (INV-23).
const (
	// maxServices is the most services one source may report for one device: nmap's normal scan reads its top 1000 ports
	// (sensor-active nmapargv), so a full list fits. Five sensor sources at most, so a device holds at most 5000 rows.
	maxServices   = 1000
	maxSvcName    = 100 // the CHECK of inv_service.name
	maxSvcProduct = 200 // the CHECK of inv_service.product (= maxObsValue, the cap of cleanText)
	maxSvcVersion = 100
	maxSvcDetail  = 200 // the CHECK of inv_service.detail
	// ServiceRetention is how long a service no source reports again is kept (DATA_MODEL); PruneServices removes older rows.
	ServiceRetention = 90 * 24 * time.Hour
)

var _ observe.ServiceSink = (*Service)(nil)

// checkServices validates a list of open ports from a sensor (SYS-6). An item whose text holds an invisible character is dropped
// and logged alone (INV-22); any other bad item refuses the list. The same port and protocol twice keeps the first.
func (s *Service) checkServices(ctx context.Context, items []observe.Service) ([]observe.Service, error) {
	if len(items) > maxServices {
		return nil, invalid("a service list has at most %d items", maxServices)
	}
	out := make([]observe.Service, 0, len(items))
	seen := map[[2]any]bool{}
	for i, it := range items {
		it, err := checkService(i, it)
		if err != nil {
			if !hasInvisible(it.Name, it.Product, it.Version, it.Detail) {
				return nil, err
			}
			s.log.WarnContext(ctx, "inventory: a service with an invisible character was dropped", "index", i)
			continue
		}
		k := [2]any{it.Port, it.Proto}
		if !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	return out, nil
}

// checkService validates one item: port 1..65535, proto tcp or udp, optional texts as cleanText with their column's length.
func checkService(i int, it observe.Service) (observe.Service, error) {
	it.Name, it.Product, it.Version, it.Detail = stripIgnorable(it.Name), stripIgnorable(it.Product), stripIgnorable(it.Version), stripIgnorable(it.Detail)
	if it.Port < 1 || it.Port > 65535 {
		return it, invalid("service %d: port must be 1 to 65535", i)
	}
	if it.Proto != "tcp" && it.Proto != "udp" {
		return it, invalid("service %d: proto must be tcp or udp", i)
	}
	if it.Name != "" && (!cleanText(it.Name) || utf8.RuneCountInString(it.Name) > maxSvcName) {
		return it, invalid("service %d: name must be at most %d printable characters", i, maxSvcName)
	}
	if it.Product != "" && (!cleanText(it.Product) || utf8.RuneCountInString(it.Product) > maxSvcProduct) {
		return it, invalid("service %d: product must be at most %d printable characters", i, maxSvcProduct)
	}
	if it.Version != "" && (!cleanText(it.Version) || utf8.RuneCountInString(it.Version) > maxSvcVersion) {
		return it, invalid("service %d: version must be at most %d printable characters", i, maxSvcVersion)
	}
	if it.Detail != "" && (!cleanText(it.Detail) || utf8.RuneCountInString(it.Detail) > maxSvcDetail) {
		return it, invalid("service %d: detail must be at most %d printable characters", i, maxSvcDetail)
	}
	if it.Confidence < 0 || it.Confidence > 1 || it.Confidence != it.Confidence {
		return it, invalid("service %d: confidence must be between 0 and 1", i)
	}
	return it, nil
}

// ReplaceServices implements observe.ServiceSink (INV-23, PRE-2b): the open ports a source reported for a device become items;
// rows of that source not in items are removed, rows of other sources stay. The device is found by MAC or IP, or created
// unapproved, as for ReplaceSoftware; a box-owned address is no device (INV-17). No event and no audit row: nothing listens
// for a port change yet.
//
// A non-zero scope (observe.ServiceScope) makes it a scoped replace, as ReplaceSoftware has: the list covers only the TCP ports
// in scope.Ports, so a scan of a few ports replaces the rows of those ports and leaves the rows of the others. A row of the source
// outside the scope that it has not seen for scope.KeepFor goes too. A port that closes (its row removed) takes the software that
// source read on it (observe.PortInstance).
func (s *Service) ReplaceServices(ctx context.Context, hint observe.AssetHint, source observe.Source, scope observe.ServiceScope, items []observe.Service) error {
	if err := checkScope(scope, items); err != nil {
		return err
	}
	return s.services(ctx, hint, source, &scope, items, true)
}

// maxScopeRanges bounds the ranges of a scope (nmap's top 1000 ports are about a hundred ranges).
const maxScopeRanges = 2000

// checkScope validates a scope and that every listed service lies inside it.
func checkScope(scope observe.ServiceScope, items []observe.Service) error {
	if scope.KeepFor < 0 || scope.KeepFor > ServiceRetention {
		return invalid("a service scope keeps rows for at most %d days", int(ServiceRetention.Hours()/24))
	}
	if scope.Ports == nil {
		return nil
	}
	if len(scope.Ports) > maxScopeRanges {
		return invalid("a service scope has at most %d port ranges", maxScopeRanges)
	}
	for _, r := range scope.Ports {
		if r.From < 1 || r.To > 65535 || r.From > r.To {
			return invalid("a service scope range must be within 1 to 65535")
		}
	}
	for i, it := range items {
		if it.Proto != "tcp" || !inScope(scope, it.Port) {
			return invalid("service %d: a scoped list holds only TCP ports inside its scope", i)
		}
	}
	return nil
}

// inScope says whether a TCP port is inside the ranges of a scope that has them.
func inScope(scope observe.ServiceScope, port int) bool {
	return slices.ContainsFunc(scope.Ports, func(r observe.PortRange) bool { return port >= r.From && port <= r.To })
}

// AddServices implements observe.ServiceSink for a partial look (INV-23, PRE-2b): a port not listed yet is added, a
// port already listed by that source gets its seen_at moved, and its name, product, version and confidence only when the item
// names a product (a -sV read of that port; a gentle look names none, so what a fuller scan said stays); no row
// is removed. Everything else is as ReplaceServices.
func (s *Service) AddServices(ctx context.Context, hint observe.AssetHint, source observe.Source, items []observe.Service) error {
	return s.services(ctx, hint, source, nil, items, false)
}

// PortReadTimes is when source last read each open TCP port of a device with version detection (inv_service.read_at, INV-23), by
// port; a port only found open is not in it. sensor-active's weekly version read picks its ports by it. An unknown device has none.
func (s *Service) PortReadTimes(ctx context.Context, assetID string, source observe.Source) (map[int]time.Time, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT port, read_at FROM inv_service
		WHERE asset_id = ? AND source = ? AND proto = 'tcp' AND read_at IS NOT NULL`, assetID, string(source))
	if err != nil {
		return nil, fmt.Errorf("inventory: read the port read times: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int]time.Time{}
	for rows.Next() {
		var port int
		var at string
		if err := rows.Scan(&port, &at); err != nil {
			return nil, fmt.Errorf("inventory: read the port read times: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, fmt.Errorf("inventory: port %d read time %q: %w", port, at, err)
		}
		out[port] = t
	}
	return out, rows.Err()
}

// services writes a list: scope is nil for a whole list (or an added one), replace says rows of the source not listed go.
func (s *Service) services(ctx context.Context, hint observe.AssetHint, source observe.Source, scope *observe.ServiceScope, items []observe.Service, replace bool) error {
	ip, mac, err := checkHint(hint)
	if err != nil {
		return err
	}
	if !observe.ValidSource(source) || source == observe.Manual {
		return invalid("service source %q is not allowed", source)
	}
	agent, err := checkAgent(hint, source)
	if err != nil {
		return err
	}
	from, err := checkFrom(hint)
	if err != nil {
		return err
	}
	clean, err := s.checkServices(ctx, items)
	if err != nil {
		return err
	}
	if isBox := s.ownedFilter(ctx); isBox != nil && isBox(ip, mac) {
		s.ownedHit.Add(1)
		return nil
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		now := s.seen(s.clock())
		id, err := s.deviceFor(ctx, tx, o, cleanObs{ip: ip, mac: mac, agent: agent, from: from, source: string(source), seenAt: now})
		if err != nil || id == "" { // "": no device may take the list (resolve)
			return err
		}
		if source == observe.Agent {
			if off, err := agentRefused(ctx, tx, id); err != nil || off { // a person turned the agent off for this device (ChangeSources)
				return err
			}
		}
		removed, err := replaceServicesTx(ctx, tx, id, clean, string(source), now, replace, scope, s.clock())
		if err != nil {
			return err
		}
		if source == observe.Nmap && len(removed) > 0 {
			// the software a scan read on a port that is gone is gone with it
			inst := make([]string, len(removed))
			for i, p := range removed {
				inst[i] = observe.PortInstance(p)
			}
			if err := s.replaceSoftwareTx(ctx, tx, o, id, nil, string(source), inst, now); err != nil {
				return err
			}
		}
		return s.earnReview(ctx, tx, o, id, false) // an open service is a reason to look (INV-49)
	})
}

// upsertService is the write of one item: a full list overwrites the row of the same port, a partial one only moves seen_at. The
// last parameter is read_at: the item's seen time when the write reads the port's name, product and version, else NULL; a row
// keeps its read_at when the write does not read it (coalesce).
const (
	upsertService = `INSERT INTO inv_service (id, asset_id, port, proto, name, product, version, detail, source, confidence, seen_at, read_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (asset_id, port, proto, source) DO UPDATE SET `
	replaceSet = `name = excluded.name, product = excluded.product, version = excluded.version, detail = excluded.detail, confidence = excluded.confidence, seen_at = excluded.seen_at,
		read_at = coalesce(excluded.read_at, read_at)`
	// a gentle look with titles adds what a port said; a partial look that read a product (the -sV follow-up of the weekly scan
	// of every port) updates the name, product, version and confidence of that port; one that did not (a gentle
	// scan) keeps them
	addSet = `seen_at = excluded.seen_at, detail = coalesce(excluded.detail, detail), product = coalesce(excluded.product, product),
		version = CASE WHEN excluded.product IS NULL THEN version ELSE excluded.version END,
		name = CASE WHEN excluded.product IS NULL THEN name ELSE excluded.name END,
		confidence = CASE WHEN excluded.product IS NULL THEN confidence ELSE excluded.confidence END,
		read_at = coalesce(excluded.read_at, read_at)`
)

// replaceServicesTx writes a list and returns the TCP ports whose rows it removed. replace removes the rows of source that the list
// does not hold, inside scope when there is one (a nil scope, or one without ports, is the source's whole list); a scope that says
// the scan read no versions only updates a port that names a product, as an added list does.
//
// read_at (INV-23) moves to seenAt on every row a write reads: each listed row of a list that read versions (a replace whose scope
// does not say NoVersions), and a listed row that names a product in the others; an added or NoVersions row that names none keeps
// its read_at (NULL for a new row).
func replaceServicesTx(ctx context.Context, tx *sql.Tx, assetID string, items []observe.Service, source, seenAt string, replace bool, scope *observe.ServiceScope, now time.Time) ([]int, error) {
	versions := replace && (scope == nil || !scope.NoVersions)
	q := upsertService + addSet
	if versions {
		q = upsertService + replaceSet
	}
	keep := map[[2]any]bool{}
	for _, it := range items {
		keep[[2]any{it.Port, it.Proto}] = true
		var readAt any
		if versions || it.Product != "" {
			readAt = seenAt
		}
		_, err := tx.ExecContext(ctx, q, store.NewID("sv"), assetID, it.Port, it.Proto, it.Name, nullStr(it.Product), nullStr(it.Version), nullStr(it.Detail), source, it.Confidence, seenAt, readAt)
		if err != nil {
			return nil, fmt.Errorf("inventory: store service: %w", err)
		}
	}
	if !replace {
		_, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID)
		if err != nil {
			return nil, fmt.Errorf("inventory: touch device: %w", err)
		}
		return nil, nil
	}
	scoped := scope != nil && scope.Ports != nil
	stale := ""
	if scoped && scope.KeepFor > 0 {
		stale = store.FormatTS(now.Add(-scope.KeepFor))
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, port, proto, seen_at FROM inv_service WHERE asset_id = ? AND source = ?`, assetID, source)
	if err != nil {
		return nil, fmt.Errorf("inventory: read services: %w", err)
	}
	var gone []string
	var removed []int
	for rows.Next() {
		var id, proto, seen string
		var port int
		if err := rows.Scan(&id, &port, &proto, &seen); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("inventory: read services: %w", err)
		}
		in := !scoped || (proto == "tcp" && inScope(*scope, port))
		switch {
		case in && !keep[[2]any{port, proto}], !in && stale != "" && seen < stale:
			gone = append(gone, id)
			if proto == "tcp" {
				removed = append(removed, port)
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, id := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_service WHERE id = ?`, id); err != nil {
			return nil, fmt.Errorf("inventory: remove service: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID); err != nil {
		return nil, fmt.Errorf("inventory: touch device: %w", err)
	}
	return removed, nil
}

// PruneServices removes the services no source has reported for ServiceRetention (INV-23) and writes one audit row when it removed
// any (inventory.services_pruned, SYS-5). It is the inventory's housekeeping
// job (the 90 days are stated in this CONTRACT and on the device page), so it runs while the module is off too.
func (s *Service) PruneServices(ctx context.Context) (int, error) {
	cut := store.FormatTS(s.clock().Add(-ServiceRetention))
	var n int64
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		r, err := tx.ExecContext(ctx, `DELETE FROM inv_service WHERE seen_at < ?`, cut)
		if err != nil {
			return fmt.Errorf("inventory: prune services: %w", err)
		}
		if n, err = r.RowsAffected(); err != nil || n == 0 {
			return err
		}
		return s.auditTx(ctx, tx, systemActor, "inventory.services_pruned", "-", fmt.Sprintf("%d services not seen for 90 days", n))
	})
	return int(n), err
}
