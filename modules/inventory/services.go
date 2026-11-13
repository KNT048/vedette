package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// Bounds of a list of open ports (INV-23, D-350).
const (
	// maxServices is the most services one source may report for one device: nmap's normal scan reads its top 1000 ports
	// (sensor-active nmapargv), so a full list fits. Five sensor sources at most, so a device holds at most 5000 rows.
	maxServices   = 1000
	maxSvcName    = 100 // the CHECK of inv_service.name
	maxSvcProduct = 200 // the CHECK of inv_service.product (= maxObsValue, the cap of cleanText)
	maxSvcVersion = 100
	maxSvcDetail  = 200 // the CHECK of inv_service.detail (D-511)
	// ServiceRetention is how long a service no source reports again is kept (DATA_MODEL, D-350); PruneServices removes older rows.
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
// for a port change yet (D-350).
func (s *Service) ReplaceServices(ctx context.Context, hint observe.AssetHint, source observe.Source, items []observe.Service) error {
	return s.services(ctx, hint, source, items, true)
}

// AddServices implements observe.ServiceSink for a partial look (INV-23, PRE-2b; D-350 (5)): a port not listed yet is added, a
// port already listed by that source only gets its seen_at moved (its name, product, version and confidence stay: they came
// from a fuller scan), and no row is removed. Everything else is as ReplaceServices.
func (s *Service) AddServices(ctx context.Context, hint observe.AssetHint, source observe.Source, items []observe.Service) error {
	return s.services(ctx, hint, source, items, false)
}

func (s *Service) services(ctx context.Context, hint observe.AssetHint, source observe.Source, items []observe.Service, replace bool) error {
	ip, mac, err := checkHint(hint)
	if err != nil {
		return err
	}
	if !observe.ValidSource(source) || source == observe.Manual {
		return invalid("service source %q is not allowed", source)
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
		id, err := s.deviceFor(ctx, tx, o, ip, mac, source, now)
		if err != nil {
			return err
		}
		return replaceServicesTx(ctx, tx, id, clean, string(source), now, replace)
	})
}

// upsertService is the write of one item: a full list overwrites the row of the same port, a partial one only moves seen_at.
const (
	upsertService = `INSERT INTO inv_service (id, asset_id, port, proto, name, product, version, detail, source, confidence, seen_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (asset_id, port, proto, source) DO UPDATE SET `
	replaceSet = `name = excluded.name, product = excluded.product, version = excluded.version, detail = excluded.detail, confidence = excluded.confidence, seen_at = excluded.seen_at`
	addSet     = `seen_at = excluded.seen_at`
)

func replaceServicesTx(ctx context.Context, tx *sql.Tx, assetID string, items []observe.Service, source, seenAt string, replace bool) error {
	q := upsertService + addSet
	if replace {
		q = upsertService + replaceSet
	}
	keep := map[[2]any]bool{}
	for _, it := range items {
		keep[[2]any{it.Port, it.Proto}] = true
		_, err := tx.ExecContext(ctx, q, store.NewID("sv"), assetID, it.Port, it.Proto, it.Name, nullStr(it.Product), nullStr(it.Version), nullStr(it.Detail), source, it.Confidence, seenAt)
		if err != nil {
			return fmt.Errorf("inventory: store service: %w", err)
		}
	}
	if !replace {
		_, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID)
		if err != nil {
			return fmt.Errorf("inventory: touch device: %w", err)
		}
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, port, proto FROM inv_service WHERE asset_id = ? AND source = ?`, assetID, source)
	if err != nil {
		return fmt.Errorf("inventory: read services: %w", err)
	}
	var gone []string
	for rows.Next() {
		var id, proto string
		var port int
		if err := rows.Scan(&id, &port, &proto); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inventory: read services: %w", err)
		}
		if !keep[[2]any{port, proto}] {
			gone = append(gone, id)
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_service WHERE id = ?`, id); err != nil {
			return fmt.Errorf("inventory: remove service: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET last_seen = max(last_seen, ?) WHERE id = ?`, seenAt, assetID); err != nil {
		return fmt.Errorf("inventory: touch device: %w", err)
	}
	return nil
}

// PruneServices removes the services no source has reported for ServiceRetention (INV-23) and writes one audit row when it removed
// any (inventory.services_pruned, SYS-5). It is the inventory's housekeeping
// job (D-160, D-202: the 90 days are stated in this CONTRACT and on the device page), so it runs while the module is off too.
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
