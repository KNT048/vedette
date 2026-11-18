package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Similar is a device that looks like another one: the same maker, the same device type, or both. sensor-active uses it for "Use
// these settings on similar devices" (SNMP): it holds what the checklist shows, not a decision.
type Similar struct {
	ID, IP, Vendor, Kind string
	SameMaker, SameType  bool
	Approved             bool
}

// SimilarDevices lists the devices that share the maker or the (known) device type of device id: not the device itself, not the box,
// not a device a person ignores, with an address. The maker is compared case-insensitively on the value the inventory shows;
// a device of unknown type is never "the same type". Same maker first, then by id. ErrNotFound when there is no such device.
func (s *Service) SimilarDevices(ctx context.Context, id string) ([]Similar, error) {
	var vendor, kind string
	var v *string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT vendor, kind FROM inv_asset WHERE id = ?`, id).Scan(&v, &kind); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("inventory: read the device: %w", err)
	}
	if v != nil {
		vendor = strings.ToLower(strings.TrimSpace(*v))
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, ip, coalesce(vendor, ''), kind, approved FROM inv_asset
		WHERE id <> ? AND is_box = 0 AND ip IS NOT NULL AND ignored_at IS NULL ORDER BY id`, id)
	if err != nil {
		return nil, fmt.Errorf("inventory: read similar devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Similar
	for rows.Next() {
		var d Similar
		if err := rows.Scan(&d.ID, &d.IP, &d.Vendor, &d.Kind, &d.Approved); err != nil {
			return nil, fmt.Errorf("inventory: read similar devices: %w", err)
		}
		d.SameMaker = vendor != "" && strings.ToLower(strings.TrimSpace(d.Vendor)) == vendor
		d.SameType = kind != "unknown" && d.Kind == kind
		if d.SameMaker || d.SameType {
			out = append(out, d)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read similar devices: %w", err)
	}
	// stable: same maker first, ids stay in order inside each group
	sorted := make([]Similar, 0, len(out))
	for _, first := range []bool{true, false} {
		for _, d := range out {
			if d.SameMaker == first {
				sorted = append(sorted, d)
			}
		}
	}
	return sorted, nil
}
