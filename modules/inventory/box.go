package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// BoxInfo says what the box knows about itself.
type BoxInfo struct {
	Hostname string
	IP       string // IPv4, "" when unknown
	OS       string // "" when unknown
}

// EnsureBox makes sure the box is in the inventory as the first device (INV-3, S-INV-5, D-53): created once
// on the first start, updated on later ones. It is approved, cannot be deleted, and everything it knows about
// itself has source "agent" at confidence 1. It returns the device id.
func (s *Service) EnsureBox(ctx context.Context, info BoxInfo) (string, error) {
	if !cleanText(info.Hostname) {
		return "", invalid("box: hostname must be 1 to %d printable characters", maxObsValue)
	}
	if info.OS != "" && !cleanText(info.OS) {
		return "", invalid("box: os is not valid")
	}
	var ip string
	if info.IP != "" {
		a, ok := ipv4(info.IP)
		if !ok {
			return "", invalid("box: ip is not an IPv4 address")
		}
		ip = a.String()
	}
	var id string
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		now := s.now()
		created := false
		err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE is_box = 1`).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			created = true
			id = store.NewID("a")
			if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, kind, origin, approved, fragile, is_box, first_seen, last_seen) VALUES (?, 'unknown', 'discovered', 1, 0, 1, ?, ?)`, id, now, now); err != nil {
				return fmt.Errorf("inventory: create the box: %w", err)
			}
		} else if err != nil {
			return fmt.Errorf("inventory: find the box: %w", err)
		}
		for _, v := range []struct{ field, value string }{
			{"hostname", info.Hostname}, {"kind", "server"}, {"vendor", "Vedette"}, {"model", "Security box (appliance)"}, {"os", info.OS},
		} {
			if v.value == "" {
				continue
			}
			if err := insertObs(ctx, tx, id, v.field, v.value, "agent", 1, now); err != nil {
				return err
			}
		}
		if err := s.claimIP(ctx, tx, id, mustAddr(ip), string(observe.Agent)); err != nil {
			return err
		}
		changed, err := s.RecomputeAsset(ctx, tx, id)
		if err != nil {
			return err
		}
		if created {
			if err := s.auditTx(ctx, tx, systemActor, "inventory.box_created", info.Hostname, id); err != nil {
				return err
			}
			o.add(EventAssetUpdated, AssetEvent{AssetID: id})
		} else if changed {
			o.add(EventAssetUpdated, AssetEvent{AssetID: id})
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// RefreshBoxPackages stores the packages installed on the box as its software (agent, confidence 1.0). It does
// nothing until a BoxPackages exists (vedette-host, WP-07).
func (s *Service) RefreshBoxPackages(ctx context.Context) error {
	if s.box == nil {
		return nil
	}
	items, err := s.box.Packages(ctx)
	if err != nil {
		return fmt.Errorf("inventory: box packages: %w", err)
	}
	for i := range items {
		items[i].Confidence = 1
	}
	var id string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE is_box = 1`).Scan(&id); err != nil {
		return fmt.Errorf("inventory: find the box: %w", err)
	}
	return s.UpsertSoftware(ctx, id, items, "agent")
}

func mustAddr(ip string) netip.Addr {
	a, _ := netip.ParseAddr(ip) // "" gives the zero Addr, which claimIP ignores
	return a
}
