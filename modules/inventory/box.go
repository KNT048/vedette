package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// BoxInfo says what the box knows about itself.
type BoxInfo struct {
	Hostname string
	IP       string // IPv4, "" when unknown
	OS       string // "" when unknown
	// ContainerOnly: the box is a container-only install (no vedette-host); its model then says so instead of appliance.
	ContainerOnly bool
}

// EnsureBox makes sure the box is in the inventory as the first device (INV-3, S-INV-5): created once
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
	model := "Security box (appliance)"
	if info.ContainerOnly {
		model = "Security box (container-only)"
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
			{"hostname", info.Hostname}, {"kind", "server"}, {"vendor", "Vedette"}, {"model", model}, {"os", info.OS},
		} {
			if v.value == "" {
				continue
			}
			if err := insertObs(ctx, tx, id, v.field, v.value, "agent", 1, now); err != nil {
				return err
			}
		}
		if err := s.claimIP(ctx, tx, o, id, mustAddr(ip), string(observe.Agent), now); err != nil {
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

// BoxEvery is how often the box reads its own packages and ports again (cmd/vedette's inventory job "box"); its agent row says when
// the next read is from it.
const BoxEvery = time.Hour

// RefreshBoxPackages stores the packages installed on the box as its software (agent, confidence 1.0; INV-3). It
// does nothing without a BoxPackages (a container-only install) or when it gives no list (nil: an older host that does not report the list): what
// is stored stays. A failed read changes nothing either.
func (s *Service) RefreshBoxPackages(ctx context.Context) error {
	if s.box == nil {
		return nil
	}
	items, err := s.box.Packages(ctx)
	if err != nil {
		return fmt.Errorf("inventory: box packages: %w", err)
	}
	if items == nil {
		return nil
	}
	for i := range items {
		items[i].Confidence = 1
	}
	var id string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE is_box = 1`).Scan(&id); err != nil {
		return fmt.Errorf("inventory: find the box: %w", err)
	}
	if err := s.UpsertSoftware(ctx, id, items, string(observe.Box)); err != nil {
		return err
	}
	s.boxRead.Store(s.clock().UnixMilli())
	return nil
}

// CheckBox is a person's "Check now" on the box's own agent row (POST /inventory/box/check): the box reads its packages and the
// ports it listens on now, as its hourly job does, and the page shows the result at once. 409 not_appliance on a container-only
// install (it has no packages of its own to read); a read that fails is the error (502 box_read_failed), what is stored stays. One
// audit row inventory.box_check. It returns the box's source rows.
func (s *Service) CheckBox(ctx context.Context, actor string) (DeviceSourcesView, error) {
	if s.box == nil {
		return DeviceSourcesView{}, conflict("not_appliance", "This is a container-only install: the box has no packages of its own to read. Its software list comes from the host it runs on.")
	}
	var id, name string
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE is_box = 1`).Scan(&id); err != nil {
		return DeviceSourcesView{}, fmt.Errorf("inventory: find the box: %w", err)
	}
	if err := errors.Join(s.RefreshBoxPackages(ctx), s.RefreshBoxServices(ctx)); err != nil {
		s.log.WarnContext(ctx, "inventory: the box could not read its own packages or ports", "error", err.Error())
		return DeviceSourcesView{}, apierr.New(502, "box_read_failed", "The box could not read its own packages just now. What it read last stays; it tries again at its next hourly read.")
	}
	name = deviceName(ctx, s.db.Reader(), id)
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_software WHERE asset_id = ? AND state = 'present'`, id).Scan(&n); err != nil {
		return DeviceSourcesView{}, fmt.Errorf("inventory: read software: %w", err)
	}
	if err := s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		return s.auditTx(ctx, tx, actor, "inventory.box_check", name, fmt.Sprintf("read its own packages and ports now: %d software lines", n))
	}); err != nil {
		return DeviceSourcesView{}, err
	}
	return s.DeviceSources(ctx, id)
}

// RefreshBoxServices stores the ports the box listens on from outside as its open services (source agent, confidence 1.0; INV-3,
// INV-23): the box is never scanned by its own sensor, so this is the only source of its Services tab. The list goes through the
// same bounds as a sensor's (checkServices) and replaces the box's agent rows; rows of other sources stay. It does nothing without a
// BoxPorts (a container-only install) or when it gives no list (nil: a host older than the read): what is stored stays. A failed
// read changes nothing either. The box's addresses are never a device (INV-17), so the row is written by its id, not by a hint.
func (s *Service) RefreshBoxServices(ctx context.Context) error {
	if s.boxPorts == nil {
		return nil
	}
	items, err := s.boxPorts(ctx)
	if err != nil {
		return fmt.Errorf("inventory: box ports: %w", err)
	}
	if items == nil {
		return nil
	}
	for i := range items {
		items[i].Confidence = 1
	}
	clean, err := s.checkServices(ctx, items)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, _ *outbox) error {
		var id string
		if err := tx.QueryRowContext(ctx, `SELECT id FROM inv_asset WHERE is_box = 1`).Scan(&id); err != nil {
			return fmt.Errorf("inventory: find the box: %w", err)
		}
		_, err := replaceServicesTx(ctx, tx, id, clean, string(observe.Agent), s.seen(s.clock()), true, nil, s.clock(), "")
		return err
	})
}

func mustAddr(ip string) netip.Addr {
	a, _ := netip.ParseAddr(ip) // "" gives the zero Addr, which claimIP ignores
	return a
}
