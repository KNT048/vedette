package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/store"
)

// AddInput is what a person gives to declare a device or software (contract.ts AddDeviceInput): a product
// from the catalog (CatalogID) or a vendor and product typed by hand.
type AddInput struct {
	CatalogID string
	Vendor    string
	Product   string
	Version   string
	Name      string
	IP        string
}

// AddResult is POST /inventory/devices.
type AddResult struct {
	ID      string `json:"id"`
	Display string `json:"display"`
	KevCVEs int    `json:"kev_cves"`
}

type addChecked struct {
	entry   *catEntry
	version string
	name    string
	ip      string
}

func notFoundDevice() *apierr.Error {
	return apierr.New(404, apierr.CodeNotFound, "No such device. It may have been removed; go back to the list to see the remaining devices.")
}

// resolveProduct finds the product: from the catalog, or built from the typed vendor and product.
func resolveProduct(c *Catalog, in AddInput) (*catEntry, *apierr.Error) {
	if in.CatalogID != "" {
		if e := c.byID[in.CatalogID]; e != nil {
			return e, nil
		}
		return nil, badRequest("unknown_product", "That product is not in the list. Pick one from the suggestions, or enter the vendor and product yourself.")
	}
	vendor, product := strings.TrimSpace(in.Vendor), strings.TrimSpace(in.Product)
	switch {
	case vendor == "" && product == "":
		return nil, nil
	case vendor == "" || product == "":
		return nil, badRequest("incomplete_product", `Enter both the vendor and the product, for example vendor "Fortinet" and product "FortiGate".`)
	case !label(vendor) || !label(product):
		return nil, badRequest("bad_product", "Vendor and product are at most 64 characters each and cannot contain < or >.")
	}
	return c.custom(vendor, product), nil
}

// checkAdd validates a declaration at the boundary in the order the mock does (INV-4). The IP clash is
// checked in the transaction, not here.
func checkAdd(c *Catalog, in AddInput, requireProduct bool) (addChecked, *apierr.Error) {
	entry, err := resolveProduct(c, in)
	if err != nil {
		return addChecked{}, err
	}
	if requireProduct && entry == nil {
		return addChecked{}, badRequest("unknown_product", `Pick a product from the suggestions. Type a vendor or product name, for example "FortiGate".`)
	}
	version := strings.TrimSpace(in.Version)
	if version != "" && !versionRE.MatchString(version) {
		return addChecked{}, badRequest("bad_version", "The version may only contain letters, digits, dots, hyphens and brackets, up to 40 characters. Example 7.2.5.")
	}
	name := strings.TrimSpace(in.Name)
	if name != "" && !label(name) {
		return addChecked{}, badRequest("bad_name", "The name is at most 64 characters and cannot contain < or >.")
	}
	ip := strings.TrimSpace(in.IP)
	if ip != "" {
		a, ok := ipv4(ip)
		if !ok {
			return addChecked{}, badRequest("bad_ip", "That IP address is not valid. Enter something like 192.168.10.25, or leave it empty if unknown.")
		}
		ip = a.String()
	}
	return addChecked{entry: entry, version: version, name: name, ip: ip}, nil
}

// createManual inserts a declared device with its observations and software (INV-4, INV-5): approved, never
// scanned, source "manual" at confidence 1.
func (s *Service) createManual(ctx context.Context, tx *sql.Tx, o *outbox, a addChecked, kind string) (string, error) {
	if a.ip != "" {
		var dup sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT coalesce(hostname, id) FROM inv_asset WHERE ip = ?`, a.ip).Scan(&dup)
		if err == nil {
			return "", conflict("duplicate_ip", fmt.Sprintf("IP %s is already in the list (%s). Open that device instead of adding a new one.", a.ip, dup.String))
		} else if !errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("inventory: check IP: %w", err)
		}
	}
	if kind == "" {
		kind = "unknown"
		if a.entry != nil {
			kind = a.entry.kind
		}
	}
	now := s.now()
	id := store.NewID("a")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, ip, kind, origin, approved, fragile, first_seen, last_seen) VALUES (?, ?, 'unknown', 'manual', 1, 0, ?, ?)`, id, nullStr(a.ip), now, now); err != nil {
		return "", fmt.Errorf("inventory: create device: %w", err)
	}
	if a.entry != nil {
		if err := insertObs(ctx, tx, id, "vendor", a.entry.vendor, "manual", 1, now); err != nil {
			return "", err
		}
	}
	if a.name != "" {
		if err := insertObs(ctx, tx, id, "hostname", a.name, "manual", 1, now); err != nil {
			return "", err
		}
	}
	if kind != "unknown" { // "unknown" says nothing; as a manual value it would beat every later detection
		if err := insertObs(ctx, tx, id, "kind", kind, "manual", 1, now); err != nil {
			return "", err
		}
	}
	if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
		return "", err
	}
	if a.entry != nil {
		sw := SoftwareItem{Display: a.entry.display, Vendor: a.entry.vendor, Product: a.entry.product, Version: a.version, KevKeys: a.entry.kev, Confidence: 1}
		if err := insertSoftware(ctx, tx, id, sw, "manual", now); err != nil {
			return "", err
		}
		o.add(EventSoftwareChanged, AssetEvent{AssetID: id})
		o.after = append(o.after, s.matchEvents(id, nil, a.entry.kev))
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: id})
	return id, nil
}

// requireDevice is the early existence check: a request about a device that is gone is 404 whatever else is
// wrong with it. The transaction checks again.
func (s *Service) requireDevice(ctx context.Context, id string) error {
	ok, err := assetExists(ctx, s.db.Reader(), id)
	if err != nil {
		return err
	}
	if !ok {
		return notFoundDevice()
	}
	return nil
}

// AddDevice declares a device by hand (S-INV-2, INV-4, INV-5).
func (s *Service) AddDevice(ctx context.Context, actor string, in AddInput) (AddResult, error) {
	c, err := s.Catalog(ctx)
	if err != nil {
		return AddResult{}, err
	}
	a, aerr := checkAdd(c, in, true)
	if aerr != nil {
		return AddResult{}, aerr
	}
	var res AddResult
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		id, err := s.createManual(ctx, tx, o, a, "")
		if err != nil {
			return err
		}
		res = AddResult{ID: id, Display: a.entry.display, KevCVEs: a.entry.kevCount}
		return s.auditTx(ctx, tx, actor, "inventory.add_manual", a.entry.display, a.ip)
	})
	return res, mapUnique(err, a.ip)
}

// mapUnique turns a lost race on the IP index into the same 409 as the check before it.
func mapUnique(err error, ip string) error {
	if err != nil && ip != "" && strings.Contains(err.Error(), "inv_asset.ip") {
		return conflict("duplicate_ip", fmt.Sprintf("IP %s is already in the list. Open that device instead of adding a new one.", ip))
	}
	return err
}

// AddSoftware declares more software on a device (S-INV-2, INV-4). The same vendor and product twice on one
// device is 409 duplicate_software; to change a version, remove the row and add it again.
func (s *Service) AddSoftware(ctx context.Context, actor, assetID string, in AddInput) (kevCVEs int, err error) {
	if err := s.requireDevice(ctx, assetID); err != nil { // 404 before 400, like the mock
		return 0, err
	}
	c, err := s.Catalog(ctx)
	if err != nil {
		return 0, err
	}
	in.IP, in.Name = "", ""
	a, aerr := checkAdd(c, in, true)
	if aerr != nil {
		return 0, aerr
	}
	err = s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundDevice()
		}
		var dup int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM inv_software WHERE asset_id = ? AND lower(vendor) = lower(?) AND lower(product) = lower(?) LIMIT 1`, assetID, a.entry.vendor, a.entry.product).Scan(&dup)
		if err == nil {
			return conflict("duplicate_software", a.entry.display+" is already on this device. To change the version, remove it and add it again.")
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("inventory: check software: %w", err)
		}
		before, err := softwareKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		sw := SoftwareItem{Display: a.entry.display, Vendor: a.entry.vendor, Product: a.entry.product, Version: a.version, KevKeys: a.entry.kev, Confidence: 1}
		if err := insertSoftware(ctx, tx, assetID, sw, "manual", s.now()); err != nil {
			return err
		}
		after, err := softwareKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		kevCVEs = a.entry.kevCount
		o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID})
		o.after = append(o.after, s.matchEvents(assetID, before, after))
		return s.auditTx(ctx, tx, actor, "inventory.add_software", deviceName(ctx, tx, assetID)+": "+a.entry.display, "")
	})
	return kevCVEs, err
}

// RemoveSoftware removes software a person declared (INV-4); what a sensor or agent saw is not removable.
func (s *Service) RemoveSoftware(ctx context.Context, actor, assetID, softwareID string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		ok, err := assetExists(ctx, tx, assetID)
		if err != nil {
			return err
		}
		if !ok {
			return notFoundDevice()
		}
		var display, source string
		err = tx.QueryRowContext(ctx, `SELECT display, source FROM inv_software WHERE id = ? AND asset_id = ?`, softwareID, assetID).Scan(&display, &source)
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.New(404, apierr.CodeNotFound, "No such software on this device.")
		} else if err != nil {
			return fmt.Errorf("inventory: read software: %w", err)
		}
		if source != "manual" {
			return badRequest("not_manual", "Only manually declared software can be removed. Software seen by a sensor or agent updates on the next scan.")
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software WHERE id = ?`, softwareID); err != nil {
			return fmt.Errorf("inventory: remove software: %w", err)
		}
		o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID})
		return s.auditTx(ctx, tx, actor, "inventory.remove_software", deviceName(ctx, tx, assetID)+": "+display, "")
	})
}

// Patch is PATCH /inventory/devices/{id}; a nil field is left alone.
type Patch struct {
	Kind        *string
	Fragile     *bool
	RegularScan *string
	Notes       *string
}

// PatchDevice changes the type, fragile flag, regular-scan override or notes of a device (PRE-4, POST-4).
// A new type is added as a manual observation: older and weaker values stay in the list (INV-1).
func (s *Service) PatchDevice(ctx context.Context, actor, id string, p Patch) error {
	if err := s.requireDevice(ctx, id); err != nil { // 404 before 400, like the mock
		return err
	}
	if p.RegularScan != nil && !slices.Contains([]string{"follow", "allow", "never"}, *p.RegularScan) {
		return badRequest("bad_regular_scan", "Regular scans must be: follow type setting, allow or never.")
	}
	if p.Kind != nil && !validKind(*p.Kind) {
		return badRequest("bad_kind", "Device type must be one of: "+strings.Join(Kinds, ", ")+".")
	}
	if p.Notes != nil && len([]rune(*p.Notes)) > maxNotes {
		return badRequest("bad_notes", "Notes are at most 2000 characters.")
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var kind string
		var kindSrc sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT a.kind, o.source FROM inv_asset a LEFT JOIN inv_observation o ON o.id = a.kind_obs_id WHERE a.id = ?`, id).Scan(&kind, &kindSrc)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		name := deviceName(ctx, tx, id)
		if p.RegularScan != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET regular_scan = ? WHERE id = ?`, *p.RegularScan, id); err != nil {
				return fmt.Errorf("inventory: set regular scan: %w", err)
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_regular_scan", name, *p.RegularScan); err != nil {
				return err
			}
		}
		// Picking the kind the device already has still records it as manual when it came from elsewhere: that is how an operator vouches
		// for a router that only a passive frame announced (D-177, TrustedKind).
		if p.Kind != nil && (*p.Kind != kind || kindSrc.String != "manual") {
			if err := insertObs(ctx, tx, id, "kind", *p.Kind, "manual", 1, s.now()); err != nil {
				return err
			}
			if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
				return err
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_kind", name, kind+" → "+*p.Kind); err != nil {
				return err
			}
		}
		if p.Fragile != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET fragile = ?, fragile_manual = 1 WHERE id = ?`, *p.Fragile, id); err != nil {
				return fmt.Errorf("inventory: set fragile: %w", err)
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_fragile", name, fmt.Sprint(*p.Fragile)); err != nil {
				return err
			}
		}
		if p.Notes != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET notes = ? WHERE id = ?`, nullStr(*p.Notes), id); err != nil {
				return fmt.Errorf("inventory: set notes: %w", err)
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_notes", name, ""); err != nil {
				return err
			}
		}
		o.add(EventAssetUpdated, AssetEvent{AssetID: id})
		return nil
	})
}

// Approve accepts a device a sensor found (S-INV-3); it also clears the suspicious flag.
func (s *Service) Approve(ctx context.Context, actor, id string) error {
	return s.setFlag(ctx, actor, id, `UPDATE inv_asset SET approved = 1, suspicious = 0 WHERE id = ?`, []any{id}, "inventory.approve")
}

// SetSuspicious marks or unmarks a device as suspicious (S-INV-3).
func (s *Service) SetSuspicious(ctx context.Context, actor, id string, suspicious bool) error {
	action := "inventory.unmark_suspicious"
	if suspicious {
		action = "inventory.mark_suspicious"
	}
	return s.setFlag(ctx, actor, id, `UPDATE inv_asset SET suspicious = ? WHERE id = ?`, []any{suspicious, id}, action)
}

func (s *Service) setFlag(ctx context.Context, actor, id, query string, args []any, action string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		res, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("inventory: %s: %w", action, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return notFoundDevice()
		}
		o.add(EventAssetUpdated, AssetEvent{AssetID: id})
		return s.auditTx(ctx, tx, actor, action, deviceName(ctx, tx, id), id)
	})
}

// DeleteDevice removes a device with its observations, services and software; the box itself is 409 box_device
// (INV-3, D-53). findings deletes the findings of the device on inventory.asset.deleted (INV-11).
func (s *Service) DeleteDevice(ctx context.Context, actor, id string) error {
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var box bool
		err := tx.QueryRowContext(ctx, `SELECT is_box FROM inv_asset WHERE id = ?`, id).Scan(&box)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box {
			return conflict("box_device", "This is the Vedette box itself, so it cannot be deleted. It is always the first device in the list. Its packages come from the box.")
		}
		name := deviceName(ctx, tx, id)
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_asset WHERE id = ?`, id); err != nil {
			return fmt.Errorf("inventory: delete device: %w", err)
		}
		detail := id
		if n := counts[id]; n > 0 {
			detail = fmt.Sprintf("%s; removed %d findings of the device", id, n)
		}
		o.add(EventAssetDeleted, AssetEvent{AssetID: id})
		return s.auditTx(ctx, tx, actor, "inventory.delete", name, detail)
	})
}
