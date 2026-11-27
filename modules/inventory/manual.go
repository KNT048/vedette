package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/observe"
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
	UserName  string // the name in Vedette: only CSV import sets it, from its name_in_vedette column
}

// AddResult is POST /inventory/devices.
type AddResult struct {
	ID      string `json:"id"`
	Display string `json:"display"`
	KevCVEs int    `json:"kev_cves"`
}

type addChecked struct {
	entry    *catEntry
	version  string
	name     string
	ip       string
	userName string
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
	user := strings.TrimSpace(in.UserName)
	if !userName(user) {
		return addChecked{}, badRequest("bad_name", badUserName)
	}
	ip := strings.TrimSpace(in.IP)
	if ip != "" {
		a, ok := ipv4(ip)
		if !ok {
			return addChecked{}, badRequest("bad_ip", "That IP address is not valid. Enter something like 192.168.10.25, or leave it empty if unknown.")
		}
		ip = a.String()
	}
	return addChecked{entry: entry, version: version, name: name, ip: ip, userName: user}, nil
}

// createManual inserts a declared device with its observations and software (INV-4, INV-5): approved, never
// scanned, source "manual" at confidence 1. actor is the person who added it: the author of the version it was added with, so that
// version is their word like any version a person gives a line (set_by).
func (s *Service) createManual(ctx context.Context, tx *sql.Tx, o *outbox, actor string, a addChecked, kind string) (string, error) {
	if a.ip != "" {
		dup, err := addressHolder(ctx, tx, a.ip) // its main address or one of its others (INV-57)
		if err != nil {
			return "", err
		}
		if dup != "" { // named as every page names it
			return "", conflict("duplicate_ip", fmt.Sprintf("IP %s is already in the list (%s). Open that device instead of adding a new one.", a.ip, deviceName(ctx, tx, dup)))
		}
	}
	if kind == "" { // the catalog's suggestion; a type a person or a CSV gave is kept as it is (review M2 of #722)
		kind = "unknown"
		if a.entry != nil {
			kind = suggestedKind(a.entry.kind, a)
		}
	}
	now := s.now()
	id := store.NewID("a")
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, ip, ip_confirmed_at, kind, origin, approved, fragile, first_seen, last_seen, user_name)
		VALUES (?1, ?2, CASE WHEN ?2 IS NULL THEN NULL ELSE ?3 END, 'unknown', 'manual', 1, 0, ?3, ?3, ?4)`, id, nullStr(a.ip), now, nullStr(a.userName)); err != nil {
		return "", fmt.Errorf("inventory: create device: %w", err)
	}
	if a.ip != "" { // a person adds the machine at an address a removal kept: the removal is undone (INV-59)
		ip, _ := netip.ParseAddr(a.ip)
		if n, err := forgetRemovedAt(ctx, tx, "", ip, true); err != nil {
			return "", err
		} else if n > 0 {
			if err := s.auditTx(ctx, tx, actor, "inventory.removal_forget", a.ip, "added by hand at the address of a removed device"); err != nil {
				return "", err
			}
		}
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
		if _, _, err := s.addEntryTx(ctx, tx, actor, id, sw); err != nil {
			return "", err
		}
		after, err := deviceKeys(ctx, tx, id)
		if err != nil {
			return "", err
		}
		o.add(EventSoftwareChanged, AssetEvent{AssetID: id})
		o.after = append(o.after, s.matchEvents(id, nil, after))
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: id})
	return id, nil
}

// suggestedKind is the type a catalog entry or feeds suggests for a declared product. A product with neither an IP nor
// a name is only a product (NoDevice, "Microsoft Office (no device)"): a computer type (pc, server, web) would name a device nobody
// declared, so it gets none. An appliance type stays: there the product is the device, and mitigation reads a declared firewall or
// router.
func suggestedKind(kind string, a addChecked) string {
	if a.ip == "" && a.name == "" && slices.Contains([]string{"pc", "server", "web"}, devicetypes.ActsAs(kind)) {
		return "unknown"
	}
	return kind
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
		id, err := s.createManual(ctx, tx, o, actor, a, "")
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
		before, err := deviceKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		sw := SoftwareItem{Display: a.entry.display, Vendor: a.entry.vendor, Product: a.entry.product, Version: a.version, KevKeys: a.entry.kev, Confidence: 1}
		dup, moved, err := s.addEntryTx(ctx, tx, actor, assetID, sw)
		if err != nil {
			return err
		}
		if dup {
			return conflict("duplicate_software", a.entry.display+" is already on this device. To change the version, remove it and add it again.")
		}
		after, err := deviceKeys(ctx, tx, assetID)
		if err != nil {
			return err
		}
		kevCVEs = a.entry.kevCount
		if moved {
			o.add(EventAssetUpdated, AssetEvent{AssetID: assetID})
		}
		o.add(EventSoftwareChanged, AssetEvent{AssetID: assetID})
		o.after = append(o.after, s.matchEvents(assetID, before, after))
		return s.auditTx(ctx, tx, actor, "inventory.add_software", deviceName(ctx, tx, assetID)+": "+a.entry.display, "")
	})
	return kevCVEs, err
}

// Patch is PATCH /inventory/devices/{id}; a nil field is left alone.
type Patch struct {
	Kind        *string
	Fragile     *bool
	RegularScan *string
	Notes       *string
	Name        *string // the name in Vedette: trimmed; "" clears it, back to the naming rule
	OS          *string // the person's OS (INV-41): trimmed; "" clears the correction, back to what the sources read
}

// PatchDevice changes the name in Vedette, type, fragile flag, regular-scan override or notes of a device (PRE-4, POST-4).
// A new type is added as a manual observation: older and weaker values stay in the list (INV-1). The name is the device's own
// column (user_name), never an observation: the host name the network reports stays as it is, shown apart.
func (s *Service) PatchDevice(ctx context.Context, actor, id string, p Patch) error {
	if err := s.requireDevice(ctx, id); err != nil { // 404 before 400, like the mock
		return err
	}
	if p.Name != nil {
		n := strings.TrimSpace(*p.Name)
		if !userName(n) {
			return badRequest("bad_name", badUserName)
		}
		p.Name = &n
	}
	if p.OS != nil {
		v := strings.TrimSpace(*p.OS)
		if v != "" && !osText(v) {
			return badRequest("bad_os", badOS)
		}
		p.OS = &v
	}
	if p.RegularScan != nil && !slices.Contains([]string{"follow", "allow", "never"}, *p.RegularScan) {
		return badRequest("bad_regular_scan", "Regular scans must be: follow type setting, allow or never.")
	}
	if p.Kind != nil && !validKind(*p.Kind) {
		return badRequest("bad_kind", "Device type is not one of the device types (for example router, switch, ip_phone, laptop).")
	}
	if p.Notes != nil && len([]rune(*p.Notes)) > maxNotes {
		return badRequest("bad_notes", "Notes are at most 2000 characters.")
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error { return s.patchTx(ctx, tx, o, actor, id, p) })
}

// patchTx is PatchDevice inside a write, with p already checked (a merge applies the values a person chose in its own write).
func (s *Service) patchTx(ctx context.Context, tx *sql.Tx, o *outbox, actor, id string, p Patch) error {
	{
		var kind string
		var kindSrc sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT a.kind, o.source FROM inv_asset a LEFT JOIN inv_observation o ON o.id = a.kind_obs_id WHERE a.id = ?`, id).Scan(&kind, &kindSrc)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		name := deviceName(ctx, tx, id)
		match := false
		if p.Name != nil {
			var old sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT user_name FROM inv_asset WHERE id = ?`, id).Scan(&old); err != nil {
				return fmt.Errorf("inventory: read name: %w", err)
			}
			if old.String != *p.Name { // the same name again changes nothing and writes no audit row
				if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET user_name = ? WHERE id = ?`, nullStr(*p.Name), id); err != nil {
					return fmt.Errorf("inventory: set name: %w", err)
				}
				renamed := deviceName(ctx, tx, id)
				if err := s.auditTx(ctx, tx, actor, "inventory.rename", renamed, name+" → "+renamed); err != nil {
					return err
				}
				// The findings' evidence names the device (MatchDevice.Name): matching it again writes the new name there too.
				name, match = renamed, true
			}
		}
		if p.OS != nil {
			changed, err := s.setOSTx(ctx, tx, actor, id, name, *p.OS)
			if err != nil {
				return err
			}
			match = match || changed // the OS decides OS and platform findings: match the device again
		}
		if p.RegularScan != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET regular_scan = ? WHERE id = ?`, *p.RegularScan, id); err != nil {
				return fmt.Errorf("inventory: set regular scan: %w", err)
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_regular_scan", name, *p.RegularScan); err != nil {
				return err
			}
		}
		// Picking the kind the device already has still records it as manual when it came from elsewhere: that is how an operator vouches
		// for a router that only a passive frame announced (TrustedKind).
		if p.Kind != nil && (*p.Kind != kind || kindSrc.String != "manual") {
			before, err := matchView(ctx, tx, id)
			if err != nil {
				return err
			}
			if err := insertObs(ctx, tx, id, "kind", *p.Kind, "manual", 1, s.now()); err != nil {
				return err
			}
			if _, err := s.RecomputeAsset(ctx, tx, id); err != nil {
				return err
			}
			// The type decides whether nmap's OS guess stands (osguess.go): an OS that changed with it is matched again.
			after, err := matchView(ctx, tx, id)
			if err != nil {
				return err
			}
			match = match || after != before
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
		o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: match})
		return nil
	}
}

// Sources is the state of a device's active sources (PUT /inventory/devices/{id}/sources): SourceOn or SourceOff each, the
// default resolved (on for a device a sensor found, off for one added by hand).
type Sources struct {
	Scan  string `json:"scan_source"`
	SNMP  string `json:"snmp_source"`
	Agent string `json:"agent_source"` // the agents' data of the device: on unless a person turned it off
}

// SetSources turns the network scan and the SNMP reads of one device on or off; a nil value is left alone, and at least one is
// needed. Turning one on is a person's consent to that traffic to this device: a device added by hand gets it from then on, inside every
// other safety rule (scope, exclusions, window, fragile, never, the box). Turning one off stops it for any device: the run in progress on
// the device stops (inventory.asset.updated), and what that source found stays. One audit row per source changed says who, which device,
// which source and on or off. The box itself is 409 box_device: nothing automatic ever probes it.
func (s *Service) SetSources(ctx context.Context, actor, id string, scan, snmp *string) (Sources, error) {
	return s.ChangeSources(ctx, actor, id, SourcesChange{Scan: scan, SNMP: snmp})
}

// SourcesChange is what PUT /inventory/devices/{id}/sources changes: nil leaves a source alone.
type SourcesChange struct{ Scan, SNMP, Agent *string }

// ChangeSources is SetSources with the agent switch too. Turning the agent off refuses every agent's data for the device from then on
// (the sinks drop it: ReplaceSoftware, ReplaceServices, Record) and what the agents read stops counting at once: their software readings
// go (each line is settled again, so a line only an agent read is removed and the history says so) and so do their open ports.
// Turning it on takes their data again; the agent's next report brings it back, and Config.AskAgent asks an osquery agent for it now.
func (s *Service) ChangeSources(ctx context.Context, actor, id string, ch SourcesChange) (Sources, error) {
	scan, snmp, agent := ch.Scan, ch.SNMP, ch.Agent
	for _, v := range []*string{scan, snmp, agent} {
		if v != nil && *v != SourceOn && *v != SourceOff {
			return Sources{}, badRequest("bad_source", "Each source is on or off.")
		}
	}
	if scan == nil && snmp == nil && agent == nil {
		return Sources{}, badRequest("bad_source", "Say which source to turn on or off: scan, snmp, agent or more than one.")
	}
	var out Sources
	agentOn := false
	err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var origin, curScan, curSNMP, curAgent, ip string
		var box, ignored bool
		err := tx.QueryRowContext(ctx, `SELECT origin, is_box, coalesce(scan_source, ''), coalesce(snmp_source, ''), coalesce(agent_source, ''), coalesce(ip, ''), ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).
			Scan(&origin, &box, &curScan, &curSNMP, &curAgent, &ip, &ignored)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box {
			return conflict("box_device", "This is the Vedette box itself: Vedette never scans or reads it on its own, and it reads its own packages.")
		}
		if ignored && (deref(scan) == SourceOn || deref(snmp) == SourceOn) { // An ignored device is not watched
			return conflict("device_ignored", "This device is ignored, so Vedette does not scan or read it. Stop ignoring it first.")
		}
		name := deviceName(ctx, tx, id)
		scanOn, changed := false, false
		for _, c := range []struct {
			col, label string
			cur        *string
			next       *string
		}{{"scan_source", "network scan", &curScan, scan}, {"snmp_source", "SNMP", &curSNMP, snmp}, {"agent_source", "agent", &curAgent, agent}} {
			if c.next == nil {
				continue
			}
			// The stored value is the consent the policies read (a stored "on" lets SNMP past lan_ranges; review r2 M1): any change of it is
			// a change, audited and announced, even when the resolved default looked the same.
			before := *c.cur
			// only the two column names above are concatenated; the value is bound
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET `+c.col+` = ? WHERE id = ?`, *c.next, id); err != nil { //nolint:gosec // G202: see above
				return fmt.Errorf("inventory: set %s: %w", c.label, err)
			}
			*c.cur = *c.next
			if before == *c.next {
				continue // saying it again changes nothing and writes no audit row
			}
			if err := s.auditTx(ctx, tx, actor, "inventory.set_source", name, c.label+": "+*c.next); err != nil {
				return err
			}
			changed = true
			scanOn = scanOn || (c.col == "scan_source" && *c.next == SourceOn)
			if c.col == "agent_source" && before != *c.next {
				if *c.next == SourceOff {
					if err := s.dropAgentData(ctx, tx, o, id); err != nil {
						return err
					}
				} else {
					agentOn = true
				}
			}
		}
		st, err := loadSettings(ctx, tx)
		if err != nil {
			return err
		}
		out = Sources{Scan: sourceState(curScan, origin), SNMP: snmpState(st, curSNMP, origin, ip), Agent: agentState(curAgent)}
		if changed { // a PUT that changes nothing stops nothing (review r1 L3)
			o.add(EventAssetUpdated, AssetEvent{AssetID: id, ScanOn: scanOn})
		}
		return nil
	})
	if err == nil && agentOn && s.askAgent != nil {
		s.askAgent(ctx, actor, id)
	}
	return out, err
}

// agentState resolves a device's stored agent switch: on unless a person turned it off.
func agentState(stored string) string {
	if stored == SourceOff {
		return SourceOff
	}
	return SourceOn
}

// agentRefused says whether a person turned the agent off for the device: its agents' data is dropped (ChangeSources).
func agentRefused(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	var off bool
	err := tx.QueryRowContext(ctx, `SELECT coalesce(agent_source, '') = 'off' AND is_box = 0 FROM inv_asset WHERE id = ?`, id).Scan(&off)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("inventory: read the agent switch: %w", err)
	}
	return off, nil
}

// dropAgentData makes what the agents read of a device stop counting: the software readings of every agent source go and the lines
// they touched are settled again (with their history), and so do the agents' open ports and their observations of the device (OS,
// name, card, kind), whose fields are chosen again from what the other sources read. What other sources read stays.
func (s *Service) dropAgentData(ctx context.Context, tx *sql.Tx, o *outbox, id string) error {
	before, err := deviceKeys(ctx, tx, id)
	if err != nil {
		return err
	}
	touched, err := candidates(ctx, tx, `SELECT DISTINCT r.software_id FROM inv_software_reading r JOIN inv_software w ON w.id = r.software_id
		WHERE w.asset_id = ? AND r.source IN ('osquery', 'wazuh') ORDER BY r.software_id`, id)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_software_reading WHERE source IN ('osquery', 'wazuh') AND software_id IN (SELECT id FROM inv_software WHERE asset_id = ?)`, id); err != nil {
		return fmt.Errorf("inventory: drop the agents' readings: %w", err)
	}
	now := s.seen(s.clock())
	for _, l := range touched {
		if _, err := s.settleLine(ctx, tx, l, now, nil); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_service WHERE asset_id = ? AND source = ?`, id, string(observe.Agent)); err != nil {
		return fmt.Errorf("inventory: drop the agents' open ports: %w", err)
	}
	// what the agents said of the device itself (its OS, name, card, kind): the device's fields are chosen again from the other sources
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND source = ?`, id, string(observe.Agent)); err != nil {
		return fmt.Errorf("inventory: drop the agents' observations: %w", err)
	}
	if changed, err := s.RecomputeAsset(ctx, tx, id); err != nil {
		return err
	} else if changed {
		o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: true})
	}
	if len(touched) == 0 {
		return nil
	}
	after, err := deviceKeys(ctx, tx, id)
	if err != nil {
		return err
	}
	o.add(EventSoftwareChanged, AssetEvent{AssetID: id})
	o.after = append(o.after, s.matchEvents(id, before, after))
	return nil
}

// Approve accepts a device a sensor found (S-INV-3); it also clears the suspicious flag.
// A device that was waiting also gets inventory.asset.approved {asset_id, actor} after the commit (B9b): notify closes its
// new-device incident naming the person. Approving again (to clear a mark) is no approval; osquery enrolment (ApproveEnrolled) is
// not a person and publishes only inventory.asset.updated.
func (s *Service) Approve(ctx context.Context, actor, id string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var was, ignored bool
		err := tx.QueryRowContext(ctx, `SELECT approved, ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).Scan(&was, &ignored)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: inventory.approve: %w", err)
		}
		if ignored {
			return conflict("device_ignored", "This device is ignored. Stop ignoring it first, then approve it.")
		}
		// approved_at keeps the first approval: approving again (to clear the unknown mark) does not move the device to "approved in the last 24 h".
		if err := s.flagTx(ctx, tx, o, actor, id, `UPDATE inv_asset SET approved_at = CASE WHEN approved = 1 THEN approved_at ELSE ? END, approved = 1, suspicious = 0 WHERE id = ?`, []any{s.now(), id}, "inventory.approve"); err != nil {
			return err
		}
		if !was {
			o.add(EventAssetApproved, AssetEvent{AssetID: id, Actor: actor})
		}
		return nil
	})
}

// SetSuspicious marks or unmarks a device as suspicious (S-INV-3).
func (s *Service) SetSuspicious(ctx context.Context, actor, id string, suspicious bool) error {
	action := "inventory.unmark_suspicious"
	if suspicious {
		action = "inventory.mark_suspicious"
	}
	return s.setFlag(ctx, actor, id, `UPDATE inv_asset SET suspicious = ? WHERE id = ?`, []any{suspicious, id}, action)
}

// SetIgnored ignores a device or stops ignoring it (S-INV-3): "this device needs no watching", a staff phone. An ignored device
// stays known (its row, so its MAC and agent key keep matching it when it is seen again) but is out of To review, the counts and the
// Devices list unless asked for; it sends no new-device alert (notify closes its open one on inventory.asset.ignored), the scan policies
// read its network scan and SNMP reads as off (effectiveSources; the stored source choice and the unknown mark are kept), and it is out
// of the vulnerability readers (MatchInput,
// AssetIDs, DevicesRunning), so findings makes none for it; the findings it has stay as they are, left out of every findings list
// and not rated by the urgency pass. A trap hit or an intrusion-detection incident from it still alerts: those modules never ask about
// it. Stopping sends it through review again: not approved, its own scan and SNMP settings in force again, inventory.asset.unignored,
// then matched again (its findings are listed and rated again at once). Saying it again changes nothing (no audit row, no event). The box is 409 box_device.
func (s *Service) SetIgnored(ctx context.Context, actor, id string, ignored bool) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var box bool
		var origin, scanSrc string
		var at sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT is_box, origin, ignored_at, coalesce(scan_source, '') FROM inv_asset WHERE id = ?`, id).Scan(&box, &origin, &at, &scanSrc)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box {
			return conflict("box_device", "This is the Vedette box itself: it cannot be ignored.")
		}
		if at.Valid == ignored {
			return nil
		}
		name := deviceName(ctx, tx, id)
		if ignored {
			// The stored scan and SNMP settings and the unknown mark stay as a person left them (review r1 M1, L4 of #945): the policies
			// read the device as off while it is ignored (effectiveSources), and To review and ApproveEnrolled check ignored_at.
			if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ignored_at = ? WHERE id = ?`, s.now(), id); err != nil {
				return fmt.Errorf("inventory: ignore a device: %w", err)
			}
			// updated first: sensor-active and scan stop what runs on it; then ignored: notify closes its new-device incident. Its
			// findings stay as they are: the lists leave them out and the urgency pass does not rate them while it is ignored.
			o.add(EventAssetUpdated, AssetEvent{AssetID: id})
			o.add(EventAssetIgnored, AssetEvent{AssetID: id, Actor: actor})
			return s.auditTx(ctx, tx, actor, "inventory.ignore", name, id)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inv_asset SET ignored_at = NULL, approved = 0, approved_at = NULL WHERE id = ?`, id); err != nil {
			return fmt.Errorf("inventory: stop ignoring a device: %w", err)
		}
		// unignored first; then updated with match: findings matches it again and rates its findings at once, and ScanOn:
		// sensor-active queues a discovered device for its next window (the default is on).
		o.add(EventAssetUnignored, AssetEvent{AssetID: id, Actor: actor})
		o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: true, ScanOn: sourceState(scanSrc, origin) == SourceOn})
		return s.auditTx(ctx, tx, actor, "inventory.unignore", name, id)
	})
}

func (s *Service) setFlag(ctx context.Context, actor, id, query string, args []any, action string) error {
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error { return s.flagTx(ctx, tx, o, actor, id, query, args, action) })
}

func (s *Service) flagTx(ctx context.Context, tx *sql.Tx, o *outbox, actor, id, query string, args []any, action string) error {
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("inventory: %s: %w", action, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return notFoundDevice()
	}
	o.add(EventAssetUpdated, AssetEvent{AssetID: id})
	return s.auditTx(ctx, tx, actor, action, deviceName(ctx, tx, id), id)
}

// DeleteDevice removes a device with its observations, services and software; the box itself is 409 box_device
// (INV-3). The other modules remove what they keep about it in the same transaction (deleteDeviceTx): findings deletes its findings
// (INV-11). The removal stays (INV-59, keepRemoved): the sensors do not make the device again. agent is the person's choice for an agent
// bound to the device: AgentStop stops it too (its record goes, and its token when made for this device alone; never a token other
// machines share), AgentKeep (or "") leaves it, and then nothing is kept, since the agent adds the device back on its next report.
func (s *Service) DeleteDevice(ctx context.Context, actor, id, agent string) error {
	if agent != "" && agent != AgentKeep && agent != AgentStop {
		return badRequest("invalid", "agent is keep or stop.")
	}
	counts, err := s.findingCounts(ctx)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx, o *outbox) error {
		var box bool
		var ip, agentKey sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT is_box, ip, agent_key FROM inv_asset WHERE id = ?`, id).Scan(&box, &ip, &agentKey)
		if errors.Is(err, sql.ErrNoRows) {
			return notFoundDevice()
		} else if err != nil {
			return fmt.Errorf("inventory: read device: %w", err)
		}
		if box {
			return conflict("box_device", "This is the Vedette box itself, so it cannot be deleted. It is always the first device in the list. Its packages come from the box.")
		}
		name := deviceName(ctx, tx, id)
		d := lifecycle.Delete{Device: id, Name: name}
		if actor != systemActor {
			d.Actor = actor
		}
		if agentKey.Valid && agent == AgentStop {
			d.StopAgent = &lifecycle.AgentStop{Key: agentKey.String}
		}
		macs, ips, err := removedIdentifiers(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := s.deleteDeviceTx(ctx, tx, o, d); err != nil {
			return err
		}
		detail := id
		if n := counts[id]; n > 0 {
			detail = fmt.Sprintf("%s; removed %d findings of the device", id, n)
		}
		switch {
		case !agentKey.Valid || d.StopAgent != nil:
			kept, err := s.keepRemoved(ctx, tx, d, ip, macs, ips)
			if err != nil {
				return err
			}
			if kept {
				detail += "; kept out of discovery"
			}
			if d.StopAgent != nil && d.StopAgent.Stopped {
				detail += "; its agent was stopped"
				if d.StopAgent.Token != "" {
					detail += " and its token " + d.StopAgent.Token + " revoked"
				}
			}
		default:
			detail += "; its agent was left running and adds the device back on its next report"
		}
		o.add(EventAssetDeleted, AssetEvent{AssetID: id, Actor: actor}) // notify says who deleted it
		return s.auditTx(ctx, tx, actor, "inventory.delete", name, detail)
	})
}

// deleteDeviceTx deletes device d.Device in tx: first every module's part (core/lifecycle: findings, SNMP settings, open incidents...),
// then the device row with what the inventory keeps about it (foreign keys). An error of any part rolls the delete back. The modules'
// in-memory state follows after the commit.
func (s *Service) deleteDeviceTx(ctx context.Context, tx *sql.Tx, o *outbox, d lifecycle.Delete) error {
	if err := s.lifecycle.DeviceDeleted(ctx, tx, d); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inv_asset WHERE id = ?`, d.Device); err != nil {
		return fmt.Errorf("inventory: delete device: %w", err)
	}
	o.after = append(o.after, func(ctx context.Context) []Event { s.lifecycle.DeleteCommitted(ctx, d); return nil })
	return nil
}
