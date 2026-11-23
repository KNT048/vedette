package inventory

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/orgtime"
	"github.com/knt048/vedette/core/productid"
)

// This file is what other modules read and ask through their own ports (feeds.Inventory, findings.Inventory,
// mitigation.Vendors). The adapters live in cmd/vedette; they convert these neutral types to the port types,
// so no module imports another.

// DeviceRef is a device as other modules name it.
type DeviceRef struct {
	ID       string
	Hostname *string // the host name the network reports (observations)
	UserName *string // the name a person gave the device in Vedette; nil = none
	IsBox    bool    // the Vedette box itself (never given a risk marker)
	IP       string  // "—" when unknown, like the API
	MAC      string  // "" when unknown
	Vendor   string  // the current vendor value, "" when none
	Kind     string
	Display  string // the first software's display name, else the kind (DisplayName's product of a declared device, notify)
	OS       string // the current operating system value ("Microsoft Windows Server 2025 10.0.26100.1742"), "" when unknown (#905)
	// OSSource is the source of the OS observation the ranking chose for OS (INV-44: manual, agent, snmp, passive, nmap, scan); ""
	// when there is none. "nmap" means the page shows the scan's OS guess; any other source means a better one won over it.
	OSSource string
	OSBasis  string // how Vedette knows that OS, as the device page says it (osBasis): "stated" (its LLDP statement), "guess" (nmap's fingerprint), ""
	Approved bool   // a person approved it, or osquery enrolment did (sensor-active sends SNMP credentials only to approved devices)
	Ignored  bool   // a person ignored it (INV-38): its findings are hidden under Findings > Ignored
	Model    string // the current model value, "" when none (notify names a device without inv.Device)
	Origin   string // "discovered" or "manual"
	// ApprovedAt is when a person or osquery enrolment approved it; nil when not approved, declared by hand, or approved before approval times were recorded.
	ApprovedAt *time.Time
}

// DeviceRefs returns the devices with these ids; unknown ids are absent. An ignored device is present (INV-38): findings' reconcile
// (its orphan pass, through cmd/vedette findingsInventory.Assets) relies on it to keep an ignored device's findings and the decisions
// on them when the ignored list cannot be read. Never filter ignored rows out here.
func (s *Service) DeviceRefs(ctx context.Context, ids []string) (map[string]DeviceRef, error) {
	out := make(map[string]DeviceRef, len(ids))
	for chunk := range slices.Chunk(ids, 400) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.user_name, a.is_box, a.ip, a.mac, a.vendor, a.kind, a.approved, a.model, a.origin, a.approved_at, a.os, a.ignored_at IS NOT NULL,
			(SELECT o.source FROM inv_observation o WHERE o.id = a.os_obs_id),
			`+firstSoftware+`
			FROM inv_asset a WHERE a.id IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
		for rows.Next() {
			var d DeviceRef
			var host, userName, ip, mac, vendor, model, approvedAt, osName, osSource, display sql.NullString
			if err := rows.Scan(&d.ID, &host, &userName, &d.IsBox, &ip, &mac, &vendor, &d.Kind, &d.Approved, &model, &d.Origin, &approvedAt, &osName, &d.Ignored, &osSource, &display); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("inventory: read devices: %w", err)
			}
			d.Hostname, d.UserName, d.IP, d.MAC, d.Vendor, d.Display, d.Model, d.OS, d.OSSource = ptr(host), ptr(userName), noIP, mac.String, vendor.String, d.Kind, model.String, osName.String, osSource.String
			if osName.Valid {
				d.OSBasis = osBasis(osName.String, osSource.String, mac.String)
			}
			if approvedAt.Valid {
				t, err := time.Parse(time.RFC3339Nano, approvedAt.String)
				if err != nil {
					_ = rows.Close()
					return nil, fmt.Errorf("inventory: read devices: approved_at: %w", err)
				}
				d.ApprovedAt = &t
			}
			if ip.Valid {
				d.IP = ip.String
			}
			if display.Valid {
				d.Display = display.String
			}
			out[d.ID] = d
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("inventory: read devices: %w", err)
		}
	}
	return out, nil
}

// MatchSoftware is one reading of a software line the matcher compares, with the line's match keys: the line's effective reading,
// or another reading the resolver keeps for matching (the same ID).
type MatchSoftware struct {
	ID, Display, Vendor, Product, Version, CPE string
	KevKeys                                    []string
	// Source is the class of who read it (MK-2): "agent" (osquery, Wazuh, the box's package list), "manual" (a person's entry),
	// "scan" (the vulnerability scan), or a sensor ("nmap", "snmp", "passive").
	Source string
	// Packaged: an agent's reading from the operating system's package database (deb/rpm/apk), so the distribution ships its fixes.
	Packaged bool
	// PkgVersion and PkgSource: a packaged reading's full package release and source package, "" otherwise; on a person's entry, the
	// package release the person gave or kept (INV-41).
	PkgVersion, PkgSource string
	// ReportedSource is, on a person's entry (Source "manual", INV-41), the class of the strongest source that reads the line, so the
	// matcher keeps that source's distribution and platform rules; "" otherwise. Correction names the person's entry for the findings
	// history: who, from what, to what, when.
	ReportedSource, Correction string
	// Superseded is "" (an entry holds or lapses; it never rests). Kept for the findings port.
	Superseded string
	// Key is the line's id on its effective reading and on a line of MatchDevice.NotInstalled; on another reading, the line's id,
	// source and instance joined by char(31).
	Key string
	// MarkedAt is, on a line of MatchDevice.NotInstalled, when the person said it is not installed (RFC 3339); "" otherwise. MarkedBy
	// is who said it ("" when unknown).
	MarkedAt, MarkedBy string
	// SeenAt is when the reading's source last read it (RFC 3339): for an agent's reading, the time of the list the version comes from.
	SeenAt string
	// ShadowedBy is "" on every row MatchInput returns. Kept for the findings port.
	ShadowedBy string
	// Guess: the reading is a sensor's guess (observe.Software.Guess, stored as nmap's os_guess instance: an OS fingerprint, an ESXi
	// build the build table does not list), never matched.
	Guess bool
}

// MatchDevice is a device with its software, for the matcher of findings.
type MatchDevice struct {
	ID    string
	Name  string // DisplayName, else the id
	OS    string // the current operating system ("Ubuntu 26.04.1 LTS", LLDP "JUNOS 15.1R7.9"), "" when unknown
	Model string // the current model ("EX4200-48T"), "" when unknown (the Juniper series of a Junos flaw)
	// StatedOS is the newest OS the device states itself (an LLDP or SNMP system description, source passive or snmp),
	// even when nmap's guess won OS; "" when none.
	StatedOS string
	// AgentOS is the newest OS the device's own agent reports (source agent: osquery, Wazuh, the box's own reading), even when a
	// person's value won OS; "" when no agent reported one (the platform of an agent's software rows, findings INV-16).
	AgentOS string
	// SNMPOS is the newest OS the device stated to Vedette's own SNMP read of its address (source snmp), "" when none (unlike
	// LLDP, which any host can send with another device's MAC).
	SNMPOS string
	// StatedOSAt and SNMPOSAt are when the device last stated StatedOS and SNMPOS (the observation's seen_at, RFC 3339), "" when none:
	// findings says when the device gave the version of its network OS.
	StatedOSAt, SNMPOSAt string
	// MAC is the device's MAC when it has an IP (the MAC it answers with at that address), "" otherwise: findings reads its OUI before an
	// LLDP statement of Junos counts for the device's scan-seen rows.
	MAC string
	// ManualOS is the OS a person set on the device (INV-41), "" when none: findings reads it as the platform of every row.
	ManualOS string
	Software []MatchSoftware
	// OSCorrection names a person's corrected OS for the findings history ("it@acme.example set the OS to Alpine Linux 3.23 on 17 Nov
	// 2026", INV-41); "" when none.
	OSCorrection string
	// StaleCorrections is nil: a person's entry holds or lapses (INV-52), it never rests. Kept for the findings port.
	StaleCorrections []string
	// NotInstalled are the lines a person said are not installed on the device (INV-41 (6)): matching leaves them out (they are not in
	// Software), and findings closes the open findings only they produce. Each is the line as its strongest source reads it, with
	// Correction naming the person ("op@example.com said OpenSSH 10.2 (nmap) is not installed on 17 Nov 2026"); nil when none.
	NotInstalled []MatchSoftware
}

// MatchInput returns the device with its software; ok is false when it does not exist or a person ignored it (an ignored
// device is outside every vulnerability reader, so nothing new is matched for it).
func (s *Service) MatchInput(ctx context.Context, id string) (d MatchDevice, ok bool, err error) {
	return s.matchInput(ctx, s.db.Reader(), id, nil)
}

// matchInput is MatchInput over q (a transaction sees what it wrote). detectedOS, when set, is the OS the sources read in place of the
// stored one: the declared OS is decided from it, before it is stored.
func (s *Service) matchInput(ctx context.Context, q querier, id string, detectedOS *string) (d MatchDevice, ok bool, err error) {
	loc := orgtime.At(ctx, s.zone)
	var ignored bool
	if err := q.QueryRowContext(ctx, `SELECT ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).Scan(&ignored); errors.Is(err, sql.ErrNoRows) || ignored {
		return MatchDevice{}, false, nil
	} else if err != nil {
		return MatchDevice{}, false, fmt.Errorf("inventory: read device: %w", err)
	}
	d = MatchDevice{ID: id, Name: deviceName(ctx, q, id), Software: []MatchSoftware{}}
	var osName, model, mac sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT os, model, CASE WHEN ip IS NOT NULL THEN mac END FROM inv_asset WHERE id = ?`, id).Scan(&osName, &model, &mac); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return MatchDevice{}, false, fmt.Errorf("inventory: read device OS: %w", err)
	}
	d.OS, d.Model, d.MAC = osName.String, model.String, mac.String
	if detectedOS != nil {
		d.OS = *detectedOS
	}
	if d.StatedOS, d.StatedOSAt, err = statedOSAt(ctx, q, id); err != nil {
		return MatchDevice{}, false, err
	}
	if d.AgentOS, err = osFrom(ctx, q, id, "agent"); err != nil {
		return MatchDevice{}, false, err
	}
	if d.SNMPOS, d.SNMPOSAt, err = osFromAt(ctx, q, id, "snmp"); err != nil {
		return MatchDevice{}, false, err
	}
	// A person's OS (INV-41) is what the device runs for every reading the matcher takes: the agent's, SNMP's and LLDP's statements it
	// corrects say the person's value while it stands. A reading the device never gave stays "" (an agent row needs an agent).
	if v, at, by, ok, err := manualOS(ctx, q, id); err != nil {
		return MatchDevice{}, false, err
	} else if ok {
		d.ManualOS = v
		d.OSCorrection = cmp.Or(by, "a person") + " set the OS to " + v + " on " + correctionDay(at, loc)
		for _, r := range []*string{&d.StatedOS, &d.AgentOS, &d.SNMPOS} {
			if *r != "" {
				*r = v
			}
		}
	}
	if d.Software, d.NotInstalled, err = matchSoftware(ctx, q, id, loc); err != nil {
		return MatchDevice{}, false, err
	}
	return d, true, nil
}

// matchSoftware reads what the matcher compares of a device: each present line's effective reading, then every other reading
// Resolve keeps for matching (an older second install, another port: the line's id, the reading's version and source); and the
// lines a person said are not installed, for MatchDevice.NotInstalled.
func matchSoftware(ctx context.Context, q querier, id string, loc *time.Location) (live, notInstalled []MatchSoftware, err error) {
	rows, err := q.QueryContext(ctx, `SELECT s.id, s.vendor, s.product, s.product_key, s.state, ifnull(s.not_installed_by, ''), ifnull(s.not_installed_at, ''),
		`+guessLine+`, `+readingCols+`
		FROM inv_software s JOIN inv_software_reading r ON r.software_id = s.id
		WHERE s.asset_id = ? AND (`+liveSW+` OR `+notInstalledSW+`) ORDER BY s.display, s.id, r.source, r.instance`, id)
	if err != nil {
		return nil, nil, fmt.Errorf("inventory: read software: %w", err)
	}
	type line struct {
		id, vendor, product, key, state, markedBy, markedAt string
		guess                                               bool
		readings                                            []Reading
	}
	var lines []*line
	for rows.Next() {
		var l line
		var r Reading
		if err := rows.Scan(&l.id, &l.vendor, &l.product, &l.key, &l.state, &l.markedBy, &l.markedAt, &l.guess,
			&r.Source, &r.Instance, &r.Display, &r.Version, &r.PkgVersion, &r.PkgSource, &r.CPE, &r.SetBy, &r.Packaged, &r.Confidence, &r.FirstSeen, &r.SeenAt); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("inventory: read software: %w", err)
		}
		if n := len(lines); n > 0 && lines[n-1].id == l.id {
			lines[n-1].readings = append(lines[n-1].readings, r)
			continue
		}
		l.readings = []Reading{r}
		lines = append(lines, &l)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, nil, fmt.Errorf("inventory: read software: %w", err)
	}
	live = []MatchSoftware{}
	for _, l := range lines {
		res := Resolve(LineState{State: statePresent}, l.readings)
		keys := matchKeys(l.key, l.guess)
		row := func(r Reading) MatchSoftware {
			return MatchSoftware{ID: l.id, Display: r.Display, Vendor: l.vendor, Product: l.product, Version: r.Version, CPE: r.CPE, KevKeys: slices.Clone(keys),
				Source: sourceClass(r.Source), Packaged: r.Packaged, PkgVersion: r.PkgVersion, PkgSource: r.PkgSource, Key: l.id, SeenAt: r.SeenAt,
				Guess: r.guess()}
		}
		entry, det := entryOf(l.readings), detectedOf(l.readings)
		if l.state == stateNotInstalled {
			base := res.Effective
			if det != nil {
				base = *det
			}
			sw := row(base)
			sw.MarkedAt, sw.MarkedBy = l.markedAt, l.markedBy
			sw.Correction = correctionNote(entry, det, base.Display, l.markedBy, l.markedAt, true, loc)
			notInstalled = append(notInstalled, sw)
			continue
		}
		sw := row(res.Effective)
		if res.Effective.entry() && det != nil {
			sw.Correction = correctionNote(entry, det, entry.Display, entry.SetBy, entry.FirstSeen, false, loc)
			sw.ReportedSource = sourceClass(det.Source) // the product its source reads: that source's distribution and platform rules hold
		}
		live = append(live, sw)
		for _, r := range res.Matched {
			o := row(r)
			o.Key = l.id + "\x1f" + r.Source + "\x1f" + r.Instance
			live = append(live, o)
		}
	}
	return live, notInstalled, nil
}

// statedOS is the newest OS observation of the device from its own statement (LLDP, SNMP: sources passive and snmp).
func statedOS(ctx context.Context, q querier, id string) (string, error) {
	v, _, err := statedOSAt(ctx, q, id)
	return v, err
}

// statedOSAt is statedOS with the time of that observation ("" when none).
func statedOSAt(ctx context.Context, q querier, id string) (v, at string, err error) {
	err = q.QueryRowContext(ctx, `SELECT value, seen_at FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source IN ('passive', 'snmp')
		ORDER BY seen_at DESC, id DESC LIMIT 1`, id).Scan(&v, &at)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("inventory: read the stated OS: %w", err)
	}
	return v, at, nil
}

// osFrom is the newest OS observation of the device from one source (agent: its own agent; snmp: Vedette's SNMP read of its address).
func osFrom(ctx context.Context, q querier, id, source string) (string, error) {
	v, _, err := osFromAt(ctx, q, id, source)
	return v, err
}

// osFromAt is osFrom with the time of that observation ("" when none).
func osFromAt(ctx context.Context, q querier, id, source string) (v, at string, err error) {
	err = q.QueryRowContext(ctx, `SELECT value, seen_at FROM inv_observation WHERE asset_id = ? AND field = 'os' AND source = ?
		ORDER BY seen_at DESC, id DESC LIMIT 1`, id, source).Scan(&v, &at)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", "", fmt.Errorf("inventory: read the %s OS: %w", source, err)
	}
	return v, at, nil
}

// matchView is what the findings matcher reads of a device besides its software: folded OS, model, stated OS, the agent's and
// SNMP's OS, and the MAC at its address.
func matchView(ctx context.Context, q querier, id string) (string, error) {
	var osName, model, mac sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT os, model, CASE WHEN ip IS NOT NULL THEN mac END FROM inv_asset WHERE id = ?`, id).Scan(&osName, &model, &mac); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("inventory: read device OS: %w", err)
	}
	stated, err := statedOS(ctx, q, id)
	if err != nil {
		return "", err
	}
	agent, err := osFrom(ctx, q, id, "agent")
	if err != nil {
		return "", err
	}
	snmp, err := osFrom(ctx, q, id, "snmp")
	return osName.String + "\x00" + model.String + "\x00" + stated + "\x00" + agent + "\x00" + snmp + "\x00" + mac.String, err
}

// HasDevice reports whether the inventory has a device of one of these kinds whose vendor (the device's own
// or that of one of its software rows) is the given one, compared without case.
func (s *Service) HasDevice(ctx context.Context, kinds []string, vendor string) (bool, error) {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	kinds = devicetypes.ActingAs(kinds) // every type that acts as one of the kinds
	if vendor == "" || len(kinds) == 0 {
		return false, nil
	}
	args := make([]any, 0, len(kinds)+2)
	for _, k := range kinds {
		args = append(args, k)
	}
	args = append(args, vendor, vendor)
	var n int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_asset a WHERE a.kind IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`)
		AND (lower(a.vendor) = ? OR EXISTS (SELECT 1 FROM inv_software s WHERE s.asset_id = a.id AND lower(s.vendor) = ? AND s.state <> 'removed' AND NOT `+hiddenGuess+`))`, args...).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("inventory: read vendors: %w", err)
	}
	return n > 0, nil
}

// KindDevice is a device of one of the kinds asked for in DevicesOfKind: who it is and the addresses it answers on.
type KindDevice struct {
	ID       string
	Hostname *string
	UserName *string // the name a person gave the device in Vedette; nil = none
	IP       string  // "—" when unknown, like the API
	MAC      *string // lower case aa:bb:cc:dd:ee:ff
	Kind     string
	// Approved: a person approved the device. KindSource is the source of the observation the kind came from ("" when the kind
	// has none: the default unknown). Passive-only kinds (SSDP, LLDP, DHCP, mDNS) are self-announced hints: see TrustedKind.
	Approved   bool
	KindSource string
}

// TrustedKind says whether the kind may feed a safety list (the never-touch gateways): a person or an agent set it, or the
// device is approved and SNMP or nmap set it. A kind that only a passive frame claimed (SSDP, LLDP, DHCP, mDNS) is a hint any host on
// the wire can send; nmap runs in the untrusted scan container and its guess is shaped by the target (an SSDP claim earns the host an -O
// scan, and a drop box answers like a router), so an unapproved device's nmap or snmp kind is not enough either. An approved device
// whose kind is still a passive frame's claim is not trusted: the operator vouches for it by picking its kind by hand.
func (d KindDevice) TrustedKind() bool {
	switch d.KindSource {
	case "manual", "agent":
		return true
	case "snmp", "nmap":
		return d.Approved
	}
	return false
}

// AssetIDs returns the id of every device, with no kind filter and no row cap, ordered by id: the list a reconcile compares
// against (findings), so a device of any kind, even one added to the schema later, is never missing. Any read error is
// returned and the caller must fail closed: a short list would make the caller drop data of devices that still exist. A device a
// person ignored is left out: every caller reads vulnerabilities (findings, the plan, the distribution feeds), and an ignored
// device has none.
func (s *Service) AssetIDs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id FROM inv_asset WHERE ignored_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read device ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: read device ids: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read device ids: %w", err)
	}
	return out, nil
}

// DevicesOfKind returns every device of the given kinds, with no row cap (Devices stops at MaxListed, newest first, which is the
// wrong read for a safety list: the oldest device, usually the gateway, would be the one cut). Read-only, ordered by id. An empty
// kinds is an empty answer. Any read error is returned and the caller must fail closed: a short list is never a valid answer.
func (s *Service) DevicesOfKind(ctx context.Context, kinds []string) ([]KindDevice, error) {
	kinds = devicetypes.ActingAs(kinds) // every type that acts as one of the kinds: a VPN gateway is a firewall, a modem a router
	if len(kinds) == 0 {
		return nil, nil
	}
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.user_name, a.ip, a.mac, a.kind, a.approved, o.source FROM inv_asset a LEFT JOIN inv_observation o ON o.id = a.kind_obs_id WHERE a.kind IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`) ORDER BY a.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []KindDevice
	for rows.Next() {
		var d KindDevice
		var host, userName, ip, mac, src sql.NullString
		if err := rows.Scan(&d.ID, &host, &userName, &ip, &mac, &d.Kind, &d.Approved, &src); err != nil {
			return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
		}
		d.Hostname, d.UserName, d.MAC, d.IP, d.KindSource = ptr(host), ptr(userName), ptr(mac), noIP, src.String
		if ip.Valid {
			d.IP = ip.String
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read devices of a kind: %w", err)
	}
	return s.trustedKindUnion(ctx, kinds, out)
}

// trustedKindUnion is the union guard of the never-touch list (INV-20): a device is listed as one of the kinds while ANY trusted
// machine observation (agent, or snmp or nmap on an approved device) says so, whatever its current kind, except those older than a
// person's latest kind: a person's explicit choice wins (it is the current kind, manual ranks first), so a person can take a wrongly
// typed device off the list, and a machine observation seen after that choice puts it back (#715). A source that ranks higher can
// change the current kind (SNMP outranks nmap, DATA_MODEL 5.1), but it can only ever add a device to the list, never take one off it: an
// on-path host answering a router's SNMP read as a printer does not make the router blockable. A device whose current kind is in kinds
// but not trusted gets the trusted observation's kind and source; a device whose current kind is another one is added with them.
func (s *Service) trustedKindUnion(ctx context.Context, kinds []string, out []KindDevice) ([]KindDevice, error) {
	args := make([]any, len(kinds))
	for i, k := range kinds {
		args[i] = k
	}
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT a.id, a.hostname, a.user_name, a.ip, a.mac, a.approved, o.value, o.source FROM inv_asset a JOIN inv_observation o ON o.asset_id = a.id
		WHERE o.field = 'kind' AND o.value IN (?`+strings.Repeat(`, ?`, len(kinds)-1)+`) AND (o.source = 'agent' OR (o.source IN ('snmp', 'nmap') AND a.approved = 1))
		AND o.seen_at > coalesce((SELECT max(m.seen_at) FROM inv_observation m WHERE m.asset_id = a.id AND m.field = 'kind' AND m.source = 'manual'), '')
		ORDER BY a.id, CASE o.source WHEN 'agent' THEN 1 WHEN 'snmp' THEN 2 ELSE 3 END, o.seen_at DESC`, args...) // only "?" placeholders are concatenated; the kinds are bound
	if err != nil {
		return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
	}
	defer func() { _ = rows.Close() }()
	at := make(map[string]int, len(out))
	for i, d := range out {
		at[d.ID] = i
	}
	added := false
	for rows.Next() {
		var d KindDevice
		var host, userName, ip, mac sql.NullString
		if err := rows.Scan(&d.ID, &host, &userName, &ip, &mac, &d.Approved, &d.Kind, &d.KindSource); err != nil {
			return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
		}
		i, listed := at[d.ID]
		switch {
		case listed && out[i].TrustedKind():
		case listed:
			out[i].Kind, out[i].KindSource = d.Kind, d.KindSource
		default:
			d.Hostname, d.UserName, d.MAC, d.IP = ptr(host), ptr(userName), ptr(mac), noIP
			if ip.Valid {
				d.IP = ip.String
			}
			at[d.ID] = len(out)
			out = append(out, d)
			added = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read trusted kinds: %w", err)
	}
	if added {
		slices.SortFunc(out, func(a, b KindDevice) int { return strings.Compare(a.ID, b.ID) })
	}
	return out, nil
}

// AddressInUse says whether a device other than the box has the address: an indexed read (inv_asset_ip_uq), with no row cap
// (Devices stops at MaxListed and would forget the oldest device). A read error is returned and the caller must fail closed.
func (s *Service) AddressInUse(ctx context.Context, ip string) (bool, error) {
	var n int
	if err := s.db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE ip = ? AND is_box = 0`, ip).Scan(&n); err != nil {
		return false, fmt.Errorf("inventory: read address: %w", err)
	}
	return n > 0, nil
}

// KnownMACs returns the MAC of every device that has one, with no row cap: the sensor's new-device budget counts a device
// absent from it as new, so a capped list would make old devices eat the budget of real new ones. Lower case, ordered; a read error is
// returned, never a short list.
func (s *Service) KnownMACs(ctx context.Context) ([]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT mac FROM inv_asset WHERE mac IS NOT NULL ORDER BY mac`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read macs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("inventory: read macs: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read macs: %w", err)
	}
	return out, nil
}

// AddressMap returns the device id of every IP the inventory knows, with no row cap. Read error: returned, never a short map.
func (s *Service) AddressMap(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT ip, id FROM inv_asset WHERE ip IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read addresses: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var ip, id string
		if err := rows.Scan(&ip, &id); err != nil {
			return nil, fmt.Errorf("inventory: read addresses: %w", err)
		}
		out[ip] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: read addresses: %w", err)
	}
	return out, nil
}

// BoxName returns the host name and IP of the box device ("" when it has none; ok false when there is no box row yet): a direct read of
// the one row, where Devices would load up to MaxListed devices to find it.
func (s *Service) BoxName(ctx context.Context) (hostname, ip string, ok bool, err error) {
	var h, i sql.NullString
	err = s.db.Reader().QueryRowContext(ctx, `SELECT hostname, ip FROM inv_asset WHERE is_box = 1`).Scan(&h, &i)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	} else if err != nil {
		return "", "", false, fmt.Errorf("inventory: read box: %w", err)
	}
	return h.String, i.String, true, nil
}

// AllDevices lists every device with no row cap, for readers that must see them all (the honeypot's conflict and spare-IP
// checks). Devices is the capped list of the API.
// ponytail: loads software and services of every device; fine to about 1,000 devices, about 100-300 ms per call at 10k-50k. Upgrade
// path: a narrow read (id, IP, hostname, kind, approved, is_box, OS, ports) with no software.
func (s *Service) AllDevices(ctx context.Context) ([]Device, error) {
	return s.loadDevices(ctx, s.db.Reader(), "", 0)
}

// ProductQuery is a vendor and product pair of KEV.
type ProductQuery struct{ Vendor, Product string }

// Key is the matching key (lower(vendor)|lower(product)) of the pair.
func (p ProductQuery) Key() string { return productid.Key(p.Vendor, p.Product) }

// DeviceMatch is a device that runs a product (Exact) or may run it (a "Multiple products" entry that only
// the vendor matches).
type DeviceMatch struct {
	DeviceRef
	Exact bool
}

const multiProducts = "multiple products"

// DevicesRunning finds, for each product, the devices that run it. The map is keyed by ProductQuery.Key();
// a product with no device has no entry. A normal product matches the devices with a software row carrying
// its key. A "Multiple products" entry matches exactly only a software row declared with that product (the
// "I have it" device); a device that has any software of the vendor, or that the vendor made, matches by
// vendor only. Display is the software row that matched (not the device's first row by name, "3cpio" on
// an Ubuntu box whose OpenSSH matched); when only its maker matched, DeviceRefs' display (first row by name, else the kind).
// A device a person ignored runs nothing here.
func (s *Service) DevicesRunning(ctx context.Context, products []ProductQuery) (map[string][]DeviceMatch, error) {
	out := map[string][]DeviceMatch{}
	var ignored map[string]bool
	var lines []keyedLine
	for _, p := range products {
		key := p.Key()
		if _, done := out[key]; done {
			continue
		}
		if lines == nil {
			var err error
			if lines, err = s.keyedLines(ctx); err != nil {
				return nil, err
			}
		}
		vendor, product := strings.ToLower(p.Vendor), strings.ToLower(p.Product)
		multi := strings.TrimSpace(product) == multiProducts
		prefix := productid.Key(p.Vendor, "")
		shown := map[string]string{}
		var exact, byVendor []string
		for _, l := range lines {
			hit, vendorHit := false, false
			for _, k := range l.keys {
				hit = hit || k == key && (!multi || l.product == product)
				vendorHit = vendorHit || multi && strings.HasPrefix(k, prefix)
			}
			switch {
			case hit: // an exact match names its own line before a vendor-only one
				if !slices.Contains(exact, l.assetID) {
					exact = append(exact, l.assetID)
					delete(shown, l.assetID)
				}
			case vendorHit && !slices.Contains(exact, l.assetID):
				if !slices.Contains(byVendor, l.assetID) {
					byVendor = append(byVendor, l.assetID)
				}
			default:
				continue
			}
			if d, ok := shown[l.assetID]; !ok || l.display < d {
				shown[l.assetID] = l.display
			}
		}
		byVendor = slices.DeleteFunc(byVendor, func(id string) bool { return slices.Contains(exact, id) })
		if multi {
			makers, err := s.assetIDs(ctx, `SELECT id FROM inv_asset WHERE lower(vendor) = ?`, vendor)
			if err != nil {
				return nil, err
			}
			for _, id := range makers {
				if !slices.Contains(byVendor, id) {
					byVendor = append(byVendor, id)
				}
			}
		}
		refs, err := s.DeviceRefs(ctx, slices.Concat(exact, byVendor))
		if err != nil {
			return nil, err
		}
		if ignored == nil {
			if ignored, err = s.ignoredIDs(ctx); err != nil {
				return nil, err
			}
		}
		var list []DeviceMatch
		for _, id := range slices.Concat(exact, byVendor) {
			if ignored[id] {
				continue // An ignored device does not answer "Do you have it?"
			}
			if r, ok := refs[id]; ok {
				if d, ok := shown[id]; ok {
					r.Display = d
				}
				list = append(list, DeviceMatch{DeviceRef: r, Exact: slices.Contains(exact, id)})
				delete(refs, id) // a device once, the exact answer first
			}
		}
		if len(list) > 0 {
			out[key] = list
		}
	}
	return out, nil
}

// keyedLine is a software line that counts for matching (liveSW) with its match keys.
type keyedLine struct {
	assetID, product, display string // product lower case
	keys                      []string
}

// keyedLines reads every software line that counts for matching, with its match keys (matchKeys), ordered by device.
func (s *Service) keyedLines(ctx context.Context) ([]keyedLine, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT s.asset_id, lower(s.product), s.display, s.product_key, `+guessLine+` FROM inv_software s WHERE `+liveSW+` ORDER BY s.asset_id, s.display`)
	if err != nil {
		return nil, fmt.Errorf("inventory: read match keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []keyedLine{}
	for rows.Next() {
		var l keyedLine
		var key string
		var guess bool
		if err := rows.Scan(&l.assetID, &l.product, &l.display, &key, &guess); err != nil {
			return nil, fmt.Errorf("inventory: read match keys: %w", err)
		}
		if l.keys = matchKeys(key, guess); len(l.keys) > 0 {
			out = append(out, l)
		}
	}
	return out, rows.Err()
}

// IgnoredIDs lists the devices a person ignored, ordered by id, no cap; a read error is an error, never a short list. findings'
// reconcile closes their open findings and keeps their findings out of the orphan pass (#945).
func (s *Service) IgnoredIDs(ctx context.Context) ([]string, error) {
	return ReadIgnoredIDs(ctx, s.db.Reader())
}

// ReadIgnoredIDs is IgnoredIDs on a handle of the box's database, for a reader without the service: the selfcheck of findings'
// urgency layers runs on its own read-only handle and leaves the ignored devices out, as the urgency pass does.
func ReadIgnoredIDs(ctx context.Context, q *sql.DB) ([]string, error) {
	return readIDs(ctx, q, `SELECT id FROM inv_asset WHERE ignored_at IS NOT NULL`)
}

// IsIgnored says whether a person ignored the device; false for a device that does not exist. findings asks it inside its
// write, so a match or a scan result that raced an Ignore never opens a finding on the ignored device (#945).
func (s *Service) IsIgnored(ctx context.Context, id string) (bool, error) {
	var ignored bool
	err := s.db.Reader().QueryRowContext(ctx, `SELECT ignored_at IS NOT NULL FROM inv_asset WHERE id = ?`, id).Scan(&ignored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inventory: read device: %w", err)
	}
	return ignored, nil
}

// ignoredIDs is the set of devices a person ignored.
func (s *Service) ignoredIDs(ctx context.Context) (map[string]bool, error) {
	ids, err := s.assetIDs(ctx, `SELECT id FROM inv_asset WHERE ignored_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

func (s *Service) assetIDs(ctx context.Context, query string, args ...any) ([]string, error) {
	return readIDs(ctx, s.db.Reader(), query, args...)
}

func readIDs(ctx context.Context, q *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := q.QueryContext(ctx, query+` ORDER BY 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("inventory: match products: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("inventory: match products: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ManualDevice is the device "I have it" declares (feeds, S-FEED-2): one device that runs the product.
type ManualDevice struct {
	Kind    string // a hint; anything that is not a device kind is ignored
	Vendor  string
	Product string
	Display string // the name people recognise; empty keeps "vendor product"
	Key     string // lower(vendor)|lower(product), must be that of Vendor and Product
}

// AddManualDevice declares a device inside the caller's write transaction tx (INV-14): the device, its
// software, the audit row and the events are the caller's one commit. It applies every check of AddDevice (a
// product from the catalog or typed by hand, the same length and character rules). The one difference: a
// vendor and product that are an exact pair of the KEV list may be longer than 64 characters, because that is
// data from the CISA list, not something a person typed. The events are kept until the caller calls Settle. It returns
// the new device's id: feeds scopes "I have this" to that one device.
func (s *Service) AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, in ManualDevice) (string, error) {
	if in.Key != productid.Key(in.Vendor, in.Product) {
		return "", badRequest("bad_product", "The product key does not match the vendor and product.")
	}
	c, err := s.Catalog(ctx)
	if err != nil {
		return "", err
	}
	a, aerr := checkAdd(c, AddInput{Vendor: in.Vendor, Product: in.Product}, true)
	if aerr != nil && aerr.Code == "bad_product" && c.kevCount[in.Key] > 0 && cleanText(strings.TrimSpace(in.Vendor)) && cleanText(strings.TrimSpace(in.Product)) {
		a, aerr = addChecked{entry: c.custom(strings.TrimSpace(in.Vendor), strings.TrimSpace(in.Product))}, nil
	}
	if aerr != nil {
		return "", aerr
	}
	e := *a.entry
	if d := strings.TrimSpace(in.Display); label(d) { // a name with markup or too long is not used; the product's own name stays
		e.display = d
	}
	if r := []rune(e.display); len(r) > maxObsValue { // vendor and product of a KEV pair may add up to more than a column holds
		e.display = string(r[:maxObsValue])
	}
	a.entry = &e
	kind := ""
	if validKind(in.Kind) {
		kind = suggestedKind(in.Kind, a) // feeds' suggestion
	}
	var o outbox
	id, err := s.createManual(ctx, tx, &o, a, kind)
	if err != nil {
		return "", err
	}
	if err := s.auditTx(ctx, tx, actor, "inventory.add_manual", a.entry.display, ""); err != nil {
		return "", err
	}
	s.keep(tx, &o)
	return id, nil
}

// keep holds o's events until Settle(tx) (AddManualDevice, SetupScope); a second call in the same transaction adds to the first.
func (s *Service) keep(tx *sql.Tx, o *outbox) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	if s.pending == nil {
		s.pending = map[*sql.Tx]*outbox{}
	}
	if p := s.pending[tx]; p != nil {
		p.events = append(p.events, o.events...)
		p.after = append(p.after, o.after...)
		return
	}
	s.pending[tx] = o
}

// Settle ends AddManualDevice and SetupScope for tx: when the caller's transaction committed the events go out, when it rolled
// back they are dropped. The caller must call it once it knows which; a transaction with no pending events is
// a no-op.
func (s *Service) Settle(ctx context.Context, tx *sql.Tx, committed bool) {
	s.pendMu.Lock()
	o := s.pending[tx]
	delete(s.pending, tx)
	s.pendMu.Unlock()
	if o == nil || !committed {
		return
	}
	events := o.events
	for _, f := range o.after {
		events = append(events, f(ctx)...)
	}
	s.publish(ctx, events)
}

// RematchAll announces inventory.match.changed once for every device with software keyed to a CISA entry (after
// a baseline pull, or when matching must be recomputed from scratch, e.g. the first NVD fill). The event names
// the device's first CVE; findings matches the whole device on it (one event per device, not per device and
// CVE, so a rematch of hundreds of devices fits its deadline). It returns how many events it published.
func (s *Service) RematchAll(ctx context.Context) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	lines, err := s.keyedLines(ctx)
	if err != nil {
		return 0, err
	}
	keys := map[string][]string{}
	var order []string
	for _, l := range lines {
		if _, ok := keys[l.assetID]; !ok {
			order = append(order, l.assetID)
		}
		keys[l.assetID] = append(keys[l.assetID], l.keys...)
	}
	for id, k := range keys {
		slices.Sort(k)
		keys[id] = slices.Compact(k)
	}
	lookup, err := s.kevIndex(ctx) // one read of the lists for every device
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range order {
		cves := lookup(keys[id])
		if len(cves) == 0 {
			continue
		}
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: slices.Min(cves), Basis: "product"}}})
		n++
	}
	return n, nil
}

// KevRef names a CISA entry by its CVE and its vendor and product.
type KevRef struct{ CVE, Vendor, Product string }

// RematchMany announces inventory.match.changed once for every device that runs the product of one of refs (a
// "Multiple products" entry: any product of its vendor), naming the first such CVE. After an NVD
// update of a few CVEs only their devices are matched again, each once. It returns how many events it published.
func (s *Service) RematchMany(ctx context.Context, refs []KevRef) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	first := map[string]string{}
	var order []string
	lines, err := s.keyedLines(ctx)
	if err != nil {
		return 0, err
	}
	for _, r := range refs {
		for _, id := range devicesIn(lines, r.Vendor, r.Product) {
			if c, ok := first[id]; !ok || r.CVE < c {
				if !ok {
					order = append(order, id)
				}
				first[id] = r.CVE
			}
		}
	}
	for _, id := range order {
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: first[id], Basis: "product"}}})
	}
	return len(order), nil
}

// devicesOf lists the devices with software keyed to vendor|product, or to any product of vendor for "Multiple products".
func (s *Service) devicesOf(ctx context.Context, vendor, product string) ([]string, error) {
	lines, err := s.keyedLines(ctx)
	if err != nil {
		return nil, err
	}
	return devicesIn(lines, vendor, product), nil
}

// devicesIn is devicesOf over lines already read.
func devicesIn(lines []keyedLine, vendor, product string) []string {
	prefix := productid.Key(vendor, "")
	multi := strings.EqualFold(strings.TrimSpace(product), multiProducts)
	exact, multiKey := productid.Key(vendor, product), productid.Key(vendor, multiProducts)
	var out []string
	for _, l := range lines {
		if slices.ContainsFunc(l.keys, func(k string) bool { return k == exact || k == multiKey || multi && strings.HasPrefix(k, prefix) }) && !slices.Contains(out, l.assetID) {
			out = append(out, l.assetID)
		}
	}
	return out
}

// RematchCVE announces inventory.match.changed for the devices that run the product of a CVE feeds has just
// listed (feeds.vuln.new_kev). A "Multiple products" entry matches every device with software of the vendor.
func (s *Service) RematchCVE(ctx context.Context, cve, vendor, product string) (int, error) {
	return s.RematchCVEExcept(ctx, cve, vendor, product, nil)
}

// RematchCVEExcept is RematchCVE that leaves out the devices known says already match the CVE (a CVE whose vendor or product
// changed is announced to the devices of its new product that have no finding for it, so a flag that changed on hundreds of entries does
// not announce each device once per entry).
// known returning an error is that error; nil known leaves nobody out.
func (s *Service) RematchCVEExcept(ctx context.Context, cve, vendor, product string, known func(ctx context.Context, assetID, cve string) (bool, error)) (int, error) {
	if s.kev == nil {
		return 0, nil
	}
	ids, err := s.devicesOf(ctx, vendor, product)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if known != nil {
			has, err := known(ctx, id, cve)
			if err != nil {
				return n, err
			}
			if has {
				continue
			}
		}
		s.publish(ctx, []Event{{Name: EventMatchChanged, Data: MatchEvent{AssetID: id, CVE: cve, Basis: "product"}}})
		n++
	}
	return n, nil
}

// LineRef is a software line as a list of findings names it: its device, display name, the version it runs now and its product.
type LineRef struct {
	ID, AssetID, Display, ProductKey string
	Version                          string // "" when the line has no version
}

// LineRefs returns the software lines with these ids, in any state (a finding keeps naming a line that was removed); unknown ids are
// absent. findings reads it to name the line of each finding in its lists and to search them by software name.
func (s *Service) LineRefs(ctx context.Context, ids []string) (map[string]LineRef, error) {
	out := make(map[string]LineRef, len(ids))
	for chunk := range slices.Chunk(ids, 400) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, asset_id, display, product_key, ifnull(version, '') FROM inv_software
			WHERE id IN (?`+strings.Repeat(`, ?`, len(chunk)-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("inventory: read software lines: %w", err)
		}
		for rows.Next() {
			var l LineRef
			if err := rows.Scan(&l.ID, &l.AssetID, &l.Display, &l.ProductKey, &l.Version); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("inventory: read software lines: %w", err)
			}
			out[l.ID] = l
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, fmt.Errorf("inventory: read software lines: %w", err)
		}
	}
	return out, nil
}
