package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/productid"
	"github.com/knt048/vedette/core/store"
)

// What a person declared is what the device is, where the matcher reads it so (INV-45). A device added by hand as "FortiGate,
// FortiOS v7.2.13" has that row on its Software tab, and findings decide on it ("runs FortiGate v7.2.13 (entered on the Devices
// page)"), but no observation says its OS or model: the Overview, the list and the export said "Not known yet". A live software row a
// person declared of a product the catalog marks as a whole operating system or firmware (curated.json "os": true, or a row of
// network-os.json) is a candidate; which candidate, if any, is the device's OS is the matcher's choice (Config.DeclaredOS =
// findings.DeclaredOSRow), never a second rule here: the page shows the OS findings are decided on. On top of it:
//   - the OS a person typed in the OS field (INV-41) stays the device's OS;
//   - a row without a version fills only an OS no source gives, or one a scan only guesses: it never hides a version a source read;
//   - without the matcher (Config.DeclaredOS nil) a candidate fills only an OS no source gives.

// osProduct is a product the catalog marks as a whole OS or firmware.
type osProduct struct {
	model string // the hardware line the catalog names it after ("FortiGate" for FortiOS), "" when its name is the OS's own
}

// osProducts are keyed by osKey; modelProducts maps each model to the keys of the products named after it (the Devices search).
var osProducts, modelProducts = func() (map[string]osProduct, map[string][]string) {
	out, models := map[string]osProduct{}, map[string][]string{}
	var curated []struct {
		Display, Kind, Vendor, Product string
		OS                             bool `json:"os"`
	}
	if err := json.Unmarshal(catalogdata.Curated, &curated); err != nil {
		panic(fmt.Sprintf("inventory: curated.json: %v", err)) // embedded data, read by NewCatalog's tests too
	}
	for _, r := range curated {
		if !r.OS {
			continue
		}
		p := osProduct{}
		// An appliance's OS listed under the appliance's name ("FortiGate" for FortiOS) names its model; a name that holds the OS's
		// own ("Juniper Junos OS", "Windows 11") does not.
		if appliance(r.Kind) && !strings.Contains(fold(r.Display), fold(r.Product)) {
			p.model = r.Display
			models[r.Display] = append(models[r.Display], productid.Key(r.Vendor, r.Product))
		}
		out[productid.Key(r.Vendor, r.Product)] = p
	}
	var netOS struct {
		OS []struct{ Vendor, Product string } `json:"os"`
	}
	if err := json.Unmarshal(catalogdata.NetworkOS, &netOS); err != nil {
		panic(fmt.Sprintf("inventory: network-os.json: %v", err))
	}
	for _, r := range netOS.OS {
		if _, ok := out[productid.Key(r.Vendor, r.Product)]; !ok {
			out[productid.Key(r.Vendor, r.Product)] = osProduct{}
		}
	}
	return out, models
}()

// osKeys are the keys of osProducts, sorted: the products a declared line may be of.
var osKeys = slices.Sorted(maps.Keys(osProducts))

// appliance says whether a catalog kind is a box whose product is the device itself (not a computer that runs it).
func appliance(kind string) bool {
	switch devicetypes.ActsAs(kind) {
	case "pc", "server", "web", "iot", "unknown":
		return false
	}
	return true
}

// declaredCandidates are the rows of sw a person declared of an OS product, live and installed, the newest first.
func declaredCandidates(sw []Software) []*Software {
	var out []*Software
	for i := range sw {
		s := &sw[i]
		if s.Source != "manual" || !s.live || s.NotInstalled {
			continue
		}
		if _, ok := osProducts[productid.Key(s.Vendor, s.Product)]; ok {
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, func(a, b *Software) int {
		if c := strings.Compare(b.seenAt, a.seenAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// outranking says whether a source the matcher may prefer to a declared row reads the device: an OS from SNMP, a passive frame (its
// LLDP statement) or the agent, or a row of the agent (its Windows release row covers a person's Windows row). Only then is the
// matcher asked; otherwise it keeps the newest candidate, as findings.DeclaredOSRow would.
func outranking(d *Device) bool {
	if d.OS != nil && (d.OS.Source == "snmp" || d.OS.Source == "passive" || d.OS.Source == "agent") {
		return true
	}
	return slices.ContainsFunc(d.Software, func(sw Software) bool { return sw.Source == "agent" })
}

// declaredEvidence marks the stored OS observation a declared row decided: an observation of source manual whose evidence is
// declaredEvidence + the software line's id. A person's own OS carries the person's name as evidence instead, so the two never mix.
const declaredEvidence = "declared:"

// declaredObsSQL is the condition on inv_observation rows that are such a stored decision.
const declaredObsSQL = `(field = 'os' AND source = 'manual' AND substr(ifnull(evidence, ''), 1, 9) = 'declared:')`

// declaredRow is the software line a stored OS came from: the id after declaredEvidence when source and evidence say a declared row
// decided it, "" otherwise.
func declaredRow(source, evidence string) string {
	if source != "manual" || !strings.HasPrefix(evidence, declaredEvidence) {
		return ""
	}
	return strings.TrimPrefix(evidence, declaredEvidence)
}

// declaredChoice is the declared row that is the device's OS, with the OS text it gives; nil when none (INV-45). detected is what
// the sources read (the winner of the OS field without a declared row), nil when none read one. The matcher chooses among the
// candidates (Config.DeclaredOS) once a source it may prefer reads the device; without a matcher a candidate fills only an OS no
// source gives. The choice is stored by recomputeColumns; nothing reads it again at read time.
func (s *Service) declaredChoice(ctx context.Context, tx *sql.Tx, id string, detected *Observed) (*Software, string, error) {
	if _, _, _, typed, err := manualOS(ctx, tx, id); err != nil || typed {
		return nil, "", err // the person typed the OS
	}
	lines, err := declaredLines(ctx, tx, id, osKeys)
	if err != nil || len(lines) == 0 {
		return nil, "", err // no declared row: most devices stop here, without reading their software
	}
	devs := []Device{{Software: []Software{}}}
	devs[0].ID, devs[0].OS = id, detected
	if err := loadSoftware(ctx, tx, `(SELECT ?)`, map[string]int{id: 0}, devs, []any{id}); err != nil {
		return nil, "", err
	}
	d := &devs[0]
	cands := slices.DeleteFunc(declaredCandidates(d.Software), func(c *Software) bool { return !slices.Contains(lines, c.ID) })
	if len(cands) == 0 {
		return nil, "", nil
	}
	var row *Software
	version := ""
	switch {
	case s.declared != nil && outranking(d):
		var os *string
		if detected != nil {
			os = &detected.Value
		} else {
			none := ""
			os = &none
		}
		md, ok, err := s.matchInput(ctx, tx, id, os)
		if err != nil {
			return nil, "", err
		}
		if ok {
			ids := make([]string, len(cands))
			for i, c := range cands {
				ids[i] = c.ID
			}
			chosen, v, err := s.declared(md, ids)
			if err != nil {
				s.log.WarnContext(ctx, "inventory: the matcher could not choose a device's declared OS; it keeps what its sources read", "device", id, "error", err.Error())
				return nil, "", nil
			}
			if i := slices.IndexFunc(cands, func(c *Software) bool { return c.ID == chosen }); i >= 0 {
				row, version = cands[i], v
			}
		}
	case s.declared != nil: // nothing outranks the row: the matcher keeps the newest candidate
		row, version = cands[0], s.osVersion(deref(cands[0].Version))
	}
	if row == nil && detected == nil { // no matcher (or an ignored device): a candidate only fills an empty OS
		row = cands[0]
		version = s.osVersion(deref(row.Version))
	}
	if row == nil || version == "" && detected != nil && detected.Basis != basisGuess {
		return nil, "", nil // a row without a version never hides an OS a source read
	}
	text := strings.TrimSpace(row.Product + " " + version)
	if !osText(text) {
		return nil, "", nil
	}
	return row, text, nil
}

// storeDeclared makes the OS field of a device follow the declared row, in recomputeColumns' transaction: the decision is one
// observation (source manual, evidence declaredEvidence + the row's id), kept while the choice stands and deleted when it does not,
// and it becomes best["os"] so inv_asset.os and os_obs_id hold it. The observation is the row's own reading (its confidence and time).
func (s *Service) storeDeclared(ctx context.Context, tx *sql.Tx, id string, best map[string]obs) error {
	var detected *Observed
	if w, ok := best["os"]; ok {
		mac := ""
		if m, ok := best["mac"]; ok {
			mac = m.value
		}
		detected = &Observed{Value: w.value, Source: w.source, Confidence: w.confidence, SeenAt: w.seenAt, Basis: osBasis(w.value, w.source, mac)}
	}
	row, text, err := s.declaredChoice(ctx, tx, id, detected)
	if err != nil {
		return err
	}
	var have struct{ id, value, seen, evidence string }
	var conf float64
	err = tx.QueryRowContext(ctx, `SELECT id, value, confidence, seen_at, evidence FROM inv_observation WHERE asset_id = ? AND `+declaredObsSQL+` ORDER BY id LIMIT 1`, id).
		Scan(&have.id, &have.value, &conf, &have.seen, &have.evidence)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("inventory: read the declared OS: %w", err)
	}
	if row != nil && have.id != "" && have.value == text && conf == row.Confidence && have.seen == row.seenAt && have.evidence == declaredEvidence+row.ID {
		best["os"] = obs{id: have.id, field: "os", value: text, source: "manual", confidence: conf, seenAt: have.seen}
		return nil
	}
	if have.id != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM inv_observation WHERE asset_id = ? AND `+declaredObsSQL, id); err != nil {
			return fmt.Errorf("inventory: drop the declared OS: %w", err)
		}
	}
	if row == nil {
		return nil
	}
	o := obs{id: store.NewID("o"), field: "os", value: text, source: "manual", confidence: row.Confidence, seenAt: row.seenAt}
	if _, err := tx.ExecContext(ctx, `INSERT INTO inv_observation (id, asset_id, field, value, source, confidence, seen_at, first_seen, evidence) VALUES (?, ?, 'os', ?, 'manual', ?, ?, ?, ?)`,
		o.id, id, o.value, o.confidence, o.seenAt, o.seenAt, declaredEvidence+row.ID); err != nil {
		return fmt.Errorf("inventory: record the declared OS: %w", err)
	}
	best["os"] = o
	return nil
}

// ReconcileDeclaredOS stores the declared-OS decision of the devices that have a declared row and no decision, and drops a decision
// no declared row backs: the devices of a box that ran before the decision was stored. A box that is up to date selects nothing, so
// the job "declared-os-reconcile" costs a query at start-up; a device it cannot store is logged and skipped.
func (s *Service) ReconcileDeclaredOS(ctx context.Context) error {
	ids, err := devicesToDecide(ctx, s.db.Reader(), osKeys)
	if err != nil {
		return err
	}
	for _, id := range ids {
		err := s.write(ctx, func(tx *sql.Tx, o *outbox) error {
			changed, err := s.RecomputeAsset(ctx, tx, id)
			if changed {
				o.add(EventAssetUpdated, AssetEvent{AssetID: id, Match: true})
			}
			return err
		})
		if err != nil { // one device never holds the others back
			s.log.WarnContext(ctx, "inventory: the declared OS of a device could not be stored", "device", id, "error", err.Error())
		}
	}
	return nil
}

// fillDeclaredHardware gives a device whose OS a declared row decided the maker and model that row names, when no source reads them
// (the catalog's line: a FortiOS row is a FortiGate by Fortinet). It reads the stored decision (the OS's software id), never decides
// the OS.
func fillDeclaredHardware(d *Device) {
	if d.OS == nil || d.OS.SoftwareID == "" {
		return
	}
	i := slices.IndexFunc(d.Software, func(s Software) bool { return s.ID == d.OS.SoftwareID })
	if i < 0 {
		return
	}
	row := d.Software[i]
	at := func(v string) *Observed {
		return &Observed{Value: v, Source: "manual", Confidence: d.OS.Confidence, SeenAt: d.OS.SeenAt, SoftwareID: row.ID}
	}
	if m := osProducts[productid.Key(row.Vendor, row.Product)].model; d.Model == nil && m != "" {
		d.Model = at(m)
	}
	if d.Vendor == nil {
		d.Vendor = at(row.Vendor)
	}
}

// osVersion is a declared version as the matcher reads it (Config.OSVersion), trimmed when there is no matcher.
func (s *Service) osVersion(v string) string {
	if s.readVersion != nil {
		return s.readVersion(v)
	}
	return strings.TrimSpace(v)
}

// modelKeys are the product keys of the OS products named after a model that holds q (the Devices search finds a device by the
// model its declared row gives it).
func modelKeys(q string) []string {
	var out []string
	for m, keys := range modelProducts {
		if strings.Contains(fold(m), fold(q)) {
			out = append(out, keys...)
		}
	}
	return out
}
