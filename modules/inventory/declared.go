package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/devicetypes"
	"github.com/knt048/vedette/core/productid"
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

// applyDeclared puts the declared identity on a listed device (INV-45). It never fails the read: when the matcher's view of the
// device cannot be read the device keeps the values its observations give, and the error is logged.
func (s *Service) applyDeclared(ctx context.Context, d *Device) {
	cands := declaredCandidates(d.Software)
	if len(cands) == 0 || d.OS != nil && d.OS.Source == "manual" {
		return // no candidate, or the person typed the OS
	}
	var row *Software
	version := ""
	switch {
	case s.declared != nil && outranking(d):
		md, ok, err := s.MatchInput(ctx, d.ID)
		if err != nil {
			s.log.WarnContext(ctx, "inventory: the matcher's view of a device could not be read; it shows what its sources read", "device", d.ID, "error", err.Error())
			return
		}
		if ok {
			ids := make([]string, len(cands))
			for i, c := range cands {
				ids[i] = c.ID
			}
			id, v, err := s.declared(md, ids)
			if err != nil {
				s.log.WarnContext(ctx, "inventory: the matcher could not choose a device's declared OS; it shows what its sources read", "device", d.ID, "error", err.Error())
				return
			}
			if i := slices.IndexFunc(cands, func(c *Software) bool { return c.ID == id }); i >= 0 {
				row, version = cands[i], v
			}
		}
	case s.declared != nil: // nothing outranks the row: the matcher keeps the newest candidate
		row, version = cands[0], s.osVersion(deref(cands[0].Version))
	}
	if row == nil && d.OS == nil { // no matcher (or an ignored device): a candidate only fills an empty OS
		row = cands[0]
		version = s.osVersion(deref(row.Version))
	}
	if row == nil || version == "" && d.OS != nil && d.OS.Basis != basisGuess {
		return // a row without a version never hides an OS a source read
	}
	at := func(v string) *Observed {
		return &Observed{Value: v, Source: "manual", Confidence: row.Confidence, SeenAt: row.seenAt, SoftwareID: row.ID}
	}
	d.OS = at(strings.TrimSpace(row.Product + " " + version))
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
