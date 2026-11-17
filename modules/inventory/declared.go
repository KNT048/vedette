package inventory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/content/devicetypes"
)

// What a person declared is what the device is (INV-45). A device added by hand as "FortiGate, FortiOS v7.2.13" has that row on its
// Software tab, and the matcher reads it ("runs FortiGate v7.2.13 (entered on the Devices page)"), but no observation says its OS
// or model: the Overview, the list and the export said "Not known yet". So a live software row a person declared (source manual:
// added by hand, or a correction in use) of an operating-system or firmware product is the device's OS, above every sensor
// (a person ranks first, INV-1); only the OS a person typed in the OS field (the INV-41 correction, a manual os observation) ranks
// above it. The product is an OS when the catalog says so: a curated row with an OS CPE (part "o") or a row of network-os.json,
// both by vendor and product, so a new one is a line of data.

// osProduct is a product the catalog knows as an operating system or firmware.
type osProduct struct {
	model string // the hardware line the catalog names it after ("FortiGate" for FortiOS), "" when its name is the OS's own
}

var osProducts = func() map[string]osProduct {
	out := map[string]osProduct{}
	var curated []struct {
		Display, Kind, Vendor, Product string
		CPE                            []string `json:"cpe"`
	}
	if err := json.Unmarshal(catalogdata.Curated, &curated); err != nil {
		panic(fmt.Sprintf("inventory: curated.json: %v", err)) // embedded data, read by NewCatalog's tests too
	}
	for _, r := range curated {
		for _, c := range r.CPE {
			if !strings.HasPrefix(c, "o:") {
				continue
			}
			p := osProduct{}
			// An appliance's OS listed under the appliance's name ("FortiGate" for FortiOS) names its model; a name that holds the
			// OS's own ("Juniper Junos OS", "Windows 11") does not.
			if appliance(r.Kind) && !strings.Contains(fold(r.Display), fold(r.Product)) {
				p.model = r.Display
			}
			out[productID(r.Vendor, r.Product)] = p
		}
	}
	var netOS struct {
		OS []struct{ Vendor, Product string } `json:"os"`
	}
	if err := json.Unmarshal(catalogdata.NetworkOS, &netOS); err != nil {
		panic(fmt.Sprintf("inventory: network-os.json: %v", err))
	}
	for _, r := range netOS.OS {
		if _, ok := out[productID(r.Vendor, r.Product)]; !ok {
			out[productID(r.Vendor, r.Product)] = osProduct{}
		}
	}
	return out
}()

func productID(vendor, product string) string { return fold(vendor) + "|" + fold(product) }

// appliance says whether a catalog kind is a box whose product is the device itself (not a computer that runs it).
func appliance(kind string) bool {
	switch devicetypes.ActsAs(kind) {
	case "pc", "server", "web", "iot", "unknown":
		return false
	}
	return true
}

// leadingV is the "v" a firmware version is often written with ("v7.2.13").
var leadingV = regexp.MustCompile(`^[vV](\d)`)

// declaredIdentity is the OS, model and maker a person's declared OS row gives the device (sw: its software as loadSoftware read
// it), or nils when there is none: the newest such row wins. The OS reads "FortiOS 7.2.13" (product and version); the model is
// the hardware line the catalog names the OS after; the maker is the row's vendor.
func declaredIdentity(sw []Software) (os, model, maker *Observed) {
	var best *Software
	for i := range sw {
		s := &sw[i]
		if s.Source != "manual" || !s.live || s.NotInstalled {
			continue
		}
		if _, ok := osProducts[productID(s.Vendor, s.Product)]; !ok {
			continue
		}
		if best == nil || s.seenAt > best.seenAt || s.seenAt == best.seenAt && s.ID < best.ID {
			best = s
		}
	}
	if best == nil {
		return nil, nil, nil
	}
	at := func(v string) *Observed {
		return &Observed{Value: v, Source: "manual", Confidence: best.Confidence, SeenAt: best.seenAt, SoftwareID: best.ID}
	}
	name := best.Product
	if best.Version != nil && strings.TrimSpace(*best.Version) != "" {
		name += " " + leadingV.ReplaceAllString(strings.TrimSpace(*best.Version), "$1")
	}
	os, maker = at(name), at(best.Vendor)
	if m := osProducts[productID(best.Vendor, best.Product)].model; m != "" {
		model = at(m)
	}
	return os, model, maker
}

// applyDeclared puts the declared identity on a listed device (INV-45): the declared OS wins over every source except a person's
// typed OS; the declared model and maker fill only what no source gives (a model a sensor reads, "FGT60F", is more exact than the
// catalog's line).
func applyDeclared(d *Device) {
	os, model, maker := declaredIdentity(d.Software)
	if os == nil {
		return
	}
	if d.OS == nil || d.OS.Source != "manual" {
		d.OS = os
	}
	if d.Model == nil && model != nil {
		d.Model = model
	}
	if d.Vendor == nil {
		d.Vendor = maker
	}
}
