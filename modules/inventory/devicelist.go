package inventory

import (
	"cmp"
	"slices"
	"strings"
)

// The Devices list (GET /inventory/devices) carries what its rows show, never a device's software lines or open ports: one device
// can run a thousand packages, and the list once sent every line of every device on every open of the page. Each row says how many
// lines and open services the device has (software_count for has:software, service_count for has:ports) and, for a device added by
// hand, the line that names it (product). The software: search asks the server (DeviceFilter.Software), which keeps the devices that
// run it and lists the matching lines; the suggestions of that search come with the list (top_software). The device page reads the
// lines and ports from GET /inventory/devices/{id}.

// topSoftwareN is how many software names the search suggests.
const topSoftwareN = 12

// ListRow is a row of GET /inventory/devices (contract.ts DeviceRow).
type ListRow struct {
	AssetCore
	SoftwareCount int `json:"software_count"`
	ServiceCount  int `json:"service_count"` // open services; the device page lists them
	// Services hides AssetCore.Services from the row (a nil slice is left out): the list sends service_count instead.
	Services []ServiceRow `json:"services,omitempty"`
	// Product is a hand-added device's first installed line by name (what names it, and what Settings › Declared software lists).
	Product *Software `json:"product"`
	// MatchedSoftware is set only with a software filter: the lines that hold one of its words.
	MatchedSoftware []Software `json:"matched_software,omitempty"`
	Suspicious      bool       `json:"suspicious"`
	FindingsCount   int        `json:"findings_count"`
	Risk            *Risk      `json:"risk"`
	Summary         *Summary   `json:"summary"`
	Sources         []string   `json:"sources"`
}

// SoftwareName is a software name of the search's suggestions and the number of listed devices that run it.
type SoftwareName struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TopSoftware is the suggestions of the search's software:, per list of the page.
type TopSoftware struct {
	Devices []SoftwareName `json:"devices"` // approved or quiet
	Review  []SoftwareName `json:"review"`  // To review
}

// ListPage is GET /inventory/devices (contract.ts DevicesResponse).
type ListPage struct {
	Items           []ListRow   `json:"items"`
	Counts          Counts      `json:"counts"`
	NotifyNew       bool        `json:"notify_new"`
	NotifyAvailable bool        `json:"notify_available"`
	RiskUnavailable bool        `json:"risk_unavailable"`
	TopSoftware     TopSoftware `json:"top_software"`
}

// softwareText is what the software search reads of a line: its name, vendor and product.
func softwareText(s Software) string {
	return strings.ToLower(s.Display + " " + s.Vendor + " " + s.Product)
}

// matchedSoftware is the device's lines that hold one of words (lower case), in the device's order (by name).
func (d Device) matchedSoftware(words []string) []Software {
	var out []Software
	for _, s := range d.Software {
		text := softwareText(s)
		if slices.ContainsFunc(words, func(w string) bool { return strings.Contains(text, w) }) {
			out = append(out, s)
		}
	}
	return out
}

// declaredOnly is a product someone declared with no device: added by hand, no host name and no address. The page lists it in
// Settings › Declared software, not in Devices (web nameOf.ts declaredSoftwareOnly).
func (d Device) declaredOnly() bool {
	return d.Origin == "manual" && d.Hostname == nil && d.IP == noIP
}

// listPage is the list as GET /inventory/devices sends it. words is the software filter (matched lines are listed only then).
func listPage(l DeviceList, words []string) ListPage {
	out := ListPage{Items: make([]ListRow, len(l.Items)), Counts: l.Counts, NotifyNew: l.NotifyNew, NotifyAvailable: l.NotifyAvailable, RiskUnavailable: l.RiskUnavailable}
	listed, review := map[string]*SoftwareName{}, map[string]*SoftwareName{}
	for i, d := range l.Items {
		r := ListRow{AssetCore: d.AssetCore, SoftwareCount: len(d.Software), ServiceCount: len(d.Services), Suspicious: d.Suspicious, FindingsCount: d.FindingsCount, Risk: d.Risk, Summary: d.Summary, Sources: d.Sources}
		if d.Origin == "manual" {
			if run := d.Running(); len(run) > 0 {
				r.Product = &run[0]
			}
		}
		if len(words) > 0 {
			if r.MatchedSoftware = d.matchedSoftware(words); r.MatchedSoftware == nil {
				r.MatchedSoftware = []Software{}
			}
		}
		out.Items[i] = r
		if d.declaredOnly() {
			continue
		}
		names := listed
		if !d.Approved && !d.Quiet {
			names = review
		}
		seen := map[string]bool{}
		for _, s := range d.Software {
			k := strings.ToLower(s.Display)
			if seen[k] {
				continue
			}
			seen[k] = true
			if n := names[k]; n != nil {
				n.Count++
			} else {
				names[k] = &SoftwareName{Name: s.Display, Count: 1}
			}
		}
	}
	out.TopSoftware = TopSoftware{Devices: topNames(listed), Review: topNames(review)}
	return out
}

// topNames is the topSoftwareN names most devices run, most first, then by name.
func topNames(m map[string]*SoftwareName) []SoftwareName {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(m[b].Count, m[a].Count), strings.Compare(a, b)) })
	out := make([]SoftwareName, 0, min(len(keys), topSoftwareN))
	for _, k := range keys[:min(len(keys), topSoftwareN)] {
		out = append(out, *m[k])
	}
	return out
}
