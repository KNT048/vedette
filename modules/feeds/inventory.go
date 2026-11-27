package feeds

import (
	"context"
	"database/sql"
)

// YouHave is the answer of "Do you have it?" (INV-11).
type YouHave string

// Answers.
const (
	HaveYes   YouHave = "yes"   // a device runs the product (confirmed match)
	HaveMaybe YouHave = "maybe" // only the vendor matches a "Multiple products" entry
	HaveNo    YouHave = "no"
)

// MatchedAsset is a device that matches a vulnerable product.
type MatchedAsset struct {
	ID       string  `json:"id"`
	Hostname *string `json:"hostname"` // the name a person gave the device in Vedette, else its host name; nil when neither
	IP       string  `json:"ip"`
	Display  string  `json:"display"`
	How      YouHave `json:"how"` // yes or maybe, never no
}

// ManualDevice is the device "I have it" declares (S-FEED-2, INV-14): one device that runs the product.
type ManualDevice struct {
	Kind    string // a hint (nas, firewall, router, camera, web, server, unknown)
	Vendor  string
	Product string
	Display string // the name people recognise
	Key     string // productid.Key of vendor and product, the KEV matching key
}

// Inventory is what feeds needs from the inventory module (FORBID-4: feeds never reads inv_* itself). The
// inventory module implements it and the wiring passes it in Deps; when it is nil or the module is off, feeds
// answers with you_have null and no matched devices (INV-10).
type Inventory interface {
	// MatchProducts returns, for each product, the devices that run it (how is yes) or may run it (maybe).
	// The map is keyed by Product.Key(); a product with no device has no entry.
	MatchProducts(ctx context.Context, products []Product) (map[string][]MatchedAsset, error)
	// AddManualDevice declares one manually added device that runs the product. It runs inside the caller's
	// write transaction (tx) so the device, the audit row of the inventory and the answer commit together. It
	// returns the new device's id, or "" when the inventory does not say it: then "I have this" scopes no device
	// (HaveSince) and findings match it like any other device.
	AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, d ManualDevice) (deviceID string, err error)
}

// DistroLister is an optional extension of Inventory: the distributions ("ubuntu", "debian", "alpine") of the devices the
// distribution feeds can answer for (a device with packages an agent read; Alpine: a device that states it), each with the source
// packages and releases of those devices as the security data names them (findings.DevicePackages): the tier rows are kept for them
// only. Without it, or with the inventory module off, feeds pulls every enabled distribution feed as before and keeps no tier row.
type DistroLister interface {
	Distros(ctx context.Context) (map[string]DistroDevices, error)
}

// DistroDevices is what the devices of one distribution run, as its security data names it.
type DistroDevices struct {
	Packages map[string]bool // source packages ("openssl", "linux" for a linux-signed kernel)
	// Releases are the releases ("26.04", "12"); nil when the rows of every release are read (Alpine: a package may come from another
	// branch's repository).
	Releases map[string]bool
}

// PlatformChecker is an optional extension of Inventory (KF-CVEPAGE): among ids, the devices that the findings matcher's platform
// rules prove are not affected by the CVE (an Ubuntu box for an Alpine-only OpenSSH flaw), so "Do you have it?" on the CVE
// page agrees with the device's findings. distro is what the distribution feeds that are on say about the CVE (DistroFixesOf): a package
// release a person gave is read against it. Without it the page answers by product only, as before.
type PlatformChecker interface {
	NotAffected(ctx context.Context, cve, vendor, product string, distro []DistroFix, ids []string) (map[string]bool, error)
}

func youHave(matched []MatchedAsset) YouHave {
	out := HaveNo
	for _, m := range matched {
		switch m.How {
		case HaveYes:
			return HaveYes
		case HaveMaybe:
			out = HaveMaybe
		}
	}
	return out
}
