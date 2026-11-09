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
	Hostname *string `json:"hostname"`
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
	Key     string // ProductKey of vendor and product, the KEV matching key
}

// Inventory is what feeds needs from the inventory module (FORBID-4: feeds never reads inv_* itself). The
// inventory module implements it and the wiring passes it in Deps; when it is nil or the module is off, feeds
// answers with you_have null and no matched devices (INV-10).
type Inventory interface {
	// MatchProducts returns, for each product, the devices that run it (how is yes) or may run it (maybe).
	// The map is keyed by Product.Key(); a product with no device has no entry.
	MatchProducts(ctx context.Context, products []Product) (map[string][]MatchedAsset, error)
	// AddManualDevice declares one manually added device that runs the product. It runs inside the caller's
	// write transaction (tx) so the device, the audit row of the inventory and the answer commit together.
	AddManualDevice(ctx context.Context, tx *sql.Tx, actor string, d ManualDevice) error
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
