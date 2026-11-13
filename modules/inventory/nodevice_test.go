package inventory_test

import (
	"database/sql"
	"testing"

	"github.com/knt048/vedette/modules/inventory"
)

// W9-1, D-515: a product declared with neither an IP nor a name ("Microsoft Office (no device)") has no device type, from the add form
// (catalog kind pc) or from "I have this" (feeds suggests pc). The same product on a device with an IP keeps the type, and an
// appliance declared alone keeps its type (the product is the device; mitigation reads a declared firewall).
func TestContract_D515_AProductWithNoDeviceHasNoDeviceType(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	kind := func(id string) string {
		t.Helper()
		d, err := e.svc.Device(e.ctx(), id)
		if err != nil {
			t.Fatal(err)
		}
		return d.Kind
	}
	var fed string
	var txp *sql.Tx
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		var err error
		txp = tx
		fed, err = e.svc.AddManualDevice(e.ctx(), tx, "kien", inventory.ManualDevice{Kind: "pc", Vendor: "Microsoft", Product: "Office", Display: "Microsoft Office", Key: "microsoft|office"})
		return err
	})
	e.svc.Settle(e.ctx(), txp, err == nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		id, want string
	}{
		"I have this":           {fed, "unknown"},
		"add form, no device":   {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop"}), "unknown"},
		"add form, with an IP":  {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", IP: "192.168.30.5"}), "pc"},
		"add form, with a name": {e.addDevice(inventory.AddInput{CatalogID: "microsoft-office-desktop", Name: "ACC-PC-01"}), "pc"},
		"an appliance alone":    {e.addDevice(inventory.AddInput{CatalogID: "fortigate"}), "firewall"},
	} {
		if got := kind(c.id); got != c.want {
			t.Errorf("%s: kind %q, want %q", name, got, c.want)
		}
	}
}
