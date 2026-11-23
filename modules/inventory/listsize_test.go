package inventory

import (
	"database/sql"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/go-faster/jx"

	"github.com/knt048/vedette/core/api/oas"
)

// listBytes is the encoded body of GET /inventory/devices for the query p, as the server writes it.
func listBytes(t *testing.T, h *Handlers, p oas.InventoryGetInventoryDevicesParams) (int, *oas.InventoryGetInventoryDevicesOK) {
	t.Helper()
	res, err := h.InventoryGetInventoryDevices(t.Context(), p)
	if err != nil {
		t.Fatal(err)
	}
	var e jx.Encoder
	res.Encode(&e)
	return len(e.Bytes()), res
}

// The Devices list is sized by the rows it shows, not by the software the devices run. The fixture is an anonymised test network
// (14 devices with 2,467 software rows, one device with 950) plus 17 devices with no software, 31 in all: the list once carried every
// device's whole software list (about 570 KB here). Each row now carries its software count; the lines stay on the device page.
func TestDevicesList_SizeFollowsTheRowsNotTheSoftware(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	ctx := t.Context()
	for i := range 17 {
		if err := r.db.Write(ctx, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO inv_asset (id, ip, hostname, kind, origin, approved, first_seen, last_seen) VALUES (?, ?, ?, 'unknown', 'discovered', 1, ?, ?)`,
				fmt.Sprintf("a-extra-%02d", i), fmt.Sprintf("10.0.9.%d", i+1), fmt.Sprintf("host-%02d", i), r.svc.now(), r.svc.now())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	lines := r.count(t, `SELECT count(*) FROM inv_software`)
	h := NewHandlers(r.svc)
	size, res := listBytes(t, h, oas.InventoryGetInventoryDevicesParams{})
	t.Logf("GET /inventory/devices: %d devices, %d software lines, %d bytes (%d bytes per device)", len(res.Items), lines, size, size/max(len(res.Items), 1))
	if len(res.Items) != 31 {
		t.Fatalf("listed %d devices, want 31", len(res.Items))
	}
	if limit := 1200 * len(res.Items); size > limit {
		t.Errorf("the list is %d bytes for %d devices, over %d: it carries more than the rows show", size, len(res.Items), limit)
	}
}

// The software: search runs on the server: ?software= keeps the devices with a line that holds one of its words and lists those
// lines; without it no row carries lines. The suggestions (top_software) and a hand-added device's product come with the list.
func TestDevicesList_SoftwareSearchAndSuggestions(t *testing.T) {
	t.Parallel()
	r := replayFixture(t)
	ctx := t.Context()
	if _, err := r.svc.AddDevice(ctx, "person@example.com", AddInput{CatalogID: "fortigate", Version: "7.2.5", IP: "10.0.9.200"}); err != nil {
		t.Fatal(err)
	}
	full, err := r.svc.DevicesPage(ctx, DeviceFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{} // device: lines that hold "openssh"
	for _, d := range full.Items {
		for _, s := range d.Software {
			if strings.Contains(strings.ToLower(s.Display+" "+s.Vendor+" "+s.Product), "openssh") {
				want[d.ID]++
			}
		}
	}
	if len(want) < 2 {
		t.Fatalf("the fixture has openssh on %d devices", len(want))
	}
	h := NewHandlers(r.svc)
	_, all := listBytes(t, h, oas.InventoryGetInventoryDevicesParams{})
	for _, it := range all.Items {
		if it.MatchedSoftware != nil {
			t.Fatalf("%s lists matched software without a software filter", it.ID)
		}
		if it.Origin == "manual" {
			if p, ok := it.Product.Get(); !ok || p.Display != "FortiGate" || it.SoftwareCount != 1 {
				t.Errorf("hand-added device: product %+v, %d lines", it.Product, it.SoftwareCount)
			}
		} else if !it.Product.Null {
			t.Errorf("%s: a discovered device has a product", it.ID)
		}
	}
	top := all.TopSoftware.Devices
	if len(top) == 0 || len(top) > topSoftwareN || top[0].Count < 2 {
		t.Fatalf("top software = %+v", top)
	}
	for i := 1; i < len(top); i++ {
		if top[i].Count > top[i-1].Count {
			t.Fatalf("top software not by count: %+v", top)
		}
	}
	_, res := listBytes(t, h, oas.InventoryGetInventoryDevicesParams{Software: oas.NewOptString("OpenSSH,no-such-software")})
	got := map[string]int{}
	for _, it := range res.Items {
		for _, s := range it.MatchedSoftware {
			if !strings.Contains(strings.ToLower(s.Display+" "+s.Vendor+" "+s.Product), "openssh") {
				t.Errorf("%s: matched %q", it.ID, s.Display)
			}
		}
		got[it.ID] = len(it.MatchedSoftware)
	}
	if !maps.Equal(got, want) {
		t.Fatalf("software=openssh kept %v, want %v", got, want)
	}
	if _, err := h.InventoryGetInventoryDevices(ctx, oas.InventoryGetInventoryDevicesParams{Software: oas.NewOptString(strings.Repeat("x", 81))}); err == nil {
		t.Fatal("a software word over 80 characters is taken")
	}
}
