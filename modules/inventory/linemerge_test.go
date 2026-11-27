package inventory_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

// One device, one line per product and train, one version: a line a person added without a version takes the release a source
// reads of that product, on the same line, and never stays beside it asking for a version.

// lineRows are the device's lines of one product key as "train:version:source:state", by train.
func lineRows(t *testing.T, e *env, dev, key string) []string {
	t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT line || ':' || ifnull(version, '') || ':' || source || ':' || state FROM inv_software
		WHERE asset_id = ? AND product_key = ? AND state <> 'removed' ORDER BY line`, dev, key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// A firewall added by hand as FortiGate without a version, whose SNMP answer states FortiOS 7.2.13: the one line is matched at
// 7.2.13 under the person's name for it, the version is the device's own (no person's name on it), and the person's row still
// gives the device its OS and model (INV-45) and is found by its name.
func TestLineMerge_VersionlessEntryTakesTheStatedRelease(t *testing.T) {
	t.Parallel()
	e := newEnv(t, withMatcher(&matcher{keep: true, version: "7.2.13"}))
	dev := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "100.66.254.1"})
	for range 2 { // two polls: the second decides on the settled line
		e.tick(time.Minute)
		e.record(observe.Observation{AssetHint: observe.AssetHint{Device: dev}, Field: observe.OS, Value: "FortiOS 7.2.13", Source: observe.SNMP, Confidence: 0.9})
	}
	if err := e.svc.ReconcileDeclaredOS(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if got, want := lineRows(t, e, dev, "fortinet|fortios"), []string{":7.2.13:snmp:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	m := matchRows(t, e, dev)
	if len(m) != 1 || m[0].Version != "7.2.13" || m[0].Source != "snmp" || m[0].SetBy != "" || m[0].Display != "FortiGate" {
		t.Fatalf("match input %+v", m)
	}
	_, mo, os := identityOf(t, e, dev)
	wantIdentity(t, "OS", os, "FortiOS 7.2.13", "declared") // the person's row, at the release SNMP states
	wantIdentity(t, "model", mo, "FortiGate", "declared")
	f := false
	l, err := e.svc.DevicesPage(e.ctx(), inventory.DeviceFilter{Q: "fortigate", Ignored: &f})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(l.Items, func(d inventory.Device) bool { return d.ID == dev }) {
		t.Errorf("searching FortiGate does not find the device the person added as FortiGate")
	}
}

// A person's version holds against another release SNMP states (said once), and gives way to a newer one.
func TestLineMerge_TypedVersionHoldsAgainstAnOlderStatedRelease(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	dev := e.addDevice(inventory.AddInput{CatalogID: "fortigate", Version: "7.2.13", IP: "100.66.254.2"})
	e.tick(time.Minute)
	e.record(observe.Observation{AssetHint: observe.AssetHint{Device: dev}, Field: observe.OS, Value: "FortiOS 7.2.5", Source: observe.SNMP, Confidence: 0.9})
	if got, want := lineRows(t, e, dev, "fortinet|fortios"), []string{":7.2.13:manual:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
}

// java is an agent's reading of a Java install.
func java(display, version string) observe.Software {
	return observe.Software{Display: display, Vendor: "Oracle", Product: "Java SE", Version: version, Confidence: 0.9}
}

// A product whose trains install side by side: Java added by hand without a version becomes the train the agent reads (the same
// line, its id kept), and a second train is a line of its own; no version-less line stays beside them.
func TestLineMerge_VersionlessEntryBecomesTheTrainAnAgentReads(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil)
	dev := c.dev()
	if _, err := c.e.svc.AddSoftware(c.e.ctx(), "it@acme.example", dev, inventory.AddInput{Vendor: "Oracle", Product: "Java SE"}); err != nil {
		t.Fatal(err)
	}
	if got, want := lineRows(t, c.e, dev, "oracle|java se"), []string{"::manual:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	before := c.line("Java SE").ID
	c.send(observe.Osquery, nil, java("Java SE Development Kit 21.0.7", "21.0.7"))
	if got, want := lineRows(t, c.e, dev, "oracle|java se"), []string{"21:21.0.7:osquery:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	if id := c.line("Java SE").ID; id != before {
		t.Errorf("the line is %s, want the person's line %s kept", id, before)
	}
	c.send(observe.Osquery, nil, java("Java SE Development Kit 21.0.7", "21.0.7"), java("Java 8 Update 491", "8.0.4910.10"))
	if got, want := lineRows(t, c.e, dev, "oracle|java se"), []string{"21:21.0.7:osquery:present", "8:8.0.4910.10:osquery:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
}

// Java added by hand without a version on a device whose agent already reads it is the software the device has: 409, no line.
func TestLineMerge_VersionlessEntryOfAReadTrainIsADuplicate(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Osquery, nil, java("Java SE Development Kit 21.0.7", "21.0.7"))
	dev := c.dev()
	_, err := c.e.svc.AddSoftware(c.e.ctx(), "it@acme.example", dev, inventory.AddInput{Vendor: "Oracle", Product: "Java SE"})
	wantAPIError(t, err, http.StatusConflict, "duplicate_software")
	if got, want := lineRows(t, c.e, dev, "oracle|java se"), []string{"21:21.0.7:osquery:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	// the message names what the device has and the step that works there: a row a source reads cannot be removed (not_manual)
	ae, _ := apierr.As(err)
	if !strings.Contains(ae.Message, "21.0.7") || !strings.Contains(ae.Message, "its agent") || strings.Contains(ae.Message, "remove it") {
		t.Errorf("message %q, want the version the agent reads and no advice to remove the row", ae.Message)
	}
}

// A version-less reading of a product with trains (a banner without its release) joins the device's line of that product.
func TestLineMerge_VersionlessReadingJoinsTheTrain(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Osquery, nil, java("Java SE Development Kit 21.0.7", "21.0.7"))
	c.send(observe.Nmap, nil, observe.Software{Display: "Java SE", Vendor: "Oracle", Product: "Java SE", Instance: "tcp/8080", Confidence: 0.5})
	if got, want := lineRows(t, c.e, c.dev(), "oracle|java se"), []string{"21:21.0.7:osquery:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
}

// A person who gives a version to the Java they added without one keeps the one line: it takes the train of that version, with its
// id and history.
func TestLineMerge_VersionOnAVersionlessEntryKeepsTheLine(t *testing.T) {
	t.Parallel()
	c := newLineCase(t)
	c.send(observe.Nmap, nil)
	dev := c.dev()
	if _, err := c.e.svc.AddSoftware(c.e.ctx(), "it@acme.example", dev, inventory.AddInput{Vendor: "Oracle", Product: "Java SE"}); err != nil {
		t.Fatal(err)
	}
	id := c.line("Java SE").ID
	v := "17.0.12"
	c.e.tick(time.Minute)
	if err := c.e.svc.EditSoftware(c.e.ctx(), "it@acme.example", dev, id, inventory.SoftwareEdit{Version: &v}); err != nil {
		t.Fatal(err)
	}
	if got, want := lineRows(t, c.e, dev, "oracle|java se"), []string{"17:17.0.12:manual:present"}; !slices.Equal(got, want) {
		t.Fatalf("lines %v, want %v", got, want)
	}
	if l := c.line("Java SE"); l.ID != id {
		t.Errorf("the line is %s, want %s kept", l.ID, id)
	}
}
