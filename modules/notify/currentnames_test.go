package notify_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/notify"
)

// An incident stored the name its device had when it opened. After the device is renamed (a person, what Vedette learned, a better
// naming rule after an update), the incidents list, the incident page and the report name it as Devices does now; a device that is
// gone keeps the stored name.
func TestIncidentsNameTheirDevicesAsDevicesDoesNow(t *testing.T) {
	devs := &stateDevices{m: map[string]notify.DeviceState{
		"esx": {Name: "Hewlett Packard", Address: "192.0.2.67"},
		"pc":  {Name: "pc-01", Address: "192.0.2.10"},
	}}
	e := newEnv(t, func(c *notify.Config) { c.Devices = devs })
	in := notify.IncidentInput{Kind: notify.IncidentIntrusion, Source: "203.0.113.45", Target: "sig", Severity: notify.High, Link: "/detection",
		Title:   "203.0.113.45 fired Linux.Kernel.Hewlett Packard.Probe at Hewlett Packard (192.0.2.67)",
		What:    "An IPS event: from 203.0.113.45 to Hewlett Packard (192.0.2.67) port 443, and to pc-01 (192.0.2.10). Hewlett Packard Enterprise is not this device.",
		Action:  "Check Hewlett Packard.",
		Devices: []notify.Device{{ID: "esx", Name: "Hewlett Packard"}, {ID: "pc", Name: "pc-01"}, {ID: "gone", Name: "old-box"}}}
	id, _, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil {
		t.Fatal(err)
	}
	devs.set("esx", notify.DeviceState{Name: "VMware ESXi", Address: "192.0.2.67"})

	list, err := e.svc.Incidents(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	var got notify.Incident
	for _, i := range list {
		if i.ID == id {
			got = i
		}
	}
	wantTitle := "203.0.113.45 fired Linux.Kernel.Hewlett Packard.Probe at VMware ESXi (192.0.2.67)"
	if got.Title != wantTitle {
		t.Errorf("list title %q, want %q", got.Title, wantTitle)
	}
	if !strings.Contains(got.What, "to VMware ESXi (192.0.2.67) port 443") || !strings.Contains(got.What, "Hewlett Packard Enterprise is not") || got.Action != "Check Hewlett Packard." { // a bare name is not a label: left as written
		t.Errorf("list what %q, action %q", got.What, got.Action)
	}
	names := []string{}
	for _, d := range got.Devices {
		names = append(names, d.Name)
	}
	if strings.Join(names, "|") != "VMware ESXi|pc-01|old-box" {
		t.Errorf("devices %v: want the current name, an unchanged one, and a gone device's stored name", names)
	}

	d, err := e.svc.IncidentDetail(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Incident.Title != wantTitle || d.Incident.Devices[0].Name != "VMware ESXi" {
		t.Errorf("detail %q %v", d.Incident.Title, d.Incident.Devices)
	}

	now := e.clock.Now()
	p, err := e.svc.IncidentsIn(e.ctx(), now.AddDate(0, 0, -7), now.Add(1), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Top) != 1 || p.Top[0].Title != wantTitle || p.Top[0].DeviceID == "esx" && p.Top[0].DeviceName != "VMware ESXi" {
		t.Errorf("report top %+v", p.Top)
	}
}

// The discovery summary stores devices by label (name and address): the current label replaces it. A bare old name is replaced only
// where a label starts with it, as a whole name.
func TestReplaceNamesWholeNamesOnly(t *testing.T) {
	pairs := [][2]string{{"Dell", "build-01"}, {"Dell (192.0.2.5)", "build-01 (192.0.2.5)"}}
	for in, want := range map[string]string{
		"Dell":                                 "Dell",
		"at Dell (192.0.2.5).":                 "at build-01 (192.0.2.5).",
		"Dellwood (x) and Dell.Remote.Fix (y)": "Dellwood (x) and Dell.Remote.Fix (y)",
		"to Dell (192.0.2.9), then Dell.":      "to build-01 (192.0.2.9), then Dell.",
		"xDell (a) Dell-2 (b) Dell (c)":        "xDell (a) Dell-2 (b) build-01 (c)",
		"Dell Technologies (d), Dell (e) is":   "Dell Technologies (d), build-01 (e) is",
	} {
		if got := notify.ReplaceNamesForTest(in, pairs); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

// The words of an incident quote what was seen: an IPS signature, a log line, the attacking address. A device is named in them as a
// label ("name (address)"); only that label takes the current name. A device first known by its address keeps the address in its
// label and in the advice to block it, and a signature or a quoted log line that happens to contain the old name stays as it was seen.
func TestIncidentsRenameOnlyTheDeviceLabels(t *testing.T) {
	devs := &stateDevices{m: map[string]notify.DeviceState{
		"esx": {Name: "192.0.2.67", Address: "192.0.2.67"},
		"pc":  {Name: "192.0.2.10", Address: "192.0.2.10"},
		"fw":  {Name: "fw01", Address: "192.0.2.1"},
	}}
	e := newEnv(t, func(c *notify.Config) { c.Devices = devs })
	in := notify.IncidentInput{Kind: notify.IncidentIntrusion, Source: "192.0.2.10", Target: "sig", Severity: notify.High, Link: "/detection",
		Title: "192.0.2.10 fired ET EXPLOIT fw01 command injection at 192.0.2.67 (192.0.2.67)",
		What: "An IPS event in the log of fw01 (192.0.2.1): ET EXPLOIT fw01 command injection (rule 1), from 192.0.2.10 to 192.0.2.67 (192.0.2.67) port 443. " +
			"Example line: fw01 sshd[12]: probe.",
		Action:  "Check whether the device runs what the rule targets and is up to date. If 192.0.2.10 is not yours and keeps trying, block it at the firewall.",
		Devices: []notify.Device{{ID: "esx", Name: "192.0.2.67"}, {ID: "pc", Name: "192.0.2.10"}, {ID: "fw", Name: "fw01"}}}
	id, _, err := e.svc.OpenIncident(e.ctx(), in)
	if err != nil {
		t.Fatal(err)
	}
	devs.set("esx", notify.DeviceState{Name: "VMware ESXi", Address: "192.0.2.67"})
	devs.set("pc", notify.DeviceState{Name: "pc-01", Address: "192.0.2.10"})
	devs.set("fw", notify.DeviceState{Name: "Main firewall", Address: "192.0.2.1"})

	d, err := e.svc.IncidentDetail(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	got := d.Incident
	if want := "192.0.2.10 fired ET EXPLOIT fw01 command injection at VMware ESXi (192.0.2.67)"; got.Title != want {
		t.Errorf("title %q, want %q", got.Title, want)
	}
	if want := "An IPS event in the log of Main firewall (192.0.2.1): ET EXPLOIT fw01 command injection (rule 1), from 192.0.2.10 to VMware ESXi (192.0.2.67) port 443. " +
		"Example line: fw01 sshd[12]: probe."; got.What != want {
		t.Errorf("what %q, want %q", got.What, want)
	}
	if got.Action != in.Action {
		t.Errorf("action %q: the address to block is gone", got.Action)
	}
}
