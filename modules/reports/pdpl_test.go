package reports

import (
	"testing"
	"time"
)

func day0(daysAgo int) time.Time { return t0.Add(-time.Duration(daysAgo) * 24 * time.Hour) }

// pdplSample is the assessment's network: a firewall, an old PC not approved yet and a server, with their findings.
func pdplSample() pdplInput {
	return pdplInput{
		now: t0,
		devices: []Device{
			{ID: "a1", Name: "fw-01", IP: "10.0.0.1", Kind: "firewall", Approved: true, OS: "FortiOS 7"},
			{ID: "a2", Name: "pc-old", IP: "10.0.0.2", Kind: "pc", Approved: false, OS: "Windows 10 Pro"},
			{ID: "a3", Name: "srv", IP: "10.0.0.3", Kind: "server", Approved: true, OS: "Windows Server 2016"},
		},
		findings: []Finding{
			{ID: "f1", AssetID: "a2", CVE: "CVE-2026-0001", Status: "confirmed", Severity: "critical", FirstSeen: day0(1)},
			{ID: "f2", AssetID: "a3", CVE: "CVE-2026-0002", Status: "suspected", Severity: "high", FirstSeen: day0(20)},
			{ID: "f3", AssetID: "a1", CVE: "CVE-2026-0003", Status: "patched", Severity: "high", FirstSeen: day0(10)},
			{ID: "f4", AssetID: "a1", CVE: "CVE-2026-0004", Status: "false_positive", Severity: "low", FirstSeen: day0(40)},
			{ID: "f5", AssetID: "a2", CVE: "CVE-2026-0005", Status: "confirmed", Severity: "medium", FirstSeen: t0.Add(time.Hour)}, // in the future: ignored
		},
		kev: []KEVEntry{
			{CVE: "CVE-2026-0001", Vendor: "Microsoft", Product: "Windows"},
			{CVE: "CVE-2026-0002", Vendor: "Acme", Product: "Srv"},
		},
	}
}

func okOrg() PdplOrg {
	return PdplOrg{Name: "Acme Ltd", TaxCode: "0312345678", Address: "1 Main Street, Hanoi", Sector: "Retail", Employees: 12, DataVolume: "lt1k", Size: "micro",
		ContactName: "An Nguyen", ContactEmail: "an@acme.example", ContactPhone: "0901234567", Level: ""}
}

func TestRegime(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		edit func(*PdplOrg)
		want string
	}{
		{"micro is exempt", func(*PdplOrg) {}, "exempt"},
		{"household is exempt", func(o *PdplOrg) { o.Size = "household" }, "exempt"},
		{"small is optional", func(o *PdplOrg) { o.Size = "small" }, "optional"},
		{"startup is optional", func(o *PdplOrg) { o.Size = "startup" }, "optional"},
		{"other is required", func(o *PdplOrg) { o.Size = "other" }, "required"},
		{"service provider loses the exemption", func(o *PdplOrg) { o.ProcessingService = true }, "required"},
		{"sensitive data loses it", func(o *PdplOrg) { o.Sensitive = true; o.Size = "small" }, "required"},
		{"100k people lose it", func(o *PdplOrg) { o.DataVolume = "gte100k" }, "required"},
	} {
		o := okOrg()
		c.edit(&o)
		if got := Regime(o); got != c.want {
			t.Errorf("%s: regime = %s, want %s", c.name, got, c.want)
		}
	}
}

func pdplFor(mods Modules, org PdplOrg) PdplReport {
	in := pdplSample()
	return buildPdpl(pdplInput{devices: in.devices, findings: in.findings, kev: in.kev, modules: mods, org: org, id: "pdpl-1", now: t0})
}

// The ApprovedOnly view of the assessment leaves the devices not approved yet and their findings out of the inventory, the
// measures and the risks; the "unapproved" measure stays the full report's (leaving them out does not approve them).
func TestPdplApprovedOnlyView(t *testing.T) {
	t.Parallel()
	r := pdplFor(fakeMods{"feeds": true, "scan": true}, okOrg())
	v := r.ApprovedOnly
	if v == nil || v.Inventory.Total != 2 || v.Inventory.Unapproved != 0 || r.Inventory.Unapproved != 1 {
		t.Fatalf("view = %+v, full inventory = %+v", v, r.Inventory)
	}
	if len(v.Risks) != 1 || v.Risks[0].ID != "f2" || len(r.Risks) != 2 {
		t.Fatalf("risks = %+v (full %+v)", v.Risks, r.Risks)
	}
	view := PdplReport{Measures: v.Measures}
	if m := measure(view, "unapproved"); m.Status != "attention" || m.N != 1 {
		t.Fatalf("unapproved measure = %+v", m)
	}
	if m := measure(view, "eol"); m.N != 1 { // pc-old (Windows 10) is left out, srv (Server 2016) stays
		t.Fatalf("eol = %+v", m)
	}
}

func measure(r PdplReport, id string) Measure {
	for _, m := range r.Measures {
		if m.ID == id {
			return m
		}
	}
	return Measure{}
}

func TestMeasuresNeverSayOkWithoutData(t *testing.T) { // INV-8, FORBID-3
	t.Parallel()
	r := pdplFor(fakeMods{}, okOrg()) // every optional module off
	for _, id := range []string{"logging", "honeypot", "scan", "backup"} {
		if m := measure(r, id); m.Status != "unknown" {
			t.Errorf("%s = %s with its module off, want unknown", id, m.Status)
		}
	}
	on := pdplFor(fakeMods{"logs": true, "honeypot": true, "scan": true}, okOrg())
	if measure(on, "logging").Status != "ok" || measure(on, "scan").Status != "ok" {
		t.Error("a module that is on may count as ok")
	}
	if measure(on, "backup").Status != "unknown" {
		t.Error("backup is never visible to the box")
	}
}

func TestMeasuresFromDevices(t *testing.T) {
	t.Parallel()
	r := pdplFor(fakeMods{}, okOrg())
	if m := measure(r, "firewall"); m.Status != "ok" {
		t.Errorf("firewall = %+v", m)
	}
	if m := measure(r, "eol"); m.Status != "attention" || m.N != 2 {
		t.Errorf("eol = %+v", m)
	}
	if m := measure(r, "patching"); m.Status != "attention" || m.N != 2 || m.Names[0] != "CVE-2026-0001" {
		t.Errorf("patching = %+v", m)
	}
	if m := measure(r, "unapproved"); m.N != 1 || m.Names[0] != "pc-old" {
		t.Errorf("unapproved = %+v", m)
	}
	in := pdplSample()
	in.devices[0].Kind = "switch"
	in.devices[2].Ports = []int{22, 3389}
	r = buildPdpl(pdplInput{devices: in.devices, findings: nil, modules: fakeMods{"feeds": true, "scan": true}, org: okOrg(), id: "x", now: t0})
	if measure(r, "firewall").Status != "attention" || measure(r, "remote").N != 1 || measure(r, "patching").Status != "ok" {
		t.Errorf("measures = %+v", r.Measures)
	}
}

func TestObligations(t *testing.T) {
	t.Parallel()
	o := okOrg()
	o.Sensitive = true
	o.ContactEmail = ""
	r := pdplFor(fakeMods{}, o)
	by := map[string]Obligation{}
	for _, ob := range r.Obligations {
		by[ob.ID] = ob
	}
	if len(r.Obligations) != 7 || by["dpia"].Regime != "required" || by["breach"].Regime != "required" {
		t.Fatalf("obligations = %+v", r.Obligations)
	}
	if by["dpia"].Done != nil || by["breach"].Done != nil || by["consent"].Done != nil {
		t.Fatal("the box cannot know whether a dossier was filed: done must be null")
	}
	if by["dpo"].Done == nil || *by["dpo"].Done {
		t.Fatal("dpo done needs a contact name and email")
	}
	if !by["sensitive"].Applies || by["cross_border"].Applies || by["processors"].Applies {
		t.Fatalf("applies = %+v", by)
	}
}

func TestPdplInventoryBlock(t *testing.T) {
	t.Parallel()
	in := pdplSample()
	in.devices[0].Sources = []string{"snmp", "nmap"}
	in.devices[1].Sources = []string{"nmap"}
	r := buildPdpl(pdplInput{devices: in.devices, modules: nil, org: okOrg(), id: "x", now: t0})
	if r.Inventory.Total != 3 || r.Inventory.Unapproved != 1 || r.Inventory.Approved != 2 {
		t.Fatalf("inventory = %+v", r.Inventory)
	}
	if len(r.Inventory.KeySystems) != 2 || r.Inventory.Sources[0] != (SourceCount{"nmap", 2}) {
		t.Fatalf("key systems / sources = %+v", r.Inventory)
	}
	for _, c := range r.Coverage {
		if c.On {
			t.Fatalf("a nil module registry means nothing is on: %+v", r.Coverage)
		}
	}
}

func TestNothingFoundIsOkOnlyWhenTheBoxCouldLook(t *testing.T) { // INV-8, FORBID-3
	t.Parallel()
	in := pdplSample()
	clean := []Device{{ID: "d", Name: "d", Kind: "firewall", Approved: true, OS: "FortiOS"}}
	for _, c := range []struct {
		name string
		devs []Device
		mods fakeMods
		id   string
		want string
	}{
		{"no devices: unapproved", nil, fakeMods{"feeds": true, "scan": true}, "unapproved", "unknown"},
		{"no devices: eol", nil, fakeMods{"feeds": true, "scan": true}, "eol", "unknown"},
		{"no devices: firewall", nil, fakeMods{"feeds": true, "scan": true}, "firewall", "unknown"},
		{"scan off: remote", clean, fakeMods{"feeds": true}, "remote", "unknown"},
		{"scan on: remote", clean, fakeMods{"scan": true}, "remote", "ok"},
		{"feeds off: patching", clean, fakeMods{"scan": true}, "patching", "unknown"},
		{"feeds on: patching", clean, fakeMods{"feeds": true}, "patching", "ok"},
		{"nil registry: patching", clean, nil, "patching", "unknown"},
	} {
		var mods Modules
		if c.mods != nil {
			mods = c.mods
		}
		r := buildPdpl(pdplInput{devices: c.devs, findings: nil, kev: in.kev, modules: mods, org: okOrg(), id: "x", now: t0})
		if got := measure(r, c.id).Status; got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
