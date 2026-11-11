package reports

import "testing"

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
		{"micro is exempt", func(o *PdplOrg) {}, "exempt"},
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
	in := sampleInput()
	return buildPdpl(pdplInput{devices: in.devices, findings: in.findings, kev: in.kev, modules: mods, org: org, id: "pdpl-1", now: t0})
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
	in := sampleInput()
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
	in := sampleInput()
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
	in := sampleInput()
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
