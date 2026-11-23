package reports

import (
	"fmt"
	"strings"
	"testing"
)

func TestCheckDefinition(t *testing.T) {
	t.Parallel()
	ok := DefinitionInput{Name: "Security report", Options: DefaultOptions, Recipients: []string{}}
	if _, err := checkDefinition(ok); err != nil {
		t.Fatalf("the default was refused: %v", err)
	}
	many := make([]string, MaxRecipients+1)
	for i := range many {
		many[i] = fmt.Sprintf("u%d@acme.example", i)
	}
	for _, c := range []struct {
		name        string
		edit        func(*DefinitionInput)
		code, field string
	}{
		{"blank name", func(d *DefinitionInput) { d.Name = " " }, "invalid_name", "name"},
		{"long name", func(d *DefinitionInput) { d.Name = strings.Repeat("x", 81) }, "invalid_name", "name"},
		{"control in name", func(d *DefinitionInput) { d.Name = "a\nb" }, "invalid_name", "name"},
		{"period", func(d *DefinitionInput) { d.Options.Period = "yearly" }, "invalid_period", "options.period"},
		{"grouping", func(d *DefinitionInput) { d.Options.Grouping = "site" }, "invalid_grouping", "options.grouping"},
		{"no section", func(d *DefinitionInput) { d.Options.Sections = Sections{} }, "no_sections", "options.sections"},
		{"too many", func(d *DefinitionInput) { d.Recipients = many }, "invalid_recipients", "recipients"},
		{"bad email", func(d *DefinitionInput) { d.Recipients = []string{"ok@acme.example", "not-an-email"} }, "invalid_email", "recipients[1]"},
		{"crlf email", func(d *DefinitionInput) { d.Recipients = []string{"a@acme.example\r\nBcc: x@y.example"} }, "invalid_email", "recipients[0]"},
	} {
		d := ok
		c.edit(&d)
		_, err := checkDefinition(d)
		if err == nil || err.Code != c.code || err.Extra["field"] != c.field {
			t.Errorf("%s: err = %v %v, want %s on %s", c.name, err, err, c.code, c.field)
		}
	}
}

func TestCheckOrg(t *testing.T) {
	t.Parallel()
	if _, err := checkOrg(okOrg()); err != nil {
		t.Fatalf("a valid organisation was refused: %v", err)
	}
	for _, c := range []struct {
		name string
		edit func(*PdplOrg)
		code string
	}{
		{"short name", func(o *PdplOrg) { o.Name = "A" }, "invalid_name"},
		{"control in name", func(o *PdplOrg) { o.Name = "Ac\x00me" }, "invalid_name"},
		{"newline in name", func(o *PdplOrg) { o.Name = "Acme\nLtd" }, "invalid_name"},
		{"bidi in name", func(o *PdplOrg) { o.Name = "Acme\u202eLtd" }, "invalid_name"},
		{"tax code letters", func(o *PdplOrg) { o.TaxCode = "03123456AB" }, "invalid_tax_code"},
		{"tax code 9 digits", func(o *PdplOrg) { o.TaxCode = "031234567" }, "invalid_tax_code"},
		{"short address", func(o *PdplOrg) { o.Address = "1" }, "invalid_address"},
		{"no sector", func(o *PdplOrg) { o.Sector = "" }, "invalid_sector"},
		{"negative staff", func(o *PdplOrg) { o.Employees = -1 }, "invalid_employees"},
		{"huge staff", func(o *PdplOrg) { o.Employees = 1_000_001 }, "invalid_employees"},
		{"size", func(o *PdplOrg) { o.Size = "giant" }, "invalid_size"},
		{"volume", func(o *PdplOrg) { o.DataVolume = "" }, "invalid_volume"},
		{"contact name", func(o *PdplOrg) { o.ContactName = "" }, "invalid_contact"},
		{"contact email", func(o *PdplOrg) { o.ContactEmail = "an@" }, "invalid_email"},
		{"contact email crlf", func(o *PdplOrg) { o.ContactEmail = "an@acme.example\r\nX: y" }, "invalid_email"},
		{"phone", func(o *PdplOrg) { o.ContactPhone = "12345" }, "invalid_phone"},
		{"level", func(o *PdplOrg) { o.Level = "9" }, "invalid_level"},
	} {
		o := okOrg()
		c.edit(&o)
		if _, err := checkOrg(o); err == nil || err.Code != c.code {
			t.Errorf("%s: err = %v, want %s", c.name, err, c.code)
		}
	}
	o := okOrg()
	o.ContactPhone = "+84 901.234.567"
	o.TaxCode = " 0312345678-001 "
	got, err := checkOrg(o)
	if err != nil || got.ContactPhone != "+84901234567" || got.TaxCode != "0312345678-001" {
		t.Fatalf("normalised = %+v, %v", got, err)
	}
}
