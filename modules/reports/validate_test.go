package reports

import (
	"strings"
	"testing"
)

func TestCheckScheduleRejects(t *testing.T) {
	t.Parallel()
	many := make([]string, 21)
	for i := range many {
		many[i] = strings.Repeat("a", i+1) + "@x.example"
	}
	for _, c := range []struct {
		name string
		in   ScheduleInput
		code string
	}{
		{"day 0", ScheduleInput{Day: 0, Hour: 8}, "invalid_day"},
		{"day 8", ScheduleInput{Day: 8, Hour: 8}, "invalid_day"},
		{"hour 24", ScheduleInput{Day: 1, Hour: 24}, "invalid_hour"},
		{"hour -1", ScheduleInput{Day: 1, Hour: -1}, "invalid_hour"},
		{"21 recipients", ScheduleInput{Day: 1, Hour: 8, Recipients: many}, "invalid_recipients"},
		{"no at", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{"nobody"}}, "invalid_email"},
		{"header injection", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{"a@x.example\r\nBcc: b@y.example"}}, "invalid_email"},
		{"semicolon", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{"a;b@x.example"}}, "invalid_email"},
		{"comma", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{"a,b@x.example"}}, "invalid_email"},
		{"space inside", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{"a b@x.example"}}, "invalid_email"},
		{"too long", ScheduleInput{Day: 1, Hour: 8, Recipients: []string{strings.Repeat("a", 120) + "@x.example"}}, "invalid_email"},
		{"on without recipients", ScheduleInput{Enabled: true, Day: 1, Hour: 8}, "no_recipients"},
	} {
		_, err := checkSchedule(c.in)
		if err == nil || err.Code != c.code {
			t.Errorf("%s: err = %v, want %s", c.name, err, c.code)
		}
	}
}

func TestCheckScheduleNormalises(t *testing.T) {
	t.Parallel()
	got, err := checkSchedule(ScheduleInput{Enabled: true, Day: 7, Hour: 23, Recipients: []string{" Boss@Acme.Example ", "boss@acme.example", "it@acme.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Recipients) != 2 || got.Recipients[0] != "boss@acme.example" {
		t.Fatalf("recipients = %v", got.Recipients)
	}
	if _, err := checkSchedule(ScheduleInput{Day: 1, Hour: 8}); err != nil {
		t.Fatalf("an off schedule with no recipients is fine: %v", err)
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
