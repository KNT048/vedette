package reports

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/apierr"
)

var (
	// ponytail: plain addresses only (no quoted local parts, no ; or ,), the form notify can always send to. Upgrade path: net/mail.
	emailRE = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$`)
	taxRE   = regexp.MustCompile(`^\d{10}(-\d{3})?$`)
	phoneRE = regexp.MustCompile(`^(0|\+84)\d{9,10}$`)
)

// MaxRecipients is the longest recipient list (INV-3).
const MaxRecipients = 20

func bad(code, format string, a ...any) *apierr.Error {
	return apierr.New(400, code, fmt.Sprintf(format, a...))
}

func validEmail(s string) bool {
	return len(s) <= 120 && emailRE.MatchString(s) && !hasControl(s)
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// checkSchedule validates the body of PUT /reports/schedule at the boundary (INV-3) and returns it normalised: addresses
// trimmed, lower-cased, without duplicates.
func checkSchedule(in ScheduleInput) (ScheduleInput, *apierr.Error) {
	if in.Day < 1 || in.Day > 7 {
		return in, bad("invalid_day", "Pick a day of the week.")
	}
	if in.Hour < 0 || in.Hour > 23 {
		return in, bad("invalid_hour", "The send hour must be 0 to 23.")
	}
	if len(in.Recipients) > MaxRecipients {
		return in, bad("invalid_recipients", "The recipient list holds %d emails at most.", MaxRecipients)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in.Recipients))
	for _, e := range in.Recipients {
		e = strings.TrimSpace(e)
		if !validEmail(e) {
			return in, bad("invalid_email", "The email %q is not valid. Use the form name@company.com.", clipRunes(e, 60))
		}
		if e = strings.ToLower(e); !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if in.Enabled && len(out) == 0 {
		return in, bad("no_recipients", "Automatic sending needs at least one recipient. Add an email, then save.")
	}
	in.Recipients = out
	return in, nil
}

func clipRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

func runes(s string) int { return utf8.RuneCountInString(s) }

// field trims a text field and refuses control characters, so nothing that reaches a header, a log or a page carries them.
func field(s string) (string, bool) {
	s = strings.TrimSpace(s)
	return s, !hasControl(s)
}

// checkOrg validates every field of the organisation form when it is saved (INV-8) and returns it normalised.
func checkOrg(o PdplOrg) (PdplOrg, *apierr.Error) {
	var ok bool
	if o.Name, ok = field(o.Name); !ok || runes(o.Name) < 2 || runes(o.Name) > 120 {
		return o, bad("invalid_name", "The organisation name must be 2 to 120 characters.")
	}
	if o.TaxCode, ok = field(o.TaxCode); !ok || !taxRE.MatchString(o.TaxCode) {
		return o, bad("invalid_tax_code", "The tax code is 10 digits, or 10 digits, a dash and 3 digits for a branch. Example 0312345678.")
	}
	if o.Address, ok = field(o.Address); !ok || runes(o.Address) < 5 || runes(o.Address) > 200 {
		return o, bad("invalid_address", "Enter the head office address (5 to 200 characters).")
	}
	if o.Sector, ok = field(o.Sector); !ok || runes(o.Sector) < 2 || runes(o.Sector) > 80 {
		return o, bad("invalid_sector", "Pick the field of activity.")
	}
	if o.Employees < 0 || o.Employees > 1_000_000 {
		return o, bad("invalid_employees", "Headcount is a whole number from 0 to 1,000,000.")
	}
	switch o.Size {
	case "household", "micro", "small", "startup", "other":
	default:
		return o, bad("invalid_size", "Pick the organisation size. It decides whether you must file an impact assessment dossier and appoint a data protection person.")
	}
	switch o.DataVolume {
	case "lt1k", "1k_10k", "10k_100k", "gte100k":
	default:
		return o, bad("invalid_volume", "Pick how many people's personal data you hold.")
	}
	if o.ContactName, ok = field(o.ContactName); !ok || runes(o.ContactName) < 2 || runes(o.ContactName) > 80 {
		return o, bad("invalid_contact", "Enter the name of the person in charge of data protection.")
	}
	if o.ContactEmail, ok = field(o.ContactEmail); !ok || len(o.ContactEmail) > 120 || !emailRE.MatchString(o.ContactEmail) {
		return o, bad("invalid_email", "The contact email is not valid. Use the form name@company.com.")
	}
	phone := strings.NewReplacer(" ", "", ".", "").Replace(strings.TrimSpace(o.ContactPhone))
	if !phoneRE.MatchString(phone) {
		return o, bad("invalid_phone", "The phone number starts with 0 or +84 and has 10 to 11 digits.")
	}
	o.ContactPhone = phone
	switch o.Level {
	case "", "1", "2", "3", "4", "5":
	default:
		return o, bad("invalid_level", "The information system level is 1 to 5, or leave it empty if not determined yet.")
	}
	return o, nil
}
