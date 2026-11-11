package ai

import (
	"strings"
	"testing"
	"time"
	"unicode"
)

// A dotted phone number whose dotted part is also a valid IPv4 address is a phone number (H1): all of these were masked
// before IP literals were skipped, and stay masked.
func TestDottedPhoneNumbersThatLookLikeAnIPv4AreMasked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{
		"+84 91.234.56.78", "+84.91.234.56.78", "84.91.234.56.78", "(+84) 91.234.56.78", "+84-91.234.56.78",
		"call +84 91.234.56.78 now", "Fax:84.91.234.56.78", "+84 98.123.45.67", "+84 35.212.34.56",
		"+33 6.12.34.56.78", "+33.6.12.34.56.78", "+33 1.23.45.67.89", "+41 79.123.45.67",
		"+84 ９１．２３４．５６．７８", "+84 91。234。56。78", "+84 91.2\u200b34.56.78", "+٨٤ ٩١.٢٣٤.٥٦.٧٨",
		"0 91.234.56.78", "+33 6 12.34.56.78", "06.12.34.56.78",
		// a label glued to the prefix is no reason to read the number as an address (R2 H-1)
		"Tel-84 91.234.56.78", "Phone-84 91.234.56.78", "Zalo-0 98.123.45.67", "SDT-0 91.234.56.78", "Tel-84-91.234.56.78",
		"Tel-84 9 1.234.56.78", "Tel-84 (91.234.56.78)", "Tel-84.91.234.56.78", "Tel\u200b-84 91.234.56.78", "Tel-\u200b84 91.234.56.78",
		"Tel-８４ ９１.２３４.５６.７８", "X-0912.345.67.89", "a-b-0 91.234.56.78",
		"(84) 91.234.56.78", "84 91.234.56.78", "(0) 91.234.56.78", "84\n91.234.56.78",
	} {
		res := run(t, r, BeforeAI, in)
		if res.Outcome == OutcomePass || strings.IndexFunc(res.Text, unicode.IsDigit) >= 0 {
			t.Errorf("%q -> %+v, want every digit masked", in, res)
		}
	}
}

// A phone number written right after "::" is not part of the address (L1), nor one right before it (R2 M-1).
func TestPhoneAfterDoubleColonIsMasked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for in, forbidden := range map[string][]string{
		"2001:db8::0912 345 678":     {"0912", "912", "345", "678"},
		"Tel::0912 345 678":          {"0912", "912", "345", "678"},
		"a:b:c:d:e:f:1:0912 345 678": {"0912", "912", "345", "678"},
		"fe80::1 0912345678":         {"0912", "912", "345", "678"},
		"0912 345 678::1":            {"0912", "912", "345", "678"},
		"call 0912 345 678:: now":    {"0912", "912", "345", "678"},
		"+84 912 345 678::1":         {"912", "345", "678"},
		"+8451-035. 003::":           {"8451", "035", "003"},
		"0912.345.678::1":            {"0912", "912", "345", "678"},
		// R3 M-1: an edge group that mixes hex letters and digits is still the end of a number
		"0912 345 678a::1": {"0912", "912", "345", "678"},
		"0912-345-678b::":  {"0912", "912", "345", "678"},
		"０９１２ ３４５ ６７８ａ：：１":       {"０９１２", "３４５", "６７８"},
		"0912 345 678\u200ca::1": {"0912", "912", "345", "678"},
		"+84 912 345 678e::1":    {"912", "345", "678"},
		"84.32.175.88)7a5::+1":   {"32.175", "88)7"},
		// R3 L-1: an address glued to +cc and a long number leaves no tail
		"::1+84255.255.255.255": {".255.255"},
	} {
		res := run(t, r, BeforeAI, in)
		for _, d := range forbidden {
			if strings.Contains(res.Text, d) {
				t.Errorf("%q -> %q: phone digits %q survive", in, res.Text, d)
			}
		}
	}
}

// An ID number next to "::" or inside an address's edge group is still an ID number (R2 M-2).
func TestIDNumbersNextToAnIPv6AreBlocked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{"::123 456 789", "fe80::123 456 789", "2001:db8::0790 1234 5678", "123 456 789::1", "0790 1234 5678::1", "::079 012 345 678",
		"123 456 789a::1", "fe80::a123 456 789", "2001:db8::f226   079560", "079 012 345 678a::1", "fe80::b079 012 345 678"} { // R3 M-1
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeBlocked {
			t.Errorf("%q -> %+v, want blocked", in, res)
		}
	}
}

// The device lines the AI is sent (cmd/vedette/ai_plan.go and ai.go: "Device: <name>, IP <ip>, kind <kind>") keep the address; the
// address is never glued to the name, so a name can not be read as the start of a number.
func TestDeviceLinesKeepTheAddress(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{
		"Device: NAS-01, IP 192.168.1.20, kind nas", "Device: Camera 0042, IP 192.168.100.42, kind camera", "Device: srv-0, IP 84.32.175.88, kind server",
		"Device: NAS 01, IP fe80::1, kind nas", "Device: NAS-0912, IP 10.0.0.5, kind nas", "Device: cam-2, IP 2001:db8::0912, kind camera",
		"Device: NAS-01, IP 192.168.1.20, kind nas, Fortinet FortiGate\nFinding status: open, severity critical, matched by cpe, confidence 0.90\n",
	} {
		if res := run(t, r, BeforeAI, in); res.Text != in {
			t.Errorf("%q -> %q, want it kept", in, res.Text)
		}
	}
}

// Dotted digits that are not an address are ID-shaped (L2): the old exclusion for "any four dotted groups" is gone, because real
// addresses are blanked before the ID finder looks.
func TestDottedIDNumbersAreBlocked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{"001.085.012.245", "CCCD: 079.095.012.245", "079.195.012.045", "001.085.012.345"} {
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeBlocked {
			t.Errorf("%q -> %+v, want blocked", in, res)
		}
	}
}

// Linear time on hostile input (M1, M1b): hostileSize bytes of it cost about what as much plain text costs. Compared with plain text of the
// same size, not with a fixed time, so it holds under -race and on a loaded box; the quadratic versions took 3-25 s here against
// a fraction of a second.
func TestHostileInputIsLinear(t *testing.T) {
	const top = hostileSize - 16
	timeOf := func(in string) time.Duration {
		start := time.Now()
		if _, err := runner(t, nil).Run(bg, BeforeAI, in); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	plain := strings.Repeat("The firewall log shows a blocked probe. ", top/40)
	base := min(timeOf(plain), timeOf(plain))
	for name, in := range map[string]string{
		"dots after a colon": "1:" + strings.Repeat(".", top),
		"hex groups":         strings.Repeat("1:", top/2),
		"ids among zeros":    strings.Repeat("123456789, ", top/22) + strings.Repeat("0 ", top/4),
		"zeros and spaces":   strings.Repeat("0 ", top/2),
		"ids and phones":     strings.Repeat("123456789, 0912345678, ", top/23),
		"dotted digits":      strings.Repeat("1.", top/2),
		"addresses":          strings.Repeat("10.0.0.1 ", top/9),
	} {
		d := timeOf(in)
		t.Logf("%-26s %8d bytes %v (plain text %v)", name, len(in), d, base)
		if d > 8*base+500*time.Millisecond {
			t.Errorf("%s: %v for %d bytes, plain text of the same size takes %v", name, d, len(in), base)
		}
	}
}
