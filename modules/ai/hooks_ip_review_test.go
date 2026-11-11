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
	} {
		res := run(t, r, BeforeAI, in)
		if res.Outcome == OutcomePass || strings.IndexFunc(res.Text, unicode.IsDigit) >= 0 {
			t.Errorf("%q -> %+v, want every digit masked", in, res)
		}
	}
}

// A phone number written right after "::" is not part of the address (L1).
func TestPhoneAfterDoubleColonIsMasked(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	for _, in := range []string{"2001:db8::0912 345 678", "Tel::0912 345 678", "a:b:c:d:e:f:1:0912 345 678", "fe80::1 0912345678"} {
		res := run(t, r, BeforeAI, in)
		for _, d := range []string{"0912", "912", "345", "678"} {
			if strings.Contains(res.Text, d) {
				t.Errorf("%q -> %q: phone digits %q survive", in, res.Text, d)
			}
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

// Linear time on hostile input (M1, M1b): 512 KiB of it costs about what 512 KiB of plain text costs. Compared with plain text of the
// same size, not with a fixed time, so it holds under -race and on a loaded box; the quadratic versions took 3-25 s here against
// a fraction of a second.
func TestHostileInputIsLinear(t *testing.T) {
	const top = 1<<19 - 16
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
