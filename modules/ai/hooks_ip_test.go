package ai

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
)

// IP address literals are not phone numbers (INV-12, D-205): the phone finder must never match inside or across one,
// and a real phone number next to one is still masked, never the address.
func TestPhoneFinderLeavesIPAddressesAlone(t *testing.T) {
	t.Parallel()
	r := runner(t, nil)
	kept := []string{
		"NAS-01 (192.168.1.20)",
		"Camera-0042 (192.168.100.42)",
		"10.0.0.5",
		"fw-edge-2 (172.16.4.1)",
		"host 192.168.1.200:8443",
		"192.168.1.0/24",
		"fe80::1", "2001:db8::42", "[2001:db8::1]:443", "::ffff:192.168.1.20", "::1",
		"00:11:22:33:44:55",
		"Device: NAS-01 (192.168.1.20), kind nas\nFinding: CVE-2024-3400\n",
		"Device: Camera-0042 (192.168.100.42), kind camera\nFinding: CVE-2024-12345\n",
		"Device: fw-edge-2 (fe80::1), kind firewall\nFinding: CVE-2024-3400\n",
	}
	for _, in := range kept {
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomePass || res.Text != in {
			t.Errorf("%q -> %+v, want it kept as is", in, res)
		}
	}
	masked := map[string]string{
		"0912 345 678":                       "[masked]",
		"+84 912 345 678":                    "[masked]",
		"(028) 3822 1234":                    "[masked]",
		"call 0912 345 678 at 192.168.1.20":  "call [masked] at 192.168.1.20",
		"192.168.1.20 0912345678":            "192.168.1.20 [masked]",
		"(0912) 345 678 192.168.1.20":        "[masked] 192.168.1.20",
		"NAS-01 (0912 345 678)":              "NAS-[masked][masked])", // the "01" before the bracket reads as the start of a number too: over-masking, never a leak
		"NAS-01 (192.168.1.20) 0912 345 678": "NAS-01 (192.168.1.20) [masked]",
		"0912 345 678 fe80::1":               "[masked] fe80::1",
		"+1 415-555-2671 on 10.0.0.5":        "[masked] on 10.0.0.5",
		"mail a@b.com on 192.168.1.20":       "mail [masked] on 192.168.1.20",
	}
	for in, want := range masked {
		if res := run(t, r, BeforeAI, in); res.Text != want {
			t.Errorf("%q -> %q, want %q", in, res.Text, want)
		}
	}
	// An ID number next to an address is blocked however they are joined: the address is never part of the ID's digit run.
	for _, in := range []string{
		"ID 079012345678 on 192.168.1.20",
		"192.168.1.20 079012345678",
		"079012345678 192.168.1.20",
		"192.168.1.20, 123456789",
		"192.168.1.20:079012345678",
		"192.168.1.20 (079012345678)",
		"192.168.1.20 079 012 345 678",
		"fe80::1 079012345678",
		"079012345678 fe80::1",
	} {
		if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeBlocked {
			t.Errorf("%q: %+v, want blocked as an ID number", in, res)
		}
	}
}

func randomIP(rng *rand.Rand) string {
	if rng.IntN(2) == 0 {
		return fmt.Sprintf("%d.%d.%d.%d", rng.IntN(256), rng.IntN(256), rng.IntN(256), rng.IntN(256))
	}
	var b [16]byte
	for i := range b {
		b[i] = byte(rng.IntN(256)) //nolint:gosec // 0..255
	}
	if rng.IntN(2) == 0 { // short forms with ::
		for i := 2 + rng.IntN(8); i < 14; i++ {
			b[i] = 0
		}
	}
	return netip.AddrFrom16(b).String()
}

func FuzzPhoneFinderIPLiteral(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(40), uint64(7))
	f.Fuzz(func(t *testing.T, a, b uint64) {
		rng := rand.New(rand.NewPCG(a, b)) //nolint:gosec // a seeded generator for a test
		r := runner(t, nil)
		ip := randomIP(rng)
		if _, err := netip.ParseAddr(ip); err != nil {
			t.Fatal(err)
		}
		// A valid address alone is kept exactly (the text may look like a number: nothing is masked).
		if res := run(t, r, BeforeAI, ip); res.Text != ip {
			t.Fatalf("%q -> %q", ip, res.Text)
		}
		// A phone number joined to it: the phone digits never reach the output, the address does.
		seps := []string{" ", ", ", " - ", ";", "\n", "\t", " (", ") ", "-", "|", "/"}
		sep := seps[rng.IntN(len(seps))]
		id := []string{"079012345678", "123456789", "079 012 345 678", "123 456 789"}[rng.IntN(4)]
		for _, in := range []string{id + sep + ip, ip + sep + id} {
			if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeBlocked {
				t.Fatalf("%q: not blocked as an ID number: %+v", in, res)
			}
		}
		phone := []string{"0912345678", "0912 345 678", "+84 912 345 678", "(028) 3822 1234", "+1 415-555-2671"}[rng.IntN(5)]
		for _, in := range []string{phone + sep + ip, ip + sep + phone} {
			res := run(t, r, BeforeAI, in)
			if res.Outcome != OutcomeMasked {
				t.Fatalf("%q: %+v, want the phone masked", in, res)
			}
			out := res.Text
			if !strings.Contains(out, ip) {
				t.Fatalf("%q -> %q: the address was masked", in, out)
			}
			rest := strings.Replace(out, ip, "", 1)
			for _, d := range []string{"912345678", "912 345 678", "3822 1234", "415-555-2671"} {
				if strings.Contains(rest, d) {
					t.Fatalf("%q -> %q: phone digits reached the output", in, out)
				}
			}
		}
	})
}
