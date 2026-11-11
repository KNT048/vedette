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

// phoneParts is a random phone number that the finder knows shapes for: a prefix, then 8-10 digits (7-12 after +cc other than 84)
// in groups of 2-4 joined by random phone separators (dots included).
func phoneParts(rng *rand.Rand) (text string, groups []string, digits int) {
	prefixes := []struct {
		text   string
		digits int
		lo, hi int
	}{{"+84", 2, 8, 10}, {"84", 2, 8, 10}, {"0", 1, 8, 10}, {"(+84)", 2, 8, 10}, {"(0)", 1, 8, 10}, {"+33", 2, 7, 12}, {"+1", 1, 7, 12}, {"+41", 2, 7, 12}}
	pf := prefixes[rng.IntN(len(prefixes))]
	seps := []string{" ", ".", "-", "  ", ". ", " -", "."}
	n := pf.lo + rng.IntN(pf.hi-pf.lo+1)
	var b strings.Builder
	b.WriteString(pf.text)
	b.WriteString([]string{"", " ", ".", "-", " "}[rng.IntN(5)])
	for left, first := n, true; left > 0; first = false {
		g := min(left, 2+rng.IntN(3))
		if left-g == 1 {
			g = left
		}
		if !first {
			b.WriteString(seps[rng.IntN(len(seps))])
		}
		var d strings.Builder
		for range g {
			d.WriteByte(byte('0' + rng.IntN(10))) //nolint:gosec // a digit
		}
		groups = append(groups, d.String())
		b.WriteString(d.String())
		left -= g
	}
	return b.String(), groups, pf.digits + n
}

// FuzzPhoneDigitsNeverSurvive: a phone number of a known shape, with random context around it (adjacent addresses
// included), never reaches the output as a group of two or more of its digits. A blocked text sends nothing, so
// blocked counts as safe only when the digits are ID-shaped: the number's own (9 or 12 in all), or its digits and an address next to it.
func FuzzPhoneDigitsNeverSurvive(f *testing.F) {
	for _, seed := range [][2]uint64{{1, 2}, {40, 7}, {3, 3}, {9, 99}, {123, 456}, {777, 1}, {5, 5}, {8, 13}, {21, 34}, {55, 89}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, a, b uint64) {
		rng := rand.New(rand.NewPCG(a, b)) //nolint:gosec // a seeded generator for a test
		r := runner(t, nil)
		phone, groups, digits := phoneParts(rng)
		ip := randomIP(rng)
		lefts := []string{"", "call ", "Fax:", "NAS-01 (", ip + " ", ip + ", ", ip + " - ", ip + "\n"}
		rights := []string{"", " now", ")", " " + ip, ", " + ip, " (" + ip + ")", "\n" + ip}
		l, rt := lefts[rng.IntN(len(lefts))], rights[rng.IntN(len(rights))]
		in := l + phone + rt
		res := run(t, r, BeforeAI, in)
		// (an address right after a number, with nothing but separators between, makes a dotted run that is ID-shaped too)
		if res.Outcome == OutcomeBlocked && (digits == 9 || digits == 12 || strings.Contains(l+rt, ip)) {
			return
		}
		if res.Outcome != OutcomeMasked {
			t.Fatalf("%q -> %+v: want masked", in, res)
		}
		context := l + rt
		for _, g := range groups {
			if strings.Contains(res.Text, g) && !strings.Contains(context, g) {
				t.Fatalf("%q -> %q: the digits %q of the phone number reached the output", in, res.Text, g)
			}
		}
	})
}

// FuzzIDNextToIP: an ID number joined to an address by any separator is blocked.
func FuzzIDNextToIP(f *testing.F) {
	f.Add(uint64(1), uint64(2))
	f.Add(uint64(40), uint64(7))
	f.Fuzz(func(t *testing.T, a, b uint64) {
		rng := rand.New(rand.NewPCG(a, b)) //nolint:gosec // a seeded generator for a test
		r := runner(t, nil)
		ip := randomIP(rng)
		// A valid address alone is kept exactly, except one that starts with a phone prefix and has the digits of a number
		// (84.255.255.255, 0.103.101.93): that is also a dotted phone number, so it is masked (fail closed).
		if res := run(t, r, BeforeAI, ip); res.Text != ip && !strings.HasPrefix(ip, "84.") && !strings.HasPrefix(ip, "0.") {
			t.Fatalf("%q -> %q", ip, res.Text)
		}
		seps := []string{" ", ", ", " - ", ";", "\n", "\t", " (", ") ", "-", "|", "/", ":"}
		sep := seps[rng.IntN(len(seps))]
		if sep == ":" && strings.Contains(ip, ":") {
			sep = " " // "678:4af9::1" is a valid address whose first group is the ID's tail: nothing to tell them apart
		}
		id := []string{"079012345678", "123456789", "079 012 345 678", "123 456 789"}[rng.IntN(4)]
		for _, in := range []string{id + sep + ip, ip + sep + id} {
			if res := run(t, r, BeforeAI, in); res.Outcome != OutcomeBlocked {
				t.Fatalf("%q: not blocked as an ID number: %+v", in, res)
			}
		}
	})
}
