package sensoractive_test

import (
	"slices"
	"strconv"
	"testing"

	sa "github.com/knt048/vedette/modules/sensor-active"
	"github.com/knt048/vedette/modules/sensor-active/nmapargv"
)

// Attempts to get past ValidateNmapArgs (M3). Only the three templates, rate 1..1000 for
// sweep/normal, exactly 1 for gentle, "-oX -" right after the flags, 1..64 canonical unique RFC 1918 IPv4 targets.
func TestValidatorCannotBeBypassed(t *testing.T) {
	t.Parallel()
	sweep := func(r string) []string {
		return []string{"--privileged", "-sn", "-PE", "-PP", "-PS21,22,23,80,135,139,443,445,554,3389,8000,8080,9100", "-PA80,443", "-n", "--max-rate", r}
	}
	normal := func(r string) []string {
		return []string{"--privileged", "-sS", "-sV", "-O", "--osscan-limit", "--script", "rdp-ntlm-info,http-ntlm-info,http-title,ssl-cert", "-n", "--max-rate", r, "--max-retries", "3", "--host-timeout", "30m", "-p", nmapargv.LANPorts}
	}
	gentle := func(r string) []string {
		return []string{"--privileged", "-sS", "-n", "-T2", "--max-retries", "1", "--max-rate", r, "--host-timeout", "15m", "--top-ports", "100"}
	}
	with := func(flags []string, targets ...string) []string {
		return append(append(slices.Clone(flags), "-oX", "-"), targets...)
	}
	many := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, "10.0.0."+strconv.Itoa(i+1))
		}
		return out
	}
	ok := map[string][]string{
		"sweep 1":         with(sweep("1"), "10.0.0.1"),
		"sweep 1000":      with(sweep("1000"), "10.0.0.1"),
		"normal 1000":     with(normal("1000"), "192.168.0.1"),
		"gentle":          with(gentle("1"), "172.16.0.1"),
		"64 targets":      with(sweep("5"), many(64)...),
		"10/8 low edge":   with(sweep("5"), "10.0.0.0"),
		"10/8 high edge":  with(sweep("5"), "10.255.255.255"),
		"172.16/12 low":   with(sweep("5"), "172.16.0.0"),
		"172.16/12 high":  with(sweep("5"), "172.31.255.255"),
		"192.168/16 high": with(sweep("5"), "192.168.255.255"),
		"100.64/10 low":   with(sweep("5"), "100.64.0.0"), // RFC 6598 (D-461)
		"100.64/10 high":  with(sweep("5"), "100.127.255.255"),
	}
	for name, argv := range ok {
		if err := sa.ValidateNmapArgs(argv); err != nil {
			t.Errorf("%s: refused a valid argv %q: %v", name, argv, err)
		}
	}
	bad := map[string][]string{
		"rate 0":                    with(sweep("0"), "10.0.0.1"),
		"rate 1001":                 with(sweep("1001"), "10.0.0.1"),
		"rate 01":                   with(sweep("01"), "10.0.0.1"),
		"rate +5":                   with(sweep("+5"), "10.0.0.1"),
		"rate 5 space":              with(sweep(" 5"), "10.0.0.1"),
		"rate -1":                   with(sweep("-1"), "10.0.0.1"),
		"rate 99999":                with(normal("99999"), "10.0.0.1"),
		"gentle rate 2":             with(gentle("2"), "10.0.0.1"),
		"normal without -sV":        with(slices.DeleteFunc(normal("5"), func(s string) bool { return s == "-sV" }), "10.0.0.1"), // without -O it is the versions shape (D-501)
		"flags reordered":           with([]string{"-sn", "--privileged", "-n", "--max-rate", "5"}, "10.0.0.1"),
		"flag duplicated":           with(append(sweep("5"), "-n"), "10.0.0.1"),
		"max-rate twice":            with(append(sweep("5"), "--max-rate", "5"), "10.0.0.1"),
		"script appended":           with(append(normal("5"), "--script", "vuln"), "10.0.0.1"),
		"-oX first":                 append([]string{"-oX", "-"}, append(sweep("5"), "10.0.0.1")...),
		"-oX to a file":             append(sweep("5"), "-oX", "/tmp/x", "10.0.0.1"),
		"-oX - twice":               with(sweep("5"), "-oX", "-", "10.0.0.1"),
		"flag among targets":        with(sweep("5"), "10.0.0.1", "-iL", "/etc/passwd"),
		"no target":                 with(sweep("5")),
		"65 targets":                with(sweep("5"), many(65)...),
		"duplicate target":          with(sweep("5"), "10.0.0.1", "10.0.0.1"),
		"172.15.255.255":            with(sweep("5"), "172.15.255.255"),
		"172.32.0.0":                with(sweep("5"), "172.32.0.0"),
		"192.169.0.1":               with(sweep("5"), "192.169.0.1"),
		"192.167.255.255":           with(sweep("5"), "192.167.255.255"),
		"11.0.0.0":                  with(sweep("5"), "11.0.0.0"),
		"9.255.255.255":             with(sweep("5"), "9.255.255.255"),
		"public":                    with(sweep("5"), "8.8.8.8"),
		"loopback":                  with(sweep("5"), "127.0.0.1"),
		"link local":                with(sweep("5"), "169.254.1.1"),
		"below RFC 6598 (D-461)":    with(sweep("5"), "100.63.255.255"),
		"above RFC 6598 (D-461)":    with(sweep("5"), "100.128.0.0"),
		"multicast":                 with(sweep("5"), "224.0.0.1"),
		"broadcast":                 with(sweep("5"), "255.255.255.255"),
		"v4-mapped v6":              with(sweep("5"), "::ffff:10.0.0.1"),
		"v6 ULA":                    with(sweep("5"), "fd00::1"),
		"CIDR target":               with(sweep("5"), "10.0.0.0/24"),
		"range target":              with(sweep("5"), "10.0.0.1-5"),
		"leading zero":              with(sweep("5"), "10.0.0.01"),
		"hostname":                  with(sweep("5"), "printer.lan"),
		"trailing space":            with(sweep("5"), "10.0.0.1 "),
		"empty target":              with(sweep("5"), ""),
		"empty argv":                {},
		"gentle shape, normal rate": with(gentle("100"), "10.0.0.1"),
	}
	for name, argv := range bad {
		if err := sa.ValidateNmapArgs(argv); err == nil {
			t.Errorf("%s: accepted %q", name, argv)
		}
	}
}
