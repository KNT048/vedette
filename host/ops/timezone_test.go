package ops

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestValidateTimedatectlArgv(t *testing.T) {
	t.Parallel()
	for _, a := range [][]string{{"set-timezone", "UTC"}, {"set-timezone", "Asia/Ho_Chi_Minh"}, {"set-timezone", "America/Argentina/Buenos_Aires"}, {"set-timezone", "Etc/GMT+7"}} {
		if err := validateTimedatectl(a); err != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
	for _, a := range [][]string{
		nil, {}, {"set-timezone"}, {"set-timezone", "UTC", "x"}, {"set-time", "2026-11-24 10:00:00"}, {"set-ntp", "false"}, {"set-local-rtc", "1"},
		{"status"}, {"-H", "root@example.com", "set-timezone", "UTC"}, {"set-timezone", "--help"}, {"set-timezone", "../../etc/passwd"},
		{"set-timezone", "/etc/passwd"}, {"set-timezone", "right/UTC"}, {"set-timezone", ""}, {"set-timezone", "UTC\n"}, {"set-timezone", strings.Repeat("A", 65)},
	} {
		if err := validateTimedatectl(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
}

func TestZoneOfLink(t *testing.T) {
	t.Parallel()
	for target, want := range map[string]string{
		"/usr/share/zoneinfo/Asia/Ho_Chi_Minh": "Asia/Ho_Chi_Minh", "../usr/share/zoneinfo/Etc/UTC": "Etc/UTC", "/usr/share/zoneinfo/UTC": "UTC",
		"/etc/zoneinfo/../../etc/passwd": "", "/usr/share/zoneinfo/right/UTC": "", "/usr/share/zoneinfo/": "", "/etc/timezone": "", "": "",
	} {
		if got := api.ZoneOfLink(target); got != want {
			t.Errorf("ZoneOfLink(%q) = %q, want %q", target, got, want)
		}
	}
}
