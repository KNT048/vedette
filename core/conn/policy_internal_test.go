package conn

import (
	"net/netip"
	"strings"
	"testing"
)

// All of 0.0.0.0/8 is "this network" (RFC 1122 3.2.1.3), never a device address: the mock refuses it as an unspecified address,
// so the backend does, not only 0.0.0.0 itself.
func TestZeroNetworkIsRefusedLikeTheMock(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		target string
		ssh    bool
	}{{"https://0.1.2.3", false}, {"https://0.0.0.1", false}, {"https://0.0.0.0", false}, {"0.1.2.3:22", true}, {"0.255.255.255", true}} {
		e := checkTarget(tc.target, tc.ssh, nil)
		if e == nil {
			t.Errorf("%q (ssh=%v) is accepted", tc.target, tc.ssh)
			continue
		}
		if !strings.Contains(e.Message, "an unspecified address") {
			t.Errorf("%q: message %q, want an unspecified address", tc.target, e.Message)
		}
	}
}

// An SSH host gets the same host-name check as the HTTP form, and every trailing dot is trimmed before the policy: "localhost.."
// is localhost, not an unknown name that the resolver may or may not reject at dial time.
func TestSSHTargetWithTrailingDotsIsRefusedAsTheHostItNames(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"localhost..:22", "localhost..", "127.0.0.1..:22", "api.localhost..:22", "169.254.169.254..:22", "-x:22"} {
		if e := checkTarget(target, true, nil); e == nil {
			t.Errorf("SSH target %q is accepted", target)
		}
	}
	for _, target := range []string{"https://localhost..", "https://127.0.0.1.."} {
		if e := checkTarget(target, false, nil); e == nil {
			t.Errorf("HTTP target %q is accepted", target)
		}
	}
	if e := checkTarget("sw-1.corp.example.:22", true, nil); e != nil {
		t.Errorf("a name with one trailing dot is refused: %v", e)
	}
}

// IPv6 forms that carry an IPv4 address can name 127.0.0.1 or 169.254.169.254 without the IPv4 spelling: refused at save time.
func TestIPv6FormsThatCarryAnIPv4AddressAreRefused(t *testing.T) {
	t.Parallel()
	for _, h := range []string{
		"[64:ff9b::7f00:1]", "[64:ff9b::a9fe:a9fe]", "[64:ff9b::192.168.10.1]", // NAT64
		"[2002:7f00:1::]", "[2002:c0a8:a01::1]", // 6to4
		"[::7f00:1]", "[::c0a8:a01]", "[::192.168.10.1]", // IPv4-compatible
		"[::ffff:0:7f00:1]", "[::ffff:0:0:0]", // IPv4-translated
		"[2001:0:4136:e378:8000:63bf:3fff:fdd2]", "[2001::1]", // Teredo
		"[::ffff:127.0.0.1]", "[::ffff:192.168.10.1]", // IPv4-mapped
	} {
		e := checkTarget("https://"+h, false, nil)
		if e == nil || e.Message != embeddedWhy {
			t.Errorf("%s: %v, want %q", h, e, embeddedWhy)
		}
	}
	// Loopback and unspecified IPv6 keep their own reasons; an ordinary global address is fine.
	if e := checkTarget("https://[::1]", false, nil); e == nil || !strings.Contains(e.Message, "a loopback address") {
		t.Errorf("[::1]: %v", e)
	}
	if e := checkTarget("https://[::]", false, nil); e == nil || !strings.Contains(e.Message, "an unspecified address") {
		t.Errorf("[::]: %v", e)
	}
	for _, ok := range []string{"https://[2001:db8::1]", "https://[2606:4700::1111]", "https://[fd00::1]"} {
		if e := checkTarget(ok, false, nil); e != nil {
			t.Errorf("%s was refused: %v", ok, e)
		}
	}
}

// A subnet of the box is refused whole, and the dial-time check uses the same function.
func TestBoxSubnetsAreRefusedWhole(t *testing.T) {
	t.Parallel()
	box := []netip.Prefix{netip.MustParsePrefix("10.88.0.0/16"), netip.MustParsePrefix("192.168.10.250/32")}
	for target, refused := range map[string]bool{"https://10.88.3.4": true, "https://10.88.0.1": true, "https://192.168.10.250": true, "https://192.168.10.251": false, "https://10.89.0.1": false} {
		e := checkTarget(target, false, box)
		if (e != nil) != refused || (e != nil && !strings.Contains(e.Message, "the box itself")) {
			t.Errorf("%s: %v, refused = %v", target, e, refused)
		}
	}
	if why := RefusedAddr(netip.MustParseAddr("10.88.9.9"), box); why != "the box itself" {
		t.Errorf("RefusedAddr in the subnet = %q", why)
	}
	if why := RefusedAddr(netip.MustParseAddr("::ffff:10.88.9.9"), box); why == "" {
		t.Error("RefusedAddr let an IPv4-mapped address of the box subnet through")
	}
	if why := RefusedAddr(netip.MustParseAddr("192.168.10.1"), box); why != "" {
		t.Errorf("RefusedAddr refused an ordinary LAN address: %q", why)
	}
}

// The target has a length limit (the column's), and a query string or a fragment is not part of an address.
func TestTargetLengthQueryAndFragment(t *testing.T) {
	t.Parallel()
	long := "https://192.168.10.50/" + strings.Repeat("a", MaxTargetLen)
	if e := checkTarget(long, false, nil); e == nil || e.Code != "invalid_target" || e.Extra["field"] != "target" {
		t.Errorf("a target over %d characters: %v", MaxTargetLen, e)
	}
	if e := checkTarget("https://192.168.10.50/?q="+strings.Repeat("a", 2100), false, nil); e == nil || e.Code != "invalid_target" {
		t.Errorf("a long query: %v", e)
	}
	for _, target := range []string{"https://192.168.10.50/?a=b", "https://192.168.10.50/api#top", "https://192.168.10.50?", "https://192.168.10.50#"} {
		e := checkTarget(target, false, nil)
		if e == nil || e.Message != "The address must not include ? or #." || e.Extra["field"] != "target" {
			t.Errorf("%s: %v", target, e)
		}
	}
	if e := checkTarget("https://192.168.10.50/"+strings.Repeat("a", 2000), false, nil); e != nil {
		t.Errorf("a 2000-character path is refused: %v", e)
	}
}

// An allow-list entry cannot hide a path separator or a dot segment behind a backslash or percent-encoding.
func TestUnderRefusesBackslashAndEncodedSeparators(t *testing.T) {
	t.Parallel()
	const target = "https://h.example/api"
	for _, bad := range []string{`https://h.example/api/..\admin`, `https://h.example/api/x\y`, "https://h.example/api/%2e%2e/admin", "https://h.example/api/%2E%2E/admin",
		"https://h.example/api%2Fx", "https://h.example/api/x%5Cy", "https://h.example/api/..%2fadmin"} {
		if under(bad, target) {
			t.Errorf("%q is accepted as under %s", bad, target)
		}
	}
	for _, good := range []string{"https://h.example/api/", "https://h.example/api/v2/x", "https://h.example:443/api/v2", "https://h.example/api/a/./b"} {
		if !under(good, target) {
			t.Errorf("%q is refused", good)
		}
	}
	if under("https://h.example/api/../other", target) {
		t.Error("a dot segment climbed out of the target")
	}
}

// D-391: the reader and the writer refuse shell characters on every line, so an SSH allow-list entry holding one could never run;
// it is refused at save, with a field error.
func TestCheckAllowSSHRefusesShellCharacters(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"show version; reload", "show run | include x", "ls & id", "echo $HOME", "a`b`"} {
		_, e := checkAllow([]string{bad}, "192.168.10.30:22", true)
		if e == nil || e.Error() == "" || !strings.Contains(e.Error(), "cannot contain the characters") {
			t.Errorf("%q: got %v, want the shell-character refusal", bad, e)
		}
	}
	if _, e := checkAllow([]string{"show version", "uname -a", "ss -tlnp"}, "192.168.10.30:22", true); e != nil {
		t.Errorf("plain commands refused: %v", e)
	}
}
