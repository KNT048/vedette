package ai

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// When two fields hit different blocking hooks, the field that comes first in key order decides which one is reported.
func TestAfterHooksReportTheFirstFieldInKeyOrder(t *testing.T) {
	t.Parallel()
	r := runner(t, nil,
		CustomHook{ID: "a", Name: "A", When: AfterAI, Match: HookMatch{MatchKeywords, "alpha"}, Action: ActionBlock, Message: "A hit.", Enabled: true},
		CustomHook{ID: "b", Name: "B", When: AfterAI, Match: HookMatch{MatchKeywords, "beta"}, Action: ActionBlock, Message: "B hit.", Enabled: true})
	for range 100 {
		res, err := afterHooks(context.Background(), r, true, `{"f6":"beta","f1":"alpha","f2":"beta","f3":"x","f4":"y","f5":"z"}`)
		if err != nil || res.Outcome != OutcomeBlocked || res.Text != "A hit." || len(res.Hits) != 1 || strings.Contains(res.Hits[0].Name, "B") {
			t.Fatalf("%+v %v", res, err)
		}
	}
}

// #897 r1 M2: the hooks see a config block as it is kept (its lines joined with line breaks), so a pattern that spans lines is caught,
// and a mask is put back line by line; a line holding a line break is replaced by a marker the block is refused for.
func TestAfterHooksSeeAConfigBlockJoined(t *testing.T) {
	t.Parallel()
	r := runner(t, nil,
		CustomHook{ID: "v", Name: "VTY", When: AfterAI, Match: HookMatch{MatchRegex, `line vty 0 4\n password \S+`}, Action: ActionMask, Message: "A password was removed.", Enabled: true},
		CustomHook{ID: "w", Name: "Word", When: AfterAI, Match: HookMatch{MatchKeywords, "alpha"}, Action: ActionMask, Message: "A word was removed.", Enabled: true})
	res, err := afterHooks(context.Background(), r, true, `{"configs":[{"lines":["line vty 0 4"," password hunter2"," login"]}]}`)
	if err != nil || res.Outcome != OutcomeMasked || strings.Contains(res.Text, "hunter2") || !strings.Contains(res.Text, `" login"`) {
		t.Fatalf("%+v %v", res, err)
	}
	res, err = afterHooks(context.Background(), r, true, `{"configs":[{"lines":["line vty 0 4\n password hunter2"]}],"x":"alpha"}`)
	if err != nil || !strings.Contains(res.Text, `"lines":["\n"]`) {
		t.Fatalf("a line with a line break must become the refused marker: %+v %v", res, err)
	}
	if code, ok := codeBlock([]string{"\n"}); ok || code != "" {
		t.Fatal("the marker must be refused")
	}
}

// #897 r1 L1: an abbreviation is not a sentence end, a closing bracket after the stop is, and an accent stays with its letter.
func TestClipSentenceEdges(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"Restrict J-Web, e.g. by a filter on the loopback interface.", 40, "Restrict J-Web, e.g. by a filter on the…"},
		{"Turn it off (the J-Web service.) Then check the logs again.", 45, "Turn it off (the J-Web service.)"},
		{"Ta\u0306t ca\u0301i", 3, "T…"},
		{"Short.", 10, "Short."},
	} {
		if got, _ := clipSentence(c.in, c.n); got != c.want {
			t.Errorf("clipSentence(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

// #897 r2 H1/M2: which literals a config names for checking. Trusted: the device 192.168.142.20 and a firewall 192.168.142.1.
func TestBriefConfig_R2_AddressesToCheck(t *testing.T) {
	trusted := []netip.Addr{netip.MustParseAddr("192.168.142.20"), netip.MustParseAddr("192.168.142.1")}
	for _, c := range []struct {
		line string
		want []string
	}{
		{"set subnet 192.168.142.20 255.255.255.255", nil},
		{"set subnet 203.0.113.9 255.255.255.255", []string{"203.0.113.9"}},      // FortiOS address object
		{"access-list 101 deny tcp any 192.168.142.0 0.0.0.255 eq 443", nil},      // Cisco wildcard
		{"ip daddr 192.168.142.20/32 drop; ip saddr 192.168.142.0/24 accept", nil}, // prefixes holding a trusted address
		{"ip saddr 0.0.0.0/0 drop; ip6 saddr ::/0 drop", nil},                    // any
		{"set gateway 192.168.142.1", nil},                                        // a sent firewall
		{"Junos 15.1R7.9 and Windows 10.0.19045.6456", nil},                      // versions, not addresses
		{"ip saddr 0.0.0.0/1 accept", []string{"0.0.0.0/1"}},                     // too wide
		{"dnat to 8.8.8.8:53", []string{"8.8.8.8"}},                              // with a port
		{"ip daddr ::ffff:8.8.8.8 accept", []string{"::ffff:8.8.8.8"}},           // 4-in-6
		{"ping 010.010.010.010", []string{"010.010.010.010"}},                    // octal form
		{"host ab8.8.8.8", []string{"8.8.8.8"}},                                  // glued to letters
		{"ip6 daddr 2001:db8::1 drop", []string{"2001:db8::1"}},                  // IPv6
		{"set system syslog host 10.66.6.6; at 12:30:00", []string{"10.66.6.6"}}, // a banner's address is not trusted
	} {
		if got := untrustedAddrs(c.line, trusted); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.line, got, c.want)
		}
	}
}
