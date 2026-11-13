package signature

import (
	"strings"
	"testing"
)

// The firewall profiles of D-489. Layouts are those of the vendors' documentation (pfSense raw filter log format, Cisco ASA syslog message
// reference, SonicOS log events, PAN-OS traffic log fields, SFOS syslog fields, netfilter LOG); the lines are built to those layouts.
const (
	pfAllow = `<134>Nov  9 10:00:00 fw filterlog[53123]: 5,,,1000000103,igc1,match,pass,in,4,0x0,,64,41237,0,DF,6,tcp,60,192.168.10.113,185.220.101.47,51234,443,0,S,2174350711,,64240,,mss`
	asaOut  = `<166>Nov 09 2026 10:00:00 asa-1 : %ASA-6-302013: Built outbound TCP connection 8001 for outside:185.220.101.47/443 (185.220.101.47/443) to inside:192.168.10.113/51234 (203.0.113.5/51234)`
	swOpen  = `<134>id=firewall sn=0006B1D1A5C4 time="2026-11-09 10:00:00 UTC" fw=203.0.113.1 pri=6 c=262144 m=98 msg="Connection Opened" n=1 src=192.168.10.113:51234:X0 dst=185.220.101.47:443:X1 proto=tcp/https`
	paAllow = `<14>Nov  9 10:00:00 PA 1,2026/11/09 10:00:00,0070,TRAFFIC,end,2562,2026/11/09 10:00:00,192.168.10.113,185.220.101.47,203.0.113.5,185.220.101.47,out-allow,,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,fwd,2026/11/09 10:00:00,12345,1,51234,443,51234,443,0x400000,tcp,allow,6200`
	ufwBlk  = `<4>Nov  9 10:00:00 gw kernel: [UFW BLOCK] IN=eth0 OUT=eth1 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=192.168.10.113 DST=185.220.101.47 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=51234 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0`
	sfAllow = `<30>device_name="SFW" log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" fw_rule_id=3 user_name="" src_ip=192.168.10.113 dst_ip=185.220.101.47 protocol="TCP" src_port=51234 dst_port=443`
)

func TestFirewallProfilesReadTheConnection(t *testing.T) {
	set := shipped(t)
	for _, c := range []struct {
		kind, line string
		blocked    bool
	}{
		{"pfsense", pfAllow, false},
		{"opnsense", strings.Replace(pfAllow, ",pass,", ",block,", 1), true},
		{"opnsense", strings.Replace(pfAllow, "1000000103", "02f4bab031b57d1e30553ce08e0ec131", 1), false},
		{"pfsense", strings.Replace(pfAllow, ",pass,", ",reject,", 1), true},
		{"cisco-asa", asaOut, false},
		{"cisco-asa", `<166>%ASA-6-302015: Built outbound UDP connection 9 for outside:185.220.101.47/53 (185.220.101.47/53) to inside:192.168.10.113/5000 (203.0.113.5/5000)`, false},
		{"cisco-asa", `<164>asa-1 : %ASA-4-106023: Deny udp src inside:192.168.10.113/5000 dst outside:185.220.101.47/53 by access-group "in" [0x0, 0x0]`, true},
		{"cisco-asa", `<166>%ASA-6-106100: access-list inside_in denied tcp inside/192.168.10.113(51234) -> outside/185.220.101.47(23) hit-cnt 1 first hit [0x1, 0x2]`, true},
		{"cisco-asa", `<166>%ASA-6-106100: access-list inside_in permitted tcp inside/192.168.10.113(51234) -> outside/185.220.101.47(443) hit-cnt 1 first hit [0x1, 0x2]`, false},
		{"sonicwall", swOpen, false},
		{"paloalto", paAllow, false},
		{"paloalto", strings.Replace(paAllow, ",allow,", ",deny,", 1), true},
		{"paloalto", strings.Replace(paAllow, "out-allow", `"rule, with comma"`, 1), false},
		{"sophos", sfAllow, false},
		{"sophos", strings.Replace(strings.Replace(sfAllow, `"Allowed"`, `"Denied"`, 1), `"Allow"`, `"Deny"`, 1), true},
		{"ubiquiti", ufwBlk, true},
		{"ubiquiti", strings.Replace(ufwBlk, "[UFW BLOCK]", "[UFW ALLOW]", 1), false},
		{"linux-rsyslog", strings.Replace(ufwBlk, "kernel: [UFW BLOCK]", "kernel: [ 1234.567890] [UFW BLOCK]", 1), true},
		{"linux-journald", strings.Replace(ufwBlk, "[UFW BLOCK]", "[WAN_IN-default-D]", 1), true},
		{"ubiquiti", strings.Replace(ufwBlk, "[UFW BLOCK]", "[LAN_IN-RET-2000-A]", 1), false},
	} {
		r := set.Of(c.kind, c.line)
		if !r.Conn.Local.IsValid() || r.Conn.Local.String() != "192.168.10.113" || len(r.Conn.Dests) != 1 || r.Conn.Dests[0].Value != "185.220.101.47" || r.Conn.Blocked != c.blocked {
			t.Errorf("%s %.60q: got %+v (profile %s)", c.kind, c.line, r.Conn, r.Profile)
		}
	}
}

// Lines that are not a new outbound connection of the LAN make none: replies, inbound, private or public endpoints the other way round,
// another kind of record, and the formats' other message ids.
func TestFirewallProfilesRefuse(t *testing.T) {
	set := shipped(t)
	for name, c := range map[string][2]string{
		"pf inbound":          {"pfsense", strings.Replace(pfAllow, ",in,4,", ",out,4,", 1)},
		"pf public source":    {"pfsense", strings.Replace(pfAllow, "192.168.10.113", "8.8.8.8", 1)},
		"pf private dest":     {"pfsense", strings.Replace(pfAllow, "185.220.101.47", "10.0.0.5", 1)},
		"pf ipv6":             {"pfsense", `<134>Nov  9 10:00:00 fw filterlog[1]: 5,,,1000000103,igc1,match,pass,in,6,0x00,0x0,64,tcp,6,40,fd00::5,2a00::1,51234,443`},
		"pf not a record":     {"pfsense", `<134>Nov  9 10:00:00 fw filterlog[1]: 5,,,1000000103,igc1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,192.168.10.113`},
		"asa inbound":         {"cisco-asa", strings.Replace(asaOut, "outbound", "inbound", 1)},
		"asa private dest":    {"cisco-asa", strings.Replace(asaOut, "185.220.101.47/443 (185.220.101.47/443)", "10.0.0.7/443 (10.0.0.7/443)", 1)},
		"asa teardown":        {"cisco-asa", `<166>%ASA-6-302014: Teardown TCP connection 8001 for outside:185.220.101.47/443 to inside:192.168.10.113/51234 duration 0:00:01 bytes 100 TCP FINs`},
		"sonic closed":        {"sonicwall", strings.Replace(swOpen, "Connection Opened", "Connection Closed", 1)},
		"sonic public source": {"sonicwall", strings.Replace(swOpen, "src=192.168.10.113", "src=8.8.8.8", 1)},
		"pan threat":          {"paloalto", strings.Replace(paAllow, "TRAFFIC,end", "THREAT,vulnerability", 1)},
		"pan inbound":         {"paloalto", strings.Replace(paAllow, "192.168.10.113,185.220.101.47", "185.220.101.47,192.168.10.113", 1)},
		"pan field shift":     {"paloalto", strings.Replace(paAllow, "out-allow", "out,allow", 1)}, // an unquoted comma in a text field: the action is no longer where it is read
		"sophos event":        {"sophos", strings.Replace(sfAllow, `log_type="Firewall"`, `log_type="Event"`, 1)},
		"sophos two dsts":     {"sophos", sfAllow + ` dst_ip=6.6.6.6`},
		"ufw inbound":         {"linux-rsyslog", strings.Replace(ufwBlk, "SRC=192.168.10.113 DST=185.220.101.47", "SRC=185.220.101.47 DST=192.168.10.113", 1)},
		"custom prefix":       {"ubiquiti", strings.Replace(ufwBlk, "[UFW BLOCK]", "[my-prefix]", 1)},
		"ufw audit":           {"linux-rsyslog", strings.Replace(ufwBlk, "[UFW BLOCK]", "[UFW AUDIT]", 1)},
	} {
		if r := set.Of(c[0], c[1]); r.Conn.Local.IsValid() || len(r.Conn.Dests) != 0 {
			t.Errorf("%s: got %+v", name, r.Conn)
		}
	}
}

// Text that someone else wrote is never a field of the device: in a free-text field, as a line of another program, or in front of the
// record (S-LOG-2: a false hit tells a person that a device of theirs talked to a criminal).
func TestFirewallProfilesInjection(t *testing.T) {
	set := shipped(t)
	bad := `192.168.10.5,6.6.6.6`
	for name, c := range map[string][2]string{
		"pf other program":      {"pfsense", strings.Replace(pfAllow, "filterlog[53123]", "sshd[1]", 1)},
		"pf no program":         {"pfsense", `<134>` + strings.TrimPrefix(pfAllow, `<134>Nov  9 10:00:00 fw filterlog[53123]: `)},
		"pf text in front":      {"pfsense", `<134>Nov  9 10:00:00 fw filterlog[1]: GET /?5,,,1,igc1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,` + bad + `,1,2`},
		"pf in the data":        {"pfsense", `<134>Nov  9 10:00:00 fw nginx[1]: 5,,,1,igc1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,` + bad + `,1,2`},
		"asa second message":    {"cisco-asa", `<166>%ASA-6-113005: AAA user authentication Rejected : reason = x : server = 1.1.1.1 : user = %ASA-6-302013: Built outbound TCP connection 1 for outside:6.6.6.6/1 (6.6.6.6/1) to inside:192.168.10.5/2 (3.3.3.3/2)`},
		"sonic text in a field": {"sonicwall", `<134>id=firewall sn=0006 time="x" fw=1.1.1.1 pri=6 c=1 m=98 msg="Connection Opened" appName="x src=192.168.10.5:1:X0 dst=6.6.6.6:2:X1" proto=tcp`},
		"sonic text in the msg": {"sonicwall", `<134>id=firewall sn=0006 time="x" fw=1.1.1.1 pri=6 c=1 m=98 msg="a Connection Opened" n=1 src=192.168.10.5:1:X0 dst=6.6.6.6:2:X1`},
		"pan text in the user":  {"paloalto", `<14>1,2026/11/09 10:00:00,0070,THREAT,url,2562,2026/11/09 10:00:00,192.168.10.113,185.220.101.47,0.0.0.0,0.0.0.0,r,"1,2026/11/09 10:00:00,0070,TRAFFIC,end,2562,x,192.168.10.5,6.6.6.6,a,b,r,,,x,v,t,u,i,o,l,t,1,1,1,1,1,1,0,tcp,allow,0"`},
		"sophos url field":      {"sophos", `<30>log_type="Content Filtering" log_component="HTTP" log_subtype="Allowed" url="http://x/ src_ip=192.168.10.5 dst_ip=6.6.6.6 " user_name=""`},
		"sophos broken quote":   {"sophos", `<30>log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" url="http://x/" src_ip=192.168.10.113 dst_ip=6.6.6.6" `},
		"ufw other program":     {"linux-rsyslog", strings.Replace(ufwBlk, "kernel:", "nginx:", 1)},
		"ufw web log":           {"linux-rsyslog", `<14>Nov  9 10:00:00 web nginx[1]: 1.2.3.4 - - "GET /?x=[UFW BLOCK] IN=eth0 OUT= SRC=192.168.10.5 DST=6.6.6.6 LEN=1" 200`},
		"ufw sshd user":         {"linux-rsyslog", `<38>Nov  9 10:00:00 web sshd[1]: Invalid user [UFW BLOCK] IN=eth0 OUT= SRC=192.168.10.5 DST=6.6.6.6 LEN=1 from 8.8.8.8`},
		"ufw text in front":     {"linux-rsyslog", strings.Replace(ufwBlk, "kernel: [UFW BLOCK]", "kernel: x [UFW BLOCK]", 1)},
	} {
		if r := set.Of(c[0], c[1]); r.Conn.Local.IsValid() && r.Conn.Local.String() != "192.168.10.113" || len(r.Conn.Dests) != 0 && r.Conn.Dests[0].Value == "6.6.6.6" {
			t.Errorf("%s: got %+v", name, r.Conn)
		}
	}
	// The pf and sonic cases above that name no real record must not give any connection at all.
	for _, c := range [][2]string{{"pfsense", strings.Replace(pfAllow, "filterlog[53123]", "sshd[1]", 1)}, {"linux-rsyslog", strings.Replace(ufwBlk, "kernel:", "nginx:", 1)},
		{"sonicwall", `<134>id=firewall sn=0006 time="x" fw=1.1.1.1 pri=6 c=1 m=98 msg="a Connection Opened" n=1 src=192.168.10.5:1:X0 dst=6.6.6.6:2:X1`}} {
		if r := set.Of(c[0], c[1]); r.Conn.Local.IsValid() {
			t.Errorf("%s: %+v", c[0], r.Conn)
		}
	}
}

// D-487: a Linux kind that now has a profile still reads its sshd lines as before: the profile does not read them (apps), so the remote address
// is found by the generic reader and the failed-login rule keeps its input.
func TestLinuxKindsKeepTheirLoginLines(t *testing.T) {
	set := shipped(t)
	for _, kind := range []string{"linux-rsyslog", "linux-journald", "ubiquiti"} {
		r := set.Of(kind, `<38>Nov  9 10:00:00 web sshd[1]: Failed password for invalid user admin from 45.155.205.233 port 4000 ssh2`)
		if r.Profile != GenericProfile || r.Remote.String() != "45.155.205.233" {
			t.Errorf("%s: profile %q remote %v", kind, r.Profile, r.Remote)
		}
	}
	if r := set.Of("syslog-generic", ufwBlk); r.Profile != GenericProfile || r.Conn.Local.IsValid() {
		t.Errorf("a kind without the profile read a firewall line: %+v", r)
	}
}

func TestConnPatternsRules(t *testing.T) {
	line := func(rule string) string {
		return `{"id":"x","title":"x","kinds":["x"],"rule":` + rule + `,"samples":[{"line":"a b","signature":"a: b"}]}`
	}
	for name, rule := range map[string]string{
		"not anchored":     `{"type":"template","prefix":"^(?P<head>a) ","conn_patterns":[{"pattern":"(?P<local>a)(?P<dest>b)"}]}`,
		"no dest":          `{"type":"template","prefix":"^(?P<head>a) ","conn_patterns":[{"pattern":"^(?P<local>a)"}]}`,
		"on kv":            `{"type":"kv","fields":["a"],"conn_patterns":[{"pattern":"^(?P<local>a)(?P<dest>b)"}]}`,
		"an upper app":     `{"type":"template","prefix":"^(?P<head>a) ","apps":["Kernel"]}`,
		"an app with junk": `{"type":"template","prefix":"^(?P<head>a) ","apps":["k e"]}`,
	} {
		if _, err := Load(profileFS(map[string]string{"x.json": line(rule)}), "profiles"); err == nil {
			t.Errorf("%s loaded", name)
		}
	}
	if _, err := Load(profileFS(map[string]string{"x.json": line(`{"type":"template","prefix":"^(?P<head>a) ","conn_patterns":[{"pattern":"^(?P<local>a)(?P<dest>b)"}]}`)}), "profiles"); err != nil {
		t.Errorf("a good rule: %v", err)
	}
}
