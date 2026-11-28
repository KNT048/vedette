package ai

import (
	"fmt"
	"strings"
	"testing"
)

// Each case is a config block and the marks it must get, as "line:kind"; "" = no mark. The safe cases are what a correct mitigation
// writes for the same devices: a narrow rule, a deny, a source-limited management rule.
func TestCheckConfigMarksRiskyLinesBySyntax(t *testing.T) {
	cases := []struct{ name, code, want string }{
		// FortiOS
		{"forti any any", "config firewall policy\n edit 0\n  set name \"x\"\n  set srcintf \"wan1\"\n  set srcaddr \"all\"\n  set dstaddr \"all\"\n  set action accept\n  set service \"ALL\"\n next\nend", "7:broad_allow"},
		{"forti narrow", "config firewall policy\n edit 0\n  set srcaddr \"all\"\n  set dstaddr \"NAS-PHOTOS\"\n  set action deny\n  set service \"HTTPS\"\n next\nend", ""},
		{"forti allow narrow", "config firewall policy\n edit 0\n  set srcaddr \"LAN\"\n  set dstaddr \"all\"\n  set action accept\n next\nend", ""},
		{"forti admin", "config system admin\n edit \"support\"\n  set accprofile \"super_admin\"\n  set password Passw0rd!\n next\nend", "2:new_credential,4:new_credential"},
		{"forti wan mgmt", "config system interface\n edit \"wan1\"\n  set allowaccess ping https ssh\n next\nend", "3:management_exposed"},
		{"forti lan mgmt", "config system interface\n edit \"internal\"\n  set allowaccess ping https ssh\n next\nend", ""},
		{"forti log off", "config firewall policy\n edit 4\n  set logtraffic disable\n next\nend", "3:logging_off"},
		// Cisco IOS / ASA
		{"ios any any", "ip access-list extended EDGE\n permit ip any any\n", "2:broad_allow"},
		{"asa any any", "access-list outside_in extended permit tcp any4 any4 eq 443", "1:broad_allow"},
		{"ios wildcard any", "access-list 101 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255", "1:broad_allow"},
		{"ios narrow", "access-list 101 deny tcp any host 192.168.10.40 eq 443\naccess-list 101 permit ip 192.168.10.0 0.0.0.255 any", ""},
		{"ios user", "username backup privilege 15 secret 0 Summer2026", "1:new_credential"},
		{"ios snmp", "snmp-server community public RO", "1:new_credential"},
		{"ios no logging", "no logging buffered", "1:logging_off"},
		{"ios aaa none", "aaa authentication login default none", "1:auth_off"},
		{"ios vty", "line vty 0 4\n transport input telnet\n no login", "2:auth_off,3:auth_off"},
		{"ios http server", "ip http server", "1:management_exposed"},
		{"asa ssh outside", "ssh 0.0.0.0 0.0.0.0 outside", "1:management_exposed"},
		{"asa ssh inside", "ssh 192.168.10.0 255.255.255.0 inside", ""},
		{"ios remove acl", "interface GigabitEthernet0/0\n no access-group EDGE in", "2:protection_off"},
		// Junos
		{"junos any any", "set security policies from-zone untrust to-zone trust policy p1 match source-address any\nset security policies from-zone untrust to-zone trust policy p1 match destination-address any\nset security policies from-zone untrust to-zone trust policy p1 match application any\nset security policies from-zone untrust to-zone trust policy p1 then permit", "4:broad_allow"},
		{"junos deny", "set security policies from-zone untrust to-zone trust policy p1 match source-address any\nset security policies from-zone untrust to-zone trust policy p1 match destination-address NAS\nset security policies from-zone untrust to-zone trust policy p1 then deny", ""},
		{"junos user", "set system login user helper class super-user authentication plain-text-password", "1:new_credential"},
		{"junos syslog", "delete system syslog", "1:logging_off"},
		{"junos telnet", "set system services telnet", "1:management_exposed"},
		// iptables / nftables / pf
		{"iptables policy", "iptables -P INPUT ACCEPT", "1:broad_allow"},
		{"iptables flush", "sudo iptables -F", "1:protection_off"},
		{"iptables wide", "iptables -A INPUT -j ACCEPT", "1:broad_allow"},
		{"iptables ssh any", "iptables -A INPUT -p tcp --dport 22 -j ACCEPT", "1:management_exposed"},
		{"iptables ssh lan", "iptables -A INPUT -s 192.168.10.0/24 -p tcp --dport 22 -j ACCEPT", ""},
		{"iptables drop", "iptables -I FORWARD -d 192.168.10.40 -p tcp --dport 443 -j DROP", ""},
		{"iptables state", "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", ""},
		{"nft flush", "nft flush ruleset", "1:protection_off"},
		{"nft policy", "nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'", "1:broad_allow"},
		{"nft narrow", "nft add rule inet filter input ip saddr 192.168.10.0/24 tcp dport 22 accept", ""},
		{"pf all", "pass in quick all", "1:broad_allow"},
		{"pf any", "pass in on em0 from any to any", "1:broad_allow"},
		{"pf block", "block in quick on em0 proto tcp from any to 192.168.10.40 port 443", ""},
		// MikroTik
		{"mikrotik accept", "/ip firewall filter add chain=input action=accept", "1:broad_allow"},
		{"mikrotik winbox", "/ip firewall filter add chain=input protocol=tcp dst-port=8291 action=accept", "1:management_exposed"},
		{"mikrotik drop", "/ip firewall filter add chain=forward dst-address=192.168.10.40 protocol=tcp dst-port=443 action=drop", ""},
		{"mikrotik user", "/user add name=helper group=full password=x", "1:new_credential"},
		{"mikrotik service", "/ip service set winbox address=\"\"", "1:management_exposed"},
		{"mikrotik logging", "/system logging remove 0", "1:logging_off"},
		// Linux, sshd, Windows
		{"useradd", "sudo useradd -m -G sudo helper", "1:new_credential"},
		{"sshd root", "PermitRootLogin yes", "1:auth_off"},
		{"sshd safe", "PermitRootLogin no\nPasswordAuthentication no", ""},
		{"systemctl", "systemctl stop auditd rsyslog\nsystemctl disable --now ufw", "1:logging_off,2:protection_off"},
		{"ufw", "ufw default allow incoming\nufw allow 22/tcp\nufw allow from 192.168.10.0/24 to any port 22", "1:broad_allow,2:management_exposed"},
		{"windows fw off", "netsh advfirewall set allprofiles state off", "1:protection_off"},
		{"windows user", "net user helper P@ss /add", "1:new_credential"},
		{"windows rdp any", "netsh advfirewall firewall add rule name=rdp dir=in action=allow protocol=TCP localport=3389", "1:management_exposed"},
		{"windows block", "netsh advfirewall firewall add rule name=block dir=in action=block protocol=TCP localport=445", ""},
		{"auditpol", "auditpol /set /category:\"Logon/Logoff\" /success:disable /failure:disable", "1:logging_off"},
		// A comment that talks about the risky thing is not the thing.
		{"comments", "# do not use permit ip any any\n! never set password here", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, w := range CheckConfig(c.code) {
				got = append(got, fmt.Sprintf("%d:%s", w.Line, w.Kind))
				if w.Text != riskText[w.Kind] || w.Text == "" {
					t.Errorf("text of %s = %q", w.Kind, w.Text)
				}
			}
			if s := strings.Join(got, ","); s != c.want {
				t.Fatalf("marks = %q, want %q\n%s", s, c.want, c.code)
			}
		})
	}
}

// A drafted block keeps every line the AI wrote; its risky lines come back as marks with the block (the page shows them on the lines).
func TestBriefMarksTheRiskyLinesOfAConfig(t *testing.T) {
	body, err := parseBrief(`{"answers":[{"key":"affected","text":"a","refs":[]},{"key":"fix","text":"b","refs":[]},{"key":"workaround","text":"c","refs":[]},{"key":"urgency","text":"d","refs":[]}],"steps":[],`+
		`"configs":[{"title":"Block the portal","lines":["config firewall policy"," edit 0","  set srcaddr \"all\"","  set dstaddr \"all\"","  set action accept"," next","end"],"side_effect":"none","based_on":"x"},`+
		`{"title":"Narrow","lines":["access-list 101 deny tcp any host 192.168.10.40 eq 443"],"side_effect":"none","based_on":"x"}],"no_config_reason":""}`, JobMitigationConfig)
	if err != nil {
		t.Fatal(err)
	}
	a := keptBrief(body, nil, nil)
	if len(a.Configs) != 2 || len(a.Configs[0].Warnings) != 1 || a.Configs[0].Warnings[0].Line != 5 || a.Configs[0].Warnings[0].Kind != RiskBroadAllow || len(a.Configs[1].Warnings) != 0 {
		t.Fatalf("configs = %+v", a.Configs)
	}
	if !strings.Contains(a.Configs[0].Code, "set action accept") {
		t.Fatal("the risky line was removed: the person must see what the AI wrote")
	}
}
