package logs

import (
	"strings"
	"testing"
)

// D-489: a connection of a LAN device to a listed address, in the line of each firewall that has a profile, is a hit through the real ingest path,
// said as "tried to reach" when the device stopped it.
func TestIOCFirewallKindsMakeHits(t *testing.T) {
	t.Parallel()
	const lan = "192.168.10.113"
	for _, c := range []struct {
		kind, line string
		blocked    bool
	}{
		{"pfsense", `<134>Nov  9 10:00:00 fw filterlog[1]: 5,,,1000000103,igc1,match,pass,in,4,0x0,,64,41237,0,DF,6,tcp,60,` + lan + `,` + badIP + `,51234,443,0,S,1,,64240,,mss`, false},
		{"opnsense", `<134>Nov  9 10:00:00 fw filterlog[1]: 5,,,1000000103,igc1,match,block,in,4,0x0,,64,41237,0,DF,6,tcp,60,` + lan + `,` + badIP + `,51234,23,0,S,1,,64240,,mss`, true},
		{"cisco-asa", `<166>Nov 09 2026 10:00:00 asa-1 : %ASA-6-302013: Built outbound TCP connection 8001 for outside:` + badIP + `/443 (` + badIP + `/443) to inside:` + lan + `/51234 (203.0.113.5/51234)`, false},
		{"sonicwall", `<134>id=firewall sn=0006B1D1A5C4 time="2026-11-09 10:00:00 UTC" fw=203.0.113.1 pri=6 c=262144 m=98 msg="Connection Opened" n=1 src=` + lan + `:51234:X0 dst=` + badIP + `:443:X1 proto=tcp/https`, false},
		{"paloalto", `<14>Nov  9 10:00:00 PA 1,2026/11/09 10:00:00,0070,TRAFFIC,end,2562,2026/11/09 10:00:00,` + lan + `,` + badIP + `,203.0.113.5,` + badIP + `,r,,,ssl,vsys1,trust,untrust,e1,e2,fwd,2026/11/09 10:00:00,1,1,51234,443,51234,443,0x0,tcp,deny,6200`, true},
		{"sophos", `<30>device_name="SFW" log_type="Firewall" log_component="Firewall Rule" log_subtype="Allowed" status="Allow" src_ip=` + lan + ` dst_ip=` + badIP + ` protocol="TCP"`, false},
		{"ubiquiti", `<4>Nov  9 10:00:00 gw kernel: [WAN_OUT-10-D]IN=eth1 OUT=eth0 MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=` + lan + ` DST=` + badIP + ` LEN=60 PROTO=TCP SPT=1 DPT=23`, true},
		{"linux-rsyslog", `<4>Nov  9 10:00:00 srv kernel: [UFW ALLOW] IN=eth0 OUT=eth1 SRC=` + lan + ` DST=` + badIP + ` LEN=60 PROTO=TCP SPT=1 DPT=443`, false},
	} {
		t.Run(c.kind, func(t *testing.T) {
			t.Parallel()
			e, _, _, p := iocEnv(t)
			src, err := e.svc.AddSource(t.Context(), "admin@acme.example", Input{Kind: c.kind, Name: "FW-2", SenderIP: "192.168.10.201", Proto: "udp", Port: 514})
			if err != nil {
				t.Fatal(err)
			}
			e.feedAll(src, []string{c.line})
			if h, b := p.counts(); h != 1 || b != 1 || p.hits[0].SrcIP != lan || p.hits[0].Dest != badIP || p.hits[0].Blocked != c.blocked {
				t.Fatalf("events %d %d %+v", h, b, p.hits)
			}
			if c.blocked != strings.Contains(p.bad[0].Title, "tried to reach") {
				t.Errorf("title %q", p.bad[0].Title)
			}
		})
	}
}
