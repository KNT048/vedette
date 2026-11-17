package inventory

import "testing"

// The statements come from content/catalog/network-os.json (the rows with lldp_oui, as findings reads them): the table loads,
// and a Junos statement counts on a Juniper card only.
func TestStatedOSReadsTheNetworkOSTable(t *testing.T) {
	if len(lldpStatements) == 0 {
		t.Fatal("no row of network-os.json lets LLDP state an OS")
	}
	for _, c := range []struct {
		os, mac string
		want    bool
	}{
		{"JUNOS 15.1R7.9", "3c:8a:b0:9c:85:ff", true},
		{"JUNOS 15.1R7.9", "00:0c:29:9c:85:ff", false}, // another vendor's card
		{"JUNOS 15.1R7.9", "3e:8a:b0:9c:85:ff", false}, // a private MAC has no vendor
		{"JUNOS 15.1R7.9", "", false},
		{"Juniper EX2200 switch (JUNOS 12)", "3c:8a:b0:9c:85:ff", false}, // a scan's name is no statement
		{"Cisco IOS XE 17.3.1", "3c:8a:b0:9c:85:ff", false},
	} {
		if got := lldpStated(c.os, c.mac); got != c.want {
			t.Errorf("lldpStated(%q, %q) = %v, want %v", c.os, c.mac, got, c.want)
		}
	}
}
