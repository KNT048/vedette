package exposure

import "testing"

func TestSanitizeKeepsTheMarksOfACarriedPort(t *testing.T) {
	got := sanitize(Content{Ports: []PortRow{
		{IP: "10.0.0.5", Port: 22, LastSeen: "2026-11-10", Misses: 2, Unchecked: true},
		{IP: "10.0.0.5", Port: 80, LastSeen: "not a date", Misses: 3},
		{IP: "10.0.0.5", Port: 443},
	}}).Ports
	if len(got) != 3 || got[0].LastSeen != "2026-11-10" || got[0].Misses != 2 || !got[0].Unchecked {
		t.Fatalf("a carried port lost its INV-22 marks: %+v", got)
	}
	if got[1].LastSeen != "" || got[1].Misses != 0 || got[2].LastSeen != "" {
		t.Fatalf("a bad date or an unmarked port gained marks: %+v", got[1:])
	}
}
