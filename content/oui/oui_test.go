package oui_test

import (
	"testing"

	"github.com/knt048/vedette/content/oui"
)

// The committed table parses and is the size of the IEEE registries (the build refuses a source under 50,000).
func TestTableHasEntries(t *testing.T) {
	t.Parallel()
	if n := oui.Len(); n <= 50000 {
		t.Fatalf("%d prefixes, want more than 50,000", n)
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mac  [6]byte
		want string
		ok   bool
	}{
		{"/24 Cisco", [6]byte{0x00, 0x00, 0x0c, 0x12, 0x34, 0x56}, "Cisco Systems, Inc", true},
		{"/24 Apple", [6]byte{0x3c, 0x07, 0x54, 0xaa, 0xbb, 0xcc}, "Apple, Inc.", true},
		{"/28 block of a shared /24", [6]byte{0x00, 0x55, 0xda, 0x1f, 0xff, 0xff}, "KoolPOS Inc.", true},
		{"/28 neighbour block", [6]byte{0x00, 0x55, 0xda, 0x00, 0x00, 0x01}, "Shinko Technos co.,ltd.", true},
		{"/36 block", [6]byte{0x00, 0x1b, 0xc5, 0x00, 0x0a, 0xbc}, "Converging Systems Inc.", true},
		{"/36 pointer in the /24: a block nobody holds", [6]byte{0x00, 0x1b, 0xc5, 0x0f, 0xff, 0x01}, "", false},
		{"locally administered (randomised)", [6]byte{0x3e, 0x07, 0x54, 0xaa, 0xbb, 0xcc}, "", false},
		{"multicast", [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, "", false},
		{"broadcast", [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "", false},
		{"unassigned", [6]byte{0xfc, 0xff, 0xff, 0xff, 0xff, 0xff}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := oui.Lookup(tc.mac)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("Lookup(% x) = %q, %v; want %q, %v", tc.mac, got, ok, tc.want, tc.ok)
			}
		})
	}
}
