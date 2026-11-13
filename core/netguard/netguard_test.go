package netguard

import (
	"net/netip"
	"slices"
	"testing"
)

// refused is what every guard refuses whatever the box: Always of any form.
func refused(a netip.Addr) bool { return slices.ContainsFunc(Forms(a), Always) }

func TestMetadata(t *testing.T) {
	for _, s := range []string{"fd00:ec2::254", "fd20:ce::254", "100.100.100.200", "192.0.0.192", "::ffff:100.100.100.200"} {
		if !Metadata(netip.MustParseAddr(s)) || !Always(netip.MustParseAddr(s)) {
			t.Errorf("%s is not a metadata endpoint", s)
		}
	}
	for _, s := range []string{"100.100.100.201", "192.0.0.193", "fd00:ec2::253", "8.8.8.8"} {
		if Metadata(netip.MustParseAddr(s)) {
			t.Errorf("%s is a metadata endpoint", s)
		}
	}
	for _, h := range []string{"metadata", "metadata.google.internal", "metadata.goog"} {
		if !MetadataName(h) {
			t.Errorf("%s is not a metadata name", h)
		}
	}
	if MetadataName("metadata.example.com") {
		t.Error("metadata.example.com is a metadata name")
	}
}

// Every transition form of a forbidden IPv4 address is refused; the same forms of a public address are not.
func TestFormsCarryTheIPv4Address(t *testing.T) {
	for _, s := range []string{
		"169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1", "::a9fe:a9fe", "::ffff:169.254.169.254", // link-local metadata
		"64:ff9b::6464:64c8", "2002:6464:64c8::", "::6464:64c8", // 100.100.100.200
		"64:ff9b:1:6464:64:c800::", "64:ff9b:1::6464:64c8", // 100.100.100.200 behind the local-use prefix, /48 and /96
		"64:ff9b::7f00:1", "fe80::1%eth0", "255.255.255.255", "0.0.0.0", "::", "ff02::1",
	} {
		if !refused(netip.MustParseAddr(s)) {
			t.Errorf("%s is allowed", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "64:ff9b::808:808", "2002:808:808::1", "2001:db8::1", "192.168.10.9", "64:ff9b:1:808:8:800::", "64:ff9b:1::808:808"} {
		if refused(netip.MustParseAddr(s)) {
			t.Errorf("%s is refused", s)
		}
	}
	if got := Forms(netip.MustParseAddr("64:ff9b::a9fe:a9fe")); !slices.Equal(got, []netip.Addr{netip.MustParseAddr("64:ff9b::a9fe:a9fe"), netip.MustParseAddr("169.254.169.254")}) {
		t.Errorf("forms %v", got)
	}
}

// A local-use NAT64 prefix (64:ff9b:1::/48, RFC 8215) is read in every RFC 6052 layout a sub-prefix of it can have (/48 /56 /64 /96).
func TestFormsNAT64LocalEveryLayout(t *testing.T) {
	b := [16]byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x01}
	for i := 6; i < 16; i++ {
		b[i] = byte(0x10 + i)
	}
	got := Forms(netip.AddrFrom16(b))
	for _, l := range nat64Layouts {
		if want := netip.AddrFrom4(nat64Embed(b, l.at)); !slices.Contains(got, want) {
			t.Errorf("layout /%d: %s is not among %v", l.bits, want, got)
		}
	}
	if got := Forms(netip.MustParseAddr("64:ff9b:1:1:64:6464:c800::")); !slices.Contains(got, netip.MustParseAddr("100.100.100.200")) {
		t.Errorf("the /64 form of 100.100.100.200 is not decoded: %v", got)
	}
}
