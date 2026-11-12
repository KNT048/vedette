package main

import (
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestBoxCardIPv4(t *testing.T) {
	st := api.NetState{Interfaces: []api.NetInterface{
		{Name: "vedette0", Addresses: []string{"10.89.0.1/24"}},
		{Name: "enp2s0", Addresses: []string{"fe80::1/64", "169.254.1.1/16", "192.168.18.141/24"}},
		{Name: "lo", Addresses: []string{"127.0.0.1/8"}},
	}}
	if got := boxCardIPv4(st, "enp2s0"); got != "192.168.18.141" {
		t.Errorf("skips link-local and IPv6: got %q", got)
	}
	if got := boxCardIPv4(st, "vedette0"); got != "10.89.0.1" {
		t.Errorf("named card: got %q", got)
	}
	for _, c := range []string{"lo", "", "nope"} {
		if got := boxCardIPv4(st, c); got != "" {
			t.Errorf("card %q: got %q", c, got)
		}
	}
}
