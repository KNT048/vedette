package main

import (
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestBoxManagementIPv4(t *testing.T) {
	st := api.NetState{
		Interfaces: []api.NetInterface{
			{Name: "vedette0", Addresses: []string{"10.89.0.1/24"}},
			{Name: "enp2s0", Addresses: []string{"fe80::1/64", "169.254.1.1/16", "192.168.18.141/24"}},
		},
		DefaultRoute: &api.NetRoute{Iface: "enp2s0"},
	}
	if got := boxManagementIPv4(st); got != "192.168.18.141" {
		t.Errorf("default-route card: got %q", got)
	}
	st.Config.Mgmt = &api.NetMgmt{Iface: "vedette0"}
	if got := boxManagementIPv4(st); got != "10.89.0.1" {
		t.Errorf("configured card wins: got %q", got)
	}
	if got := boxManagementIPv4(api.NetState{}); got != "" {
		t.Errorf("no card: got %q", got)
	}
}
