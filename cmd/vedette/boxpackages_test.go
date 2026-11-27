package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/modules/inventory"
)

// The box's dpkg list from vedette-host becomes the box's software the way an osquery deb_packages snapshot does (mapped
// names and upstream versions); a host older than the packages read gives no list (nil, so the inventory keeps what it has).
func TestBoxPackagesMapsTheHostsDpkgList(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	old := servertest.Start(t, nil)
	if items, err := (boxPackages{c: old.Client}).Packages(ctx); items != nil || err != nil {
		t.Fatalf("a host without the read: %v, %v; want nil, nil", items, err)
	}
	h := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers.Packages = func(context.Context) (any, error) {
			return api.PackagesState{Packages: []api.Package{
				{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Arch: "amd64", Source: "openssh"},
				{Name: "zzz-local-tool", Version: "2.0-1", Arch: "all", Source: "zzz-local-tool"},
			}}, nil
		}
	})
	items, err := (boxPackages{c: h.Client}).Packages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("items %+v", items)
	}
	ssh := items[slices.IndexFunc(items, func(i inventory.SoftwareItem) bool { return i.Product == "OpenSSH" })]
	if ssh.Vendor != "OpenBSD" || ssh.Version != "9.6p1" || !slices.Equal(ssh.KevKeys, []string{"openbsd|openssh"}) ||
		ssh.PkgVersion != "1:9.6p1-3ubuntu13.5" || ssh.PkgSource != "openssh" { // The full version and source go to findings
		t.Errorf("openssh-server mapped to %+v", ssh)
	}
}

// While dpkg is mid-change the host answers 409 packages_changing; that is no list (nil, nil), so the inventory keeps the
// last good one instead of closing findings for the packages apt is replacing.
func TestBoxPackagesKeepsTheListWhileDpkgIsChanging(t *testing.T) {
	t.Parallel()
	h := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers.Packages = func(context.Context) (any, error) {
			return nil, server.NewReadError(http.StatusConflict, api.CodePackagesChanging, "dpkg is busy")
		}
	})
	if items, err := (boxPackages{c: h.Client}).Packages(t.Context()); items != nil || err != nil {
		t.Fatalf("dpkg mid-change: %v, %v; want nil, nil", items, err)
	}
}

// A read whose running kernel the host does not give (its info call failed while it was busy or restarting) keeps the last good list,
// so the Kernel line never moves back to the lowest installed image for one read; a host that answers without a kernel keeps the old
// reading.
func TestBoxPackagesNeedTheRunningKernel(t *testing.T) {
	t.Parallel()
	if k, ok := runningKernel(api.Info{OS: api.OSInfo{Kernel: "7.0.0-44-generic"}}, nil); !ok || k != "7.0.0-44-generic" {
		t.Fatalf("an answer: %q %v", k, ok)
	}
	if _, ok := runningKernel(api.Info{}, errors.New("connection refused")); ok {
		t.Fatal("no answer still gave a kernel: every image would be the Kernel row and the lowest would win")
	}
	if k, ok := runningKernel(api.Info{}, nil); !ok || k != "" {
		t.Fatalf("an answer without a kernel: %q %v", k, ok)
	}
}

// The host lists up to 20 000 packages; the box path never cuts the mapped list at an agent's 5 000 rows, so the inventory
// stores the whole box or refuses the list (and keeps the last one), never a part of it.
func TestBoxPackagesAreNeverCut(t *testing.T) {
	t.Parallel()
	pkgs := make([]api.Package, 5001)
	for i := range pkgs {
		pkgs[i] = api.Package{Name: fmt.Sprintf("pkg%d", i), Version: "1.0-1", Arch: "amd64", Source: fmt.Sprintf("pkg%d", i)}
	}
	h := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers.Packages = func(context.Context) (any, error) { return api.PackagesState{Packages: pkgs}, nil }
	})
	items, err := (boxPackages{c: h.Client}).Packages(t.Context())
	if err != nil || len(items) != len(pkgs) {
		t.Fatalf("%d items, %v; want all %d", len(items), err, len(pkgs))
	}
}

// INV-3 (#933 review L8): the box's listening ports from vedette-host become its open services named by what holds them; a host
// older than the read (404 unknown_command) gives no list (nil, so the inventory keeps what it has).
func TestBoxPortsReadsTheHostsListeningPorts(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	old := servertest.Start(t, nil)
	if items, err := (boxPorts{c: old.Client}).Ports(ctx); items != nil || err != nil {
		t.Fatalf("a host without the read: %v, %v; want nil, nil", items, err)
	}
	h := servertest.Start(t, nil, func(o *server.Options) {
		o.Readers.Ports = func(context.Context) (any, error) {
			return api.PortsState{Ports: []api.ListenPort{{Port: 22, Proto: api.ProtoTCP, Process: "sshd"}, {Port: 514, Proto: api.ProtoUDP, Process: "vedette-core"}}}, nil
		}
	})
	items, err := (boxPorts{c: h.Client}).Ports(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []observe.Service{{Port: 22, Proto: "tcp", Name: "sshd"}, {Port: 514, Proto: "udp", Name: "vedette-core"}}
	if !slices.Equal(items, want) {
		t.Fatalf("items %v", items)
	}
}
