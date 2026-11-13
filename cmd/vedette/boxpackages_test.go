package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
	"github.com/knt048/vedette/host/server/servertest"
	"github.com/knt048/vedette/modules/inventory"
)

// D-470: the box's dpkg list from vedette-host becomes the box's software the way an osquery deb_packages snapshot does (mapped
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
	if ssh.Vendor != "OpenBSD" || ssh.Version != "9.6p1" || !slices.Equal(ssh.KevKeys, []string{"openbsd|openssh"}) {
		t.Errorf("openssh-server mapped to %+v", ssh)
	}
}

// D-470: while dpkg is mid-change the host answers 409 packages_changing; that is no list (nil, nil), so the inventory keeps the
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

// D-470: the host lists up to 20 000 packages; the box path never cuts the mapped list at an agent's 5 000 rows, so the inventory
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
