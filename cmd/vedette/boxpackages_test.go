package main

import (
	"context"
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
