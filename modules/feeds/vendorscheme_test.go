package feeds

import (
	"testing"

	"github.com/knt048/vedette/core/versionscheme"
)

// RangeScheme reads a row in its product's scheme only when the row says its versions in bounds: an NVD row that names one release
// in its CPE (no bounds) is not every version and is never read as one; a row of every version, and VMware's bounds, are.
func TestRangeScheme(t *testing.T) {
	t.Parallel()
	installed, ok := versionscheme.VMwareESXi.Installed("8.0.3", "24022510")
	if !ok {
		t.Fatal("8.0.3 build 24022510")
	}
	for _, c := range []struct {
		name string
		r    Range
		ok   bool
		want versionscheme.State
	}{
		{"NVD's exact release", Range{Origin: OriginNVD, Part: "o", Vendor: "vmware", Product: "esxi", CPE: "cpe:2.3:o:vmware:esxi:7.0:update_1:*:*:*:*:*:*"}, false, 0},
		{"NVD's exact release, any update", Range{Origin: OriginNVD, Part: "o", Vendor: "vmware", Product: "esxi", CPE: "cpe:2.3:o:vmware:esxi:8.0:*:*:*:*:*:*:*"}, false, 0},
		{"NVD's version not applicable", Range{Origin: OriginNVD, Part: "o", Vendor: "vmware", Product: "esxi", CPE: "cpe:2.3:o:vmware:esxi:-:*:*:*:*:*:*:*"}, false, 0},
		{"every version", Range{Origin: OriginNVD, Part: "o", Vendor: "vmware", Product: "esxi", CPE: "cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*"}, true, versionscheme.Affected},
		{"VMware's U3d", Range{Origin: OriginCNA, Vendor: "vmware", Product: "esxi", StartIncl: "8.0", EndExcl: "ESXi80U3d-24585383", Fixed: "ESXi80U3d-24585383",
			VersionType: "vendor:custom", DefaultStatus: DefaultUnaffected}, true, versionscheme.Affected},
		{"a product without a scheme", Range{Origin: OriginCNA, Vendor: "acme", Product: "gateway", StartIncl: "1.0", EndExcl: "2.0"}, false, 0},
	} {
		_, sp, _, ok := RangeScheme(c.r)
		if ok != c.ok {
			t.Errorf("%s: ok %v", c.name, ok)
			continue
		}
		if ok {
			if v := versionscheme.Judge(installed, []versionscheme.Span{sp}); v.State != c.want {
				t.Errorf("%s: %v", c.name, v.State)
			}
		}
	}
}
