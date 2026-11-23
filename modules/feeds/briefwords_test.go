package feeds

import "testing"

// A record's workaround that only says there is none is no workaround: the page says so in its own words, never "None".
func TestBrief_WorkaroundThatSaysNone(t *testing.T) {
	t.Parallel()
	for _, none := range []string{"None", "None\n\nNone", " n/a ", "No workarounds known.", "There is no known mitigation.",
		"No mitigation is currently available.", "There is no workaround solution.", "No workaround available", "There are no mitigations.",
		"No mitigation exists for this issue.", "There is no known mitigation available."} {
		if got := statedWorkaround(none); got != "" {
			t.Errorf("%q: kept as %q", none, got)
		}
	}
	for _, real := range []string{"Apply the patch.", "Restrict listeners to trusted networks.", "Set the diaglevel to 2, 1 or 0",
		"No workaround is needed when the HTTP/3 module is not enabled.", "None of the listed versions is affected if TLS is off.",
		"None\nDisable the admin interface."} {
		if got := statedWorkaround(real); got != real {
			t.Errorf("%q: read as %q", real, got)
		}
	}
}

// The product a CVE page names is the one most of the rows the matcher reads name, a vendor's own rows a product's scheme reads
// included: three ESX rows in VMware's build notation and one Workstation row name ESXi, not Workstation.
func TestBrief_ProductOfTheSchemeRows(t *testing.T) {
	t.Parallel()
	esx := func(start, end string) Range {
		return Range{CVE: "CVE-2026-41703", Origin: OriginCNA, Vendor: "vmware", Product: "esx", StartIncl: start, EndExcl: end, Fixed: end,
			VersionType: VendorNotation + "custom", DefaultStatus: DefaultUnaffected}
	}
	rows := []Range{
		esx("9.1.x.x", "ESXi-9.1.0.0-25370933"), esx("9.0.x.x", "ESXi-9.0.2.0100-25595025"), esx("8.0", "ESXi80U3i-25205845"),
		{CVE: "CVE-2026-41703", Origin: OriginCNA, Vendor: "vmware", Product: "workstation", StartIncl: "25H2", EndExcl: "26H1",
			VersionType: "custom", DefaultStatus: DefaultUnaffected},
	}
	br, _, _ := briefRanges(rows)
	if got := catalogueProduct(br); got != "VMware ESXi" {
		t.Fatalf("product %q, want VMware ESXi", got)
	}
}

// Another assessor's rows a product's scheme reads do not name the CVE: CISA's ADP rows of Oracle's Java and GraalVM on a WebKit flaw
// NVD lists for Apple's systems leave the page naming Apple's product, as NVD's rows do.
func TestBrief_ProductOfAnotherAssessorsRows(t *testing.T) {
	t.Parallel()
	const cve = "CVE-2023-41993"
	nvd := func(part, vendor, product, end string) Range {
		return Range{CVE: cve, Origin: OriginNVD, Part: part, Vendor: vendor, Product: product, CPE: "cpe:2.3:" + part + ":" + vendor + ":" + product + ":*:*:*:*:*:*:*:*", EndExcl: end}
	}
	adp := func(part, vendor, product, start, end, endIncl string) Range {
		return Range{CVE: cve, Origin: OriginADP, Part: part, Vendor: vendor, Product: product, StartIncl: start, EndExcl: end, EndIncl: endIncl,
			VersionType: "custom", DefaultStatus: DefaultUnknown}
	}
	rows := []Range{
		{CVE: cve, Origin: OriginCNA, Vendor: "apple", Product: "macos", EndExcl: "14", VersionType: "custom", DefaultStatus: DefaultUnknown},
		adp("o", "apple", "iphone_os", "", "17.0.1", ""), adp("o", "apple", "ipad_os", "", "17.0.1", ""), adp("o", "apple", "macos", "", "14.0", ""),
		adp("a", "oracle", "graalvm", "20.3.13", "", "20.3.13"), adp("a", "oracle", "graalvm", "21.3.9", "", "21.3.9"),
		adp("a", "oracle", "jdk", "1.8.0", "", "1.8.0"), adp("a", "oracle", "jre", "1.8.0", "", "1.8.0"),
		nvd("o", "apple", "ipados", "17.0.1"), nvd("o", "apple", "iphone_os", "17.0.1"), nvd("o", "apple", "macos", "14.0"),
		nvd("a", "oracle", "graalvm", ""), nvd("a", "oracle", "graalvm", ""), nvd("a", "oracle", "jdk", ""), nvd("a", "oracle", "jre", ""),
		nvd("a", "webkitgtk", "webkitgtk\\+", "2.42.2"),
	}
	br, _, _ := briefRanges(rows)
	if got := catalogueProduct(br); got != "Apple iOS" {
		t.Fatalf("product %q, want Apple iOS", got)
	}
}
