package productid

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
)

func TestKey(t *testing.T) {
	t.Parallel()
	for _, c := range [][3]string{
		{"Oracle", "Java SE", "oracle|java se"},
		{" Microsoft ", " Windows ", "microsoft|windows"},
		{"Microsoft", "", "microsoft|"},
	} {
		if got := Key(c[0], c[1]); got != c[2] {
			t.Errorf("Key(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	if Norm("Photo Station") != "photostation" || Norm("photo_station") != "photostation" {
		t.Error("Norm")
	}
	if NormVendor("Progress Software Corporation") != "progress" || NormVendor("Juniper Networks") != "juniper" {
		t.Error("NormVendor")
	}
	if NormProduct("Apache HTTP Server", "Apache Software Foundation") != "httpserver" || NormProduct("HTTP Server", "Apache") != "httpserver" {
		t.Error("NormProduct")
	}
}

// The catalogue loads, and every exploited-list key it names is a pair of CISA's list (no dead key).
func TestCatalogue_Loads(t *testing.T) {
	t.Parallel()
	if _, err := load(catalogdata.Products, catalogdata.Curated, catalogdata.KEVProducts); err != nil {
		t.Fatal(err)
	}
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &kev); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, k := range kev {
		listed[Key(k.Vendor, k.Product)] = true
	}
	for _, p := range Products() {
		for _, k := range p.KEV[1:] {
			if !listed[k] {
				t.Errorf("%s: kev %q is not in kev-products.json", p.ID, k)
			}
		}
	}
	if n := len(AgentProducts()); n < 90 {
		t.Errorf("only %d products have agent names", n)
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		src                  Source
		name                 string
		id, dist, ver, line  string
		upstream, versionNot bool
	}{
		{Windows, "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "openjdk", "Temurin", "21.0.7", "21", false, true},
		{Windows, "Eclipse Temurin JRE with Hotspot 8u442-b06 (x64)", "openjdk", "Temurin", "1.8.0_442", "8", false, true},
		{Windows, "Java 8 Update 491 (64-bit)", "openjdk", "Oracle", "", "", false, false},
		{Windows, "Java(TM) SE Development Kit 21.0.7 (64-bit)", "openjdk", "Oracle", "21.0.7", "21", false, true},
		{Windows, "Microsoft Build of OpenJDK with Hotspot 17.0.15+6 (x64)", "openjdk", "Microsoft", "17.0.15", "17", false, true},
		{Windows, "Amazon Corretto 21.0.7.6.1 (x64)", "openjdk", "Corretto", "21.0.7", "21", false, true},
		{Windows, "Zulu JDK 17.44 (17.0.8), 64-bit", "openjdk", "Zulu", "17.0.8", "17", false, true},
		{Windows, "IBM Semeru Runtime Open Edition 21.0.7.0 (x64)", "openjdk", "Semeru", "21.0.7", "21", false, true},
		{Windows, "Liberica JDK 21.0.7+9 (64-bit)", "openjdk", "Liberica", "21.0.7", "21", false, true},
		{Linux, "openjdk-17-jre-headless", "openjdk", "OpenJDK", "", "", false, false},
		{Linux, "java-21-openjdk-headless", "openjdk", "OpenJDK", "", "", false, false},
		{Windows, "Microsoft .NET Runtime - 8.0.19 (x64)", "dotnet", "", "8.0.19", "8.0", false, true},
		{Windows, "Microsoft .NET Host FX Resolver - 6.0.25 (x86)", "dotnet", "", "6.0.25", "6.0", false, true},
		{Windows, "Microsoft Windows Desktop Runtime 10.0.1 (x64)", "dotnet", "", "10.0.1", "10.0", false, true},
		{Windows, "Microsoft ASP.NET Core 8.0.19 Shared Framework (x64)", "aspnet-core", "", "8.0.19", "8.0", false, true},
		{Windows, "Microsoft .NET 8.0.19 - Windows Server Hosting", "aspnet-core", "", "8.0.19", "8.0", false, true},
		{Windows, "Python 3.14.10 (64-bit)", "python", "python.org", "3.14.10", "3.14", false, true},
		{Linux, "libpython3.13-stdlib", "python", "", "", "", false, false},
		{Windows, "Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40664", "visual-cpp-redistributable", "", "12.0.40664", "12", false, true},
		{Windows, "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.50.35719", "visual-cpp-redistributable", "", "14.50.35719", "14", false, true},
		{Windows, "Microsoft Visual C++ 2005 Redistributable (x64)", "visual-cpp-redistributable", "", "", "", false, false},
		{Windows, "OpenSSL 3.5.0 Light (64-bit)", "openssl", "Win32/Win64 OpenSSL", "3.5.0", "", false, true},
		{Linux, "openssh-server", "openssh", "", "", "", false, false},
		{Linux, "google-chrome-stable", "google-chrome", "", "", "", true, false},
		{Linux, "linux-image-7.0.0-43-generic", "linux-kernel", "", "", "", false, false},
		{Windows, "Mozilla Firefox 128.0 (x64 en-US)", "firefox", "", "", "", false, false},
		{Windows, "PuTTY release 0.80 (64-bit)", "putty", "", "0.80", "", false, true},
	} {
		p, ok := Resolve(c.src, c.name, "", "")
		if !ok || p.ID != c.id || p.Distribution != c.dist || p.Version != c.ver || p.Line(p.Version) != c.line ||
			p.Upstream != c.upstream || p.VersionNotOwn != c.versionNot {
			t.Errorf("%s %q = %v %+v (line %q)", c.src, c.name, ok, p, p.Line(p.Version))
		}
	}
	for _, name := range []string{"Java Auto Updater", "Python Install Manager", "Microsoft .NET SDK 8.0.413 (x64)", "javascript-common", "python3"} {
		if p, ok := Resolve(Windows, name, "", ""); ok {
			t.Errorf("%q resolves to %s", name, p.ID)
		}
		if p, ok := Resolve(Linux, name, "", ""); ok {
			t.Errorf("package %q resolves to %s", name, p.ID)
		}
	}
}

func TestLine(t *testing.T) {
	t.Parallel()
	java := Product{Scheme: "java", Trains: TrainsMajor}
	for v, want := range map[string]string{"1.8.0_491": "8", "8.0.4910.10": "8", "21.0.7": "21", "": "", "latest": ""} {
		if got := java.Line(v); got != want {
			t.Errorf("Java line of %q = %q, want %q", v, got, want)
		}
	}
	if got := (Product{Trains: TrainsMajorMinor}).Line("8.0.19-0ubuntu1"); got != "8.0" {
		t.Errorf(".NET line = %q", got)
	}
	if got := (Product{}).Line("3.0.13"); got != "" {
		t.Errorf("no trains: %q", got)
	}
}

func TestResolveCPE(t *testing.T) {
	t.Parallel()
	p, ok := Resolve(CPE, "", "", "cpe:/a:igor_sysoev:nginx:1.18.0")
	if !ok || p.ID != "nginx" || p.Key != "f5|nginx" {
		t.Errorf("nmap's nginx = %+v", p)
	}
	p, ok = Resolve(CPE, "", "", "cpe:/a:nlnetlabs:unbound")
	if !ok || p.ID != "" || p.Key != "nlnetlabs|unbound" || len(p.CPEs) != 1 || p.CPEs[0].Base() != "a:nlnetlabs:unbound" {
		t.Errorf("a CPE the catalogue does not list = %+v", p)
	}
	if _, ok := Resolve(CPE, "", "", "cpe:/x:bad"); ok {
		t.Error("a malformed CPE resolved")
	}
	if got := NmapAliases("a:igor_sysoev:nginx"); !slices.Equal(got, []string{"a:f5:nginx", "a:nginx:nginx", "a:f5:nginx_open_source"}) {
		t.Errorf("NmapAliases = %v", got)
	}
}

// A stored row resolves by its other names too: nmap's lower-case vendor and product, a publisher's legal name.
func TestResolveStored(t *testing.T) {
	t.Parallel()
	for _, c := range [][5]string{
		{"igor sysoev", "nginx", "nginx", "", "nginx"},
		{"apple", "mac os x", "", "", "macos"},
		{"Node.js Foundation", "Node.js", "Node.js", "", "nodejs"},
		{"Eclipse Adoptium", "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "", "openjdk"},
		{"juniper", "junos", "", "cpe:/o:juniper:junos", "juniper-junos-os"},
		// a product a person declares by the name its maker or the exploited list gives it, not the catalogue's own
		{"Synology", "DiskStation Manager (DSM)", "Synology DiskStation Manager (DSM)", "", "synology-dsm"},
		{"Synology", "DiskStation Manager", "Synology NAS (DSM)", "", "synology-dsm"},
		{"F5", "NGINX Open Source", "F5 NGINX Open Source", "", "nginx"},
		{"", "", "", "cpe:2.3:a:f5:nginx_open_source:1.30.5:*:*:*:*:*:*:*", "nginx"},
		// every OpenJDK build is the one Java product, with its distribution
		{"Eclipse Adoptium", "Temurin", "Eclipse Adoptium Temurin", "", "openjdk"},
		{"Red Hat", "OpenJDK", "Red Hat OpenJDK", "", "openjdk"},
		{"Red Hat", "build of OpenJDK", "Red Hat build of OpenJDK", "", "openjdk"},
		{"Amazon", "Corretto", "Amazon Corretto", "", "openjdk"},
		{"Azul", "Zulu", "Azul Zulu", "", "openjdk"},
		{"Microsoft", "Build of OpenJDK", "Microsoft Build of OpenJDK", "", "openjdk"},
		{"OpenJDK", "OpenJDK", "OpenJDK", "", "openjdk"},
	} {
		p, ok := ResolveStored(c[0], c[1], c[2], c[3])
		if !ok || p.ID != c[4] {
			t.Errorf("%v = %v %+v", c, ok, p)
		}
	}
	for _, c := range [][3]string{
		{"Brother Industries Ltd.", "BrLauncher", "BrLauncher"},
		{"Veeam Software", "Veeam Agent for Microsoft Windows", "Veeam Agent for Microsoft Windows"}, // not the package "veeam*"
		{"Claris", "Code", "Code"}, // not Visual Studio Code's package "code"
		{"Foo", "Bind", "Bind"},    // not ISC BIND's package "bind"
	} {
		if p, ok := ResolveStored(c[0], c[1], c[2], ""); ok {
			t.Errorf("%v resolves to %+v", c, p)
		}
	}
	if p, ok := ResolveStored("bind9", "bind9", "bind9", ""); !ok || p.ID != "isc-bind" {
		t.Errorf("the package bind9 = %v %+v", ok, p)
	}
	if p, ok := ResolveStored("Wazuh, Inc.", "Wazuh Agent", "Wazuh Agent", ""); !ok || p.ID != "wazuh-agent" || p.HasCPE() {
		t.Errorf("the Wazuh agent must not carry the server's NVD name: %v %+v", ok, p)
	}
	if p, ok := Resolve(Linux, "wazuh-manager", "", ""); !ok || p.ID != "wazuh-server" || !p.Upstream || !p.HasCPE() {
		t.Errorf("wazuh-manager = %v %+v", ok, p)
	}
	if strings.Contains(Products()[0].Key, " |") {
		t.Error("keys are trimmed")
	}
}

// Every curated product (what a person picks when declaring a device) resolves, edge and management devices with their class.
func TestCuratedProductsResolve(t *testing.T) {
	t.Parallel()
	var rows []curatedRow
	if err := json.Unmarshal(catalogdata.Curated, &rows); err != nil {
		t.Fatal(err)
	}
	classes := map[Class]int{}
	for _, r := range rows {
		p, ok := ResolveStored(r.Vendor, r.Product, r.Display, "")
		if !ok {
			t.Errorf("curated %q (%s|%s) does not resolve", r.Display, r.Vendor, r.Product)
			continue
		}
		if !p.Class.Valid() {
			t.Errorf("%q: class %q", r.Display, p.Class)
		}
		classes[p.Class]++
	}
	for name, want := range map[string]Class{
		"FortiGate": ClassFirewall, "Ivanti Connect Secure (Pulse Secure VPN)": ClassVPN, "VMware ESXi": ClassHypervisor,
		"Progress MOVEit Transfer": ClassFileTransfer, "ConnectWise ScreenConnect": ClassRemoteAccess, "MikroTik RouterOS": ClassRouter,
	} {
		i := slices.IndexFunc(rows, func(r curatedRow) bool { return r.Display == name })
		if i < 0 {
			t.Errorf("no curated %q", name)
			continue
		}
		if p, ok := ResolveStored(rows[i].Vendor, rows[i].Product, rows[i].Display, ""); !ok || p.Class != want {
			t.Errorf("%q = %v class %q, want %q", name, ok, p.Class, want)
		}
	}
	if p, ok := ByKey("Fortinet|FortiOS"); !ok || p.Class != ClassFirewall || !slices.Contains(p.KEV, "fortinet|fortios") {
		t.Errorf("ByKey(fortinet|fortios) = %v %+v", ok, p)
	}
	if classes[ClassNone] == len(rows) || classes[ClassFirewall] < 5 {
		t.Errorf("classes = %v", classes)
	}
}

// The OS a network device states is a product of the catalogue with the exploited-list keys of network-os.json.
func TestStatedOS(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ text, key, version, lldp string }{
		{"JUNOS 15.1R7.9", "juniper|junos os", "15.1R7.9", "Juniper Networks"},
		{"FortiOS 7.0.1", "fortinet|fortios", "7.0.1", ""},
	} {
		p, v, lldp, ok := StatedOS(c.text)
		if !ok || p.Key != c.key || v != c.version || lldp != c.lldp {
			t.Fatalf("%q: %q %q %q %v", c.text, p.Key, v, lldp, ok)
		}
		q, ok := ByKey(p.Key)
		if !ok || !slices.Contains(q.KEV, p.Key) || c.key == "fortinet|fortios" && !slices.Contains(q.KEV, "fortinet|multiple products") {
			t.Fatalf("%q: ByKey %v %v", c.text, q.KEV, ok)
		}
	}
	if _, _, _, ok := StatedOS("Linux 4.15 - 5.19"); ok {
		t.Fatal("a fingerprint is no statement")
	}
}
