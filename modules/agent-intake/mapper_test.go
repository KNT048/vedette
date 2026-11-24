package agentintake

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/productid"
)

// Every product the old package map named is still named by the same package and program names (the catalogue took them over).
func TestCatalogueKeepsThePackageNames(t *testing.T) {
	t.Parallel()
	for name, key := range map[string]string{
		"openssh-server": "openbsd|openssh", "libssl3t64": "openssl|openssl", "libc6": "gnu|gnu c library", "policykit-1": "red hat|polkit",
		"linux-image-6.8.0-45-generic": "linux|kernel", "php8.3": "php|php", "google-chrome-stable": "google|chrome", "tomcat9": "apache|tomcat",
	} {
		if p, ok := linuxProduct(name); !ok || p.Key != key {
			t.Errorf("package %q = %v %q, want %q", name, ok, p.Key, key)
		}
	}
	for name, key := range map[string]string{
		"7-Zip 24.08 (x64)": "7-zip|7-zip", "Java 8 Update 491 (64-bit)": "oracle|java se", "Microsoft Edge": "microsoft|edge",
		"Veeam Backup & Replication": "veeam|backup & replication", "Microsoft SQL Server 2022 (64-bit)": "microsoft|sql server",
	} {
		if p, ok := productid.Resolve(productid.Windows, name, "", ""); !ok || p.Key != key {
			t.Errorf("program %q = %v %q, want %q", name, ok, p.Key, key)
		}
	}
}

// Golden: 20 real package names and what they become.
func TestMapPackagesGolden(t *testing.T) {
	snaps := map[string][]row{
		"deb_packages": {
			{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5"},
			{"name": "openssh-client", "version": "1:9.6p1-3ubuntu13.5"}, // the same product and version once
			{"name": "apache2", "version": "2.4.58-1ubuntu8.4"},
			{"name": "libssl3t64", "version": "3.0.13-0ubuntu3.4"},
			{"name": "sudo", "version": "1.9.15p5-3ubuntu5"},
			{"name": "linux-image-6.8.0-45-generic", "version": "6.8.0-45.45"},
			{"name": "policykit-1", "version": "124-2ubuntu1"},
			{"name": "libc6", "version": "2.39-0ubuntu8.3", "source": "glibc"},
			{"name": "libssl-dev", "version": "3.0.13-0ubuntu3.4", "source": "openssl"}, // by source
			{"name": "tomcat9", "version": "9.0.70-2"},
			{"name": "tomcatjss", "version": "8.4.0"}, // a prefix of tomcat but not tomcat8/9/10: not Apache Tomcat
			{"name": "postgresql-common", "version": "261"},
			{"name": "htop", "version": "3.3.0-4build1"},
		},
		"rpm_packages": {
			{"name": "nginx", "version": "1.20.1", "release": "14.el9", "epoch": "1"},
			{"name": "httpd", "version": "2.4.57", "release": "5.el9"},
			{"name": "bash", "version": "5.1.8", "release": "6.el9_1"},
		},
		"programs": {
			{"name": "7-Zip 23.01 (x64 edition)", "version": "23.01", "publisher": "Igor Pavlov"},
			{"name": "Google Chrome", "version": "130.0.6723.92", "publisher": "Google LLC"},
			{"name": "Microsoft Office Professional Plus 2019 - en-us", "version": "16.0.10412.20002", "publisher": "Microsoft Corporation"},
			{"name": "Git", "version": "2.46.0", "publisher": "The Git Development Community"},
			{"name": "GitHub Desktop", "version": "3.4", "publisher": "GitHub, Inc."}, // not Git
			{"name": "Notepad++ (64-bit x64)", "version": "8.6.9", "publisher": "Notepad++ Team"},
			{"name": "Mystery Tool", "version": "1.0"},
		},
	}
	items, dropped := mapPackages(snaps, maxRows)
	if dropped != 0 {
		t.Fatalf("dropped %d", dropped)
	}
	type g struct{ vendor, product, version, key string }
	want := []g{
		{"OpenBSD", "OpenSSH", "9.6p1", "openbsd|openssh"},
		{"Apache", "HTTP Server", "2.4.58", "apache|http server"},
		{"OpenSSL", "OpenSSL", "3.0.13", "openssl|openssl"},
		{"Sudo", "Sudo", "1.9.15p5", "sudo|sudo"},
		{"Linux", "Kernel", "6.8.0", "linux|kernel"},
		{"Red Hat", "Polkit", "124", "red hat|polkit"},
		{"GNU", "GNU C Library", "2.39", "gnu|gnu c library"},
		{"Apache", "Tomcat", "9.0.70", "apache|tomcat"},
		{"tomcatjss", "tomcatjss", "8.4.0", ""},
		{"postgresql-common", "postgresql-common", "261", ""},
		{"htop", "htop", "3.3.0", ""},
		{"F5", "nginx", "1.20.1", "f5|nginx"},
		{"Apache", "HTTP Server", "2.4.57", "apache|http server"},
		{"GNU", "GNU Bash", "5.1.8", "gnu|gnu bash"},
		{"7-Zip", "7-Zip", "23.01", "7-zip|7-zip"},
		{"Google", "Chrome", "130.0.6723.92", "google|chrome"},
		{"Microsoft", "Office", "16.0.10412.20002", "microsoft|office"},
		{"Git", "Git", "2.46.0", "git|git"},
		{"GitHub, Inc.", "GitHub Desktop", "3.4", ""},
		{"Notepad++", "Notepad++", "8.6.9", "notepad++|notepad++"},
		{"Mystery Tool", "Mystery Tool", "1.0", ""},
	}
	if len(items) != len(want) {
		for _, it := range items {
			t.Logf("%s | %s | %s | %v", it.Vendor, it.Product, it.Version, it.KevKeys)
		}
		t.Fatalf("%d items, want %d", len(items), len(want))
	}
	for i, w := range want {
		it := items[i]
		key := ""
		if len(it.KevKeys) > 0 {
			key = it.KevKeys[0]
		}
		if it.Vendor != w.vendor || it.Product != w.product || it.Version != w.version || key != w.key || it.Confidence != softwareConfidence {
			t.Errorf("item %d = %s | %s | %s | %v, want %+v", i, it.Vendor, it.Product, it.Version, it.KevKeys, w)
		}
		if packaged := i < 14; it.Packaged != packaged { // MK-2: the 11 deb and 3 rpm rows came from the package database, programs did not
			t.Errorf("item %d (%s) packaged = %v, want %v", i, it.Product, it.Packaged, packaged)
		}
	}
}

func TestDebUpstream(t *testing.T) {
	for in, want := range map[string]string{
		"1:9.6p1-3ubuntu13.5": "9.6p1", "2.4.58-1ubuntu8.4": "2.4.58", "5.1.8": "5.1.8", "1.2-3-4": "1.2-3", "": "", "10:abc": "abc",
		"a:b-1": "a:b", "-1": "-1", "1:": "",
	} {
		if got := debUpstream(in); got != want {
			t.Errorf("debUpstream(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMapPackagesBoundsAndKeyLength(t *testing.T) {
	long := strings.Repeat("x", 200)
	items, dropped := mapPackages(map[string][]row{"deb_packages": {{"name": long, "version": "1"}, {"name": "ok", "version": strings.Repeat("9", 101)}, {"name": "", "version": "1"}}}, maxRows)
	if len(items) != 0 || dropped != 3 { // a 200+200+1 byte key is over the inventory's 400, so the row is dropped, not the list
		t.Fatalf("%d items, %d dropped", len(items), dropped)
	}
	many := make([]row, 6000)
	for i := range many {
		many[i] = row{"name": "p" + strings.Repeat("a", i%50) + string(rune('a'+i%26)) + strings.Repeat("b", i/50), "version": "1"}
	}
	items, _ = mapPackages(map[string][]row{"deb_packages": many}, maxRows)
	if len(items) > maxRows {
		t.Fatalf("%d items over the cap", len(items))
	}
}

// The kind comes from the OS and stays within the inventory's kind list; an unknown platform gives none.
func TestKindFromTheOS(t *testing.T) {
	for _, c := range []struct{ platform, name, want string }{
		{"ubuntu", "Ubuntu", "server"},
		{"rhel", "Red Hat Enterprise Linux", "server"},
		{"rocky", "Rocky Linux", "server"},
		{"windows", "Microsoft Windows Server 2022 Datacenter", "server"},
		{"windows", "Microsoft Windows 11 Pro", "pc"},
		{"darwin", "macOS", "pc"},
		{"Ubuntu", "Ubuntu", "server"},
		{"linuxmint", "Linux Mint", ""},
		{"", "", ""},
	} {
		if got := kindOf(row{"platform": c.platform, "name": c.name}); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.platform, c.name, got, c.want)
		}
	}
	obs := observations(observe.AssetHint{}, map[string][]row{"os_version": {{"name": "Ubuntu", "version": "26.04.1 LTS", "platform": "ubuntu"}}}, "")
	if len(obs) != 2 || obs[1].Field != observe.Kind || obs[1].Value != "server" || obs[1].Source != observe.Agent {
		t.Fatalf("observations %+v", obs)
	}
}

// A deb row carries its full Debian version and source package; binaries of one source that become one row keep the
// lowest full version (a binary that was not updated keeps its finding); rpm and programs rows carry neither.
func TestMapDebPackagesKeepsFullVersionAndSource(t *testing.T) {
	t.Parallel()
	items, dropped := MapDebPackages([]DebPackage{
		{Name: "openssh-client", Version: "1:9.6p1-3ubuntu13.14", Source: "openssh"},
		{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Source: "openssh"},
		{Name: "openssh-sftp-server", Version: "1:9.6p1-3ubuntu13.14", Source: "openssh (1:9.6p1-3ubuntu13.14)"},
		{Name: "sudo", Version: "1.9.15p5-3ubuntu5.24.04.1"}, // osquery leaves source empty when it is the package's own name
		{Name: "htop", Version: "not a version"},
	})
	if dropped != 0 || len(items) != 3 {
		t.Fatalf("%d items, %d dropped: %+v", len(items), dropped, items)
	}
	want := map[string][2]string{"OpenSSH": {"1:9.6p1-3ubuntu13.5", "openssh"}, "Sudo": {"1.9.15p5-3ubuntu5.24.04.1", "sudo"}, "htop": {}}
	for _, it := range items {
		if got := [2]string{it.PkgVersion, it.PkgSource}; got != want[it.Product] || !it.Packaged {
			t.Errorf("%s: %v packaged %v, want %v", it.Product, got, it.Packaged, want[it.Product])
		}
	}
	rpm, _ := mapPackages(map[string][]row{"rpm_packages": {{"name": "sudo", "version": "1.9.5p2"}}, "programs": {{"name": "Google Chrome", "version": "130.0"}}}, 10)
	for _, it := range rpm {
		if it.PkgVersion != "" || it.PkgSource != "" {
			t.Errorf("%s carries a Debian version: %+v", it.Product, it)
		}
	}
}

// The Kernel row takes the version of the kernel that RUNS (the "kernel" column of the deb rows,
// osquery kernel_info.version): running 7.0.0-43 with 7.0.0-30 installed gives 43, running 30 with 43 installed (not
// rebooted yet) gives 30, and an unknown or unlisted running kernel gives the lowest installed image, as every package. The
// metapackage linux-image-generic (source linux-meta) never gives the row its version, whatever the order.
func TestMapPackagesKernelFollowsTheRunningKernel(t *testing.T) {
	t.Parallel()
	list := func(running string, order ...int) []row {
		all := []row{
			{"name": "linux-image-7.0.0-30-generic", "version": "7.0.0-30.30", "source": "linux-signed"},
			{"name": "linux-image-7.0.0-43-generic", "version": "7.0.0-43.43", "source": "linux-signed"},
			{"name": "linux-image-generic", "version": "7.0.0-43.44", "source": "linux-meta"},
		}
		var out []row
		for _, i := range order {
			r := all[i]
			r["kernel"] = running
			out = append(out, r)
		}
		return out
	}
	for _, c := range []struct {
		running, want string
	}{
		{"7.0.0-43-generic", "7.0.0-43.43"},
		{"7.0.0-30-generic", "7.0.0-30.30"},
		{"", "7.0.0-30.30"},                    // not known (an old report, the box's own list): the lowest
		{"7.0.0-50-generic", "7.0.0-30.30"},    // a kernel no installed image is: the lowest
		{"7.0.0-43-generic; x", "7.0.0-30.30"}, // not a kernel release: unknown
	} {
		for _, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}} {
			items, _ := mapPackages(map[string][]row{"deb_packages": list(c.running, order...)}, 10)
			var kernels []observe.Software
			own := map[string]string{} // the other images, listed under their own names: name -> full version
			for _, it := range items {
				if it.Product == "Kernel" {
					kernels = append(kernels, it)
				} else {
					own[it.Product] = it.PkgVersion
				}
			}
			if len(kernels) != 1 || kernels[0].PkgVersion != c.want || kernels[0].PkgSource != "linux-signed" {
				t.Fatalf("running %q, order %v: %+v, want one Kernel row at %s", c.running, order, items, c.want)
			}
			// the metapackage names no kernel: never the Kernel row, whatever runs
			if own["linux-image-generic"] != "7.0.0-43.44" {
				t.Fatalf("running %q, order %v: the metapackage %+v", c.running, order, items)
			}
			// a known running kernel: the image that does not run keeps its own name and release (a restart would bring it)
			other := map[string]string{"7.0.0-43-generic": "linux-image-7.0.0-30-generic", "7.0.0-30-generic": "linux-image-7.0.0-43-generic"}[c.running]
			if other != "" && own[other] == "" || other == "" && len(own) != 1 {
				t.Fatalf("running %q, order %v: the other image %+v", c.running, order, items)
			}
		}
	}
	if items, _ := mapPackages(map[string][]row{"deb_packages": list("7.0.0-43-generic", 2)}, 10); len(items) != 1 || items[0].Product == "Kernel" {
		t.Fatalf("a metapackage alone made a Kernel row: %+v", items)
	}
	// Wazuh: the running kernel is the third field of the agent's uname
	var a wzAgent
	a.OS.Uname = "Linux |srv01 |7.0.0-43-generic |#43-Ubuntu SMP PREEMPT_DYNAMIC |x86_64"
	if k := wazuhKernel(a); k != "7.0.0-43-generic" {
		t.Fatalf("wazuhKernel = %q", k)
	}
	if rows := wazuhSnaps([]wzPackage{{Name: "linux-image-7.0.0-43-generic", Version: "7.0.0-43.43", Format: "deb", Source: "linux-signed"}}, "7.0.0-43-generic"); rows["deb_packages"][0]["kernel"] != "7.0.0-43-generic" {
		t.Fatalf("wazuh rows %+v", rows)
	}
}

// Review L1 of #732: a binary built from another source release (its Source names another epoch or upstream) gives no full
// version; a binNMU of the same release and the signed kernels keep it.
func TestMapPackagesSourceOfAnotherRelease(t *testing.T) {
	t.Parallel()
	items, _ := mapPackages(map[string][]row{"deb_packages": {
		{"name": "openssh-server", "version": "1:9.6p1-3ubuntu13.5", "source": "openssh (1:9.7p1-1)"},
		{"name": "sudo", "version": "1.9.15p5-3ubuntu5+b1", "source": "sudo (1.9.15p5-3ubuntu5)"},
		{"name": "linux-image-6.1.0-18-amd64", "version": "6.1.76-1", "source": "linux-signed-amd64 (6.1.76+1)"},
	}}, 10)
	want := map[string]string{"OpenSSH": "", "Sudo": "1.9.15p5-3ubuntu5+b1", "Kernel": "6.1.76-1"}
	for _, it := range items {
		if it.PkgVersion != want[it.Product] {
			t.Errorf("%s: %q, want %q", it.Product, it.PkgVersion, want[it.Product])
		}
	}
}

// #910, review r1 (4) of #913: a vendor's own package (Google's, Microsoft's repository) carries the product's own release, so its
// row is not Packaged and findings compares it with NVD's ranges; the distribution's own browser package stays Packaged.
func TestMapPackagesVendorBuildIsNotTheDistributions(t *testing.T) {
	t.Parallel()
	items, _ := mapPackages(map[string][]row{
		"deb_packages": {
			{"name": "google-chrome-stable", "version": "120.0.6099.109-1"},
			{"name": "microsoft-edge-stable", "version": "120.0.2210.61-1"},
			{"name": "firefox-esr", "version": "115.6.0esr-1~deb12u1", "source": "firefox-esr"},
		},
		"rpm_packages": {{"name": "google-chrome-stable", "version": "121.0.6167.85"}},
	}, 10)
	want := map[string]bool{"Chrome 120.0.6099.109": false, "Edge 120.0.2210.61": false, "Firefox 115.6.0esr": true, "Chrome 121.0.6167.85": false}
	if len(items) != len(want) {
		t.Fatalf("%d items: %+v", len(items), items)
	}
	for _, it := range items {
		k := it.Product + " " + it.Version
		if p, ok := want[k]; !ok || it.Packaged != p || !p && (it.PkgVersion != "" || it.PkgSource != "") || len(it.KevKeys) == 0 {
			t.Errorf("%s: packaged %v pkg %q/%q keys %v", k, it.Packaged, it.PkgVersion, it.PkgSource, it.KevKeys)
		}
	}
}

// A JDK of any distribution is the one Java product, with the release its name states: Windows lists Temurin 21.0.7+6 as
// 21.0.7.6, which compared as a number would be newer than 21.0.7 and miss every fix in 21.0.8.
func TestMapPackages_JDKDistributions(t *testing.T) {
	t.Parallel()
	items, _ := mapPackages(map[string][]row{"programs": {
		{"name": "Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "version": "21.0.7.6", "publisher": "Eclipse Adoptium"},
		{"name": "Java 8 Update 491 (64-bit)", "version": "8.0.4910.10", "publisher": "Oracle Corporation"},
		{"name": "Zulu JDK 17.44, 64-bit", "version": "17.44.15", "publisher": "Azul Systems, Inc."},
		{"name": "Java Auto Updater", "version": "2.8.491.10", "publisher": "Oracle Corporation"},
	}}, 100)
	want := []struct{ display, product, version string }{
		{"Eclipse Temurin JDK with Hotspot 21.0.7+6 (x64)", "Java SE", "21.0.7"},
		{"Java 8 Update 491 (64-bit)", "Java SE", "8.0.4910.10"},
		{"Zulu JDK 17.44, 64-bit", "Java SE", ""}, // Zulu's own build number is not Java's release
		{"Java Auto Updater", "Java Auto Updater", "2.8.491.10"},
	}
	if len(items) != len(want) {
		t.Fatalf("%d items: %+v", len(items), items)
	}
	for i, w := range want {
		it := items[i]
		java := w.product == "Java SE"
		if it.Display != w.display || it.Product != w.product || it.Version != w.version || java != slices.Contains(it.KevKeys, "oracle|java se") {
			t.Errorf("item %d = %+v, want %+v", i, it, w)
		}
	}
}
