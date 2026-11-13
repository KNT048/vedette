package agentintake

import (
	"encoding/json"
	"strings"
	"testing"

	catalogdata "github.com/knt048/vedette/content/catalog"
	"github.com/knt048/vedette/core/observe"
)

// catalogKeys is every lower(vendor)|lower(product) the inventory can match: the KEV pairs and the curated products and match keys.
func catalogKeys(t *testing.T) map[string]bool {
	t.Helper()
	var kev []struct{ Vendor, Product string }
	if err := json.Unmarshal(catalogdata.KEVProducts, &kev); err != nil {
		t.Fatal(err)
	}
	var cur []struct {
		Vendor, Product string
		KevMatch        []string `json:"kev_match"`
	}
	if err := json.Unmarshal(catalogdata.Curated, &cur); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, k := range kev {
		keys[strings.ToLower(k.Vendor)+"|"+strings.ToLower(k.Product)] = true
	}
	for _, c := range cur {
		keys[strings.ToLower(c.Vendor)+"|"+strings.ToLower(c.Product)] = true
		for _, m := range c.KevMatch {
			keys[m] = true
		}
	}
	return keys
}

// D-169 (11): no dead key in the table: every pair is one the catalog knows.
func TestPkgmapPairsExistInTheCatalog(t *testing.T) {
	keys := catalogKeys(t)
	check := func(where, vendor, product string) {
		if k := strings.ToLower(vendor) + "|" + strings.ToLower(product); !keys[k] {
			t.Errorf("%s: %q is in no catalog", where, k)
		}
	}
	for _, tb := range []struct {
		name string
		t    pkgTable
	}{{"linux", pkgmap.Linux}, {"windows", pkgmap.Windows}} {
		for n, p := range tb.t.Exact {
			if n != strings.ToLower(n) {
				t.Errorf("%s %q is not lower case", tb.name, n)
			}
			check(tb.name+" "+n, p.Vendor, p.Product)
		}
		for _, p := range tb.t.Prefix {
			if p.Prefix != strings.ToLower(p.Prefix) || p.Prefix == "" {
				t.Errorf("%s prefix %q is empty or not lower case", tb.name, p.Prefix)
			}
			check(tb.name+" prefix "+p.Prefix, p.Vendor, p.Product)
		}
	}
	if n := len(pkgmap.Linux.Exact) + len(pkgmap.Linux.Prefix) + len(pkgmap.Windows.Exact) + len(pkgmap.Windows.Prefix); n < 60 {
		t.Errorf("only %d entries", n)
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
	items, dropped := mapPackages(snaps)
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
		{"Notepad++ Team", "Notepad++ (64-bit x64)", "8.6.9", ""},
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
	items, dropped := mapPackages(map[string][]row{"deb_packages": {{"name": long, "version": "1"}, {"name": "ok", "version": strings.Repeat("9", 101)}, {"name": "", "version": "1"}}})
	if len(items) != 0 || dropped != 3 { // a 200+200+1 byte key is over the inventory's 400, so the row is dropped, not the list
		t.Fatalf("%d items, %d dropped", len(items), dropped)
	}
	many := make([]row, 6000)
	for i := range many {
		many[i] = row{"name": "p" + strings.Repeat("a", i%50) + string(rune('a'+i%26)) + strings.Repeat("b", i/50), "version": "1"}
	}
	items, _ = mapPackages(map[string][]row{"deb_packages": many})
	if len(items) > maxRows {
		t.Fatalf("%d items over the cap", len(items))
	}
}

// D-503 (W2-12): the kind comes from the OS and stays within the inventory's kind list; an unknown platform gives none.
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
