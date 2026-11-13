package host_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

// INV-9 (D-470): GET /v1/state/packages lists the packages whose files are on the box, from one fixed dpkg-query, read-only:
// no lock, no command, no argument from the request. The output is parsed fail-closed.
func TestContract_INV9_PackagesAreTheBoxsDpkgList(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.RuleText("dpkg-query", "${Package}", strings.Join([]string{
		"openssh-server\t1:9.6p1-3ubuntu13.5\tamd64\topenssh\tinstalled",
		"g++\t4:13.2.0-7ubuntu1\tamd64\tgcc-defaults\tinstalled",
		"libc6\t2.39-0ubuntu8.4\ti386\tglibc\ttriggers-pending",
		"libc6\t2.39-0ubuntu8.4\tamd64\tglibc\tinstalled",
		"man-db\t2.12.0-4build2\tamd64\tman-db\ttriggers-awaited",
		"oldpkg\t1.0-1\tall\toldpkg\tconfig-files", // removed, configuration left: not on the box
		"",
	}, "\n"), 0, "", "")
	st, err := e.h.Client.StatePackages(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []api.Package{
		{Name: "g++", Version: "4:13.2.0-7ubuntu1", Arch: "amd64", Source: "gcc-defaults"},
		{Name: "libc6", Version: "2.39-0ubuntu8.4", Arch: "amd64", Source: "glibc"},
		{Name: "libc6", Version: "2.39-0ubuntu8.4", Arch: "i386", Source: "glibc"},
		{Name: "man-db", Version: "2.12.0-4build2", Arch: "amd64", Source: "man-db"},
		{Name: "openssh-server", Version: "1:9.6p1-3ubuntu13.5", Arch: "amd64", Source: "openssh"},
	}
	if !slices.Equal(st.Packages, want) {
		t.Fatalf("packages %+v", st.Packages)
	}
	calls := e.m.Calls("dpkg-query")
	if len(calls) != 1 || len(calls[0]) != 2 || calls[0][0] != "-W" || !strings.HasPrefix(calls[0][1], "-f=${Package}") {
		t.Fatalf("dpkg-query calls %q", calls)
	}
	if code, _ := rawGet(t, e.h, "/v1/state/packages?name=x"); code != 400 {
		t.Errorf("a query string answered %d", code)
	}
}

// One line that is not a package, an unknown status or no installed package at all: the whole read fails (500), so core keeps the
// list it had instead of storing half of one or emptying it.
func TestContract_INV9_PackagesFailClosed(t *testing.T) {
	t.Parallel()
	for name, out := range map[string]string{
		"extra field":       "bash\t5.2-1\tamd64\tbash\tinstalled\tx\n",
		"only bad names":    "Bash\t5.2-1\tamd64\tbash\tinstalled\n",
		"only bad versions": "bash\t5.2 1\tamd64\tbash\tinstalled\n",
		// over the 8 MiB bound of the runner in fewer lines than the line bound, so only the cut output refuses it
		"cut output":     strings.Repeat("bash"+strings.Repeat("x", 100)+"\t5."+strings.Repeat("1", 100)+"\tamd64\tbash"+strings.Repeat("x", 100)+"\tinstalled\n", 30000),
		"unknown status": "bash\t5.2-1\tamd64\tbash\tgone\n",
		"none installed": "bash\t5.2-1\tamd64\tbash\tconfig-files\n",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := startSys(t)
			e.m.RuleText("dpkg-query", "${Package}", out, 0, "", "")
			if code, body := rawGet(t, e.h, "/v1/state/packages"); code != 500 || strings.Contains(string(body), "bash") {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
	e := startSys(t)
	e.m.RuleText("dpkg-query", "${Package}", "bash\t5.2-1\tamd64\tbash\tinstalled\n", 2, "", "")
	if code, _ := rawGet(t, e.h, "/v1/state/packages"); code != 500 {
		t.Errorf("a failing dpkg-query answered %d", code)
	}
}

// One installed package whose name or version breaks dpkg's rules is left out (and logged), not the whole box (D-470).
func TestContract_INV9_AnOddPackageDoesNotHideTheRest(t *testing.T) {
	t.Parallel()
	e := startSys(t)
	e.m.RuleText("dpkg-query", "${Package}", "bash\t5.2-1\tamd64\tbash\tinstalled\nOld_Tool\t1.0\tamd64\tOld_Tool\tinstalled\n", 0, "", "")
	st, err := e.h.Client.StatePackages(t.Context())
	if err != nil || len(st.Packages) != 1 || st.Packages[0].Name != "bash" {
		t.Fatalf("packages %+v, %v; want bash only", st.Packages, err)
	}
}

// While apt runs (or after an interrupted run) a package is half-installed, unpacked or half-configured: the list is no
// snapshot of the box, so the read answers 409 packages_changing (no list, no 500) and core keeps the last good one (D-470).
func TestContract_INV9_PackagesMidChangeAreRetryable(t *testing.T) {
	t.Parallel()
	for _, st := range []string{"half-installed", "unpacked", "half-configured"} {
		t.Run(st, func(t *testing.T) {
			t.Parallel()
			e := startSys(t)
			e.m.RuleText("dpkg-query", "${Package}", "bash\t5.2-1\tamd64\tbash\tinstalled\nzsh\t5.9-6\tamd64\tzsh\t"+st+"\n", 0, "", "")
			if code, body := rawGet(t, e.h, "/v1/state/packages"); code != 409 || !strings.Contains(string(body), api.CodePackagesChanging) || strings.Contains(string(body), "bash") {
				t.Fatalf("%d %s", code, body)
			}
		})
	}
}
