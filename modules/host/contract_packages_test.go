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
		"extra field":    "bash\t5.2-1\tamd64\tbash\tinstalled\tx\n",
		"bad name":       "Bash\t5.2-1\tamd64\tbash\tinstalled\n",
		"bad version":    "bash\t5.2 1\tamd64\tbash\tinstalled\n",
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
