package agentintake

import (
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/observe"
)

// D-524: Windows's update revision is asked of Windows nodes only, from os_version (no registry table), and is first-report data.
func TestScheduleAsksTheWindowsRevisionOfWindowsOnly(t *testing.T) {
	i := slices.IndexFunc(schedule, func(q scheduleQuery) bool { return q.name == "os_revision" })
	if i < 0 {
		t.Fatal("no os_revision query")
	}
	q := schedule[i]
	if q.platform != "windows" || q.interval != 3600 || !strings.Contains(q.query, "revision") || !strings.HasSuffix(q.query, "FROM os_version;") {
		t.Fatalf("os_revision: %+v", q)
	}
	if firstReport["os_revision"] != "os_revision" || !slices.Contains(answers, "os_revision") {
		t.Fatalf("os_revision is an answer of its own of the first report: %q", firstReport["os_revision"])
	}
	for _, q := range schedule {
		if strings.Contains(strings.ToLower(q.query), "registry") {
			t.Fatalf("query %s reads the registry table", q.name)
		}
		if q.name != "os_revision" && strings.Contains(q.query, "revision") {
			t.Fatalf("query %s asks for a Windows-only column on every platform", q.name)
		}
	}
}

func TestParseWinOS(t *testing.T) {
	good := row{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "4460", "arch": "64-bit"}
	with := func(k, v string) []row {
		r := row{}
		for k2, v2 := range good {
			r[k2] = v2
		}
		r[k] = v
		return []row{r}
	}
	w, ok := parseWinOS([]row{good})
	if !ok || w != (winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"}) {
		t.Fatalf("good row: %+v %v", w, ok)
	}
	for name, rows := range map[string][]row{
		"none":            nil,
		"no revision":     with("revision", ""),
		"zero":            with("revision", "0"),
		"negative":        with("revision", "-1"),
		"leading zero":    with("revision", "04460"),
		"plus sign":       with("revision", "+4460"),
		"space":           with("revision", "4460 "),
		"not a number":    with("revision", "4460; DROP"),
		"too big":         with("revision", "1000000"),
		"old release":     with("version", "6.3.9600"),
		"revision inside": with("version", "10.0.22631.4460"),
		"no name":         with("name", ""),
		"long name":       with("name", strings.Repeat("x", maxName+1)),
	} {
		if w, ok := parseWinOS(rows); ok {
			t.Errorf("%s: taken as %+v", name, w)
		}
	}
	if w, ok := parseWinOS(with("revision", "999999")); !ok || w.version != "10.0.22631.999999" {
		t.Errorf("the largest revision: %+v %v", w, ok)
	}
	for arch, want := range map[string]string{"64-bit": "x64", "64 bits": "x64", "64-Bit": "x64", "32-bit": "x86", "ARM 64-bit Processor": "arm64", "": "", "unknown": ""} {
		if got := winTarget(arch); got != want {
			t.Errorf("arch %q: %q, want %q", arch, got, want)
		}
	}
}

// The node's release shows on the OS: on the request's os_version row of the same build, or from the revision's own row alone. Another
// build, Linux, or no release leave the snapshots as they are, and no software row is made (matching is D-524's follow-up).
func TestWithWindows(t *testing.T) {
	w := winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"}
	osv := func(build string) []row {
		return []row{{"name": "Microsoft Windows 11 Pro", "version": "10.0." + build, "build": build, "platform": "windows"}}
	}
	osText := func(snaps map[string][]row) string {
		t.Helper()
		obs := observations(observe.AssetHint{}, snaps, "")
		if len(obs) == 0 {
			return ""
		}
		return obs[0].Value
	}
	in := map[string][]row{"os_version": osv("22631"), "programs": {{"name": "7-Zip 24.08 (x64)", "version": "24.08"}}}
	out := withWindows(in, w)
	if in["os_version"][0]["version"] != "10.0.22631" {
		t.Fatal("the request's snapshots were changed")
	}
	if got := osText(out); got != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("OS: %q", got)
	}
	if items, _ := mapPackages(out, maxRows); len(items) != 1 || items[0].Product == "Windows 11 23H2" {
		t.Fatalf("items: %+v", items)
	}
	// the revision alone (its first report): the OS at once, typed by its name
	alone := map[string][]row{"os_revision": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "4460", "arch": "64-bit"}}}
	if got := osText(withWindows(alone, w)); got != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("revision alone: %q", got)
	}
	// a stored release the revision row of this request does not give (it was refused): no OS from the stored value alone
	bad := map[string][]row{"os_revision": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "0"}}}
	if got := withWindows(bad, w); got["os_version"] != nil {
		t.Fatalf("a refused revision made an OS: %v", got)
	}
	// another build than the stored one (a feature update whose revision is not reported yet): the OS keeps the build text
	if got := osText(withWindows(map[string][]row{"os_version": osv("26100")}, w)); got != "Microsoft Windows 11 Pro 10.0.26100 build 26100" {
		t.Fatalf("another build: %q", got)
	}
	linux := map[string][]row{"deb_packages": {{"name": "bash", "version": "5.3-1"}}}
	if got := withWindows(linux, winOS{}); len(got) != 1 {
		t.Fatalf("no Windows release: %v", got)
	}
}
