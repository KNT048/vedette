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
	for arch, want := range map[string]string{"64-bit": "x64", "64 bits": "x64", "64-Bit": "x64", "32-bit": "x86", "ARM 64-bit Processor": "arm64", "": "", "unknown": "",
		"x86_64": "x64", "AMD64": "x64", "i686": "x86", "i386": "x86", "x86": "x86", "aarch64": "arm64", "ARM64": "arm64"} { // osquery (WMI), then Wazuh
		if got := winTarget(arch); got != want {
			t.Errorf("arch %q: %q, want %q", arch, got, want)
		}
	}
}

// D-546: the OS row names the release as NVD's ranges do (core/winrel), client or server by the name, with the full version, the
// machine's target and CISA's key. A build the table does not list, no revision, or a 6.x release give no row, as before.
func TestWindowsRow(t *testing.T) {
	s, ok := windowsRow(winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"})
	if !ok || s.Display != "Windows 11 23H2" || s.Vendor != "microsoft" || s.Product != "Windows 11 23H2" || s.Version != "10.0.22631.4460" ||
		s.CPE != "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*" || !slices.Equal(s.KevKeys, []string{"microsoft|windows"}) || s.Guess || s.Packaged {
		t.Fatalf("Windows 11 23H2: %+v %v", s, ok)
	}
	for _, c := range []struct{ name, version, product string }{
		{"Microsoft Windows Server 2025 Standard", "10.0.26100.2314", "windows_server_2025"},
		{"Microsoft Windows 11 Enterprise", "10.0.26100.2314", "windows_11_24h2"},
		{"Microsoft Windows 11 Pro", "10.0.26200.7092", "windows_11_25h2"},
		{"Microsoft Windows 11 Pro", "10.0.22000.3260", "windows_11_21h2"}, // review L4
		{"Microsoft Windows 10 Enterprise", "10.0.19043.2364", "windows_10_21h1"},
		{"Microsoft Windows 10 Pro", "10.0.19041.1415", "windows_10_2004"},
		{"Microsoft Windows Server 2019 Datacenter", "10.0.17763.6532", "windows_server_2019"},
		{"Microsoft Windows 10 Enterprise LTSC 2019", "10.0.17763.6532", "windows_10_1809"},
		{"Microsoft Windows 10 Pro", "10.0.19045.5131", "windows_10_22h2"},
		{"Microsoft Windows Server 2022 Standard", "10.0.20348.2849", "windows_server_2022"},
		{"Microsoft Windows Server Datacenter", "10.0.25398.1965", "windows_server_2022_23h2"},
	} {
		s, ok := windowsRow(winOS{name: c.name, version: c.version})
		if !ok || s.CPE != "cpe:2.3:o:microsoft:"+c.product+":"+c.version+":*:*:*:*:*:*:*" {
			t.Errorf("%s %s: %+v %v", c.name, c.version, s, ok)
		}
	}
	for _, w := range []winOS{
		{name: "Microsoft Windows 11 Pro", version: "10.0.22631"},         // no revision
		{name: "Microsoft Windows Server 2012 R2", version: "6.3.9600.1"}, // NVD names 6.x without build ranges
	} {
		if s, ok := windowsRow(w); ok {
			t.Errorf("%+v: row %+v", w, s)
		}
	}
	// review r1 M3, LOW-4: a build the table does not list yet, a server-only build named as a client, Azure Local on a build clients
	// share: a row named by the machine, keyed to Windows, without a release CPE (findings: "not checked", not nothing)
	for _, c := range []struct{ name, version, display string }{
		{"Microsoft Windows 11 Pro", "10.0.28000.1", "Windows 11 Pro"},
		{"Microsoft Windows 10 Pro", "10.0.20348.2849", "Windows 10 Pro"},
		{"Microsoft Azure Stack HCI", "10.0.26100.4652", "Azure Stack HCI"},
		{"Microsoft Azure Local", "10.0.26100.4652", "Azure Local"},
	} {
		s, ok := windowsRow(winOS{name: c.name, version: c.version, target: "x64"})
		if !ok || s.Display != c.display || s.Product != c.display || s.Vendor != "microsoft" || s.Version != c.version || s.CPE != "" ||
			!slices.Equal(s.KevKeys, []string{"microsoft|windows"}) {
			t.Errorf("%s %s: %+v %v", c.name, c.version, s, ok)
		}
	}
}

// The node's release shows on the OS: on the request's os_version row of the same build, or from the revision's own row alone. A
// Windows package list carries the operating system's row first (D-546), unless the request's os_version is of another build (a
// feature update whose revision is not reported yet: the stored release is stale, review M2). Linux or no release leave the
// snapshots as they are.
func TestWithWindows(t *testing.T) {
	w := winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"}
	osv := func(build string) []row {
		return []row{{"name": "Microsoft Windows 11 Pro", "version": "10.0." + build, "build": build, "platform": "windows"}}
	}
	progs := []row{{"name": "7-Zip 24.08 (x64)", "version": "24.08"}}
	osText := func(snaps map[string][]row) string {
		t.Helper()
		obs := observations(observe.AssetHint{}, snaps, "")
		if len(obs) == 0 {
			return ""
		}
		return obs[0].Value
	}
	in := map[string][]row{"os_version": osv("22631"), "programs": progs}
	out := withWindows(in, w)
	if in["os_version"][0]["version"] != "10.0.22631" || in["windows_os"] != nil {
		t.Fatal("the request's snapshots were changed")
	}
	if got := osText(out); got != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("OS: %q", got)
	}
	items, _ := mapPackages(out, 1) // a list cut at its limit keeps the operating system
	if len(items) != 1 || items[0].Product != "Windows 11 23H2" || items[0].CPE != "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*" {
		t.Fatalf("items: %+v", items)
	}
	if items, _ := mapPackages(withWindows(map[string][]row{"programs": progs}, w), maxRows); len(items) != 2 || items[0].Product != "Windows 11 23H2" {
		t.Fatalf("a list without os_version: %+v", items)
	}
	// the revision alone (its first report): the OS at once, typed by its name; no package list, no row
	alone := map[string][]row{"os_revision": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "4460", "arch": "64-bit"}}}
	if got := withWindows(alone, w); osText(got) != "Microsoft Windows 11 Pro 10.0.22631.4460" || got["windows_os"] != nil {
		t.Fatalf("revision alone: %v", got)
	}
	// a stored release the revision row of this request does not give (it was refused): no OS from the stored value alone
	bad := map[string][]row{"os_revision": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "revision": "0"}}}
	if got := withWindows(bad, w); got["os_version"] != nil {
		t.Fatalf("a refused revision made an OS: %v", got)
	}
	// another build than the stored one (a feature update whose revision is not reported yet): the OS keeps the build text, and the
	// package list carries no row of the old release
	up := withWindows(map[string][]row{"os_version": osv("26100"), "programs": progs}, w)
	if got := osText(up); got != "Microsoft Windows 11 Pro 10.0.26100 build 26100" || up["windows_os"] != nil {
		t.Fatalf("another build: %q %v", got, up["windows_os"])
	}
	linux := map[string][]row{"deb_packages": {{"name": "bash", "version": "5.3-1"}}}
	if got := withWindows(linux, winOS{}); len(got) != 1 {
		t.Fatalf("no Windows release: %v", got)
	}
}

// D-546: a Wazuh Windows agent whose os version carries the revision gets the same row, with the target of its os.arch (review M1).
func TestWazuhWindows(t *testing.T) {
	var a wzAgent
	a.OS.Name, a.OS.Version, a.OS.Platform, a.OS.Arch = "Microsoft Windows Server 2022 Standard", "10.0.20348.2700", "windows", "x86_64"
	w := wazuhWindows(a)
	if w != (winOS{name: "Microsoft Windows Server 2022 Standard", version: "10.0.20348.2700", target: "x64"}) {
		t.Fatalf("full version: %+v", w)
	}
	if s, ok := windowsRow(w); !ok || s.CPE != "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:x64:*" {
		t.Fatalf("row: %+v %v", s, ok)
	}
	a.OS.Arch = ""
	if w := wazuhWindows(a); w.target != "" {
		t.Fatalf("no arch: %+v", w)
	}
	a.OS.Version = "10.0.20348" // no revision: nothing
	if w := wazuhWindows(a); w != (winOS{}) {
		t.Fatalf("no revision: %+v", w)
	}
	a.OS.Version, a.OS.Platform = "10.0.20348.2700", "ubuntu"
	if w := wazuhWindows(a); w != (winOS{}) {
		t.Fatalf("not Windows: %+v", w)
	}
}
