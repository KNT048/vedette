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
	if firstReport["os_revision"] != "os_version" {
		t.Fatalf("os_revision belongs to the first report's os_version answer: %q", firstReport["os_revision"])
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

// The OS row names the release as NVD's ranges do, client or server by the name, with the full version and the CISA key.
func TestWindowsRow(t *testing.T) {
	s, ok := windowsRow(winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"})
	if !ok || s.Display != "Windows 11 23H2" || s.Vendor != "microsoft" || s.Product != "Windows 11 23H2" || s.Version != "10.0.22631.4460" ||
		s.CPE != "cpe:2.3:o:microsoft:windows_11_23h2:10.0.22631.4460:*:*:*:*:*:x64:*" || !slices.Equal(s.KevKeys, []string{"microsoft|windows"}) || s.Guess || s.Packaged {
		t.Fatalf("Windows 11 23H2: %+v %v", s, ok)
	}
	for _, c := range []struct{ name, version, product string }{
		{"Microsoft Windows Server 2025 Standard", "10.0.26100.2314", "windows_server_2025"},
		{"Microsoft Windows 11 Enterprise", "10.0.26100.2314", "windows_11_24h2"},
		{"Microsoft Windows Server 2019 Datacenter", "10.0.17763.6532", "windows_server_2019"},
		{"Microsoft Windows 10 Pro", "10.0.19045.5131", "windows_10_22h2"},
		{"Microsoft Windows Server 2022 Standard", "10.0.20348.2849", "windows_server_2022"},
	} {
		s, ok := windowsRow(winOS{name: c.name, version: c.version})
		if !ok || s.CPE != "cpe:2.3:o:microsoft:"+c.product+":"+c.version+":*:*:*:*:*:*:*" {
			t.Errorf("%s %s: %+v %v", c.name, c.version, s, ok)
		}
	}
	for _, w := range []winOS{
		{name: "Microsoft Windows 10 Pro", version: "10.0.18363.1556"},    // a release not in the table: no row, as before
		{name: "Microsoft Windows 10 Pro", version: "10.0.20348.2849"},    // a server-only build named as a client
		{name: "Microsoft Windows 11 Pro", version: "10.0.22631"},         // no revision
		{name: "Microsoft Windows Server 2012 R2", version: "6.3.9600.1"}, // NVD names 6.x without build ranges
	} {
		if s, ok := windowsRow(w); ok {
			t.Errorf("%+v: row %+v", w, s)
		}
	}
}

// The node's release goes into the package list of a Windows request and onto its os_version row; Linux requests stay as they are.
func TestWithWindows(t *testing.T) {
	w := winOS{name: "Microsoft Windows 11 Pro", version: "10.0.22631.4460", target: "x64"}
	in := map[string][]row{
		"os_version": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "build": "22631", "platform": "windows"}},
		"programs":   {{"name": "7-Zip 24.08 (x64)", "version": "24.08"}},
	}
	out := withWindows(in, w)
	if in["os_version"][0]["version"] != "10.0.22631" || in["windows_os"] != nil {
		t.Fatal("the request's snapshots were changed")
	}
	obs := observations(observe.AssetHint{}, out, "")
	if len(obs) == 0 || obs[0].Value != "Microsoft Windows 11 Pro 10.0.22631.4460" {
		t.Fatalf("OS: %+v", obs)
	}
	items, _ := mapPackages(out, 1) // a list cut at its limit keeps the operating system
	if len(items) != 1 || items[0].Product != "Windows 11 23H2" {
		t.Fatalf("items: %+v", items)
	}
	// another build than the stored one (the machine was upgraded, its revision not reported yet): the OS keeps the build text
	up := withWindows(map[string][]row{"os_version": {{"name": "Microsoft Windows 11 Pro", "version": "10.0.26100", "build": "26100", "platform": "windows"}}}, w)
	if obs := observations(observe.AssetHint{}, up, ""); obs[0].Value != "Microsoft Windows 11 Pro 10.0.26100 build 26100" {
		t.Fatalf("another build: %q", obs[0].Value)
	}
	linux := map[string][]row{"deb_packages": {{"name": "bash", "version": "5.3-1"}}}
	if got := withWindows(linux, winOS{}); len(got) != 1 || got["windows_os"] != nil {
		t.Fatalf("no Windows release: %v", got)
	}
}

func TestWazuhWindows(t *testing.T) {
	var a wzAgent
	a.OS.Name, a.OS.Version, a.OS.Platform = "Microsoft Windows Server 2022 Standard", "10.0.20348.2700", "windows"
	if w := wazuhWindows(a); w != (winOS{name: "Microsoft Windows Server 2022 Standard", version: "10.0.20348.2700"}) {
		t.Fatalf("full version: %+v", w)
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
