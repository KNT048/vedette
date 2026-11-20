package ids

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

type fixtureLine struct {
	Profile string `json:"profile"`
	Kind    string `json:"kind"`
	Note    string `json:"note"`
	Line    string `json:"line"`
	Want    *struct {
		SID       int64    `json:"sid"`
		Signature string   `json:"signature"`
		Category  string   `json:"category"`
		Priority  int      `json:"priority"`
		Src       string   `json:"src"`
		Dst       string   `json:"dst"`
		DstPort   int      `json:"dst_port"`
		Proto     string   `json:"proto"`
		CVEs      []string `json:"cves"`
	} `json:"want"`
}

// fixtureLines are invented lines in each vendor's documented IPS event format (documentation addresses, example.com), and lines of
// the same devices that are not IPS events.
func fixtureLines(t testing.TB) []fixtureLine {
	t.Helper()
	b, err := os.ReadFile("testdata/ips_lines.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []fixtureLine
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseReadsEachVendorsIPSEvent(t *testing.T) {
	t.Parallel()
	for _, f := range fixtureLines(t) {
		t.Run(f.Profile+"/"+f.Note, func(t *testing.T) {
			t.Parallel()
			e, ok := Parse(f.Kind, f.Line)
			if f.Want == nil {
				if ok {
					t.Fatalf("not an IPS event, read as %+v", e)
				}
				return
			}
			if !ok {
				t.Fatal("an IPS event was not read")
			}
			w := f.Want
			got := []any{e.Profile, e.SID, e.Signature, e.Category, e.Priority, e.Src.String(), e.Dst.String(), e.DstPort, e.Proto}
			want := []any{f.Profile, w.SID, w.Signature, w.Category, w.Priority, w.Src, w.Dst, w.DstPort, w.Proto}
			if !slices.Equal(got, want) {
				t.Errorf("read %v\nwant %v", got, want)
			}
			if !slices.Equal(e.CVEs, w.CVEs) && (len(e.CVEs) > 0 || len(w.CVEs) > 0) {
				t.Errorf("CVEs %v, want %v", e.CVEs, w.CVEs)
			}
		})
	}
}

// The class: every device profile that has an IPS event format. Its N event lines make N events, M of them with CVE ids; its other
// lines make none. The numbers are printed so a profile that reads less than before shows.
func TestCountIPSLinesPerProfile(t *testing.T) {
	t.Parallel()
	type tally struct{ events, read, withCVE, others, misread int }
	per := map[string]*tally{}
	for _, f := range fixtureLines(t) {
		c := per[f.Profile]
		if c == nil {
			c = &tally{}
			per[f.Profile] = c
		}
		e, ok := Parse(f.Kind, f.Line)
		if f.Want != nil {
			c.events++
			if ok {
				c.read++
				if len(e.CVEs) > 0 {
					c.withCVE++
				}
			}
		} else {
			c.others++
			if ok {
				c.misread++
			}
		}
	}
	profiles := []string{"fortigate", "suricata", "snort", "suricata_eve", "sophos", "sonicwall", "paloalto", "meraki"}
	for _, p := range profiles {
		c := per[p]
		if c == nil || c.events == 0 {
			t.Errorf("%s: no IPS event fixture", p)
			continue
		}
		t.Logf("%-13s %d IPS lines -> %d alerts, %d with CVE ids; %d other lines -> %d alerts", p, c.events, c.read, c.withCVE, c.others, c.misread)
		if c.read != c.events || c.misread != 0 {
			t.Errorf("%s: %d of %d IPS lines read, %d of %d other lines read as events", p, c.read, c.events, c.misread, c.others)
		}
	}
	// every format the module reads has its own fixture
	for kind, formats := range profileKinds {
		for _, f := range formats { // the format "suricata" also covers snort and suricata_eve, which have fixtures of their own
			if per[f] == nil {
				t.Errorf("kind %s: format %s has no fixture", kind, f)
			}
		}
	}
}

func TestParseRefusesWhatIsNotSafeToRead(t *testing.T) {
	t.Parallel()
	ok := `<33>Nov 20 10:15:22 fw suricata[1]: [1:2034647:2] ET EXPLOIT x [Classification: y] [Priority: 1] {TCP} 198.51.100.7:44312 -> 10.0.10.5:8080`
	if _, read := Parse("pfsense", ok); !read {
		t.Fatal("the base line is not read")
	}
	for name, line := range map[string]string{
		"a cut line":         ok + cutMark,
		"an unknown kind":    "",
		"too long":           ok + strings.Repeat(" ", MaxLineBytes),
		"invalid UTF-8":      strings.Replace(ok, "ET EXPLOIT", "ET \xff", 1),
		"bad address":        strings.Replace(ok, "198.51.100.7", "198.51.100.700", 1),
		"no port on TCP":     strings.Replace(ok, "10.0.10.5:8080", "10.0.10.5", 1),
		"port out of range":  strings.Replace(ok, ":8080", ":80800", 1),
		"priority zero":      strings.Replace(ok, "[Priority: 1]", "[Priority: 0]", 1),
		"zone in an address": `<33>Nov 20 10:15:22 fw suricata[1]: [1:1:1] x [Priority: 1] {TCP} fe80::1%eth0:1 -> 10.0.10.5:80`,
	} {
		kind := "pfsense"
		if name == "an unknown kind" {
			kind, line = "mikrotik", ok
		}
		if e, read := Parse(kind, line); read {
			t.Errorf("%s: read as %+v", name, e)
		}
	}
	// Values are bounded: a long signature is cut, CVE ids are capped and sorted, controls never reach a value.
	long := strings.Replace(ok, "ET EXPLOIT x", strings.Repeat("A", 380)+"\u202e CVE-2024-9 CVE-2021-44228 CVE-2019-0708 CVE-2021-9999 CVE-2021-10000 CVE-2020-1 CVE-2022-1111 CVE-2023-2222 CVE-2023-3333 CVE-2024-4444 CVE-2025-5555", 1)
	e, read := Parse("pfsense", long)
	if !read {
		t.Fatal("long line not read")
	}
	if utf8.RuneCountInString(e.Signature) > MaxSignatureLen || strings.ContainsRune(e.Signature, '\u202e') {
		t.Errorf("signature not bounded: %d characters", utf8.RuneCountInString(e.Signature))
	}
	if len(e.CVEs) != MaxCVEs || !slices.IsSortedFunc(e.CVEs, cmpCVE) || e.CVEs[0] != "CVE-2019-0708" || !slices.Contains(e.CVEs, "CVE-2021-9999") {
		t.Errorf("CVEs %v", e.CVEs)
	}
	if i, j := slices.Index(e.CVEs, "CVE-2021-9999"), slices.Index(e.CVEs, "CVE-2021-10000"); i < 0 || j < 0 || i > j {
		t.Errorf("CVE-2021-9999 must sort before CVE-2021-10000: %v", e.CVEs)
	}
}

var cveShape = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// Every byte of a log line is untrusted (SYS-6): whatever the input and the kind, Parse never panics, and what it reads is within
// the bounds of a row.
func FuzzParse(f *testing.F) {
	for _, l := range fixtureLines(f) {
		f.Add(l.Kind, l.Line)
	}
	f.Add("pfsense", "<1>x suricata: [1:1:1]  [Priority: 9] {TCP} [::1]:1 -> [::2]:2")
	f.Add("paloalto", `1,a,b,THREAT,spyware,`+strings.Repeat(`"",`, 200))
	f.Add("fortigate", `type=utm subtype=ips attack="`+strings.Repeat(`\"`, 300))
	f.Fuzz(func(t *testing.T, kind, line string) {
		e, ok := Parse(kind, line)
		if !ok {
			return
		}
		if e.Signature == "" || !utf8.ValidString(e.Signature) || utf8.RuneCountInString(e.Signature) > MaxSignatureLen {
			t.Fatalf("signature %q", e.Signature)
		}
		if !utf8.ValidString(e.Category) || utf8.RuneCountInString(e.Category) > MaxCategoryLen {
			t.Fatalf("category %q", e.Category)
		}
		if e.Priority < 1 || e.Priority > 4 || e.DstPort < -1 || e.DstPort > 65535 || e.SID < -1 || len(e.Proto) > 16 {
			t.Fatalf("bounds %+v", e)
		}
		if !e.Src.IsValid() || !e.Dst.IsValid() || e.Src.Zone() != "" || e.Dst.Zone() != "" {
			t.Fatalf("addresses %+v", e)
		}
		if len(e.CVEs) > MaxCVEs || !slices.IsSortedFunc(e.CVEs, cmpCVE) {
			t.Fatalf("CVEs %v", e.CVEs)
		}
		for _, c := range e.CVEs {
			if !cveShape.MatchString(c) {
				t.Fatalf("CVE %q", c)
			}
		}
		for _, r := range e.Signature + e.Category {
			if r < 0x20 || r == 0x7f || r == 0x202e {
				t.Fatalf("control %U in %q", r, e.Signature+e.Category)
			}
		}
	})
}
