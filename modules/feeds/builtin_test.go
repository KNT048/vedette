package feeds

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed fixture names under testdata
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseKEV(t *testing.T) {
	t.Parallel()
	c, err := ParseKEV(fixture(t, "kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "2026.11.04" || c.Released != "2026-11-04" || c.Accepted != 3 || c.Rejected != 4 || len(c.Vulns) != 3 || c.Truncated {
		t.Fatalf("%q %q %+v", c.Version, c.Released, c.Stats)
	}
	v := c.Vulns[0]
	want := Vuln{
		CVE: "CVE-2026-10001", Vendor: "Synology", Product: "DiskStation Manager",
		Name:           "Synology DSM Authentication Bypass Vulnerability",
		Description:    "Synology DSM contains an authentication bypass vulnerability.",
		RequiredAction: "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
		Links:          []string{"https://example.com/advisory/1", "https://nvd.nist.gov/vuln/detail/CVE-2026-10001"},
		DateAdded:      "2026-11-03", DueDate: "2026-11-24", Ransomware: true,
	}
	if !reflect.DeepEqual(v, want) {
		t.Errorf("entry 0 = %+v", v)
	}
	if c.Vulns[1].CVE != "CVE-2026-10002" || c.Vulns[1].DueDate != "" || c.Vulns[1].Ransomware || !reflect.DeepEqual(c.Vulns[1].Links, []string{"https://fortiguard.example.com/psirt/FG-IR-26-402"}) {
		t.Errorf("entry 1 = %+v", c.Vulns[1])
	}
	if c.Vulns[2].Links == nil || len(c.Vulns[2].Links) != 0 || c.Vulns[2].Key() != "qnap|photo station" {
		t.Errorf("entry 2 = %+v", c.Vulns[2])
	}
	wantRej := []Reject{
		{4, `cveID: "TBD" is not a CVE ID`},
		{5, `dateAdded: unrecognised date "31/13/2026"`},
		{6, "entry has a field of the wrong type"},
		{7, "cveID: duplicate in the catalog"},
	}
	if !reflect.DeepEqual(c.Rejects, wantRej) {
		t.Errorf("rejects = %+v", c.Rejects)
	}
}

func TestParseKEVFailsClosed(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"", "[]", "{", `{"vulnerabilities":{}}`, `{"vulnerabilities":[}`, `{"a":1}`, `{"vulnerabilities":[]} x`, `{"vulnerabilities":[{"cveID":"CVE-2026-1234","product":}]}`} {
		if _, err := ParseKEV([]byte(s)); !errors.Is(err, ErrBadSample) {
			t.Errorf("%q: %v", s, err)
		}
	}
	if _, err := ParseKEV(make([]byte, MaxBodyBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Error("size limit")
	}
	// Empty catalog is valid and yields no entries.
	c, err := ParseKEV([]byte(`{"vulnerabilities":[]}`))
	if err != nil || len(c.Vulns) != 0 || c.Vulns == nil {
		t.Errorf("%v %+v", err, c)
	}
	// Row limit.
	var b strings.Builder
	b.WriteString(`{"vulnerabilities":[`)
	for i := 0; i < MaxRows+5; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"cveID":"CVE-2026-`)
		b.WriteString(itoaPad(i))
		b.WriteString(`","vendorProject":"v","product":"p","dateAdded":"2026-01-01"}`)
	}
	b.WriteString(`]}`)
	if b.Len() > MaxBodyBytes {
		t.Skip("fixture too big")
	}
	c, err = ParseKEV([]byte(b.String()))
	if err != nil || !c.Truncated || c.Accepted != MaxRows {
		t.Errorf("row limit: %v %+v", err, c.Stats)
	}
}

func itoaPad(i int) string {
	s := []byte("000000")
	for p := 5; p >= 0 && i > 0; p-- {
		s[p] = byte('0' + i%10)
		i /= 10
	}
	return string(s)
}

func TestKEVFieldRules(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("é", 5000)
	in := `{"vulnerabilities":[
	 {"cveID":"CVE-2026-2001","vendorProject":" V ","product":"P","vulnerabilityName":"` + long + `","shortDescription":"` + long + `","dateAdded":"2026-01-01","dueDate":"2026-02-30"},
	 {"cveID":"CVE-2026-2002","vendorProject":"V\u0007","product":"P","dateAdded":"2026-01-01"},
	 {"cveID":"CVE-2026-2003","vendorProject":"","product":"P","dateAdded":"2026-01-01"},
	 {"cveID":"CVE-2026-2004","vendorProject":"` + strings.Repeat("v", 201) + `","product":"P","dateAdded":"2026-01-01"},
	 {"cveID":"CVE-2026-2005","vendorProject":"V","product":"P","dateAdded":"2026-01-01T00:00:00Z"},
	 {"cveID":"CVE-2026-2006","vendorProject":"V","product":"P","dateAdded":"2026-01-01","knownRansomwareCampaignUse":"known"}
	]}`
	c, err := ParseKEV([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if c.Accepted != 1 || c.Vulns[0].CVE != "CVE-2026-2006" || c.Vulns[0].Ransomware {
		t.Fatalf("%+v %+v", c.Stats, c.Vulns)
	}
	// Clipping is visible on a record that is otherwise good.
	c, _ = ParseKEV([]byte(strings.Replace(in, `,"dueDate":"2026-02-30"`, "", 1)))
	if c.Accepted != 2 || utf8.RuneCountInString(c.Vulns[0].Name) != maxNameText || utf8.RuneCountInString(c.Vulns[0].Description) != maxDescText || c.Vulns[0].Vendor != "V" {
		t.Errorf("clipping: %+v", c.Vulns)
	}
}

func TestParseNucleiCVEs(t *testing.T) {
	t.Parallel()
	r, err := ParseNucleiCVEs(fixture(t, "nuclei-cves.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.CVEs, []string{"CVE-2026-10001", "CVE-2026-10003"}) || r.Accepted != 2 || r.Rejected != 4 {
		t.Fatalf("%+v", r)
	}
	// JSON Lines only: an array is one rejected line; CR alone separates lines.
	if a, err := ParseNucleiCVEs([]byte("[{\"ID\":\"CVE-2026-1234\"}]")); err != nil || a.Accepted != 0 || a.Rejected != 1 {
		t.Errorf("array: %v %+v", err, a.Stats)
	}
	if a, err := ParseNucleiCVEs([]byte("{\"ID\":\"CVE-2026-1234\"}\r{\"ID\":\"CVE-2026-5678\"}\r")); err != nil || a.Accepted != 2 {
		t.Errorf("CR: %v %+v", err, a.Stats)
	}
	if _, err := ParseNucleiCVEs(make([]byte, MaxBodyBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Error("size")
	}
}

func TestBuiltinGenericParsersOnRealisticFixtures(t *testing.T) {
	t.Parallel()
	feodo := "# Feodo\n#\n185.220.101.47\n# c\n45.148.10.95\n"
	ipsum := "# IPsum\n1.1.1.1\t8\n2.2.2.2\t3\n"
	tor := "185.220.101.1\n185.220.101.2\n"
	hagezi := "# hagezi\nevil.example.com\nphish.example.net\n"
	cases := map[string]struct {
		in       string
		accepted int
		rejected int
		first    string
	}{"abusech-feodo": {feodo, 2, 0, "185.220.101.47"}, "ipsum": {ipsum, 2, 0, "1.1.1.1"}, "tor-exit": {tor, 2, 0, "185.220.101.1"}, "hagezi-tif": {hagezi, 2, 0, "evil.example.com"}}
	for id, c := range cases {
		s, _ := BuiltinByID(id)
		r, err := ParseFeed(context.Background(), []byte(c.in), s.Kind, *s.Parser)
		if err != nil || r.Accepted != c.accepted || r.Rejected != c.rejected || r.Records[0]["indicator"] != c.first {
			t.Errorf("%s: %v %+v %v", id, err, r.Stats, r.Records)
		}
	}
}
