package pagetext

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// A risk matrix: a two-level header, then rows. The row naming the CVE comes with both header rows and the heading above the table.
const matrix = `<html><head><title>Critical Patch Update - July 2026</title></head><body>
<h1>Critical Patch Update Advisory - July 2026</h1>
<h3>Widget Risk Matrix</h3>
<p>This Critical Patch Update contains 3 new security fixes for Acme Widget. The English text form of this Risk Matrix can be found here.</p>
<table>
<tr><th rowspan="2">CVE#</th><th rowspan="2">Product</th><th colspan="2">CVSS</th><th rowspan="2">Supported Versions Affected</th></tr>
<tr><th>Base Score</th><th>Attack Vector</th></tr>
<tr><td>CVE-2026-90001</td><td>Acme Widget</td><td>9.8</td><td>Network</td><td>Widget 4.0.0-4.2.0</td></tr>
<tr><td>CVE-2026-90002</td><td>Acme Widget Embedded</td><td>5.3</td><td>Local</td><td>Widget 3.1</td></tr>
</table></body></html>`

func TestCut_ATableRowComesWithItsHeaderRows(t *testing.T) {
	t.Parallel()
	_, title := HTML(matrix)
	if title != "Critical Patch Update - July 2026" {
		t.Errorf("title %q", title)
	}
	page := matrix[:len(matrix)-len("</body></html>")] + strings.Repeat("<p>Unrelated text of the advisory, repeated to make the page long.</p>", 200) + "</body></html>"
	blocks, _ := HTML(page)
	ps := Cut(blocks, IDPattern("CVE-2026-90002", nil), nil, false)
	if len(ps) != 1 || ps[0].Kind != "row" {
		t.Fatalf("passages %+v, want one row", ps)
	}
	want := []string{"[section] Widget Risk Matrix", "[table header] CVE# | Product | CVSS | Supported Versions Affected",
		"[table header] Base Score | Attack Vector", "[row] CVE-2026-90002 | Acme Widget Embedded | 5.3 | Local | Widget 3.1"}
	for _, w := range want {
		if !strings.Contains(ps[0].Text, w) {
			t.Errorf("passage lacks %q:\n%s", w, ps[0].Text)
		}
	}
	if strings.Contains(ps[0].Text, "CVE-2026-90001") {
		t.Error("the passage carries another CVE's row")
	}
	if !strings.Contains(Text(blocks), "CVE-2026-90002 | Acme Widget Embedded | 5.3 | Local | Widget 3.1") {
		t.Error("the full text lacks the row as the passage writes it")
	}
}

// The row of a long page is found wherever it is: a cap on the page's start would never reach it.
func TestCut_ARowPastAnyCapIsFound(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	b.WriteString("<html><body><h2>Risk matrix</h2><table><tr><th>CVE#</th><th>Product</th><th>Affected</th></tr>")
	for i := range 1100 {
		fmt.Fprintf(&b, "<tr><td>CVE-2026-1%04d</td><td>Other Product</td><td>9.9 and before</td></tr>", i)
	}
	b.WriteString("<tr><td>CVE-2015-2590</td><td>Java SE</td><td>Java SE 6u95, Java SE 7u80, Java SE 8u45</td></tr></table></body></html>")
	blocks, _ := HTML(b.String())
	full := Text(blocks)
	if at := strings.Index(full, "CVE-2015-2590"); at < 49_000 {
		t.Fatalf("the row is at %d, want past 49,000 characters", at)
	}
	ps := Cut(blocks, IDPattern("CVE-2015-2590", nil), nil, false)
	if len(ps) != 1 || !strings.Contains(ps[0].Text, "[table header] CVE# | Product | Affected") || !strings.Contains(ps[0].Text, "Java SE 8u45") || len(ps[0].Text) > 600 {
		t.Fatalf("passages %+v", ps)
	}
}

// A short page that names the CVE is kept whole: its fix is in a sentence that does not repeat the id.
func TestCut_AShortPageIsKeptWhole(t *testing.T) {
	t.Parallel()
	blocks, _ := HTML(`<html><body><nav>Menu</nav><h1>Vulnerability Note VU#644655</h1><table><tr><th>Vendor</th><th>Status</th></tr><tr><td>UltraVNC</td><td>Not Affected</td></tr></table>
<p>CVE-2026-128321 is a buffer overflow in the viewer.</p><p>The issue is addressed in version 1.8.2.8.</p></body></html>`)
	ps := Cut(blocks, IDPattern("CVE-2026-128321", nil), nil, false)
	if len(ps) != 1 || ps[0].Kind != "page" || !strings.Contains(ps[0].Text, "addressed in version 1.8.2.8") || strings.Contains(ps[0].Text, "Menu") {
		t.Fatalf("passages %+v", ps)
	}
	if ps := Cut(blocks, IDPattern("CVE-2026-1", nil), nil, false); len(ps) != 0 {
		t.Errorf("a page that names no id gave %+v", ps)
	}
}

// Advisory ids come from the record's text and its reference addresses, by shape; a year alone is not an id.
func TestAdvisoryIDs(t *testing.T) {
	t.Parallel()
	got := AdvisoryIDs("See MS15-044 and VMSA-2019-0022.", []string{"https://www.mozilla.org/security/advisories/mfsa2010-73/",
		"https://access.redhat.com/errata/RHSA-2016:1430", "https://example.com/cve/CVE-2026-1234"})
	for _, w := range []string{"MS15-044", "VMSA-2019-0022", "mfsa2010-73", "RHSA-2016:1430"} {
		if !slices.Contains(got, w) {
			t.Errorf("ids %v lack %s", got, w)
		}
	}
	if slices.ContainsFunc(got, func(s string) bool {
		return strings.EqualFold(s, "mfsa2010") || strings.HasPrefix(strings.ToLower(s), "cve")
	}) {
		t.Errorf("ids %v", got)
	}
	if !IDPattern("CVE-2026-1", []string{"MS15-044"}).MatchString("Microsoft Security Bulletin ms15_044") {
		t.Error("the id pattern misses another writing of the advisory id")
	}
}

// A page that ships its text in <noscript> or a script template is read; scripts and styles are not.
func TestHTML_NoscriptAndTemplates(t *testing.T) {
	t.Parallel()
	blocks, _ := HTML(`<html><body><script>var x = "CVE-2026-1111";</script><noscript><p>Stable channel update: CVE-2026-2222 fixed in 148.0.</p></noscript>
<script type="text/template"><div><p>Template text CVE-2026-3333</p></div></script></body></html>`)
	full := Text(blocks)
	if strings.Contains(full, "CVE-2026-1111") || !strings.Contains(full, "CVE-2026-2222 fixed in 148.0") || !strings.Contains(full, "CVE-2026-3333") {
		t.Fatalf("text %q", full)
	}
}
