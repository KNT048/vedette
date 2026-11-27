package findings

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeIdentifier is the binary's adapter over feeds and the ai module, for the identification: a fixed catalogue, and the AI's
// answer per item given by choose (by the line's display name and its candidates).
type fakeIdentifier struct {
	products []CatalogueName
	choose   func(it IdentifyItem) (choice, reason string)
	err      error
	private  []string
	sent     []IdentifyRequest
}

func (f *fakeIdentifier) Products(context.Context) ([]CatalogueName, error) { return f.products, nil }

func (f *fakeIdentifier) PrivateNames(context.Context) ([]string, error) { return f.private, nil }

func (f *fakeIdentifier) Identify(_ context.Context, _ string, req IdentifyRequest) (IdentifyAnswer, error) {
	f.sent = append(f.sent, req)
	if f.err != nil {
		return IdentifyAnswer{}, f.err
	}
	ans := IdentifyAnswer{Model: "test-model", ActivityID: "act-1"}
	for _, it := range req.Items {
		c, r := f.choose(it)
		ans.Choices = append(ans.Choices, IdentifyChoice{Index: it.Index, Choice: c, Reason: r})
	}
	return ans, nil
}

// asked is every item the AI was asked about, by display name.
func (f *fakeIdentifier) asked() []string {
	var out []string
	for _, r := range f.sent {
		for _, it := range r.Items {
			out = append(out, it.Name)
		}
	}
	return out
}

// pick chooses the candidate whose catalogue names are product ("acme:widget_studio"), else none.
func choose(product string) func(IdentifyItem) (string, string) {
	return func(it IdentifyItem) (string, string) {
		for _, c := range it.Candidates {
			if c.Product == product {
				return c.ID, "The publisher and name are this product's."
			}
		}
		return ChoiceNone, "No candidate is this software."
	}
}

const (
	cveWidgetIn  = "CVE-2026-90001" // Widget Studio before 3.3.0: 3.2.1 is inside
	cveWidgetOut = "CVE-2026-90002" // Widget Studio before 3.0.0: 3.2.1 is outside
)

// identityWorld is two Windows PCs that run the same program no standard data names (no CPE, no catalogue alias, no CVE record that
// writes its names): "Widget Studio 3.2.1 (x64)" of "Acme Software, Inc.", whose catalogue product is acme:widget_studio, plus a
// program no catalogue names at all. The catalogue holds two CVEs of acme:widget_studio, one the version is inside and one it is past.
func identityWorld(t *testing.T) (*env, *fakeChecker, *fakeIdentifier) {
	t.Helper()
	e := newEnv(t)
	e.feeds.vulns = []Vuln{
		{CVE: cveWidgetIn, NVDAnswered: true, Origin: RangeNVD, Published: t0.AddDate(0, -2, 0), Affected: []Affected{uncAff("cpe:2.3:a:acme:widget_studio:*:*:*:*:*:*:*:*", "3.3.0")}},
		{CVE: cveWidgetOut, NVDAnswered: true, Origin: RangeNVD, Published: t0.AddDate(0, -2, 0), Affected: []Affected{uncAff("cpe:2.3:a:acme:widget_studio:*:*:*:*:*:*:*:*", "3.0.0")}},
	}
	pc := func(id string) Asset {
		return Asset{ID: id, Name: id, OS: "Microsoft Windows 11 Pro 10.0.26100.4061", Software: []Software{
			{ID: "sw-" + id + "-widget", Display: "Widget Studio 3.2.1 (x64)", Vendor: "Acme Software, Inc.", Product: "Widget Studio 3.2.1 (x64)", Version: "3.2.1", Source: "agent"},
			{ID: "sw-" + id + "-orbital", Display: "Zyxo Orbital Notes", Vendor: "Zyxo Labs", Product: "Zyxo Orbital Notes", Version: "2.0.1", Source: "agent"},
		}}
	}
	e.inv.assets, e.inv.match = map[string]AssetView{}, map[string]Asset{}
	for _, id := range []string{"pc-01", "pc-02"} {
		e.inv.assets[id] = AssetView{ID: id, Name: id, Hostname: ptr(id), IP: "192.0.2.10", Kind: "workstation", Approved: true}
		e.inv.match[id] = pc(id)
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	fc := &fakeChecker{budget: ReadBudget{Auto: true}}
	e.svc.SetChecker(fc)
	fi := &fakeIdentifier{
		products: []CatalogueName{
			{Vendor: "acme", Product: "widget_studio", CVEs: 2},
			{Vendor: "acme", Product: "widget_cloud", CVEs: 4},
			{Vendor: "otherco", Product: "studio", CVEs: 9},
			{Vendor: "acme", Product: "widget_studio", Record: true, CVEs: 1}, // the record key of the same product: one candidate
		},
		choose:  choose("acme:widget_studio"),
		private: []string{"pc-01", "pc-02"},
	}
	e.svc.SetIdentifier(fi)
	return e, fc, fi
}

// runIdentify runs one identification of what the last pass left unidentified to its end, in the test's goroutine.
func runIdentify(t *testing.T, e *env) int {
	t.Helper()
	asks, devices := e.svc.covers.unlinked()
	n, err := e.svc.identify(t.Context(), asks, devices)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func widgetFindings(t *testing.T, e *env, cve string) int {
	t.Helper()
	return e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cve + `' AND state = 'open' AND detected = 1`)
}

func identityLines(t *testing.T, e *env) map[string]int {
	t.Helper()
	c, ok, err := e.svc.Coverage(t.Context())
	if err != nil || !ok {
		t.Fatalf("coverage: %v %v", ok, err)
	}
	out := map[string]int{}
	for _, m := range c.Identity {
		out[m.Method] = m.Lines
	}
	return out
}

// One AI answer per name serves every device: the product it chose opens a finding on both PCs for the CVE whose range holds the
// version, labelled with the identification; the CVE the version is past gives nothing (no finding, no question); the coverage counts
// the lines as identified by AI. A name no catalogue product shares a word with is never sent. Nothing but the line's publisher, name
// and version and the candidates goes out.
func TestAIIdentity_AChoiceOpensALabelledFindingOnEveryDevice(t *testing.T) {
	t.Parallel()
	e, _, fi := identityWorld(t)
	if n := widgetFindings(t, e, cveWidgetIn); n != 0 {
		t.Fatalf("%d findings before any identification", n)
	}
	if got := identityLines(t, e); got[IdentityNone] != 4 || got[IdentityAI] != 0 {
		t.Fatalf("identity before: %v, want 4 lines none", got)
	}
	if n := runIdentify(t, e); n != 1 {
		t.Fatalf("%d names identified, want 1", n)
	}
	if asked := fi.asked(); len(asked) != 1 || asked[0] != "Widget Studio 3.2.1 (x64)" || len(fi.sent) != 1 {
		t.Fatalf("asked %v in %d calls: want the widget once for both devices, never the program no catalogue names", asked, len(fi.sent))
	}
	it := fi.sent[0].Items[0]
	if it.Publisher != "Acme Software, Inc." || it.Version != "3.2.1" || len(it.Candidates) != 3 || it.Candidates[0].Product != "acme:widget_studio" {
		t.Errorf("item sent %+v: want publisher, name, version and 3 candidates, the same name first", it)
	}
	if n := widgetFindings(t, e, cveWidgetIn); n != 2 {
		t.Fatalf("%d open findings of %s, want one per PC", n, cveWidgetIn)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveWidgetIn + `' AND verified = 'no' AND json_extract(evidence, '$.summary') LIKE
		'%the AI identified it as acme widget studio%'`); n != 2 {
		t.Errorf("%d of the findings not confirmed: the agent states the version, not that the CVE is about this software (suspected)", n)
	}
	if n := widgetFindings(t, e, cveWidgetOut) + e.count(`SELECT count(*) FROM fnd_question WHERE cve = '`+cveWidgetOut+`'`); n != 0 {
		t.Errorf("%d findings or questions of the CVE the version is past: the AI's identity decides nothing but a finding", n)
	}
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = 'pc-01' AND cve = ?`, cveWidgetIn).Scan(&id); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.View(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	got := v.JSON().Identity
	if got == nil || got.Method != IdentityAI || got.Title != "acme widget studio" || got.Reason == "" || got.Model != "test-model" {
		t.Errorf("view identity %+v: want the AI's identification with its title, reason and model", got)
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil { // the next pass keeps it and counts it
		t.Fatal(err)
	}
	if n := widgetFindings(t, e, cveWidgetIn); n != 2 {
		t.Errorf("%d open findings after the next pass, want 2", n)
	}
	if got := identityLines(t, e); got[IdentityAI] != 2 || got[IdentityNone] != 2 {
		t.Errorf("identity after: %v, want 2 lines ai and the other program's 2 none", got)
	}
}

// A choice the AI was not offered is ignored: no product is stored, nothing opens, and the same candidates are not asked again.
func TestAIIdentity_AChoiceNotOfferedIsIgnored(t *testing.T) {
	t.Parallel()
	e, _, fi := identityWorld(t)
	fi.choose = func(IdentifyItem) (string, string) { return "c99", "It is the widget." }
	if n := runIdentify(t, e); n != 0 {
		t.Fatalf("%d names identified from a choice not offered", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_identity WHERE choice = 'product'`); n != 0 {
		t.Errorf("%d products stored from a choice not offered", n)
	}
	if n := widgetFindings(t, e, cveWidgetIn); n != 0 {
		t.Errorf("%d findings from a choice not offered", n)
	}
	runIdentify(t, e)
	if len(fi.sent) != 1 {
		t.Errorf("asked %d times: the same candidates were asked again", len(fi.sent))
	}
}

// None and unsure decide nothing: no finding, the line stays none in the coverage, and the AI is asked again only when the candidates
// change (an unsure answer also after 30 days).
func TestAIIdentity_NoneOrUnsureDecidesNothing(t *testing.T) {
	t.Parallel()
	for _, choice := range []string{ChoiceNone, ChoiceUnsure} {
		t.Run(choice, func(t *testing.T) {
			t.Parallel()
			e, _, fi := identityWorld(t)
			fi.choose = func(IdentifyItem) (string, string) { return choice, "Cannot tell from the name." }
			runIdentify(t, e)
			if n := widgetFindings(t, e, cveWidgetIn); n != 0 {
				t.Errorf("%d findings after %s", n, choice)
			}
			if _, err := e.svc.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := identityLines(t, e); got[IdentityNone] != 4 {
				t.Errorf("identity %v: want every line none", got)
			}
			runIdentify(t, e)
			if len(fi.sent) != 1 {
				t.Errorf("asked %d times with the same candidates", len(fi.sent))
			}
			fi.products = append(fi.products, CatalogueName{Vendor: "acme", Product: "widget_studio_pro", CVEs: 1}) // a new candidate
			runIdentify(t, e)
			if len(fi.sent) != 2 {
				t.Errorf("asked %d times: a changed candidate set asks again", len(fi.sent))
			}
			if choice == ChoiceUnsure {
				e.advance(31 * 24 * time.Hour)
				runIdentify(t, e)
				if len(fi.sent) != 3 {
					t.Errorf("asked %d times: an unsure answer is asked again after 30 days", len(fi.sent))
				}
			}
		})
	}
}

// A person's "Not this product" wins over the AI: the finding closes on every device at once, the rejection is stored for the name and
// audited, and the product is never offered for that name again (the AI may be asked again about the rest).
func TestAIIdentity_APersonsCorrectionWins(t *testing.T) {
	t.Parallel()
	e, _, fi := identityWorld(t)
	runIdentify(t, e)
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = 'pc-01' AND cve = ?`, cveWidgetIn).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RejectIdentity(t.Context(), id, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if n := widgetFindings(t, e, cveWidgetIn); n != 0 {
		t.Errorf("%d findings still open after Not this product, want 0 on every device", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_identity WHERE kind = 'rejected' AND vendor = 'acme' AND product = 'widget_studio' AND by = 'ana@example.com'`); n != 1 {
		t.Error("the rejection is not stored for the name")
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.ai_identity_rejected' AND target = '` + id + `'`); n != 1 {
		t.Error("the rejection is not audited")
	}
	runIdentify(t, e) // the AI is asked again, without the rejected product
	if len(fi.sent) != 2 {
		t.Fatalf("asked %d times, want once more without the rejected product", len(fi.sent))
	}
	for _, c := range fi.sent[1].Items[0].Candidates {
		if c.Product == "acme:widget_studio" {
			t.Error("the product a person rejected was offered again")
		}
	}
	if _, err := e.svc.Reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := widgetFindings(t, e, cveWidgetIn); n != 0 {
		t.Errorf("%d findings reopened after the rejection", n)
	}
	if err := e.svc.RejectIdentity(t.Context(), id, "ana@example.com"); err != nil { // a second click changes nothing
		t.Errorf("a second rejection: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.ai_identity_rejected'`); n != 1 {
		t.Errorf("%d audit rows after a second rejection, want 1", n)
	}
}

// The findings a person's "Not this product" closes are closed by that person, on every device: the finding's history and the Handled
// list name them, not Vedette, and the close is not left out of the Handled list as Vedette's own correction of its match.
func TestAIIdentity_NotThisProductIsThePersonsClose(t *testing.T) {
	t.Parallel()
	e, _, _ := identityWorld(t)
	runIdentify(t, e)
	var id string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT id FROM fnd_finding WHERE asset_id = 'pc-01' AND cve = ?`, cveWidgetIn).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RejectIdentity(t.Context(), id, "ana@example.com"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE cve = '` + cveWidgetIn + `' AND state = 'handled' AND resolved_by = 'ana@example.com'`); n != 2 {
		t.Errorf("%d findings closed by the person, want 2 (every device)", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event ev JOIN fnd_finding f ON f.id = ev.finding_id WHERE f.cve = '` + cveWidgetIn +
		`' AND ev.kind = 'handled' AND ev.actor = 'ana@example.com'`); n != 2 {
		t.Errorf("%d history events of the close name the person, want 2", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding_event ev JOIN fnd_finding f ON f.id = ev.finding_id WHERE f.cve = '` + cveWidgetIn +
		`' AND ev.kind = 'handled' AND ev.actor = '` + SystemUser + `'`); n != 0 {
		t.Errorf("%d history events say Vedette closed what the person rejected", n)
	}
}

// The identification runs only while the automatic run is on and today's reads are not used up, and a budget reached in the middle
// stops it: what was stored stays, nothing else is stored.
func TestAIIdentity_Budget(t *testing.T) {
	t.Parallel()
	e, fc, fi := identityWorld(t)
	fc.budget = ReadBudget{Auto: true, Reached: true}
	if e.svc.AutoIdentify(t.Context()) {
		t.Error("the identification started with today's reads used up")
	}
	fc.budget = ReadBudget{Auto: false}
	if e.svc.AutoIdentify(t.Context()) {
		t.Error("the identification started with the automatic run switched off")
	}
	fc.budget = ReadBudget{Auto: true}
	fi.err = &CheckStop{Reason: "Today's automatic AI reads are used up."}
	if n := runIdentify(t, e); n != 0 || len(fi.sent) != 1 {
		t.Errorf("identified %d in %d calls: want the run stopped at the first call", n, len(fi.sent))
	}
	if n := e.count(`SELECT count(*) FROM fnd_identity`); n != 0 {
		t.Errorf("%d rows stored from a call the budget stopped", n)
	}
}

// Without an AI the line stays unlinked and is counted as identity none: nothing runs, nothing is sent.
func TestAIIdentity_NoAIIsCountedNone(t *testing.T) {
	t.Parallel()
	e, _, fi := identityWorld(t)
	e.svc.SetChecker(nil)
	if e.svc.AutoIdentify(t.Context()) {
		t.Error("the identification started with no AI")
	}
	if len(fi.sent) != 0 {
		t.Error("something was sent with no AI")
	}
	if got := identityLines(t, e); got[IdentityNone] != 4 || got[IdentityAI] != 0 {
		t.Errorf("identity %v: want every line none", got)
	}
}

// The AI's identity only opens (the matcher's guard): a version outside the chosen product's ranges proves nothing, so an existing
// finding of that CVE on the line is not closed by a proof from it, and no question comes of it.
func TestAIIdentity_ANoOnTheAIsIdentityProvesNothing(t *testing.T) {
	t.Parallel()
	sw := Software{ID: "s-1", Display: "Widget Studio 3.2.1 (x64)", Vendor: "Acme Software, Inc.", Product: "Widget Studio 3.2.1 (x64)", Version: "3.2.1", Source: "agent",
		AIProduct: &AIProduct{Vendor: "acme", Product: "widget_studio", Title: "Acme Widget Studio", Publisher: "acme", Name: "widget studio"}}
	a := Asset{ID: "pc-01", Name: "pc-01", OS: "Microsoft Windows 11 Pro", Software: []Software{sw}}
	vulns := []Vuln{
		{CVE: cveWidgetIn, NVDAnswered: true, Origin: RangeNVD, Published: t0, Affected: []Affected{uncAff("cpe:2.3:a:acme:widget_studio:*:*:*:*:*:*:*:*", "3.3.0")}},
		{CVE: cveWidgetOut, NVDAnswered: true, Origin: RangeNVD, Published: t0, Affected: []Affected{uncAff("cpe:2.3:a:acme:widget_studio:*:*:*:*:*:*:*:*", "3.0.0")}},
		uncVuln("CVE-2026-90003", "Acme", "Widget Studio", t0, uncAff("cpe:2.3:a:acme:widget_studio:*:*:*:*:*:*:*:*", "3.0.0")),
	}
	res := MatchAsset(a, vulns, map[string]bool{cveWidgetOut: true, "CVE-2026-90003": true}, t0)
	if len(res.New) != 1 || res.New[0].CVE != cveWidgetIn || res.New[0].Evidence.Identity == nil || res.New[0].Evidence.Identity.Title != "Acme Widget Studio" {
		t.Fatalf("new %+v: want the CVE inside the range, labelled with the AI's identity", res.New)
	}
	if len(res.NotAffected) != 0 || len(res.Asked) != 0 || len(res.NeedVersion) != 0 {
		t.Errorf("not affected %d, asked %d, need version %d: the AI's identity proves nothing and asks nothing", len(res.NotAffected), len(res.Asked), len(res.NeedVersion))
	}
	sw.AIProduct = nil // the line's own names reach none of them
	a.Software = []Software{sw}
	if res := MatchAsset(a, vulns, nil, t0); len(res.New) != 0 {
		t.Errorf("new %+v without the AI's identity", res.New)
	}
}

// Candidates come from the catalogue only, by the words of the cleaned names: the line's own version, version numbers, architecture,
// language and text in parentheses never count, the same cleaned name is first (and only a candidate), and a program no catalogue
// product shares a word with has none.
func TestIdentityCandidates(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		vendor, product, version, wantPub, wantName string
	}{
		{"Acme Software, Inc.", "Widget Studio 3.2.1 (x64)", "3.2.1", "acme software", "widget studio"},
		{"Zen OSS Team", "Zen Browser (x64 en-US)", "1.24.3b", "zen oss", "zen browser"},
		{"Antibody Software", "WizTree v4.31", "4.31", "antibody software", "wiztree"},
		{"Microsoft Corporation", "Microsoft 365 - en-us", "16.0.1", "microsoft", "microsoft 365"},
		{"Notepad++ Team", "Notepad++ (64-bit x64)", "8.6", "notepad notepad++", "notepad notepad++"},
		{"Python Software Foundation", "Python 3.12.1 (64-bit)", "3.12.1", "python software foundation", "python"},
	} {
		pub, name, ok := IdentityKey(Software{Vendor: c.vendor, Product: c.product, Version: c.version})
		if !ok || pub != c.wantPub || name != c.wantName {
			t.Errorf("IdentityKey(%q, %q) = %q, %q; want %q, %q", c.vendor, c.product, pub, name, c.wantPub, c.wantName)
		}
	}
	ix := newProductIndex(mergeCatalogue([]CatalogueName{
		{Vendor: "cisco", Product: "packet_tracer", CVEs: 1}, {Vendor: "cisco", Product: "ultra_packet_core", CVEs: 1, Exploited: 1},
		{Vendor: "jgraph", Product: "drawio", CVEs: 3}, {Vendor: "Cisco", Product: "IOS XE", Kev: true, CVEs: 9, Exploited: 9},
		{Vendor: "cisco", Product: "ios_xe", CVEs: 400, Exploited: 9},
	}))
	top := func(pub, name string) []string {
		var out []string
		for _, c := range ix.identityCandidates(strings.Fields(pub), strings.Fields(name), nil) {
			out = append(out, c.Product.Vendor+":"+c.Product.Product)
		}
		return out
	}
	if got := top("cisco systems", "cisco packet tracer"); len(got) != 2 || got[0] != "cisco:packet_tracer" {
		t.Errorf("Cisco Packet Tracer: %v, want packet_tracer first", got)
	}
	if got := top("jgraph", "draw io"); !slices.Equal(got, []string{"jgraph:drawio"}) {
		t.Errorf("draw.io: %v, want jgraph:drawio by the joined words", got)
	}
	if got := top("zyxo labs", "zyxo orbital notes"); len(got) != 0 {
		t.Errorf("a program no catalogue product names: %v, want none", got)
	}
	cs := ix.identityCandidates([]string{"cisco"}, []string{"ios", "xe"}, map[string]bool{"cisco|packettracer": true})
	if len(cs) != 1 || cs[0].Product.Kev != "cisco|ios xe" || cs[0].Title != "Cisco IOS XE" {
		t.Errorf("IOS XE: %+v, want the range product with the exploited list's key and title, once", cs)
	}
	if !sharesNameWord("widget_studio", []string{"widget", "studio"}) || sharesNameWord("windows", []string{"widget", "studio", "for", "windows"}) {
		t.Error("sharesNameWord: a stopword alone must not pass, a product word must")
	}
}

// What goes to the AI never names the customer: the box's own device and account names, email addresses and user folders are replaced.
func TestIdentityScrubber(t *testing.T) {
	t.Parallel()
	sc := newScrubber([]string{"ACCT-PC-7", "nguyen.an", "x", "ws-acct-9.corp.example"})
	for in, want := range map[string]string{
		"Sync nguyen.an nguyen.an":                       "Sync [name] [name]", // every occurrence, also one right after another
		"acct-pc-7,ACCT-PC-7":                            "[name],[name]",
		"Agent for WS-ACCT-9":                            "Agent for [name]",                     // a hostname's own name, without its domain
		`Tool (C:\Users\Nguyen Van An\AppData\Local)`:    `Tool (C:\Users\[user]\AppData\Local)`, // a user folder with spaces
		`Tool C:\Documents and Settings\nguyen2\Desktop`: `Tool C:\Documents and Settings\[user]\Desktop`,
		"OneDrive - nguyen.an":                           "OneDrive - [name]",
		"Backup agent for acct-pc-7 (x64)":               "Backup agent for [name] (x64)",
		"Mail sync an@example.com":                       "Mail sync [email]",
		`Tool (C:\Users\nguyen\AppData\Local)`:           `Tool (C:\Users\[user]\AppData\Local)`,
		"Xbox":                                           "Xbox",
	} {
		if got := sc.clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
}
