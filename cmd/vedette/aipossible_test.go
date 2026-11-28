package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
)

// readProvider answers every reading call "unsure" for item 0 and keeps what it was sent.
type readProvider struct {
	mu   sync.Mutex
	reqs []provider.Request
}

func (p *readProvider) Complete(_ context.Context, req provider.Request) (provider.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reqs = append(p.reqs, req)
	text := `{"verdict":"unsure","confidence":"low","basis":"stated","fixed_in":"","line":"","introduced":"","last_affected":"","url":"","quote":"","reason":"No range.","trap":""}`
	return provider.Response{Text: text, Usage: provider.Usage{InputTokens: 10, OutputTokens: 5}, Stop: provider.StopEnd}, nil
}

// The reading's errors through the binary's checker: a hook that stops one call's text is that item's refusal (the check goes on with
// the next item and the automatic reading leaves it for a day), not a stop of the whole check; a CERT/CC reference page whose text
// carries the institute's phone number is read; the reading switched off still stops the check.
func TestPossibleChecker_ARefusedCallIsTheItemsAlone(t *testing.T) {
	ctx := t.Context()
	db := storetest.New(t)
	for name, m := range map[string]fs.FS{"core": core.Migrations, "ai": ai.Migrations} {
		if err := store.Migrate(ctx, db, name, m); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	rp := &readProvider{}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler),
		Factory: func(ai.Profile) (provider.Provider, error) { return rp, nil }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Local", Kind: "openai-compatible", APIStyle: provider.StyleOpenAI, BaseURL: "http://10.0.0.5:11434/v1",
		Model: "m", Location: ai.LocationInternal, MonthlyBudget: 600000})
	if err != nil {
		t.Fatal(err)
	}
	asg := svc.Assignments()
	asg.Jobs[string(ai.JobResearchCVEs)] = ai.SlotView{Primary: &p.ID}
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	c := possibleChecker{ai: svc}
	page := "Vulnerability Note VU#644655: Widget 3.4 is affected.\n\nCarnegie Mellon University\n\nPittsburgh, PA 15213-2612\n\n412-268-5800"
	req := findings.ResearchRequest{CVE: "CVE-2099-72003", Description: "A flaw in Widget.", Digest: "CVE-2099-72003\nDescription: A flaw in Widget.",
		Item:  findings.ProposeItem{Vendor: "acme", Product: "Widget", Version: "3.4.1", Line: "3.4"},
		Pages: []findings.FetchedPage{{URL: "https://www.kb.cert.org/vuls/id/644655", Status: "ok", Text: page}}}
	if ans, err := c.Research(ctx, findings.SystemUser, req); err != nil || ans.Verdict.Status != "unsure" || len(ans.Steps) != 1 {
		t.Fatalf("the CERT/CC page was not read: %+v %v", ans, err)
	}

	refused := req
	refused.Item = findings.ProposeItem{Vendor: "acme", Product: "Widget 079201234567", Version: "3.4.1", Line: "3.4"}
	_, err = c.Research(ctx, findings.SystemUser, refused)
	var item *findings.ItemRefused
	if !errors.As(err, &item) || item.RetryAfter < time.Hour || !strings.Contains(item.Reason, "hook") {
		t.Fatalf("a call a hook stopped: %#v, want the item refused with a retry time", err)
	}
	if _, err := c.Research(ctx, findings.SystemUser, req); err != nil {
		t.Fatalf("the call after a refused one: %v", err)
	}

	if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: ai.TierMed, MonthlyBudget: 6000000, RedactPII: true, AutoReadOff: true}); err != nil {
		t.Fatal(err)
	}
	var stop *findings.CheckStop
	if _, err := c.Research(ctx, findings.SystemUser, req); !errors.As(err, &stop) {
		t.Fatalf("the reading switched off: %#v, want the check stopped", err)
	}
	// the run's own time is up (its context ended while it waited for its pace): the run stops, the item is not held as failed
	if _, err := svc.SetConfig(ctx, "test", ai.Settings{Tier: ai.TierMed, MonthlyBudget: 6000000, RedactPII: true}); err != nil {
		t.Fatal(err)
	}
	done, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.Research(done, findings.SystemUser, req); !errors.As(err, &stop) {
		t.Fatalf("a call after the run's time was up: %#v, want the check stopped", err)
	}
}

// How each error of a call of a background run (the reading of advisories, the identification of software) is sorted: refusals of the
// call are its items' alone and the run goes on, the AI unavailable, a budget or the fuse stops the run, the rest is the call's failure
// for a later run.
func TestAICallError_SortsRefusalsStopsAndFailures(t *testing.T) {
	t.Parallel()
	refused, systemic, stop, other := "refused", "refused, counted in the streak", "stop", "other"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{apierr.New(http.StatusConflict, "blocked_by_hook", "a hook stopped it"), refused},
		// the hooks could not finish in time: they decided nothing, so the call is a failure (an hour, counted in the streak)
		{apierr.New(http.StatusConflict, "blocked_by_hook", "could not be checked in time").With("retry_after", 60), other},
		{apierr.New(http.StatusBadGateway, "ai_bad_format", "bad format"), systemic},
		{apierr.New(http.StatusBadGateway, "ai_cut_off", "cut off"), systemic},
		{apierr.New(http.StatusConflict, "ai_unavailable", "no profile"), stop},
		{apierr.New(http.StatusTooManyRequests, "budget_reached", "used up"), stop},
		{apierr.New(http.StatusTooManyRequests, "rate_limited", "fuse"), stop},
		{apierr.New(http.StatusBadGateway, "unreachable", "no route"), stop},
		{apierr.New(http.StatusBadGateway, "provider_error", "HTTP 500"), other},
		{apierr.New(http.StatusGatewayTimeout, "ai_timeout", "slow"), other},
		{errors.New("plain"), other},
	} {
		got := aiCallError(t.Context(), tc.err)
		var r *findings.ItemRefused
		var s *findings.CheckStop
		kind := other
		switch {
		case errors.As(got, &r) && r.Systemic:
			kind = systemic
		case errors.As(got, &r):
			kind = refused
		case errors.As(got, &s):
			kind = stop
		}
		if kind != tc.want {
			t.Errorf("%v: %s, want %s", tc.err, kind, tc.want)
		}
	}
}

// Each affected row of the record reaches the reading as a person reads it: the product, the edition or system its CPE pins, the
// versions, the fixed release when it differs from the range's end, and who wrote the row.
func TestRecordRowText_EveryProductsRowAsAPersonReadsIt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		r    feeds.BriefRange
		want string
	}{
		{feeds.BriefRange{Range: feeds.Range{Origin: "nvd", Vendor: "quillfeather", Product: "browser", CPE: "cpe:2.3:a:quillfeather:browser:*:*:*:*:esr:*:*:*"},
			Versions: "from 115.1.0 before 115.42.0"}, "quillfeather browser (edition esr): affected from 115.1.0 before 115.42.0 [nvd]"},
		{feeds.BriefRange{Range: feeds.Range{Origin: "cna", Vendor: "Quillfeather", Product: "Mail", Fixed: "140.17.2", EndExcl: "140.17"},
			Versions: "from 140.0 before 140.17"}, "Quillfeather Mail: affected from 140.0 before 140.17, fixed in 140.17.2 [cna]"},
		{feeds.BriefRange{Range: feeds.Range{Origin: "nvd", Vendor: "quillfeather", Product: "mail", CPE: "cpe:2.3:a:quillfeather:mail:*:*:*:*:*:macos:x64:*"},
			Versions: "every version"}, "quillfeather mail (hardware x64, on macos): affected every version [nvd]"},
	} {
		if got := recordRowText(tc.r, nil); got != tc.want {
			t.Errorf("%q, want %q", got, tc.want)
		}
	}
}

// A row whose CPE writes "-" (no value: CPE 2.3's NA) for an edition, system or hardware that another row of the same product names
// is about the build of none of those values, and its text says so ("edition not esr"): read as "no edition named", it would seem to
// speak for every build. A "-" no other row of the product names a value for, and every other product's rows, are as before.
func TestRecordRows_ANoValueBesideNamedValuesIsNotThoseBuilds(t *testing.T) {
	t.Parallel()
	row := func(vendor, product, cpe, versions string) feeds.BriefRange {
		return feeds.BriefRange{Range: feeds.Range{Origin: "nvd", Vendor: vendor, Product: product, CPE: cpe}, Versions: versions}
	}
	got := recordRows([]feeds.BriefRange{
		row("quillfeather", "mail", "cpe:2.3:a:quillfeather:mail:*:*:*:*:-:*:*:*", "before 157.0"),
		row("quillfeather", "mail", "cpe:2.3:a:quillfeather:mail:*:*:*:*:esr:*:*:*", "from 140.0 before 140.17.0"),
		row("quillfeather", "mail", "cpe:2.3:a:quillfeather:mail:*:*:*:*:lts:*:*:*", "from 150.0 before 150.2.0"),
		row("quillfeather", "browser", "cpe:2.3:a:quillfeather:browser:*:*:*:*:-:*:*:*", "before 157.0"),
		row("quillfeather", "sync", "cpe:2.3:a:quillfeather:sync:*:*:*:*:*:-:*:*", "before 3.0"),
		row("quillfeather", "sync", "cpe:2.3:a:quillfeather:sync:*:*:*:*:*:macos:*:*", "before 3.1"),
	})
	want := []findings.RecordRow{
		{Vendor: "quillfeather", Product: "mail", NotEditions: []string{"esr", "lts"}, Text: "quillfeather mail (edition not esr or lts): affected before 157.0 [nvd]"},
		{Vendor: "quillfeather", Product: "mail", Edition: "esr", Text: "quillfeather mail (edition esr): affected from 140.0 before 140.17.0 [nvd]"},
		{Vendor: "quillfeather", Product: "mail", Edition: "lts", Text: "quillfeather mail (edition lts): affected from 150.0 before 150.2.0 [nvd]"},
		{Vendor: "quillfeather", Product: "browser", Text: "quillfeather browser: affected before 157.0 [nvd]"},
		{Vendor: "quillfeather", Product: "sync", Text: "quillfeather sync (not on macos): affected before 3.0 [nvd]"},
		{Vendor: "quillfeather", Product: "sync", Text: "quillfeather sync (on macos): affected before 3.1 [nvd]"},
	}
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if g, w := got[i], want[i]; g.Vendor != w.Vendor || g.Product != w.Product || g.Edition != w.Edition || g.Text != w.Text ||
			strings.Join(g.NotEditions, ",") != strings.Join(w.NotEditions, ",") {
			t.Errorf("row %d: %+v, want %+v", i, g, w)
		}
	}
}

// The binary's record door says what the older-build group of the possible list relies on: whether the CVE record itself was read (a
// record never read, only NVD's copy, cannot say the vendor gave nothing, so its CVE stays in the main list) and whether the reporting
// window keeps the CVE for an exploitation signal (an exploited signal not on any list, an old public exploit not counting).
func TestPossibleCheckerRecord_ReadAndKept(t *testing.T) {
	s := newStack(t)
	ctx := t.Context()
	fs, err := feedsService(*s.d)
	if err != nil {
		t.Fatal(err)
	}
	c := possibleChecker{feeds: fs.Store()}
	const cve = "CVE-2019-90111"
	s.exec(`INSERT INTO feeds_cve (cve, published, description, updated_at) VALUES (?, '2019-03-01T00:00:00.000Z', 'Acme Desk 3.0.4 contains a flaw.', '2026-11-20T00:00:00.000Z')`, cve)
	signal := func(kind, source, first string) {
		s.exec(`INSERT INTO feeds_signal (cve, kind, source, first_seen, stored_at, last_seen, qualifies) VALUES (?, ?, ?, ?, ?, ?, 1)`,
			cve, kind, source, first, "2026-11-20T00:00:00.000Z", "2026-11-20T00:00:00.000Z")
	}
	signal("public_exploit", "exploit-db", "2019-03-04T00:00:00.000Z") // the third party's old exploit: not a reason the window keeps it
	rec, err := c.Record(ctx, cve)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Read || rec.Kept {
		t.Errorf("only NVD's copy, an old public exploit: read %v, kept %v; want neither", rec.Read, rec.Kept)
	}
	s.exec(`UPDATE feeds_cve SET record_at = '2026-11-20T00:00:00.000Z' WHERE cve = ?`, cve)
	signal("exploited", "msrc", "2026-11-10T00:00:00.000Z") // a vendor says it is exploited, on no list
	if rec, err = c.Record(ctx, cve); err != nil {
		t.Fatal(err)
	}
	if !rec.Read || !rec.Kept {
		t.Errorf("record read, a vendor's exploited signal: read %v, kept %v; want both", rec.Read, rec.Kept)
	}
}

// A research step carries the addresses fetch_page refused (not in the data for the job) to findings, which keeps them with the run.
func TestResearchStepKeepsTheRefusedAddresses(t *testing.T) {
	st := researchStepOf(ai.ResearchStep{Layer: "quick", Web: "box", Pages: []string{"https://example.com/sa"}, Refused: []string{"https://example.com/collect?q=Widget-4.1.3"}})
	if len(st.Refused) != 1 || st.Refused[0] != "https://example.com/collect?q=Widget-4.1.3" || st.Web != "box" || len(st.Pages) != 1 {
		t.Fatalf("step %+v", st)
	}
}
