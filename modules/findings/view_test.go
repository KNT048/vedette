package findings

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// The findings model API on a fixture: four devices (two added, one nobody added, one ignored), OpenSSH on two of them with CVEs
// that need different releases, Java 8 and Java 21 side by side with one CVE on both, handled findings and a question.

func modelEnv(t *testing.T) *httpEnv {
	t.Helper()
	e := newHTTPEnv(t)
	e.inv.mu.Lock()
	e.inv.assets = map[string]AssetView{
		"a-nas": {ID: "a-nas", Name: "nas01", IP: "192.0.2.10", Kind: "nas", Approved: true},
		"a-fw":  {ID: "a-fw", Name: "fw01", IP: "192.0.2.1", Kind: "firewall", Approved: true},
		"a-new": {ID: "a-new", Name: "printer-07", IP: "192.0.2.77", Kind: "printer"},
		"a-ign": {ID: "a-ign", Name: "lab-box", IP: "198.51.100.5", Kind: "server", Approved: true, Ignored: true},
	}
	e.inv.ignored = map[string]bool{"a-ign": true}
	e.inv.lines = map[string]Line{
		"s-ssh-nas": {ID: "s-ssh-nas", AssetID: "a-nas", Display: "OpenSSH", ProductKey: "openbsd|openssh", Version: "10.2p1"},
		"s-ssh-fw":  {ID: "s-ssh-fw", AssetID: "a-fw", Display: "OpenSSH", ProductKey: "openbsd|openssh", Version: "9.6p1"},
		"s-j8":      {ID: "s-j8", AssetID: "a-fw", Display: "Java 8", ProductKey: "oracle|jre", Version: "8u401"},
		"s-j21":     {ID: "s-j21", AssetID: "a-fw", Display: "Java 21", ProductKey: "oracle|jre", Version: "21.0.2"},
		"s-cups":    {ID: "s-cups", AssetID: "a-new", Display: "CUPS", ProductKey: "openprinting|cups", Version: "2.4.2"},
		"s-ign":     {ID: "s-ign", AssetID: "a-ign", Display: "nginx", ProductKey: "f5|nginx", Version: "1.20.0"},
	}
	e.inv.mu.Unlock()
	e.feeds.cvss = map[string]CVSS{
		"CVE-2026-1001": {Score: 9.8, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		"CVE-2026-1002": {Score: 7.5, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"CVE-2026-1003": {Score: 5.3, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		"CVE-2026-2001": {Score: 8.1, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	ssh := func(v string) Fix { return Fix{Kind: FixUpdate, Version: v} }
	rows := []Finding{
		// nas01: three OpenSSH CVEs that need 10.3, 10.6 and 10.6: one block, "update to 10.6"
		{ID: "f-n1", AssetID: "a-nas", CVE: "CVE-2026-1001", SoftwareID: "s-ssh-nas", Fix: ssh("10.3"), Urgency: 2, Verified: VerifiedDevice, Basis: DetectDeviceVersion},
		{ID: "f-n2", AssetID: "a-nas", CVE: "CVE-2026-1002", SoftwareID: "s-ssh-nas", Fix: ssh("10.6"), Urgency: 5},
		{ID: "f-n3", AssetID: "a-nas", CVE: "CVE-2026-1003", SoftwareID: "s-ssh-nas", Fix: ssh("10.6"), Urgency: 5},
		// fw01: OpenSSH 9.6 needs 10.6 for one CVE; Java 8 and Java 21 both have CVE-2026-2001, each with its own fix
		{ID: "f-f1", AssetID: "a-fw", CVE: "CVE-2026-1002", SoftwareID: "s-ssh-fw", Fix: ssh("10.6"), Urgency: 3},
		{ID: "f-f2", AssetID: "a-fw", CVE: "CVE-2026-2001", SoftwareID: "s-j8", Fix: Fix{Kind: FixUpdate, Version: "8u461"}, Urgency: 4},
		{ID: "f-f3", AssetID: "a-fw", CVE: "CVE-2026-2001", SoftwareID: "s-j21", Fix: Fix{Kind: FixUpdate, Version: "21.0.8"}, Urgency: 4},
		{ID: "f-f4", AssetID: "a-fw", CVE: "CVE-2026-2002", SoftwareID: "s-j21", Fix: Fix{Kind: FixNoneYet}, Urgency: 5},
		// printer-07, nobody added it: one urgent finding not confirmed
		{ID: "f-p1", AssetID: "a-new", CVE: "CVE-2026-3001", SoftwareID: "s-cups", Fix: Fix{Kind: FixUnknown}, Urgency: 2},
		// lab-box is ignored: only its tab shows it
		{ID: "f-i1", AssetID: "a-ign", CVE: "CVE-2026-4001", SoftwareID: "s-ign", Fix: ssh("1.27.0"), Urgency: 2},
		// handled
		{ID: "f-h1", AssetID: "a-fw", CVE: "CVE-2025-9001", SoftwareID: "s-ssh-fw", Fix: ssh("9.6p1"), State: StateHandled, Resolution: ResolutionPatched,
			Via: ViaVersionMoved, FromVersion: "9.3p1", ToVersion: "9.6p1", ResolvedBy: SystemUser, Urgency: 5},
		{ID: "f-h2", AssetID: "a-nas", CVE: "CVE-2025-9002", SoftwareID: "s-ssh-nas", Fix: ssh("10.0"), State: StateHandled, Resolution: ResolutionAccepted,
			AcceptedUntil: time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC), Note: "isolated segment", Urgency: 5},
	}
	ctx := t.Context()
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		for _, f := range rows {
			f.FirstSeen = t0.Add(-48 * time.Hour)
			if f.State == StateHandled {
				f.ResolvedAt = t0.Add(-time.Hour)
			}
			if f.Basis == "" {
				f.Basis = DetectBannerVersion
			}
			if f.Verified == "" {
				f.Verified = VerifiedNo
			}
			l := e.inv.lines[f.SoftwareID]
			f.FixKey = FixKey(l.ProductKey, f.Fix)
			if err := writeTestFinding(ctx, tx, f); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO fnd_question (id, asset_id, software_id, cve, kind, detail, cves, asked_at)
			VALUES ('q-1', 'a-nas', 's-ssh-nas', 'CVE-2026-5001', 'no_range_data', '{}', 1, '2026-01-01T00:00:00.000Z')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

// raw calls the API and returns the status and the body.
func (e *httpEnv) raw(method, path, user, body string) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), method, server.Prefix+path, rd)
	r.Header.Set("Content-Type", "application/json")
	if user != "" {
		r.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: user, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	r.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// conform decodes a 200 answer into the generated type of the contract and validates it (enums, patterns, lengths, ranges).
func conform[T any, P interface {
	*T
	UnmarshalJSON([]byte) error
	Validate() error
}](t *testing.T, e *httpEnv, method, path, user, body string) *T {
	t.Helper()
	code, b := e.raw(method, path, user, body)
	if code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, code, b)
	}
	var out T
	if err := P(&out).UnmarshalJSON(b); err != nil {
		t.Fatalf("%s %s: does not parse as the contract: %v\n%s", method, path, err, b)
	}
	if err := P(&out).Validate(); err != nil {
		t.Fatalf("%s %s: does not fit the contract: %v\n%s", method, path, err, b)
	}
	return &out
}

func TestModelAPI_EveryAnswerFitsTheContract(t *testing.T) {
	e := modelEnv(t)
	conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices", "viewer", "")
	conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?ignored=true", "viewer", "")
	conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-fw&status=critical_edge,update_recommended", "viewer", "")
	conform[oas.FindingsGetFindingsFixesOK](t, e, "GET", "/findings/fixes?limit=2&offset=1", "viewer", "")
	in := conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input", "viewer", "")
	conform[oas.FindingsGetFindingsHandledOK](t, e, "GET", "/findings/handled?resolution=patched,accepted", "viewer", "")
	conform[oas.FindingsGetFindingsOverviewOK](t, e, "GET", "/findings/overview", "viewer", "")
	for _, id := range []string{"f-n1", "f-f2", "f-h1", "f-h2", "f-p1"} {
		conform[oas.FindingsGetFindingsIDViewOK](t, e, "GET", "/findings/"+id+"/view", "viewer", "")
	}
	conform[oas.FindingsPostFindingsIDVerifyOK](t, e, "POST", "/findings/f-p1/verify", "admin", `{"note":"the vendor confirmed it"}`)
	conform[oas.FindingsPostFindingsIDReopenOK](t, e, "POST", "/findings/f-h2/reopen", "operator", `{"note":"the segment is joined again"}`)
	conform[oas.FindingsPostFindingsHandleOK](t, e, "POST", "/findings/handle", "operator", `{"ids":["f-f4"],"resolution":"mitigated","note":"blocked at the edge"}`)
	if code, b := e.call("POST", "/findings/questions/q-1/answer", "operator", `{"answer":"not_affected","note":""}`); code != 200 || b["finding"] != nil {
		t.Errorf("answer not affected: %d %v", code, b)
	}
	if in.Total != len(in.Items) || in.Total == 0 {
		t.Errorf("input: total %d, items %d", in.Total, len(in.Items))
	}
	for _, c := range []struct{ path, code string }{{"/findings/devices?status=nope", "bad_filter"}, {"/findings/handled?resolution=fixed", "bad_filter"}, {"/findings/f-none/view", "not_found"}} {
		code, b := e.call("GET", c.path, "viewer", "")
		if code/100 != 4 || errCode(b) != c.code {
			t.Errorf("%s: %d %v, want %s", c.path, code, b, c.code)
		}
	}
}

// allCards reads every page of a list at the default page size and sums its findings.
func allCards(t *testing.T, e *httpEnv, path string) (pages, findings int) {
	t.Helper()
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for off := 0; ; off += 2 {
		_, b := e.call("GET", fmt.Sprintf("%s%soffset=%d&limit=2", path, sep, off), "viewer", "")
		items, _ := b["items"].([]any)
		for _, it := range items {
			pages += int(it.(map[string]any)["findings"].(float64))
		}
		total := int(b["total"].(float64))
		findings = int(b["findings"].(float64))
		if len(items) == 0 || off+2 >= total {
			return pages, findings
		}
	}
}

// On the API: open findings == the sum over By device == the sum over By fix, for every filter, page by page.
func TestModelAPI_OpenEqualsSumByDeviceEqualsSumByFix(t *testing.T) {
	e := modelEnv(t)
	_, ov := e.call("GET", "/findings/overview", "viewer", "")
	open := int(ov["open"].(map[string]any)["findings"].(float64))
	if open != 8 { // nine open, the ignored device's one left out
		t.Errorf("open %d, want 8", open)
	}
	for _, q := range []string{"", "status=exploited", "status=critical_edge,update_recommended", "q=openssh", "q=fw01", "q=cve-2026-2001", "q=192.0.2.77"} {
		dp, df := allCards(t, e, "/findings/devices?"+q)
		fp, ff := allCards(t, e, "/findings/fixes?"+q)
		if dp != df || fp != ff || df != ff {
			t.Errorf("%q: by device %d (pages %d), by fix %d (pages %d)", q, df, dp, ff, fp)
		}
		if q == "" && df != open {
			t.Errorf("by device %d, open %d", df, open)
		}
	}
	_, ig := e.call("GET", "/findings/devices?ignored=true", "viewer", "")
	if ig["findings"].(float64) != 1 || ig["total"].(float64) != 1 {
		t.Errorf("ignored tab: %v", ig)
	}
}

// One software that needs several releases is one block, the newest release; two lines of one product stay two blocks.
func TestModelAPI_OneBlockPerLineWithTheNewestRelease(t *testing.T) {
	e := modelEnv(t)
	cards := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-nas", "viewer", "")
	if len(cards.Items) != 1 || len(cards.Items[0].Blocks) != 1 {
		t.Fatalf("nas01: %+v", cards.Items)
	}
	b := cards.Items[0].Blocks[0]
	if v, _ := b.Fix.Version.Get(); v != "10.6" || len(b.Findings) != 3 || b.Cause != "CVE-2026-1001" || string(b.Status) != CodeExploited {
		t.Errorf("block %+v", b)
	}
	if b.Findings[0].Cve != "CVE-2026-1001" || b.Severity.Critical != 1 || b.Severity.High != 1 || b.Severity.Medium != 1 {
		t.Errorf("rows %+v severity %+v", b.Findings, b.Severity)
	}
	fw := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-fw", "viewer", "")
	if c := fw.Items[0]; len(c.Blocks) != 4 || c.Findings != 4 || c.Cves != 3 {
		t.Errorf("fw01: %d blocks, %d findings, %d CVEs", len(c.Blocks), c.Findings, c.Cves)
	}
	fixes := conform[oas.FindingsGetFindingsFixesOK](t, e, "GET", "/findings/fixes?q=openssh", "viewer", "")
	if len(fixes.Items) != 1 || fixes.Items[0].Devices != 2 || fixes.Items[0].Findings != 4 {
		t.Errorf("By fix OpenSSH: %+v", fixes.Items)
	}
	// the view of each finding names its own stored fix, and the block's release reaches it
	for _, r := range b.Findings {
		v := conform[oas.FindingsGetFindingsIDViewOK](t, e, "GET", "/findings/"+r.ID+"/view", "viewer", "")
		own, _ := v.Fix.Version.Get()
		if c, ok := compareFix(FixUpdate, "", own, "10.6"); !ok || c > 0 {
			t.Errorf("%s: own fix %s beyond the block's 10.6", r.ID, own)
		}
	}
}

// Handling one fix on one device acts on exactly its findings there, one history and audit row each; the other device keeps its own.
func TestModelAPI_HandleOneFixOnOneDevice(t *testing.T) {
	e := modelEnv(t)
	cards := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-nas", "viewer", "")
	key := cards.Items[0].Blocks[0].Fix.Key
	before := len(e.auditActions())
	out := conform[oas.FindingsPostFindingsHandleOK](t, e, "POST", "/findings/handle", "operator",
		fmt.Sprintf(`{"device":"a-nas","fix":%q,"software":"s-ssh-nas","resolution":"accepted","note":"replaced next week","until":"%s"}`, key, t0.AddDate(0, 0, 7).Format(time.DateOnly)))
	if out.Handled != 3 || out.Skipped != 0 {
		t.Errorf("handled %d skipped %d", out.Handled, out.Skipped)
	}
	if n := len(e.auditActions()) - before; n != 3 {
		t.Errorf("%d audit rows, want 3", n)
	}
	if n := e.count(`SELECT count(*) FROM fnd_finding WHERE asset_id = 'a-fw' AND state = 'open'`); n != 4 {
		t.Errorf("fw01 has %d open, want 4", n)
	}
	for _, body := range []string{`{"resolution":"patched","note":""}`, `{"ids":["f-n1"],"device":"a-nas","fix":"x","resolution":"patched","note":""}`,
		`{"ids":["f-f1","f-n1"],"resolution":"patched","note":""}`} {
		if code, b := e.call("POST", "/findings/handle", "operator", body); code != 400 {
			t.Errorf("%s: %d %v", body, code, b)
		}
	}
	if code, _ := e.call("POST", "/findings/handle", "viewer", `{"ids":["f-f1"],"resolution":"patched","note":""}`); code != 403 {
		t.Errorf("a viewer handled a finding: %d", code)
	}
}

// The queue: the device nobody added, the urgent finding not confirmed, the question; each leaves when it is answered.
func TestModelAPI_NeedsYourInput(t *testing.T) {
	e := modelEnv(t)
	kinds, _ := queueIDs(t, e, "")
	if got := strings.Join(kinds, ","); got != "device:a-new,f-f1,f-f2,f-f3,f-p1,sw:s-ssh-nas" {
		t.Errorf("queue %v", kinds)
	}
	if code, _ := e.call("POST", "/findings/questions/q-1/answer", "operator", `{"answer":"affected","note":"vendor says so"}`); code != 403 {
		t.Errorf("an operator answered affected: %d", code)
	}
	_, b := e.call("POST", "/findings/questions/q-1/answer", "admin", `{"answer":"affected","note":"vendor says so"}`)
	id, _ := b["finding"].(string)
	v := conform[oas.FindingsGetFindingsIDViewOK](t, e, "GET", "/findings/"+id+"/view", "viewer", "")
	if string(v.Verification.Verified) != "person" || string(v.Verification.Basis) != "person" {
		t.Errorf("answered finding: %+v", v.Verification)
	}
	e.call("POST", "/findings/f-p1/verify", "admin", `{"note":"the vendor confirmed it"}`)
	kinds, _ = queueIDs(t, e, "")
	if got := strings.Join(kinds, ","); got != "device:a-new,f-f1,f-f2,f-f3" {
		t.Errorf("after the answers: %v", kinds)
	}
}

// The device status is one function: the most urgent open status with its distinct CVEs, else the questions.
func TestDeviceStatuses(t *testing.T) {
	e := modelEnv(t)
	got, err := e.svc.DeviceStatuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]DeviceStatus{"a-nas": {CodeExploited, 1}, "a-fw": {CodePublicExploit, 1}, "a-new": {CodeExploited, 1}, "a-ign": {CodeExploited, 1}}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: %+v, want %+v", id, got[id], w)
		}
	}
	e.call("POST", "/findings/handle", "operator", `{"ids":["f-f1"],"resolution":"patched","note":""}`)
	got, _ = e.svc.DeviceStatuses(context.Background())
	if got["a-fw"] != (DeviceStatus{CodeCriticalEdge, 1}) { // CVE-2026-2001 on two lines is one CVE
		t.Errorf("fw01 after patching: %+v", got["a-fw"])
	}
	_ = url.QueryEscape
}

// Two lines of one product can share a fix key (no fix known yet on both Java 8 and Java 21): handling one line's block never touches
// the other line's findings, and a handle without the line acts on the block on no line only.
func TestModelAPI_HandleOneLineOfTwoSharingAFixKey(t *testing.T) {
	e := modelEnv(t)
	ctx := t.Context()
	if err := e.db.Write(ctx, func(tx *sql.Tx) error {
		return writeTestFinding(ctx, tx, Finding{ID: "f-j8n", AssetID: "a-fw", CVE: "CVE-2026-2003", SoftwareID: "s-j8", Fix: Fix{Kind: FixNoneYet},
			FixKey: FixKey("oracle|jre", Fix{Kind: FixNoneYet}), Urgency: 5, FirstSeen: t0.Add(-time.Hour)})
	}); err != nil {
		t.Fatal(err)
	}
	cards := conform[oas.FindingsGetFindingsDevicesOK](t, e, "GET", "/findings/devices?device=a-fw", "viewer", "")
	var key string
	shared := 0
	for _, b := range cards.Items[0].Blocks {
		if string(b.Fix.Kind) == "none_yet" {
			key = b.Fix.Key
			shared++
		}
	}
	if shared != 2 {
		t.Fatalf("%d none_yet blocks on fw01, want one per Java line", shared)
	}
	out := conform[oas.FindingsPostFindingsHandleOK](t, e, "POST", "/findings/handle", "operator",
		fmt.Sprintf(`{"device":"a-fw","fix":%q,"software":"s-j21","resolution":"mitigated","note":"blocked at the edge"}`, key))
	if out.Handled != 1 {
		t.Errorf("handled %d, want Java 21's one", out.Handled)
	}
	if f, _ := e.svc.Finding(ctx, "f-j8n"); f.State != StateOpen {
		t.Errorf("Java 8's finding was handled with Java 21's block: %+v", f)
	}
	out = conform[oas.FindingsPostFindingsHandleOK](t, e, "POST", "/findings/handle", "operator",
		fmt.Sprintf(`{"device":"a-fw","fix":%q,"resolution":"mitigated","note":"blocked at the edge"}`, key))
	if out.Handled != 0 {
		t.Errorf("without the line: handled %d, want 0 (no block on no line)", out.Handled)
	}
}

// The queue searches on the server like every other list: the device's name or address, the software's name, the CVE id; the
// total counts what the search finds, so the pager pages the matches.
func TestModelAPI_NeedsYourInputSearch(t *testing.T) {
	e := modelEnv(t)
	for _, c := range []struct{ q, want string }{
		{"printer", "device:a-new,f-p1"},    // the device's name: its not-added item and its finding
		{"192.0.2.77", "device:a-new,f-p1"}, // its address
		{"cups", "device:a-new,f-p1"},       // the software's name (any case): the finding, and the device not added that has it
		{"cve-2026-2001", "f-f2,f-f3"},      // the CVE id
		{"nothing-here", ""},                // no match: an empty page, not the whole queue
		{"lab-box", ""},                     // an ignored device stays out
	} {
		ids, total := queueIDs(t, e, "?q="+url.QueryEscape(c.q))
		_ = total
		if got := strings.Join(ids, ","); got != c.want {
			t.Errorf("q=%q: %q (total %d), want %q", c.q, got, total, c.want)
		}
	}
	ids, total := queueIDs(t, e, "?q=fw01&limit=1&offset=0")
	if total != 1 || strings.Join(ids, ",") != "f-f1,f-f2,f-f3" {
		t.Errorf("q=fw01: total %d, items %v; want the one card of the device with its 3 findings", total, ids)
	}
}

// A device nobody added is one item of the queue that names neither a CVE nor a software line, yet a search by the CVE id or the
// software of any of its open findings finds it, as the device's name does: a person looking for "cups" or a CVE sees the device to
// add even when none of its findings is an item of its own (an update-recommended finding asks nothing).
func TestModelAPI_NeedsYourInputSearchFindsADeviceNotAddedByItsFindings(t *testing.T) {
	e := modelEnv(t)
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		f := Finding{ID: "f-p2", AssetID: "a-new", CVE: "CVE-2026-3002", SoftwareID: "s-cups", Fix: Fix{Kind: FixUnknown}, Urgency: 5,
			Basis: DetectBannerVersion, Verified: VerifiedNo, FirstSeen: t0.Add(-48 * time.Hour)}
		f.FixKey = FixKey(e.inv.lines["s-cups"].ProductKey, f.Fix)
		return writeTestFinding(t.Context(), tx, f)
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ q, want string }{
		{"cve-2026-3002", "device:a-new"}, // the CVE of its update-recommended finding: only the device item has it
		{"CUPS", "device:a-new,f-p1"},     // the software of its findings, any case
		{"cve-2026-1002", "f-f1"},         // another device's CVE does not find it
	} {
		ids, total := queueIDs(t, e, "?q="+url.QueryEscape(c.q))
		_ = total
		if got := strings.Join(ids, ","); got != c.want {
			t.Errorf("q=%q: %q, want %q", c.q, got, c.want)
		}
	}
}

// The words a device not added yet is searched by (the CVE ids and software names of its open findings) are read only for a search:
// the queue without search text does not read inventory for the software of every open finding (Home's overview counts the same
// queue without search text).
func TestModelAPI_NeedsYourInputReadsSearchTermsOnlyForASearch(t *testing.T) {
	e := modelEnv(t)
	e.inv.mu.Lock()
	e.inv.lines["s-lpd"] = Line{ID: "s-lpd", AssetID: "a-new", Display: "LPRng", ProductKey: "lprng|lprng", Version: "3.8"}
	e.inv.mu.Unlock()
	if err := e.db.Write(t.Context(), func(tx *sql.Tx) error {
		f := Finding{ID: "f-p3", AssetID: "a-new", CVE: "CVE-2026-3003", SoftwareID: "s-lpd", Fix: Fix{Kind: FixUnknown}, Urgency: 5,
			Basis: DetectBannerVersion, Verified: VerifiedNo, FirstSeen: t0.Add(-48 * time.Hour)}
		f.FixKey = FixKey(e.inv.lines["s-lpd"].ProductKey, f.Fix)
		return writeTestFinding(t.Context(), tx, f)
	}); err != nil {
		t.Fatal(err)
	}
	asked := func() bool {
		e.inv.mu.Lock()
		defer e.inv.mu.Unlock()
		found := slices.Contains(e.inv.asked, "s-lpd")
		e.inv.asked = nil
		return found
	}
	all := conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input", "viewer", "")
	if asked() {
		t.Error("the queue without search text read the software of a device's update-recommended finding")
	}
	if ov := conform[oas.FindingsGetFindingsOverviewOK](t, e, "GET", "/findings/overview", "viewer", ""); ov.Input != all.Total {
		t.Errorf("overview counts %d items needing input, the queue %d", ov.Input, all.Total)
	}
	asked() // the overview reads lines for its own blocks
	if ids, total := queueIDs(t, e, "?q=lprng"); total != 1 || ids[0] != "device:a-new" {
		t.Fatalf("q=lprng: %v, want the device not added that has it", ids)
	}
	if all.Total == 0 || all.Items[0].FindingsGetFindingsInput2DeviceNotAdded.Findings != 2 {
		t.Fatalf("the queue: %d items, first %+v; want the device not added first with its 2 open findings", all.Total, all.Items[0])
	}
}

// A device nobody added yet that has open findings is its own Add device / Ignore card. The devices nobody added yet with no open
// finding are one grouped card (how many; Review opens the Devices list's To review), after the urgent findings and the questions,
// counted as one item: a sweep of a large network that found hundreds of devices never buries the urgent items. The group leaves
// when none is left; the box is never in it; a queue read for one device or by a search has no group.
func TestModelAPI_NotAddedWithoutFindingsIsOneGroupCard(t *testing.T) {
	e := modelEnv(t)
	type item struct {
		Kind  string `json:"kind"`
		ID    string `json:"id"`
		Count int    `json:"count"`
	}
	// overview: also read Home's count (kept until something changes, so read once, after the devices are there)
	read := func(path string, overview bool) (items []item, total, home int) {
		t.Helper()
		conform[oas.FindingsGetFindingsInputOK](t, e, "GET", path, "viewer", "")
		_, b := e.raw("GET", path, "viewer", "")
		var l struct {
			Items []item `json:"items"`
			Total int    `json:"total"`
		}
		if err := json.Unmarshal(b, &l); err != nil {
			t.Fatal(err)
		}
		if !overview {
			return l.Items, l.Total, -1
		}
		_, ob := e.raw("GET", "/findings/overview", "viewer", "")
		var o struct {
			Input int `json:"input"`
		}
		if err := json.Unmarshal(ob, &o); err != nil {
			t.Fatal(err)
		}
		return l.Items, l.Total, o.Input
	}
	_, before, _ := read("/findings/input?limit=200", false)
	const n = 300
	e.inv.mu.Lock()
	e.inv.assets["a-box"] = AssetView{ID: "a-box", Name: "vedette", IP: "192.0.2.2", Kind: "server", Box: true}
	e.inv.match["a-box"] = Asset{}
	for i := range n {
		id := fmt.Sprintf("a-d%03d", i)
		e.inv.assets[id] = AssetView{ID: id, Name: id, IP: fmt.Sprintf("10.0.%d.%d", i/250, i%250+1), Kind: "unknown"}
		e.inv.match[id] = Asset{}
	}
	e.inv.mu.Unlock()
	items, total, overview := read("/findings/input?limit=200", true)
	if total != before+1 || overview != before {
		t.Fatalf("%d devices not added with no finding: queue length %d (before %d), the count on the tab and Home %d; want one more item (the grouped card) and the count unchanged: it counts the devices that wait for an answer, and the grouped card is a review, not an answer", n, total, before, overview)
	}
	var cards, groups []item
	for _, it := range items {
		switch it.Kind {
		case "device_not_added":
			cards = append(cards, it)
		case "devices_not_added":
			groups = append(groups, it)
		}
	}
	if len(cards) != 1 || cards[0].ID != "device:a-new" {
		t.Fatalf("Add device cards: %+v; want only printer-07, the device not added that has a finding", cards)
	}
	if len(groups) != 1 || groups[0].Count != n || items[len(items)-1].Kind != "devices_not_added" {
		t.Fatalf("grouped card: %+v (last item %+v); want one, last, counting %d", groups, items[len(items)-1], n)
	}
	if _, one, _ := read("/findings/input?device=a-d007", false); one != 0 {
		t.Errorf("the queue of one device not added with no finding: %d items, want none", one)
	}
	if _, q, _ := read("/findings/input?q=a-d007", false); q != 0 {
		t.Errorf("search a-d007: %d items, want none", q)
	}
	e.inv.mu.Lock()
	for i := range n - 1 {
		id := fmt.Sprintf("a-d%03d", i)
		a := e.inv.assets[id]
		a.Approved = true
		e.inv.assets[id] = a
	}
	e.inv.mu.Unlock()
	if items, _, _ := read("/findings/input?limit=200", false); items[len(items)-1].Kind != "devices_not_added" || items[len(items)-1].Count != 1 {
		t.Fatalf("one left: last item %+v", items[len(items)-1])
	}
	e.inv.mu.Lock()
	e.inv.ignored["a-d299"] = true
	delete(e.inv.match, "a-d299")
	e.inv.mu.Unlock()
	if items, total, _ := read("/findings/input?limit=200", false); total != before || slices.ContainsFunc(items, func(it item) bool { return it.Kind == "devices_not_added" }) {
		t.Fatalf("none left: %d items, %+v", total, items)
	}
}

// queueIDs reads Needs your input and lists what it names, flat: a device not added by its item id, a device's card by what it holds
// (an unconfirmed finding by its id, a software line as "sw:<line>"); total is the queue's own count (cards). The reply must match the
// contract.
func queueIDs(t *testing.T, e *httpEnv, query string) (ids []string, total int) {
	t.Helper()
	_ = conform[oas.FindingsGetFindingsInputOK](t, e, "GET", "/findings/input"+query, "viewer", "")
	_, b := e.call("GET", "/findings/input"+query, "viewer", "")
	total = int(b["total"].(float64))
	for _, raw := range b["items"].([]any) {
		it := raw.(map[string]any)
		switch it["kind"] {
		case "device_not_added":
			ids = append(ids, it["id"].(string))
		case "device_needs":
			for _, r := range it["entries"].([]any) {
				ids = append(ids, r.(map[string]any)["id"].(string))
			}
		default:
			ids = append(ids, it["kind"].(string))
		}
	}
	return ids, total
}
