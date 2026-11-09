package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kiennt048/vedette/core/secrets"
	"github.com/kiennt048/vedette/modules/notify/channel"
)

func vuln(id, product, cve string, devices []string, sev Severity, t time.Time) Notice {
	return Notice{ID: id, Kind: KindVuln, Severity: sev, Product: product, CVEs: []string{cve}, Devices: devices,
		Title: product + " is being exploited (" + cve + ")", What: "Attackers are using " + cve + " right now.",
		Action: "Update " + product + " today.", Link: "https://192.168.10.2/findings/" + id, At: t}
}

func TestContract_INV2_NoUnmatchedCVE(t *testing.T) {
	t.Parallel()
	matched := vuln("f-1", "QNAP Photo Station", "CVE-2022-27593", []string{"NAS-01"}, High, at(9, 0))
	unmatched := vuln("f-2", "Acme Gadget", "CVE-2026-0002", nil, Critical, at(9, 5))
	incident := Notice{ID: "al-4", Kind: KindIncident, Severity: Critical, Title: "x", Link: "https://h/x", At: at(9, 6)}
	send, suppressed := SplitSendable([]Notice{matched, unmatched, incident, unmatched})
	if len(send) != 2 || send[0].ID != "f-1" || send[1].ID != "al-4" || suppressed != 2 {
		t.Fatalf("send=%v suppressed=%d", send, suppressed)
	}
	if unmatched.Sendable() || !matched.Sendable() || !incident.Sendable() {
		t.Error("Sendable wrong")
	}
}

func TestContract_INV3_GroupsSameProductInsideWindow(t *testing.T) {
	t.Parallel()
	ns := []Notice{
		vuln("a", "WordPress", "CVE-1", []string{"WEB01"}, Medium, at(9, 0)),
		vuln("b", "Other", "CVE-9", []string{"PC1"}, High, at(9, 10)),
		vuln("c", "wordpress ", "CVE-2", []string{"WEB01", "WEB02"}, High, at(9, 14)), // same product, case/space-insensitive
		vuln("d", "WordPress", "CVE-3", []string{"WEB01"}, Low, at(9, 16)),            // 16 min after the first: outside a 15-minute window
		{ID: "i1", Kind: KindIncident, Severity: High, Title: "t", Link: "https://h/x", At: at(9, 1)},
		{ID: "i2", Kind: KindIncident, Severity: High, Title: "t", Link: "https://h/x", At: at(9, 2)}, // incidents never group
	}
	got := Group(ns, Grouping{Enabled: true, WindowMin: 15}, Low)
	var ids [][]string
	for _, b := range got {
		var r []string
		for _, n := range b.Notices {
			r = append(r, n.ID)
		}
		ids = append(ids, r)
	}
	want := `[["a","c"],["i1"],["i2"],["b"],["d"]]`
	if j, _ := json.Marshal(ids); string(j) != want {
		t.Errorf("batches = %s, want %s", j, want)
	}
	if b := got[0]; b.Severity() != High {
		t.Errorf("batch severity = %s", b.Severity())
	}

	// 60 minutes pulls "d" in as well.
	if got := Group(ns, Grouping{Enabled: true, WindowMin: 60}, Low); len(got) != 4 || len(got[0].Notices) != 3 {
		t.Errorf("60 min: %d batches", len(got))
	}
	// Disabled or invalid window: nothing is grouped.
	for _, g := range []Grouping{{Enabled: false, WindowMin: 60}, {Enabled: true, WindowMin: 7}} {
		if got := Group(ns, g, Low); len(got) != len(ns) {
			t.Errorf("%+v grouped %d notices into %d batches", g, len(ns), len(got))
		}
	}
	// Held during quiet hours: one batch per product whatever the window.
	if got := GroupHeld(ns, Low); len(got) != 4 || len(got[0].Notices) != 3 {
		t.Errorf("GroupHeld: %d batches", len(got))
	}
	// Input order does not matter and the input is not modified.
	rev := []Notice{ns[3], ns[2], ns[1], ns[0]}
	if got := Group(rev, Grouping{Enabled: true, WindowMin: 15}, Low); got[0].Notices[0].ID != "a" || rev[0].ID != "d" {
		t.Errorf("order handling: first batch starts with %s", got[0].Notices[0].ID)
	}
}

func TestGroupingValidate(t *testing.T) {
	t.Parallel()
	for _, w := range []int{15, 60, 240} {
		if err := (Grouping{Enabled: true, WindowMin: w}).Validate(); err != nil {
			t.Errorf("%d: %v", w, err)
		}
	}
	for _, w := range []int{0, 5, 30, 120, -60} {
		if err := (Grouping{Enabled: true, WindowMin: w}).Validate(); !errors.Is(err, ErrBadGrouping) {
			t.Errorf("%d: %v", w, err)
		}
	}
}

// oneBatch groups ns for a channel with min_severity low and expects one batch.
func oneBatch(t *testing.T, ns ...Notice) Batch {
	t.Helper()
	b := Group(ns, Grouping{Enabled: true, WindowMin: 240}, Low)
	if len(b) != 1 {
		t.Fatalf("expected one batch, got %d", len(b))
	}
	return b[0]
}

func msgOf(t *testing.T, b Batch) channel.Message {
	t.Helper()
	m, err := b.Message()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBatchDueAt(t *testing.T) {
	t.Parallel()
	b := oneBatch(t, vuln("a", "P", "CVE-1", []string{"d"}, High, at(9, 0)))
	if got := b.DueAt(Grouping{Enabled: true, WindowMin: 240}); !got.Equal(at(13, 0)) {
		t.Errorf("DueAt = %v", got)
	}
	if got := b.DueAt(Grouping{Enabled: false}); !got.Equal(at(9, 0)) {
		t.Errorf("disabled DueAt = %v", got)
	}
}

// D-62: critical is never delayed by grouping, so INV-6 (60 minutes) holds for it
// whatever window is configured.
func TestContract_INV6_CriticalIsNeverGrouped(t *testing.T) {
	t.Parallel()
	g := Grouping{Enabled: true, WindowMin: 240}
	ns := []Notice{
		vuln("h1", "WordPress", "CVE-1", []string{"WEB01"}, High, at(9, 0)),
		vuln("c1", "WordPress", "CVE-2", []string{"WEB01"}, Critical, at(9, 5)),
		vuln("h2", "WordPress", "CVE-3", []string{"WEB01"}, High, at(9, 10)),
		vuln("c2", "WordPress", "CVE-4", []string{"WEB01"}, Critical, at(9, 11)),
	}
	for name, got := range map[string][]Batch{"Group": Group(ns, g, Low), "GroupHeld": GroupHeld(ns, Low)} {
		var ids [][]string
		for _, b := range got {
			var r []string
			for _, n := range b.Notices {
				r = append(r, n.ID)
				if n.Severity == Critical && len(b.Notices) != 1 {
					t.Errorf("%s: critical notice %s rides in a batch of %d", name, n.ID, len(b.Notices))
				}
			}
			ids = append(ids, r)
		}
		if j, _ := json.Marshal(ids); string(j) != `[["h1","h2"],["c1"],["c2"]]` {
			t.Errorf("%s: batches = %s", name, j)
		}
	}
	for _, b := range Group(ns, g, Low) {
		first := b.Notices[0]
		want := first.At.Add(4 * time.Hour)
		if first.Severity == Critical {
			want = first.At // due at its own time
		}
		if got := b.DueAt(g); !got.Equal(want) {
			t.Errorf("%s: DueAt = %v, want %v", first.ID, got, want)
		}
	}
	// The bypass does not depend on the order notices arrive in.
	rev := []Notice{ns[3], ns[2], ns[1], ns[0]}
	if got := Group(rev, g, Low); len(got) != 3 {
		t.Errorf("reversed input: %d batches", len(got))
	}
}

// FORBID-1 is enforced inside the library, not only by SplitSendable.
func TestContract_INV2_LibraryNeverBatchesUnmatched(t *testing.T) {
	t.Parallel()
	g := Grouping{Enabled: true, WindowMin: 60}
	ok := vuln("ok", "WordPress", "CVE-1", []string{"WEB01"}, High, at(9, 0))
	for name, devices := range map[string][]string{"none": nil, "empty": {}, "blank": {""}, "spaces": {"  ", "\t"}} {
		bad := vuln("bad", "WordPress", "CVE-2", devices, Critical, at(9, 1))
		if bad.Sendable() {
			t.Errorf("%s: Sendable", name)
		}
		for gname, batches := range map[string][]Batch{"Group": Group([]Notice{ok, bad}, g, Low), "GroupHeld": GroupHeld([]Notice{ok, bad}, Low)} {
			if len(batches) != 1 || len(batches[0].Notices) != 1 || batches[0].Notices[0].ID != "ok" {
				t.Errorf("%s/%s: unsendable notice reached a batch: %+v", name, gname, batches)
			}
		}
		// Message refuses a batch someone assembled by hand around it.
		b := Group([]Notice{ok}, g, Low)[0]
		b.Notices = append(b.Notices, bad)
		if _, err := b.Message(); !errors.Is(err, ErrUnsendable) {
			t.Errorf("%s: Message of a tampered batch: %v", name, err)
		}
	}
	if _, err := (Batch{}).Message(); !errors.Is(err, ErrUnsendable) {
		t.Errorf("empty batch: %v", err)
	}
	if _, err := (Batch{Notices: []Notice{ok}}).Message(); !errors.Is(err, ErrUnsendable) {
		t.Errorf("hand-built batch (no channel filter): %v", err)
	}
	// A blank name is not listed as a device either.
	m := msgOf(t, oneBatch(t, vuln("x", "P", "CVE-1", []string{"", "NAS-01", " "}, Low, at(9, 0))))
	if m.Device != "NAS-01" {
		t.Errorf("device = %q", m.Device)
	}
}

// Grouping is per channel: a Low notice never rides in a batch to a High-only channel.
func TestContract_INV4_GroupingIsPerChannel(t *testing.T) {
	t.Parallel()
	g := Grouping{Enabled: true, WindowMin: 60}
	ns := []Notice{
		vuln("lo", "WordPress", "CVE-LOW", []string{"WEB01"}, Low, at(9, 0)),
		vuln("hi", "WordPress", "CVE-HIGH", []string{"WEB01"}, High, at(9, 1)),
		vuln("md", "WordPress", "CVE-MED", []string{"WEB01"}, Medium, at(9, 2)),
	}
	highOnly := Group(ns, g, High)
	if len(highOnly) != 1 || len(highOnly[0].Notices) != 1 {
		t.Fatalf("high-only channel got %d batches", len(highOnly))
	}
	m := msgOf(t, highOnly[0])
	all := m.Title + m.What + strings.Join(m.Items, " ")
	if strings.Contains(all, "CVE-LOW") || strings.Contains(all, "CVE-MED") || !strings.Contains(all, "CVE-HIGH") {
		t.Errorf("message for the high-only channel: %+v", m)
	}
	lowOK := Group(ns, g, Low)
	if len(lowOK) != 1 || len(lowOK[0].Notices) != 3 {
		t.Errorf("low channel: %d batches", len(lowOK))
	}
	if got := GroupHeld(ns, Medium); len(got) != 1 || len(got[0].Notices) != 2 {
		t.Errorf("GroupHeld for medium: %+v", got)
	}
	if len(Group(ns, g, "")) != 0 || len(Group(ns, g, Info)) != 0 {
		t.Error("an invalid minimum must pass nothing")
	}
	// A batch built for a lenient channel cannot be rendered for the strict one by adding a notice.
	b := highOnly[0]
	b.Notices = append(b.Notices, ns[0])
	if _, err := b.Message(); !errors.Is(err, ErrUnsendable) {
		t.Errorf("tampered batch: %v", err)
	}
}

func TestBatchMessage(t *testing.T) {
	t.Parallel()
	one := msgOf(t, oneBatch(t, vuln("f-1", "QNAP Photo Station", "CVE-2022-27593", []string{"NAS-01"}, High, at(9, 0))))
	if one.Title != "QNAP Photo Station is being exploited (CVE-2022-27593)" || one.Device != "NAS-01" || one.Severity != "high" ||
		one.Link != "https://192.168.10.2/findings/f-1" || len(one.Items) != 1 || one.Items[0] != "CVE-2022-27593" || one.Kind != KindVuln {
		t.Errorf("single: %+v", one)
	}
	many := msgOf(t, oneBatch(t,
		vuln("a", "WordPress", "CVE-1", []string{"WEB01"}, Medium, at(9, 0)),
		vuln("b", "WordPress", "CVE-2", []string{"WEB01", "WEB02"}, High, at(9, 5)),
		vuln("c", "WordPress", "CVE-2", []string{"WEB02"}, Low, at(9, 6)),
	))
	if many.Severity != "high" || many.Title != "WordPress: 3 vulnerabilities are being exploited" || many.Device != "WEB01, WEB02" || len(many.Items) != 3 ||
		many.Items[1] != "CVE-2 on WEB01, WEB02" || many.Action != "Update WordPress today." || many.Link != "https://192.168.10.2/findings/a" {
		t.Errorf("grouped: %+v", many)
	}
	var devs []string
	for i := range 8 {
		devs = append(devs, string(rune('A'+i)))
	}
	if got := msgOf(t, oneBatch(t, vuln("x", "P", "CVE-1", devs, Low, at(1, 0)))).Device; got != "A, B, C, D, E and 3 more" {
		t.Errorf("device list = %q", got)
	}
}

// rewriteTo sends every request to the fake server: the Telegram API address is
// not configurable, so a test steers it with the HTTP client.
type rewriteTo struct{ host string }

func (r rewriteTo) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = "http", r.host
	return http.DefaultTransport.RoundTrip(c)
}

// A grouped, hostile notice goes through a real adapter and arrives neutralised.
func TestBatchMessageThroughAdapters(t *testing.T) {
	t.Parallel()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	tg, err := channel.NewTelegram(channel.TelegramConfig{Token: secrets.NewValue("123456789:AAHexampleExampleExampleExample_0123456789"), ChatID: "-1002145678901",
		Client: &http.Client{Transport: rewriteTo{host: strings.TrimPrefix(srv.URL, "http://")}}})
	if err != nil {
		t.Fatal(err)
	}
	evil := vuln("a", "<b>Evil</b>", "CVE-1", []string{"PC <!channel>"}, High, at(9, 0))
	evil2 := vuln("b", "<b>Evil</b>", "CVE-2", []string{"PC2"}, High, at(9, 1))
	m := msgOf(t, oneBatch(t, evil, evil2))
	rec := Deliver(context.Background(), "sd-1", tg, m, func() time.Time { return at(9, 2) })
	if !rec.OK || rec.To != "chat -1002145678901" || !rec.At.Equal(at(9, 2)) {
		t.Fatalf("record %+v", rec)
	}
	text, _ := got["text"].(string)
	plain := strings.ReplaceAll(text, string(rune(0x200d)), "") // the joiners neutralise auto-links and are invisible
	for _, want := range []string{"High: <b>Evil</b>: 2 vulnerabilities are being exploited", "- CVE-1 on PC <!channel>", "- CVE-2 on PC2", "Details: https://192.168.10.2/findings/a"} {
		if !strings.Contains(plain, want) {
			t.Errorf("telegram text lacks %q:\n%s", want, plain)
		}
	}
	if strings.Contains(strings.Split(text, "\nDetails: ")[0], "</b>") {
		t.Errorf("slash in feed text was not neutralised:\n%s", text)
	}
}

type fakeSender struct {
	typ   channel.Type
	to    string
	rec   channel.Receipt
	err   error
	panic any
	seen  int
}

func (f *fakeSender) Type() channel.Type { return f.typ }
func (f *fakeSender) Dest() string       { return f.to }
func (f *fakeSender) Send(context.Context, channel.Message) (channel.Receipt, error) {
	f.seen++
	if f.panic != nil {
		panic(f.panic)
	}
	return f.rec, f.err
}

func TestContract_INV6_EveryAttemptHasRecord(t *testing.T) {
	t.Parallel()
	now := func() time.Time { return at(10, 0) }
	m := channel.Message{Severity: "high", Title: "t", Link: "https://h/x"}
	ok := &fakeSender{typ: channel.Slack, to: "Slack webhook", rec: channel.Receipt{To: "#it-alerts"}}
	if r := Deliver(context.Background(), "sd-1", ok, m, now); !r.OK || r.Channel != channel.Slack || r.To != "#it-alerts" || r.Error != "" || r.ID != "sd-1" || !r.At.Equal(at(10, 0)) {
		t.Errorf("success record %+v", r)
	}
	long := strings.Repeat("é", 1000)
	for name, err := range map[string]error{
		"status":      &channel.StatusError{Channel: channel.Email, Code: 535, Reason: "bad login"},
		"unsupported": channel.ErrUnsupported,
		"long":        errors.New(long),
	} {
		f := &fakeSender{typ: channel.Email, to: "it@acme.example", err: err}
		r := Deliver(context.Background(), "sd-2", f, m, now)
		if r.OK || r.Error == "" || r.To != "it@acme.example" || r.Channel != channel.Email || f.seen != 1 || len([]rune(r.Error)) > maxRecordError {
			t.Errorf("%s: record %+v", name, r)
		}
	}
}

// A sender that panics (a bug, a hostile response that trips one) still yields a record.
func TestContract_INV6_PanickingSenderStillHasRecord(t *testing.T) {
	t.Parallel()
	now := func() time.Time { return at(10, 0) }
	m := channel.Message{Severity: "high", Title: "t", Link: "https://h/x"}
	for name, p := range map[string]any{"string": "boom with a secret hunter2", "error": errors.New("boom hunter2"), "nil deref": 42} {
		f := &fakeSender{typ: channel.Webhook, to: "https://hooks.example.com", panic: p}
		r := Deliver(context.Background(), "sd-9", f, m, now)
		if r.OK || r.Error != "internal error" || r.ID != "sd-9" || r.Channel != channel.Webhook || r.To != "https://hooks.example.com" || !r.At.Equal(at(10, 0)) {
			t.Errorf("%s: record %+v", name, r)
		}
		mustNotContain(t, r.Error, "hunter2")
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("%q contains %q", s, sub)
	}
}

func FuzzBatchMessage(f *testing.F) {
	f.Add("WordPress", "CVE-2026-1", "WEB01", "title")
	f.Add("<b>\u202e", "\x00", "a\r\nb", strings.Repeat("é", 400))
	f.Add("P", "CVE-1", "  ", "t")
	f.Fuzz(func(t *testing.T, product, cve, device, title string) {
		a := Notice{ID: "a", Kind: KindVuln, Severity: High, Product: product, CVEs: []string{cve}, Devices: []string{device}, Title: title, Link: "https://h/x", At: at(9, 0)}
		b := a
		b.ID, b.At = "b", at(9, 1)
		for _, ns := range [][]Notice{{a}, {a, b}} {
			want := 0
			for _, n := range ns {
				if n.Sendable() {
					want++
				}
			}
			total := 0
			for _, bt := range Group(ns, Grouping{Enabled: true, WindowMin: 15}, Low) {
				total += len(bt.Notices)
				m, err := bt.Message()
				if err != nil {
					t.Fatalf("a sendable batch was refused: %v", err)
				}
				if m.Link != "https://h/x" || m.Severity != "high" {
					t.Fatalf("message lost link or severity: %+v", m)
				}
			}
			if total != want {
				t.Fatalf("grouping kept %d notices, want the %d sendable ones", total, want)
			}
		}
	})
}
