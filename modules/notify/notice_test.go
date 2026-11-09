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
	got := Group(ns, Grouping{Enabled: true, WindowMin: 15})
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
	if got := Group(ns, Grouping{Enabled: true, WindowMin: 60}); len(got) != 4 || len(got[0].Notices) != 3 {
		t.Errorf("60 min: %d batches", len(got))
	}
	// Disabled or invalid window: nothing is grouped.
	for _, g := range []Grouping{{Enabled: false, WindowMin: 60}, {Enabled: true, WindowMin: 7}} {
		if got := Group(ns, g); len(got) != len(ns) {
			t.Errorf("%+v grouped %d notices into %d batches", g, len(ns), len(got))
		}
	}
	// Held during quiet hours: one batch per product whatever the window.
	if got := GroupHeld(ns); len(got) != 4 || len(got[0].Notices) != 3 {
		t.Errorf("GroupHeld: %d batches", len(got))
	}
	// Input order does not matter and the input is not modified.
	rev := []Notice{ns[3], ns[2], ns[1], ns[0]}
	if got := Group(rev, Grouping{Enabled: true, WindowMin: 15}); got[0].Notices[0].ID != "a" || rev[0].ID != "d" {
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

func TestBatchDueAt(t *testing.T) {
	t.Parallel()
	b := Batch{Notices: []Notice{vuln("a", "P", "CVE-1", []string{"d"}, High, at(9, 0))}}
	if got := b.DueAt(Grouping{Enabled: true, WindowMin: 240}); !got.Equal(at(13, 0)) {
		t.Errorf("DueAt = %v", got)
	}
	if got := b.DueAt(Grouping{Enabled: false}); !got.Equal(at(9, 0)) {
		t.Errorf("disabled DueAt = %v", got)
	}
}

func TestBatchMessage(t *testing.T) {
	t.Parallel()
	one := Batch{Notices: []Notice{vuln("f-1", "QNAP Photo Station", "CVE-2022-27593", []string{"NAS-01"}, High, at(9, 0))}}.Message()
	if one.Title != "QNAP Photo Station is being exploited (CVE-2022-27593)" || one.Device != "NAS-01" || one.Severity != "high" ||
		one.Link != "https://192.168.10.2/findings/f-1" || len(one.Items) != 1 || one.Items[0] != "CVE-2022-27593" || one.Kind != KindVuln {
		t.Errorf("single: %+v", one)
	}
	many := Batch{Notices: []Notice{
		vuln("a", "WordPress", "CVE-1", []string{"WEB01"}, Medium, at(9, 0)),
		vuln("b", "WordPress", "CVE-2", []string{"WEB01", "WEB02"}, Critical, at(9, 5)),
		vuln("c", "WordPress", "CVE-2", []string{"WEB02"}, Low, at(9, 6)),
	}}.Message()
	if many.Severity != "critical" || many.Title != "WordPress: 3 vulnerabilities are being exploited" || many.Device != "WEB01, WEB02" || len(many.Items) != 3 ||
		many.Items[1] != "CVE-2 on WEB01, WEB02" || many.Action != "Update WordPress today." || many.Link != "https://192.168.10.2/findings/a" {
		t.Errorf("grouped: %+v", many)
	}
	var devs []string
	for i := range 8 {
		devs = append(devs, string(rune('A'+i)))
	}
	if got := (Batch{Notices: []Notice{vuln("x", "P", "CVE-1", devs, Low, at(1, 0))}}).Message().Device; got != "A, B, C, D, E and 3 more" {
		t.Errorf("device list = %q", got)
	}
}

// A grouped, hostile notice goes through two real adapters and arrives escaped.
func TestBatchMessageThroughAdapters(t *testing.T) {
	t.Parallel()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	tg, err := channel.NewTelegram(channel.TelegramConfig{Token: channel.NewSecret("123456789:AAHexampleExampleExampleExample_0123456789"), ChatID: "-1002145678901", BaseURL: srv.URL, Client: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	evil := vuln("a", "<b>Evil</b>", "CVE-1", []string{"PC <!channel>"}, High, at(9, 0))
	evil2 := vuln("b", "<b>Evil</b>", "CVE-2", []string{"PC2"}, High, at(9, 1))
	m := Batch{Notices: []Notice{evil, evil2}}.Message()
	rec := Deliver(context.Background(), "sd-1", tg, m, func() time.Time { return at(9, 2) })
	if !rec.OK || rec.To != "chat -1002145678901" || !rec.At.Equal(at(9, 2)) {
		t.Fatalf("record %+v", rec)
	}
	text, _ := got["text"].(string)
	for _, want := range []string{"High: <b>Evil</b>: 2 vulnerabilities are being exploited", "- CVE-1 on PC <!channel>", "- CVE-2 on PC2", "Details: https://192.168.10.2/findings/a"} {
		if !strings.Contains(text, want) {
			t.Errorf("telegram text lacks %q:\n%s", want, text)
		}
	}
}

type fakeSender struct {
	typ  channel.Type
	to   string
	rec  channel.Receipt
	err  error
	seen int
}

func (f *fakeSender) Type() channel.Type { return f.typ }
func (f *fakeSender) Dest() string       { return f.to }
func (f *fakeSender) Send(context.Context, channel.Message) (channel.Receipt, error) {
	f.seen++
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

func FuzzBatchMessage(f *testing.F) {
	f.Add("WordPress", "CVE-2026-1", "WEB01", "title")
	f.Add("<b>\u202e", "\x00", "a\r\nb", strings.Repeat("é", 400))
	f.Fuzz(func(t *testing.T, product, cve, device, title string) {
		a := Notice{ID: "a", Kind: KindVuln, Severity: High, Product: product, CVEs: []string{cve}, Devices: []string{device}, Title: title, Link: "https://h/x", At: at(9, 0)}
		b := a
		b.ID, b.At = "b", at(9, 1)
		for _, ns := range [][]Notice{{a}, {a, b}} {
			batches := Group(ns, Grouping{Enabled: true, WindowMin: 15})
			total := 0
			for _, bt := range batches {
				total += len(bt.Notices)
				m := bt.Message()
				if m.Link != "https://h/x" || m.Severity != "high" {
					t.Fatalf("message lost link or severity: %+v", m)
				}
			}
			if total != len(ns) {
				t.Fatalf("grouping lost notices: %d of %d", total, len(ns))
			}
		}
	})
}
