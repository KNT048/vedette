package notify_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// firstRun is one findings.urgency.first_run event of the box's own first look, at the clock's time.
func firstRun(e *env, ids ...string) findings.FirstRunEvent {
	return findings.FirstRunEvent{Key: "install", At: e.clock.Now().UTC().Format(time.RFC3339Nano), Findings: len(ids), Devices: 1, Layer: 4, FindingIDs: ids}
}

// summaries is every delivered first-run summary, oldest first.
func summaries(e *env) []channel.Message {
	e.t.Helper()
	var out []channel.Message
	for _, m := range sentMessages(e) {
		if strings.HasPrefix(m.ID, "nt-first-run-") {
			out = append(out, m)
		}
	}
	return out
}

// The finding page's words on each line of a first-run summary: a three-finding summary sent its lines as bare CVE ids, with a link to a
// tab the Findings page does not have. Now each line is the finding as a grouped alert says it (product, CVE, device, the status and its
// reasons, the verification line), the most urgent first, and the link opens the open findings filtered to the statuses it names.
func TestFirstRunSummaryLinesAreTheFindingsAsTheirPagesSayThem(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	java := finding("Java", "CVE-2026-114938", "java-app-01", notify.High)
	java.Reasons, java.Verification = "Public exploit available: PoC-in-GitHub (17 Nov 2026)", "Not confirmed yet: based on a scan banner"
	nas := finding("Example NAS OS", "CVE-2026-13639", "nas-office", notify.Critical)
	nas.Verification = "Confirmed by a safe check"
	web := finding("nginx", "CVE-2026-123007", "web-01", notify.Critical)
	web.Reasons, web.Verification = "Critical on an edge device: CVSS 9.8 (19 Mar 2025)", "Not confirmed yet: based on a version someone entered"
	dir.at("f-java", 3, java)
	dir.at("f-nas", 2, nas)
	dir.at("f-web", 4, web)
	pub(notify.EventFirstRun, firstRun(e, "f-java", "f-nas", "f-web"))
	e.flush()
	if got := summaries(e); len(got) != 0 {
		t.Fatalf("a summary went out before its load settled: %+v", got)
	}
	e.clock.Add(3 * time.Minute)
	e.flush()
	got := summaries(e)
	if len(got) != 1 {
		t.Fatalf("summaries = %+v, want one", got)
	}
	m := got[0]
	if m.Title != "Patch first: 3 urgent findings on 3 devices" || strings.Contains(m.What, "since its last summary") {
		t.Errorf("title %q, what %q", m.Title, m.What)
	}
	want := []string{
		"Example NAS OS: CVE-2026-13639 on nas-office — Exploited in the wild: CISA KEV (4 Mar); fix by 25 Mar 2025 · Confirmed by a safe check",
		"Java: CVE-2026-114938 on java-app-01 — Public exploit available: PoC-in-GitHub (17 Nov 2026) · Not confirmed yet: based on a scan banner",
		"nginx: CVE-2026-123007 on web-01 — Critical on an edge device: CVSS 9.8 (19 Mar 2025) · Not confirmed yet: based on a version someone entered",
	}
	if strings.Join(m.Items, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(m.Items, "\n"), strings.Join(want, "\n"))
	}
	if m.Link != "https://box.example:8443/findings?tab=device&status=exploited,public_exploit,critical_edge" {
		t.Errorf("link %q", m.Link)
	}
	h, err := e.svc.History(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Items) != 1 || h.Items[0].Link != "/findings?tab=device&status=exploited,public_exploit,critical_edge" {
		t.Errorf("History opens the summary at %+v, want the list of what it told", h.Items)
	}
}

// The passes of one load are one message: findings told a re-match per device as one event per pass, and each event became its own
// summary ("1 more urgent finding on 1 device", then "6 more urgent findings on 3 devices" five seconds later). A summary of the load that
// still waits in the queue is replaced by one that tells both.
func TestFirstRunPassesOfOneLoadAreOneMessage(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	dir.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-02", notify.High))
	dir.at("f-2", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	dir.at("f-3", 4, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-1"))
	e.clock.Add(5 * time.Second)
	e.flush()
	pub(notify.EventFirstRun, firstRun(e, "f-2", "f-3"))
	pub(notify.EventFirstRun, firstRun(e, "f-2", "f-3")) // the same event delivered twice changes nothing
	e.clock.Add(3 * time.Minute)
	e.flush()
	got := summaries(e)
	if len(got) != 1 || got[0].Title != "Patch first: 3 urgent findings on 3 devices" || len(got[0].Items) != 3 {
		t.Fatalf("summaries = %+v, want one that tells the three findings", got)
	}
	if n := e.count(`SELECT count(*) FROM notify_notice WHERE event = 'first_run'`); n != 1 {
		t.Errorf("%d summary notices kept, want 1 (the replaced one leaves no trace)", n)
	}
	for id, n := range toldOK(e) {
		if n != 1 {
			t.Errorf("notice %s named by %d delivered messages", id, n)
		}
	}
	if n := e.count(`SELECT count(*) FROM notify_notice_finding nf JOIN notify_notice n ON n.id = nf.notice_id WHERE n.event = 'first_run'`); n != 3 {
		t.Errorf("%d findings recorded as told by the summary, want 3", n)
	}

	// A load that keeps bringing passes is still told within firstRunSettleMax of its first one.
	for i := range 8 {
		id := "f-late-" + string(rune('a'+i))
		dir.at(id, 4, finding("nginx", "CVE-2026-20000", "web-0"+string(rune('2'+i)), notify.Critical))
		e.clock.Add(90 * time.Second)
		pub(notify.EventFirstRun, firstRun(e, id))
		e.flush()
	}
	if got := summaries(e); len(got) != 2 {
		t.Errorf("after 12 minutes of passes %d summaries went out, want the second one by its 10-minute bound", len(got))
	}
}

// "N more" only after a summary of the load reached the customer as its own message, and it says when that was. A box upgraded from a
// build that folded the summary into a digest line had never shown one, yet every later summary said "since its last summary".
func TestFirstRunSaysMoreOnlyAfterASummaryWentOut(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	// An earlier build folded the load's first summary into a digest of other findings: it was a line of that message, not a summary.
	e.write(func(tx *sql.Tx) error {
		for _, q := range []string{
			`INSERT INTO notify_notice (id, event, created_at, product, cves) VALUES ('nt-first-run-install-20261109T080000.000', 'first_run', '2026-11-09T08:00:00.000Z', '', '["CVE-2026-59309"]')`,
			`INSERT INTO notify_notice (id, event, created_at, product, cves) VALUES ('nt-f-old-created', 'created', '2026-11-09T08:00:00.000Z', 'Example Manager', '["CVE-2026-1"]')`,
			`INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('sd-old', 'vuln', 'nt-f-old-created', 'telegram', 'chat', '2026-11-09T08:01:00.000Z', 1, '3 vulnerabilities need patching on your devices', '/findings', '{}')`,
			`INSERT INTO notify_send_notice (send_id, notice_id) VALUES ('sd-old', 'nt-first-run-install-20261109T080000.000'), ('sd-old', 'nt-f-old-created')`,
		} {
			if _, err := tx.ExecContext(e.ctx(), q); err != nil {
				return err
			}
		}
		return nil
	})
	dir.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-02", notify.High))
	pub(notify.EventFirstRun, firstRun(e, "f-1"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	got := summaries(e)
	if len(got) != 1 || got[0].Title != "Patch first: 1 urgent finding on 1 device" || strings.Contains(got[0].What, "more") {
		t.Fatalf("the first summary the customer gets = %+v, want the first-summary words", got)
	}

	e.clock.Add(time.Hour)
	dir.at("f-2", 4, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	pub(notify.EventFirstRun, firstRun(e, "f-2"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	got = summaries(e)
	if len(got) != 2 {
		t.Fatalf("summaries = %+v", got)
	}
	if m := got[1]; m.Title != "1 more urgent finding on 1 device to patch first" || !strings.HasPrefix(m.What, "Since the summary sent at 9 Nov 2026, 10:03, Vedette rated 1 more finding on 1 device") {
		t.Errorf("second summary: %q / %q", m.Title, m.What)
	}
}

// A grouped alert opens the list of what it names, not a tab the Findings page does not have.
func TestGroupedAlertLinksToTheListOfItsStatuses(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	dir.at("f-1", 2, finding("Example Manager", "CVE-2026-123890", "manager-01", notify.Critical))
	dir.at("f-2", 2, finding("Example Hypervisor", "CVE-2025-22224", "hypervisor-01", notify.High))
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", CVE: "CVE-x", Severity: findings.SeverityHigh})
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-2", CVE: "CVE-x", Severity: findings.SeverityHigh})
	e.flush()
	got := sentMessages(e)
	if len(got) != 1 || got[0].Link != "https://box.example:8443/findings?tab=device&status=exploited" {
		t.Fatalf("messages = %+v, want one digest linking the exploited findings", got)
	}
}

// Send now: an urgent finding no channel delivered (here below the channel's minimum) goes to every channel that is on, in today's
// words, and leaves the Not sent list; it is refused once delivered, and for a finding handled since.
func TestSendNowSendsAnAlertThatWasNotSent(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	e.telegram(notify.Critical)
	pub := func(id string) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFindingCreated, findings.CreatedEvent{FindingID: id, CVE: "CVE-x", Severity: findings.SeverityHigh})); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-1", 3, finding("Example NAS", "CVE-2026-1", "nas-01", notify.High))
	pub("f-1")
	dir.at("f-2", 3, finding("Example NAS", "CVE-2026-2", "nas-01", notify.High))
	pub("f-2")
	e.flush()
	if n := len(sentMessages(e)); n != 0 {
		t.Fatalf("%d messages sent below the minimum", n)
	}
	dir.at("f-1", 3, func() notify.FindingInfo {
		f := finding("Example NAS", "CVE-2026-1", "nas-01", notify.High)
		f.Verification = "Confirmed by a safe check"
		return f
	}())
	got, err := e.svc.SendNow(e.ctx(), "it@acme.example", "nt-f-1-created")
	if err != nil {
		t.Fatal(err)
	}
	if got.NotSent.Reason != notify.UnsentQueued || got.Link != "/findings/f-1" {
		t.Errorf("answer %+v", got)
	}
	e.flush()
	sent := sentMessages(e)
	if len(sent) != 1 || sent[0].ID != "nt-f-1-created" || !strings.Contains(sent[0].What, "Confirmed by a safe check") {
		t.Fatalf("sent = %+v, want the notice in today's words", sent)
	}
	h, err := e.svc.History(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(h.NotSent) != 1 || h.NotSent[0].ID != "nt-f-2-created" {
		t.Errorf("not sent = %+v, want only the one not sent now", h.NotSent)
	}
	if n := e.count(`SELECT count(*) FROM core_audit WHERE action = 'notify.notice_send_now'`); n != 1 {
		t.Errorf("%d audit rows", n)
	}
	conflict := func(id, code string) {
		t.Helper()
		_, err := e.svc.SendNow(e.ctx(), "it@acme.example", id)
		var ae *apierr.Error
		if !errors.As(err, &ae) || ae.Status != http.StatusConflict || ae.Code != code {
			t.Errorf("%s: %v, want 409 %s", id, err, code)
		}
	}
	conflict("nt-f-1-created", "already_sent")
	dir.handle("f-2")
	conflict("nt-f-2-created", "nothing_to_send")
	if _, err := e.svc.SendNow(e.ctx(), "it@acme.example", "nt-none"); err == nil {
		t.Error("an unknown alert was sent")
	}
}

// Not sent says what is known: a notice an earlier build made kept no reason (it is not "its line did not fit"), and a notice that was
// queued and went out in a message that left its line out says that.
func TestNotSentOfAnOldNoticeAndOfALineLeftOut(t *testing.T) {
	e := newEnv(t)
	at := e.clock.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	e.write(func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice (id, event, created_at, product, cves) VALUES ('nt-f-old-created', 'created', ?, 'Example Hypervisor', '["CVE-2026-41709"]')`, at); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice (id, event, created_at, product, cves, title, severity, unsent) VALUES ('nt-f-cut-created', 'created', ?, 'Example NAS', '["CVE-2026-2"]', 'Example NAS on nas-01: exploited in the wild (CVE-2026-2)', 'critical', 'queued')`, at)
		return err
	})
	h, err := e.svc.History(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]notify.NotSent{}
	for _, n := range h.NotSent {
		got[n.ID] = n.NotSent
	}
	if n := got["nt-f-old-created"]; n.Reason != notify.UnsentUnknown || n.Text != "Not sent when it was found. The version of Vedette that found it did not keep the reason." {
		t.Errorf("old notice: %+v", n)
	}
	if n := got["nt-f-cut-created"]; n.Reason != notify.UnsentLineLeftOut || !strings.Contains(n.Text, "its line was past what the message could hold") {
		t.Errorf("line left out: %+v", n)
	}
}

// Not sent lists only what still needs telling, each row on its device: two notices of one CVE an earlier build wrote (no title) read
// "<product> on <device>: <CVE>"; the one whose finding was handled since leaves the list, and so does the other once another message
// that arrived told its finding at that status. Rows before and after are counted.
func TestNotSentDropsHandledAndToldAndNamesTheDevice(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	at := e.clock.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000Z")
	dir.at("f-esx", 2, finding("Example Hypervisor", "CVE-2026-41709", "esxi-01", notify.Low))
	dir.at("f-hp", 2, finding("Example Hypervisor", "CVE-2026-41709", "hp-01", notify.Low))
	e.write(func(tx *sql.Tx) error {
		for _, f := range []string{"f-esx", "f-hp"} {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice (id, event, created_at, product, cves) VALUES (?, 'created', ?, 'Example Hypervisor', '["CVE-2026-41709"]')`, "nt-"+f+"-created", at); err != nil {
				return err
			}
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice_finding (notice_id, finding_id, layer) VALUES (?, ?, 2)`, "nt-"+f+"-created", f); err != nil {
				return err
			}
		}
		return nil
	})
	rows := func() map[string]string {
		t.Helper()
		h, err := e.svc.History(e.ctx())
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, n := range h.NotSent {
			out[n.ID] = n.What
		}
		return out
	}
	before := rows()
	if len(before) != 2 || before["nt-f-esx-created"] != "Example Hypervisor on esxi-01: CVE-2026-41709" || before["nt-f-hp-created"] != "Example Hypervisor on hp-01: CVE-2026-41709" {
		t.Fatalf("rows = %v, want both, each on its device", before)
	}
	dir.handle("f-esx")
	if got := rows(); len(got) != 1 || got["nt-f-hp-created"] == "" {
		t.Fatalf("after the esxi-01 finding was handled: %v, want only hp-01", got)
	}
	// another message that arrived told f-hp at its status (a summary, a later notice)
	e.write(func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice (id, event, created_at, product, cves) VALUES ('nt-sum', 'first_run', ?, '', '[]')`, at); err != nil {
			return err
		}
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_notice_finding (notice_id, finding_id, layer) VALUES ('nt-sum', 'f-hp', 2)`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_send (id, kind, ref_id, channel, "to", at, ok, what, link, message) VALUES ('sd-sum', 'vuln', 'nt-sum', 'email', 'a@example.com', ?, 1, 'summary', '/findings', '{}')`, at); err != nil {
			return err
		}
		_, err := tx.ExecContext(e.ctx(), `INSERT INTO notify_send_notice (send_id, notice_id) VALUES ('sd-sum', 'nt-sum')`)
		return err
	})
	if got := rows(); len(got) != 0 {
		t.Fatalf("after another message told hp-01: %v, want none", got)
	}
	t.Logf("Not sent rows: %d before, %d after", len(before), len(rows()))
}

// A waiting summary that already lists as many findings as a notice holds still takes the next pass's findings: they are counted, never
// dropped as "nothing new".
func TestFirstRunSummaryPastItsListLimitStillCountsNewFindings(t *testing.T) {
	dir := &liveFindings{}
	e, pub := alertEnv(t, dir)
	var ids []string
	for i := range 100 {
		id := fmt.Sprintf("f-%03d", i)
		dir.at(id, 4, finding("nginx", fmt.Sprintf("CVE-2026-%d", 1000+i), fmt.Sprintf("web-%03d", i), notify.Critical))
		ids = append(ids, id)
	}
	pub(notify.EventFirstRun, firstRun(e, ids...))
	dir.at("f-new", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	pub(notify.EventFirstRun, firstRun(e, "f-new"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	got := summaries(e)
	if len(got) != 1 || got[0].Title != "Patch first: 101 urgent findings on 101 devices" || !strings.Contains(got[0].Items[0], "CVE-2026-114938") {
		t.Fatalf("summaries = %+v", got)
	}
}

// hookFindings is a finding directory that runs a hook once, on the first read of a given finding: another pass of the same load
// published from another goroutine while this one reads its findings.
type hookFindings struct {
	*liveFindings
	on   string
	hook func()
}

func (h *hookFindings) Finding(ctx context.Context, id string) (notify.FindingInfo, bool, error) {
	if id == h.on && h.hook != nil {
		f := h.hook
		h.hook = nil
		f()
	}
	return h.liveFindings.Finding(ctx, id)
}

// Two passes of one load told at the same time are still one message: the second pass's summary is written while the first one reads
// its findings, and the first one must then take it in, not queue a second summary beside it.
func TestFirstRunPassesToldAtOnceAreOneMessage(t *testing.T) {
	live := &liveFindings{}
	dir := &hookFindings{liveFindings: live, on: "f-1"}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.telegram(notify.Medium)
	e.svc.Subscribe(e.bus)
	pub := func(data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFirstRun, data)); err != nil {
			t.Fatal(err)
		}
	}
	live.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	live.at("f-2", 4, finding("nginx", "CVE-2026-123007", "web-01", notify.Critical))
	first := firstRun(e, "f-1")
	e.clock.Add(time.Second)
	dir.hook = func() { pub(firstRun(e, "f-2")) }
	pub(first)
	e.clock.Add(3 * time.Minute)
	e.flush()
	if got := summaries(e); len(got) != 1 || len(got[0].Items) != 2 {
		t.Fatalf("summaries = %+v, want one that tells both findings", got)
	}
}

// Send now never tells a finding twice: a notice not sent at the time whose finding a later alert (its rise) already told is refused.
func TestSendNowRefusesAFindingAlreadyToldSince(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.svc.Subscribe(e.bus)
	e.telegram(notify.Critical)
	pub := func(name string, data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(name, data)); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-1", 3, finding("Example NAS", "CVE-2026-1", "nas-01", notify.High))
	pub(notify.EventFindingCreated, findings.CreatedEvent{FindingID: "f-1", CVE: "CVE-2026-1", Severity: findings.SeverityHigh})
	e.flush()
	dir.at("f-1", 2, finding("Example NAS", "CVE-2026-1", "nas-01", notify.High))
	pub(notify.EventUrgencyRaised, rise("f-1", 3, 2, e.clock.Now()))
	e.flush()
	if n := len(sentMessages(e)); n != 1 {
		t.Fatalf("%d messages, want the rise's alert", n)
	}
	_, err := e.svc.SendNow(e.ctx(), "it@acme.example", "nt-f-1-created")
	var ae *apierr.Error
	if !errors.As(err, &ae) || ae.Status != http.StatusConflict || ae.Code != "already_sent" {
		t.Errorf("send now of a finding told since: %v, want 409 already_sent", err)
	}
	e.flush()
	if n := len(sentMessages(e)); n != 1 {
		t.Errorf("%d messages: the finding was told twice", n)
	}
}

// A summary a person sent with Send now goes out as they asked: the next pass of its load does not take it back into a new summary that
// the channel's minimum severity drops again.
func TestSendNowOfASummaryIsNotTakenBackByTheNextPass(t *testing.T) {
	dir := &liveFindings{}
	e := newEnv(t, func(c *notify.Config) { c.Findings = dir })
	e.telegram(notify.Critical)
	e.svc.Subscribe(e.bus)
	pub := func(data any) {
		t.Helper()
		if err := e.bus.Publish(e.ctx(), eventOf(notify.EventFirstRun, data)); err != nil {
			t.Fatal(err)
		}
	}
	dir.at("f-1", 3, finding("Java", "CVE-2026-114938", "java-app-01", notify.High))
	pub(firstRun(e, "f-1"))
	e.clock.Add(3 * time.Minute)
	e.flush()
	if got := summaries(e); len(got) != 0 {
		t.Fatalf("a high summary went to a channel that takes only critical: %+v", got)
	}
	var id string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM notify_notice WHERE event = 'first_run'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SendNow(e.ctx(), "it@acme.example", id); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(time.Second)
	dir.at("f-2", 4, finding("nginx", "CVE-2026-123007", "web-01", notify.High))
	pub(firstRun(e, "f-2"))
	e.flush()
	if got := summaries(e); len(got) != 1 || got[0].ID != id {
		t.Fatalf("summaries = %+v, want the one sent now", got)
	}
}
