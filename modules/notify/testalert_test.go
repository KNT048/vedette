package notify_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

// The test alert of a honeypot test is the real trap alert marked Test, sent now to every channel that is on and would take the real
// one: it says what each channel did, opens no incident, writes no history row; a channel that would not take the real alert is
// skipped and says why; quiet hours that would hold the real one are said in it.
func TestTrapTestAlertTakesThePathOfTheRealOne(t *testing.T) {
	e := newEnv(t)
	e.plain()
	e.telegram(notify.Critical)
	e.slack(notify.Low)
	trap := notify.TrapHit{ID: "hit-1", Kind: "service", Service: "ssh", SrcIP: "192.0.2.2", Label: "SSH", Decoy: "FILES-SRV-02"}
	got, err := e.svc.SendTrapTest(e.ctx(), trap)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Channel != channel.Slack || !got[0].OK || got[1].Channel != channel.Telegram || !got[1].OK {
		t.Fatalf("deliveries %+v", got)
	}
	tg := e.net.to("api.telegram.org")
	if len(tg) != 1 || !strings.Contains(tg[0].Body, "Test: 192.0.2.2 touched the SSH trap") || !strings.Contains(tg[0].Body, "nobody touched the trap") {
		t.Fatalf("telegram %+v", tg)
	}
	if n := e.count(`SELECT count(*) FROM notify_incident`); n != 0 {
		t.Fatalf("%d incidents opened by a test", n)
	}
	if n := e.count(`SELECT count(*) FROM notify_send`); n != 0 {
		t.Fatalf("%d history rows written by a test", n)
	}
	// A scan alert is High: the critical-only channel would not send the real one, so it skips the test and says so.
	got, err = e.svc.SendTrapTest(e.ctx(), notify.TrapHit{ID: "hit-2", Kind: "scan", SrcIP: "192.0.2.2", Label: "Port scan across 2 decoy IPs", Decoy: "A, B"})
	if err != nil || len(got) != 2 || !got[0].OK || got[1].OK || !got[1].Skipped || !strings.Contains(got[1].Detail, "only sends critical and above") {
		t.Fatalf("scan %+v %v", got, err)
	}
	if n := len(e.net.to("api.telegram.org")); n != 1 {
		t.Fatalf("a skipped channel sent: %d calls", n)
	}
	// a failure is said, not hidden
	e.net.failTelegram(500)
	if got, _ = e.svc.SendTrapTest(e.ctx(), trap); got[1].OK || got[1].Skipped || got[1].Detail == "" {
		t.Fatalf("failed %+v", got)
	}
	// quiet hours that hold critical alerts: the test still goes, and says when the real one would
	e.net.failTelegram(200)
	e.rules(notify.Quiet{Enabled: true, From: "09:00", To: "18:00", AllowCritical: false}, notify.Grouping{Enabled: false, WindowMin: 60})
	if _, err = e.svc.SendTrapTest(e.ctx(), trap); err != nil {
		t.Fatal(err)
	}
	if tg = e.net.to("api.telegram.org"); !strings.Contains(tg[len(tg)-1].Body, "a real alert would wait until 18:00") {
		t.Fatalf("quiet hours not said: %s", tg[len(tg)-1].Body)
	}
	// no channel on: nothing sent, an empty list
	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, MinSeverity: notify.Critical})
	e.save(channel.Slack, notify.ChannelInput{Enabled: false, Fields: map[string]string{"label": "#it-alerts"}, MinSeverity: notify.Low})
	if got, err = e.svc.SendTrapTest(e.ctx(), trap); err != nil || len(got) != 0 {
		t.Fatalf("no channel on: %+v %v", got, err)
	}
}
