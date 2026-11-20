package notify_test

import (
	"testing"

	"github.com/knt048/vedette/core/events"
	"github.com/knt048/vedette/modules/notify"
	"github.com/knt048/vedette/modules/notify/channel"
)

func intrusion(severity, title, link string) map[string]any {
	return map[string]any{"source": "198.51.100.9", "target": "cve:CVE-2021-44228", "title": title, "what": "w", "action": "a", "severity": severity,
		"link": link, "devices": []map[string]string{{"id": "a-nas", "name": "nas-01"}}}
}

// pubIntrusion publishes ids.alert.detected as the ids module does.
func (e *env) pubIntrusion(data any) {
	e.t.Helper()
	if err := e.bus.Publish(e.ctx(), events.Event{Name: notify.EventIntrusion, Data: data}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) intrusionIncident() notify.Incident {
	e.t.Helper()
	l, err := e.svc.Incidents(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []notify.Incident
	for _, i := range l {
		if i.Kind == notify.IncidentIntrusion {
			out = append(out, i)
		}
	}
	if len(out) != 1 {
		e.t.Fatalf("%d intrusion incidents, want 1: %+v", len(out), out)
	}
	return out[0]
}

// INV-26: a repeat of an intrusion incident at a higher severity raises it (severity, title, devices) and sends one notice of the
// raise; its send is filed under the incident. A repeat at the same severity only counts.
func TestIntrusionRepeatRaisesTheIncidentAndItsSendIsTheIncidents(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.telegram(notify.Low)
	e.plain()
	defer e.svc.Subscribe(e.bus)()
	e.pubIntrusion(intrusion("medium", "198.51.100.9 fired Log4j at app-01", "/detection/alerts/ida-1"))
	e.pubIntrusion(intrusion("medium", "198.51.100.9 fired Log4j at app-01", "/detection/alerts/ida-1"))
	e.flush()
	e.pubIntrusion(intrusion("critical", "198.51.100.9 fired Log4j at nas-01", "/detection/alerts/ida-2"))
	e.flush()
	i := e.intrusionIncident()
	if i.Severity != notify.Critical || i.Title != "198.51.100.9 fired Log4j at nas-01" || i.Count != 3 || i.Link != "/detection/alerts/ida-1" {
		t.Fatalf("incident %+v", i)
	}
	if n := e.count(`SELECT count(*) FROM notify_send WHERE kind = 'incident' AND ref_id = ? AND ok = 1`, i.ID); n != 2 {
		t.Fatalf("%d sends filed under the incident, want 2 (the first notice and the raise)", n)
	}
	if n := e.count(`SELECT count(*) FROM notify_send WHERE ref_id LIKE '%-raised-%'`); n != 0 {
		t.Fatal("a send was filed under the raise's notice id")
	}
	d, err := e.svc.IncidentDetail(e.ctx(), i.ID)
	if err != nil || len(d.Incident.Sends) != 2 {
		t.Fatalf("detail sends %v %+v", err, d.Incident.Sends)
	}
	// raised once to critical: the same level again sends nothing more
	e.pubIntrusion(intrusion("critical", "198.51.100.9 fired Log4j at nas-01", "/detection/alerts/ida-2"))
	e.flush()
	if n := e.count(`SELECT count(*) FROM notify_send WHERE ref_id = ?`, i.ID); n != 2 {
		t.Fatalf("%d sends after a repeat at the same level", n)
	}
}

// The hourly summary of the ids module links to the Intrusion detection page itself; any other link outside /detection is refused.
func TestIntrusionLinksStayUnderDetection(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	defer e.svc.Subscribe(e.bus)()
	e.pubIntrusion(map[string]any{"source": "ids", "target": "more intrusion alerts 1", "title": "At least 3 more intrusion alerts this hour",
		"what": "w", "action": "a", "severity": "medium", "link": "/detection", "devices": []map[string]string{}})
	e.pubIntrusion(intrusion("high", "elsewhere", "/settings"))
	i := e.intrusionIncident()
	if i.Link != "/detection" || i.Title != "At least 3 more intrusion alerts this hour" {
		t.Fatalf("summary incident %+v", i)
	}
}

// INV-24 with a raise: the raise's notice waiting in the queue is the incident's ("queued"), and when the queue drops it (the channel
// was turned off) the incident says so.
func TestARaisedIntrusionNoticeIsTheIncidentsInNotSent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.telegram(notify.Critical) // the medium incident is below the channel's minimum; the raise to critical is not
	e.plain()
	defer e.svc.Subscribe(e.bus)()
	e.pubIntrusion(intrusion("medium", "198.51.100.9 fired Log4j at app-01", "/detection/alerts/ida-1"))
	if ns := e.intrusionIncident().NotSent; ns == nil || ns.Reason != notify.UnsentBelowMin {
		t.Fatalf("before the raise: %+v", ns)
	}
	e.pubIntrusion(intrusion("critical", "198.51.100.9 fired Log4j at nas-01", "/detection/alerts/ida-2"))
	if ns := e.intrusionIncident().NotSent; ns == nil || ns.Reason != notify.UnsentQueued {
		t.Fatalf("raise queued: %+v", ns)
	}
	e.save(channel.Telegram, notify.ChannelInput{Enabled: false, Fields: map[string]string{"chat_id": "-1002145678901"}, Secret: tgToken, MinSeverity: notify.Critical})
	e.flush()
	if ns := e.intrusionIncident().NotSent; ns == nil || ns.Reason != notify.UnsentChannelOff || ns.Channel != channel.Telegram {
		t.Fatalf("raise dropped with the channel off: %+v", ns)
	}
}
