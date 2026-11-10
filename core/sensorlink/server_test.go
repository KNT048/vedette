package sensorlink_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
)

const (
	obsBody  = `{"epoch":"0123456789abcdef0123456789abcdef","seq":41,"items":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.10.23","field":"hostname","value":"printer-3f","confidence":0.6,"seen_at":"2026-11-10T08:00:01Z"}]}`
	hbSpan   = `{"version":"1.4.0","interfaces":[{"name":"enp1s0","mac":"aa:bb:cc:00:00:01","link":true,"ipv4":["192.168.10.5/24"]}],"span":{"pps":1200,"other_macs":37,"last_packet_at":null},"drops":{"malformed_dhcp":2},"devices_seen":214}`
	hbActive = `{"version":"1.4.0","nmap":{"present":true,"version":"7.94SVN"}}`
	jobID    = "c0ffee00c0ffee00c0ffee00c0ffee00"
	resBody  = `{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"PHhtbC8+"}`
)

func errCode(t *testing.T, r resp) string {
	t.Helper()
	i := strings.Index(r.body, `"code":"`)
	if i < 0 {
		t.Fatalf("no error code in %q (status %d)", r.body, r.status)
	}
	rest := r.body[i+len(`"code":"`):]
	return rest[:strings.Index(rest, `"`)]
}

func mustCall(t *testing.T, p *peer, base, method, path string, body []byte, hdr map[string]string) resp {
	t.Helper()
	r, err := p.call(t, base, method, path, body, hdr)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return r
}

// D-111 (1): each role has its own routes and they work.
func TestRolesReachTheirRoutes(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass, act := r.good(t), r.goodActive(t)
	for _, c := range []struct {
		name, method, path, body string
		peer                     *peer
		want                     int
	}{
		{"config", "GET", "/sensor/v1/config?wait=0", "", pass, 200},
		{"observations", "POST", "/sensor/v1/observations", obsBody, pass, 200},
		{"heartbeat passive", "POST", "/sensor/v1/heartbeat", hbSpan, pass, 200},
		{"jobs", "GET", "/sensor/v1/jobs?wait=0&running=", "", act, 200},
		{"result", "POST", "/sensor/v1/jobs/" + jobID + "/result", resBody, act, 204},
		{"heartbeat active", "POST", "/sensor/v1/heartbeat", hbActive, act, 200},
	} {
		var b []byte
		if c.body != "" {
			b = []byte(c.body)
		}
		got := mustCall(t, c.peer, r.url(), c.method, c.path, b, nil)
		if got.status != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, got.status, c.want, got.body)
		}
	}
	// the conditional config: 304 with the ETag when the sensor has the current one
	got := mustCall(t, pass, r.url(), "GET", "/sensor/v1/config?wait=0", nil, map[string]string{"If-None-Match": `"e1"`})
	if got.status != 304 || got.hdr.Get("ETag") != `"e1"` {
		t.Errorf("conditional config: %d %v", got.status, got.hdr)
	}
	// the reply never has a null where a list belongs
	hb := mustCall(t, act, r.url(), "GET", "/sensor/v1/jobs?wait=0", nil, nil)
	if !strings.Contains(hb.body, `"jobs":[]`) || !strings.Contains(hb.body, `"cancel":[]`) {
		t.Errorf("empty jobs reply = %s", hb.body)
	}
}

// D-111 (1): a route of the other role, an unknown path and a wrong method are all 403 forbidden_route, and the body is not
// read first: a 12 MiB body for a route that exists for the other role is 403, not 413, and the backend is never called.
func TestForbiddenRouteBeforeTheBody(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass, act := r.good(t), r.goodActive(t)
	huge := bytes.Repeat([]byte("x"), 12<<20)
	for _, c := range []struct {
		name, method, path string
		peer               *peer
		body               []byte
	}{
		{"passive calls jobs", "GET", "/sensor/v1/jobs", pass, nil},
		{"passive posts a result with a huge body", "POST", "/sensor/v1/jobs/" + jobID + "/result", pass, huge},
		{"active calls config", "GET", "/sensor/v1/config", act, nil},
		{"active posts observations with a huge body", "POST", "/sensor/v1/observations", act, huge},
		{"unknown path", "GET", "/sensor/v1/nothing", pass, nil},
		{"outside the prefix", "GET", "/healthz", pass, nil},
		{"trailing slash", "GET", "/sensor/v1/config/", pass, nil},
		{"wrong method", "GET", "/sensor/v1/observations", pass, nil},
		{"wrong method 2", "POST", "/sensor/v1/config", pass, []byte("{}")},
		{"result without an id", "POST", "/sensor/v1/jobs//result", act, []byte("{}")},
		{"result with a nested id", "POST", "/sensor/v1/jobs/a/b/result", act, []byte("{}")},
	} {
		got := mustCall(t, c.peer, r.url(), c.method, c.path, c.body, nil)
		if got.status != 403 || errCode(t, got) != "forbidden_route" {
			t.Errorf("%s: %d %s, want 403 forbidden_route", c.name, got.status, got.body)
		}
	}
	if calls := r.be.Calls(); len(calls) != 0 {
		t.Errorf("the backend was called: %v", calls)
	}
}

// D-109 (3): no X-Vedette-Proto, or another one, is 426; it is checked before the route.
func TestProtoHeader(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	p := r.good(t)
	for _, v := range []string{"", "0", "2", "1.0", "11"} {
		hdr := map[string]string{sensorlink.ProtoHeader: v}
		if v == "" {
			hdr[sensorlink.ProtoHeader] = "" // removes it
		}
		got := mustCall(t, p, r.url(), "GET", "/sensor/v1/config?wait=0", nil, hdr)
		if got.status != 426 || errCode(t, got) != "proto_unsupported" {
			t.Errorf("proto %q: %d %s, want 426", v, got.status, got.body)
		}
	}
	got := mustCall(t, p, r.url(), "GET", "/sensor/v1/jobs", nil, map[string]string{sensorlink.ProtoHeader: "2"})
	if got.status != 426 {
		t.Errorf("a forbidden route with a wrong proto = %d, want 426 first (sensor-protocol section 7 order)", got.status)
	}
}

// D-109 (3), D-112 (1), spec section 9: every body has a cap that is enforced before decoding, whether the length is declared or
// streamed in chunks.
func TestBodyCaps(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass, act := r.good(t), r.goodActive(t)
	pad := func(n int) []byte { return bytes.Repeat([]byte(" "), n) }
	big := func(prefix string, n int) []byte { return append([]byte(prefix), pad(n)...) }
	for _, c := range []struct {
		name, path string
		peer       *peer
		body       []byte
	}{
		{"observations 1 MiB + 1", "/sensor/v1/observations", pass, big(obsBody, 1<<20-len(obsBody)+1)},
		{"heartbeat 64 KiB + 1", "/sensor/v1/heartbeat", pass, big(hbSpan, 64<<10-len(hbSpan)+1)},
		{"result 11 MiB + 1", "/sensor/v1/jobs/" + jobID + "/result", act, big(resBody, 11<<20-len(resBody)+1)},
	} {
		got := mustCall(t, c.peer, r.url(), "POST", c.path, c.body, nil)
		if got.status != 413 || errCode(t, got) != "payload_too_large" {
			t.Errorf("%s: %d %.80s, want 413", c.name, got.status, got.body)
		}
	}
	// A body without a Content-Length (chunked) is cut at the cap as well.
	req, _ := http.NewRequestWithContext(t.Context(), "POST", r.url()+"/sensor/v1/observations", bytes.NewReader(big(obsBody, 1<<20)))
	req.ContentLength = -1
	req.Header.Set(sensorlink.ProtoHeader, "1")
	req.Header.Set("Content-Type", "application/json")
	res, err := pass.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 413 {
		t.Errorf("chunked 1 MiB + : %d, want 413", res.StatusCode)
	}
	// The cap is not a limit on valid bodies: a result at the XML cap goes through, one byte over is 413.
	xml := bytes.Repeat([]byte("a"), sensorlink.MaxResultXML)
	mk := func(x []byte) []byte {
		return []byte(`{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"` + base64.StdEncoding.EncodeToString(x) + `"}`)
	}
	if got := mustCall(t, act, r.url(), "POST", "/sensor/v1/jobs/"+jobID+"/result", mk(xml), nil); got.status != 204 {
		t.Errorf("result with 8 MiB of XML: %d %.80s, want 204", got.status, got.body)
	}
	if got := mustCall(t, act, r.url(), "POST", "/sensor/v1/jobs/"+jobID+"/result", mk(append(xml, 'a')), nil); got.status != 413 || errCode(t, got) != "payload_too_large" {
		t.Errorf("result with 8 MiB + 1 of XML: %d %.80s, want 413", got.status, got.body)
	}
}

// D-109 (3), spec section 3: strict decoding and the other things that make a request a 400.
func TestStrictDecodingAnd400(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass, act := r.good(t), r.goodActive(t)
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	item := `{"field":"hostname","value":"x","confidence":0.5,"seen_at":"2026-11-10T08:00:01Z","ip":"192.168.10.2"}`
	cases := []struct {
		name, path string
		peer       *peer
		body       string
		hdr        map[string]string
	}{
		{"unknown field", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"items":[` + item + `],"extra":1}`, nil},
		{"unknown field in an item (source)", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"items":[{"source":"manual","field":"hostname","value":"x","confidence":0.5,"seen_at":"2026-11-10T08:00:01Z","ip":"192.168.10.2"}]}`, nil},
		{"repeated key", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"seq":2,"items":[` + item + `]}`, nil},
		{"repeated key after case folding", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"SEQ":2,"items":[` + item + `]}`, nil},
		{"nesting over 32", "/sensor/v1/heartbeat", pass, deep, nil},
		{"trailing data", "/sensor/v1/heartbeat", act, hbActive + ` {}`, nil},
		{"not JSON", "/sensor/v1/heartbeat", act, `<xml/>`, nil},
		{"array at the top", "/sensor/v1/observations", pass, `[]`, nil},
		{"epoch not hex", "/sensor/v1/observations", pass, `{"epoch":"zz","seq":1,"items":[` + item + `]}`, nil},
		{"seq 0", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":0,"items":[` + item + `]}`, nil},
		{"seq over 2^53-1", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":9007199254740992,"items":[` + item + `]}`, nil},
		{"no items", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"items":[]}`, nil},
		{"501 items", "/sensor/v1/observations", pass, `{"epoch":"0123456789abcdef0123456789abcdef","seq":1,"items":[` + strings.Repeat(item+",", 500) + item + `]}`, nil},
		{"passive heartbeat with the active body", "/sensor/v1/heartbeat", pass, hbActive, nil},
		{"active heartbeat with the passive body", "/sensor/v1/heartbeat", act, hbSpan, nil},
		{"33 interfaces", "/sensor/v1/heartbeat", pass, `{"version":"1.4.0","interfaces":[` + strings.TrimSuffix(strings.Repeat(`{"name":"e","mac":"aa:bb:cc:00:00:01","link":true,"ipv4":[]},`, 33), ",") + `],"span":{"pps":0,"other_macs":0,"last_packet_at":null},"drops":{},"devices_seen":0}`, nil},
		{"negative counter", "/sensor/v1/heartbeat", pass, strings.Replace(hbSpan, `"devices_seen":214`, `"devices_seen":-1`, 1), nil},
		{"drops key with a space", "/sensor/v1/heartbeat", pass, strings.Replace(hbSpan, `malformed_dhcp`, `malformed dhcp`, 1), nil},
		{"drops key outside the closed set", "/sensor/v1/heartbeat", pass, strings.Replace(hbSpan, `malformed_dhcp`, `something_else`, 1), nil},
		{"result with an unknown status", "/sensor/v1/jobs/" + jobID + "/result", act, strings.Replace(resBody, `"done"`, `"great"`, 1), nil},
		{"result xml on a failed job", "/sensor/v1/jobs/" + jobID + "/result", act, strings.Replace(resBody, `"done"`, `"failed"`, 1), nil},
		{"result with bad base64", "/sensor/v1/jobs/" + jobID + "/result", act, strings.Replace(resBody, `PHhtbC8+`, `!!!`, 1), nil},
		{"result id not hex", "/sensor/v1/jobs/NOTHEX/result", act, resBody, nil},
		{"exit code 256", "/sensor/v1/jobs/" + jobID + "/result", act, strings.Replace(resBody, `"exit_code":0`, `"exit_code":256`, 1), nil},
		{"Content-Encoding gzip", "/sensor/v1/heartbeat", act, hbActive, map[string]string{"Content-Encoding": "gzip"}},
		{"Content-Type text", "/sensor/v1/heartbeat", act, hbActive, map[string]string{"Content-Type": "text/plain"}},
		{"Content-Type missing", "/sensor/v1/heartbeat", act, hbActive, map[string]string{"Content-Type": ""}},
	}
	for _, c := range cases {
		got := mustCall(t, c.peer, r.url(), "POST", c.path, []byte(c.body), c.hdr)
		if got.status != 400 || errCode(t, got) != "invalid_request" {
			t.Errorf("%s: %d %.100s, want 400 invalid_request", c.name, got.status, got.body)
		}
	}
	for _, c := range []struct{ name, path string }{ // each call is on its own tick of the rate limit
		{"unknown query parameter", "/sensor/v1/config?wait=0&x=1"},
		{"wait over 30", "/sensor/v1/config?wait=31"},
		{"wait negative", "/sensor/v1/config?wait=-1"},
		{"wait not a number", "/sensor/v1/config?wait=soon"},
		{"wait twice", "/sensor/v1/config?wait=1&wait=2"},
		{"running on config", "/sensor/v1/config?running=" + jobID},
	} {
		r.clk.Advance(200 * time.Millisecond)
		got := mustCall(t, pass, r.url(), "GET", c.path, nil, nil)
		if got.status != 400 {
			t.Errorf("%s: %d, want 400", c.name, got.status)
		}
	}
	for _, c := range []struct{ name, path string }{
		{"running is not an id", "/sensor/v1/jobs?running=../../x"},
		{"running twice", "/sensor/v1/jobs?running=" + jobID + "&running=" + jobID},
	} {
		if got := mustCall(t, act, r.url(), "GET", c.path, nil, nil); got.status != 400 {
			t.Errorf("%s: %d, want 400", c.name, got.status)
		}
	}
	r.clk.Advance(time.Second)
	if got := mustCall(t, pass, r.url(), "GET", "/sensor/v1/config?wait=0", nil, map[string]string{"If-None-Match": "W/not an etag"}); got.status != 400 {
		t.Errorf("bad If-None-Match: %d, want 400", got.status)
	}
	if calls := r.be.Calls(); len(calls) != 0 {
		t.Errorf("a 400 reached the backend: %v", calls)
	}
}

// D-112 (4): 429 with Retry-After at 10 requests a second, burst 20, per role.
func TestRateLimit(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	pass, act := r.good(t), r.goodActive(t)
	ok, limited := 0, 0
	var retry string
	for range 30 {
		got := mustCall(t, pass, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil)
		switch got.status {
		case 200:
			ok++
		case 429:
			limited++
			retry = got.hdr.Get("Retry-After")
			if errCode(t, got) != "rate_limited" {
				t.Errorf("429 code = %s", errCode(t, got))
			}
		default:
			t.Fatalf("status %d", got.status)
		}
	}
	if ok != 20 || limited != 10 {
		t.Errorf("30 quick requests: %d ok, %d limited; want 20 and 10", ok, limited)
	}
	if retry != "1" {
		t.Errorf("Retry-After = %q, want 1", retry)
	}
	// the other role has its own bucket
	if got := mustCall(t, act, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbActive), nil); got.status != 200 {
		t.Errorf("the active role was limited by the passive one: %d", got.status)
	}
	// tokens come back with time: 0.5 s is five requests
	r.clk.Advance(500 * time.Millisecond)
	ok = 0
	for range 8 {
		if mustCall(t, pass, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil).status == 200 {
			ok++
		}
	}
	if ok != 5 {
		t.Errorf("after 0.5 s: %d requests passed, want 5", ok)
	}
}

// D-111 (1): one long poll per role; the second is 409 poll_in_progress. The roles do not share the gate, and the gate opens
// again when the poll ends.
func TestOneLongPollPerRole(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	inside, release := make(chan struct{}, 4), make(chan struct{})
	r.be.config = func(ctx context.Context, _ time.Duration, _ string) (sensorlink.ConfigReply, error) {
		inside <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return sensorlink.ConfigReply{ETag: `"e2"`}, nil
	}
	r.be.jobs = func(ctx context.Context, _ time.Duration, _ string) (sensorlink.JobsReply, error) {
		inside <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return sensorlink.JobsReply{Instance: instanceID}, nil
	}
	pass, act := r.good(t), r.goodActive(t)
	first := make(chan resp, 1)
	go func() {
		got, _ := pass.call(t, r.url(), "GET", "/sensor/v1/config?wait=25", nil, nil)
		first <- got
	}()
	<-inside
	second := mustCall(t, r.peer(t, r.ca.leaf(t, leafOpts{serial: 101})), r.url(), "GET", "/sensor/v1/config?wait=0", nil, nil)
	if second.status != 409 || errCode(t, second) != "poll_in_progress" {
		t.Errorf("second long poll: %d %s, want 409 poll_in_progress", second.status, second.body)
	}
	// the active role may poll while the passive one does
	actFirst := make(chan resp, 1)
	go func() {
		got, _ := act.call(t, r.url(), "GET", "/sensor/v1/jobs?wait=25", nil, nil)
		actFirst <- got
	}()
	<-inside
	// other routes of the role are not blocked by its poll
	if got := mustCall(t, pass, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil); got.status != 200 {
		t.Errorf("heartbeat during a poll: %d", got.status)
	}
	close(release)
	for _, ch := range []chan resp{first, actFirst} {
		if got := <-ch; got.status != 200 {
			t.Errorf("held poll ended with %d %s", got.status, got.body)
		}
	}
	r.be.config = nil
	if got := mustCall(t, pass, r.url(), "GET", "/sensor/v1/config?wait=0", nil, nil); got.status != 200 {
		t.Errorf("a poll after the first ended: %d, want 200", got.status)
	}
}

// A poll whose client goes away frees the gate: goroutines of long polls do not pile up.
func TestLongPollEndsWhenTheClientLeaves(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	inside, gone := make(chan struct{}, 1), make(chan struct{}, 1)
	r.be.config = func(ctx context.Context, _ time.Duration, _ string) (sensorlink.ConfigReply, error) {
		inside <- struct{}{}
		<-ctx.Done()
		gone <- struct{}{}
		return sensorlink.ConfigReply{}, ctx.Err()
	}
	p := r.good(t)
	ctx, cancel := context.WithCancel(t.Context())
	req, _ := http.NewRequestWithContext(ctx, "GET", r.url()+"/sensor/v1/config?wait=30", nil)
	req.Header.Set(sensorlink.ProtoHeader, "1")
	done := make(chan struct{})
	go func() {
		if res, err := p.c.Do(req); err == nil {
			_ = res.Body.Close()
		}
		close(done)
	}()
	<-inside
	cancel()
	select {
	case <-gone:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler still waits after its client left")
	}
	<-done
}

// D-111 (4): a role whose module is off gets 409 module_off on every route, before its body is read; the other role is not
// affected.
func TestModuleOff(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{moduleOn: func(role sensorlink.Role) bool { return role != sensorlink.Passive }})
	pass, act := r.good(t), r.goodActive(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/sensor/v1/config?wait=0", ""},
		{"POST", "/sensor/v1/observations", obsBody},
		{"POST", "/sensor/v1/heartbeat", hbSpan},
		{"POST", "/sensor/v1/observations", "not even json"},
	} {
		var b []byte
		if c.body != "" {
			b = []byte(c.body)
		}
		got := mustCall(t, pass, r.url(), c.method, c.path, b, nil)
		if got.status != 409 || errCode(t, got) != "module_off" {
			t.Errorf("%s %s: %d %s, want 409 module_off", c.method, c.path, got.status, got.body)
		}
	}
	if got := mustCall(t, act, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbActive), nil); got.status != 200 {
		t.Errorf("active role with its module on: %d", got.status)
	}
	for _, c := range r.be.Calls() {
		if strings.Contains(c, "passive") || c == "config" || c == "observations" {
			t.Errorf("the backend saw a call of the role that is off: %v", r.be.Calls())
		}
	}
}

// Spec section 7: the codes a backend may use, and nothing internal leaks.
func TestBackendErrorsBecomeTheTable(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	act := r.goodActive(t)
	for _, c := range []struct {
		name   string
		err    error
		status int
		code   string
		retry  string
	}{
		{"unknown job", sensorlink.NewError(sensorlink.CodeUnknownJob), 404, "unknown_job", ""},
		{"store busy", sensorlink.StoreBusy(2500 * time.Millisecond), 503, "store_busy", "3"},
		{"store busy without a time", sensorlink.StoreBusy(0), 503, "store_busy", "1"},
		{"a plain error", errors.New("sql: database is locked at /var/lib/vedette/secret.db"), 500, "internal", ""},
		{"an Error outside the table", &sensorlink.Error{Status: 418, Code: "teapot"}, 500, "internal", ""},
		{"a code with the wrong status", &sensorlink.Error{Status: 200, Code: "unknown_job"}, 500, "internal", ""},
	} {
		r.be.result = func(context.Context, string, *sensorlink.JobResult) error { return c.err }
		got := mustCall(t, act, r.url(), "POST", "/sensor/v1/jobs/"+jobID+"/result", []byte(resBody), nil)
		if got.status != c.status || errCode(t, got) != c.code || got.hdr.Get("Retry-After") != c.retry {
			t.Errorf("%s: %d %s retry=%q, want %d %s retry=%q", c.name, got.status, got.body, got.hdr.Get("Retry-After"), c.status, c.code, c.retry)
		}
		for _, leak := range []string{"sql", "secret.db", "teapot", "/var"} {
			if strings.Contains(got.body, leak) {
				t.Errorf("%s: the body leaks %q: %s", c.name, leak, got.body)
			}
		}
	}
}

// A reply over the cap of its route is a bug of the backend, not something to send.
func TestReplyCaps(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	r.be.config = func(context.Context, time.Duration, string) (sensorlink.ConfigReply, error) {
		return sensorlink.ConfigReply{Config: sensorlink.Config{Filters: []sensorlink.Filter{{Type: "host", Value: strings.Repeat("a", sensorlink.MaxConfigReply)}}}}, nil
	}
	if got := mustCall(t, r.good(t), r.url(), "GET", "/sensor/v1/config?wait=0", nil, nil); got.status != 500 {
		t.Errorf("an oversize config: %d, want 500", got.status)
	}
}

// D-109 (2): TLS 1.3 only, and the timeouts of the production http.Server.
func TestProductionServerSettings(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{})
	hs := r.srv.HTTPServer("127.0.0.1:8444")
	if hs.ReadHeaderTimeout != 5*time.Second || hs.WriteTimeout != 35*time.Second || hs.TLSConfig == nil || hs.IdleTimeout == 0 {
		t.Errorf("http.Server = %+v", hs)
	}
	cfg := hs.TLSConfig
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.VerifyConnection == nil || cfg.GetCertificate == nil {
		t.Errorf("tls.Config = %+v", cfg)
	}
	// a TLS 1.2 client is refused
	cert := r.ca.leaf(t, leafOpts{serial: 100})
	old := &tls.Config{MaxVersion: tls.VersionTLS12, RootCAs: r.ca.pool, Certificates: []tls.Certificate{cert}} //nolint:gosec // a deliberately old client
	c12, err := (&tls.Dialer{Config: old}).DialContext(t.Context(), "tcp", r.addr())
	if err == nil {
		_ = c12.Close()
		t.Error("a TLS 1.2 handshake succeeded")
	}
}

// Slowloris: a connection that sends its headers or its body slowly is cut, and the backend is never reached.
func TestSlowlorisTimeouts(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{hdrTimeout: 300 * time.Millisecond, bodyTimeout: 300 * time.Millisecond})
	cert := r.ca.leaf(t, leafOpts{serial: 100})
	dial := func() net.Conn {
		c, err := (&tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.ca.pool, Certificates: []tls.Certificate{cert}, Time: r.clk.Now}}).DialContext(t.Context(), "tcp", r.addr())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	readsUntilClosed := func(c net.Conn, within time.Duration) (string, bool) {
		_ = c.SetReadDeadline(time.Now().Add(within))
		var sb strings.Builder
		buf := make([]byte, 512)
		for {
			n, err := c.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				var ne net.Error
				return sb.String(), !errors.As(err, &ne) || !ne.Timeout() // closed by the server, not by our deadline
			}
		}
	}
	t.Run("headers", func(t *testing.T) {
		c := dial()
		_, _ = c.Write([]byte("GET /sensor/v1/config HTTP/1.1\r\nHost: x\r\nX-Vedette-Proto: 1\r\n")) // never finished
		if _, closed := readsUntilClosed(c, 3*time.Second); !closed {
			t.Error("a request with unfinished headers was not cut")
		}
	})
	t.Run("body", func(t *testing.T) {
		c := dial()
		_, _ = c.Write([]byte("POST /sensor/v1/observations HTTP/1.1\r\nHost: x\r\nX-Vedette-Proto: 1\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"epoch\":"))
		out, closed := readsUntilClosed(c, 3*time.Second)
		if !closed {
			t.Error("a body that stalls was not cut")
		}
		if strings.Contains(out, "200 OK") {
			t.Errorf("a stalled body got a 200: %s", out)
		}
	})
	if calls := r.be.Calls(); len(calls) != 0 {
		t.Errorf("a slow request reached the backend: %v", calls)
	}
}

// h2 carries the same checks: the serial is looked at per request on an HTTP/2 connection too.
func TestHTTP2(t *testing.T) {
	t.Parallel()
	r := newRig(t, rigOpt{http2: true})
	cert := r.ca.leaf(t, leafOpts{serial: 100})
	p := r.peer(t, cert)
	p.tr.ForceAttemptHTTP2 = true
	got := mustCall(t, p, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil)
	if got.status != 200 || got.tls == nil || got.tls.NegotiatedProtocol != "h2" {
		t.Fatalf("h2 request: %d proto %v", got.status, got.tls)
	}
	r.id.allow(sensorlink.Passive, 101) // 100 retired while the h2 connection is up
	got = mustCall(t, p, r.url(), "POST", "/sensor/v1/heartbeat", []byte(hbSpan), nil)
	if got.status != 403 || errCode(t, got) != "cert_retired" {
		t.Errorf("retired serial on a live h2 connection: %d %s", got.status, got.body)
	}
}
