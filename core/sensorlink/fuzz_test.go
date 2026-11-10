package sensorlink

import (
	"context"
	"net/http"
	"testing"
)

// D-116 (4): every decoder of a request is fuzzed. The property is the same for all: no panic, and whatever is accepted is
// within the bounds the spec gives.

func FuzzDecodeObservations(f *testing.F) {
	f.Add([]byte(`{"epoch":"0123456789abcdef0123456789abcdef","seq":41,"items":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.168.10.23","field":"hostname","value":"printer-3f","confidence":0.6,"seen_at":"2026-11-10T08:00:01Z"}]}`))
	f.Add([]byte(`{"epoch":"0123456789abcdef0123456789abcdef","seq":9007199254740991,"items":[{}]}`))
	f.Add([]byte(`{"seq":1,"seq":2}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeObservations(b)
		if err != nil {
			return
		}
		if !epochRE.MatchString(r.Epoch) || r.Seq < 1 || r.Seq > maxSeq || len(r.Items) < 1 || len(r.Items) > MaxItems {
			t.Fatalf("accepted %+v", r)
		}
	})
}

func FuzzDecodePassiveHeartbeat(f *testing.F) {
	f.Add([]byte(`{"version":"1.4.0","interfaces":[{"name":"enp1s0","mac":"aa:bb:cc:00:00:01","link":true,"ipv4":["192.168.10.5/24"]}],"span":{"pps":1200,"other_macs":37,"last_packet_at":"2026-11-10T08:00:29Z"},"drops":{"malformed_dhcp":2},"devices_seen":214}`))
	f.Add([]byte(`{"version":"1.0.0","interfaces":[],"span":{"pps":0,"other_macs":0,"last_packet_at":null},"drops":{},"devices_seen":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := decodePassiveHeartbeat(b)
		if err != nil {
			return
		}
		if len(h.Interfaces) > 32 || len(h.Drops) > 64 || h.DevicesSeen < 0 || h.Span.PPS < 0 || h.Span.OtherMACs < 0 || !versionRE.MatchString(h.Version) {
			t.Fatalf("accepted %+v", h)
		}
		for _, i := range h.Interfaces {
			if len(i.IPv4) > 8 || !macRE.MatchString(i.MAC) || !ifaceRE.MatchString(i.Name) {
				t.Fatalf("accepted interface %+v", i)
			}
		}
		for k, v := range h.Drops {
			if v < 0 || !dropKeyRE.MatchString(k) {
				t.Fatalf("accepted drop %q=%d", k, v)
			}
		}
	})
}

func FuzzDecodeActiveHeartbeat(f *testing.F) {
	f.Add([]byte(`{"version":"1.4.0","nmap":{"present":true,"version":"7.94SVN"}}`))
	f.Add([]byte(`{"version":"1.4.0","nmap":{"present":false,"version":""}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := decodeActiveHeartbeat(b)
		if err != nil {
			return
		}
		if !versionRE.MatchString(h.Version) || len(h.Nmap.Version) > 32 {
			t.Fatalf("accepted %+v", h)
		}
	})
}

func FuzzDecodeJobResult(f *testing.F) {
	f.Add([]byte(`{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"PHhtbC8+"}`))
	f.Add([]byte(`{"status":"refused","reason":"invalid_job","exit_code":-1,"truncated":false,"xml_b64":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := decodeJobResult(b)
		if err != nil {
			return
		}
		if !resultStat[r.Status] || !resultCode[r.Reason] || r.ExitCode < -1 || r.ExitCode > 255 || len(r.XML()) > MaxResultXML {
			t.Fatalf("accepted %+v", r)
		}
		if r.XMLB64 == "" && r.XML() != nil || r.XMLB64 != "" && r.Status != "done" {
			t.Fatalf("xml rules broken: %+v", r)
		}
	})
}

// FuzzQuery covers the query string and the conditional header, the only request input that is not a body.
func FuzzQuery(f *testing.F) {
	f.Add("wait=25", `"e1"`, true)
	f.Add("wait=0&running=c0ffee00c0ffee00c0ffee00c0ffee00", "", false)
	f.Add("wait=%zz&x", "W/x", true)
	f.Fuzz(func(t *testing.T, raw, inm string, config bool) {
		r := newReq()
		r.URL.RawQuery = raw
		if inm != "" {
			r.Header["If-None-Match"] = []string{inm}
		}
		id := rJobs
		if config {
			id = rConfig
		}
		q, err := queryOf(r, id)
		if err != nil {
			return
		}
		if q.wait < 0 || q.wait > MaxWait || q.running != "" && !jobIDRE.MatchString(q.running) || q.etag != "" && !etagRE.MatchString(q.etag) {
			t.Fatalf("accepted %+v", q)
		}
	})
}

// FuzzParseBundle is the decoder of the file a sensor reads from its volume, which another container's attacker may reach.
func FuzzParseBundle(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		if bu, err := ParseBundle(b); err == nil {
			if _, e := ClientRole(bu.Leaf); e != nil || !bu.CA.IsCA {
				t.Fatalf("accepted a bundle that is not a sensor bundle")
			}
		}
	})
}

func newReq() *http.Request {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/sensor/v1/x", nil)
	return r
}
