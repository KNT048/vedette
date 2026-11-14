package sensorlink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/jsonstrict"
)

// Protocol 2 (D-125): Job.kind, the nuclei job and result, the nuclei heartbeat, two running ids.

const nucleiJobJSON = `{"id":"c0ffee00c0ffee00c0ffee00c0ffee00","kind":"nuclei","timeout_s":600,"pack":{"version":"2026.11.10","sha256":"` +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"},"templates":["CVE-2024-1","CVE-2024-2"],` +
	`"targets":[{"host":"192.168.10.20","port":8080,"scheme":"http"},{"host":"192.168.10.21","port":22,"scheme":""}],"rate":5,"max_host_errors":3}`

func decodeReply(t *testing.T, jobs ...string) (JobsReply, error) {
	t.Helper()
	var rep JobsReply
	err := jsonstrict.Decode([]byte(`{"instance":"`+strings.Repeat("a", 32)+`","jobs":[`+strings.Join(jobs, ",")+`],"cancel":[]}`), &rep)
	return rep, err
}

func TestNucleiJobRoundTripsOnTheWire(t *testing.T) {
	t.Parallel()
	rep, err := decodeReply(t, nucleiJobJSON)
	if err != nil {
		t.Fatal(err)
	}
	j := rep.Jobs[0]
	if j.Kind != KindNuclei || j.Nuclei == nil || len(j.Nuclei.Templates) != 2 || j.Nuclei.Targets[1].Port != 22 || j.Nuclei.MaxHostErrors != 3 || j.TimeoutS != 600 || j.Nuclei.Pack.Version != "2026.11.10" {
		t.Fatalf("decoded %+v %+v", j, j.Nuclei)
	}
	out, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	var back Job
	if err := json.Unmarshal(out, &back); err != nil || back.Nuclei == nil || back.Nuclei.Targets[0].Host != "192.168.10.20" || back.Nuclei.Rate != 5 {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}

func TestOldKindlessJobIsNmap(t *testing.T) {
	t.Parallel()
	rep, err := decodeReply(t, `{"id":"c0ffee00c0ffee00c0ffee00c0ffee00","shape":"normal","rate":100,"targets":["192.168.10.20"],"timeout_s":60}`)
	if err != nil {
		t.Fatal(err)
	}
	if j := rep.Jobs[0]; j.Kind != "" || j.Shape != "normal" || j.Nuclei != nil || len(j.Targets) != 1 {
		t.Fatalf("decoded %+v", j)
	}
}

func TestJobStrictness(t *testing.T) {
	t.Parallel()
	id := `"id":"c0ffee00c0ffee00c0ffee00c0ffee00"`
	for name, job := range map[string]string{
		"nuclei with an unknown field":   strings.Replace(nucleiJobJSON, `"rate":5`, `"rate":5,"flags":"-x"`, 1),
		"nuclei with nmap's shape":       strings.Replace(nucleiJobJSON, `"rate":5`, `"rate":5,"shape":"sweep"`, 1),
		"nmap with a nuclei field":       `{` + id + `,"kind":"nmap","shape":"normal","rate":1,"targets":["192.168.10.1"],"timeout_s":5,"templates":["x"]}`,
		"nmap with an unknown field":     `{` + id + `,"shape":"normal","rate":1,"targets":["192.168.10.1"],"timeout_s":5,"argv":["x"]}`,
		"a repeated key in the target":   strings.Replace(nucleiJobJSON, `"port":8080,`, `"port":8080,"port":1,`, 1),
		"a nuclei target that is a text": strings.Replace(nucleiJobJSON, `{"host":"192.168.10.20","port":8080,"scheme":"http"}`, `"192.168.10.20"`, 1),
	} {
		if _, err := decodeReply(t, job); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An unknown kind is not a decode error: the worker refuses it (invalid_job) and the poll goes on.
func TestUnknownKindDecodesToARefusableJob(t *testing.T) {
	t.Parallel()
	rep, err := decodeReply(t, `{"id":"c0ffee00c0ffee00c0ffee00c0ffee00","kind":"shell","cmd":"id"}`)
	if err != nil {
		t.Fatal(err)
	}
	if j := rep.Jobs[0]; j.Kind != "shell" || j.Nuclei != nil || j.Shape != "" || j.Targets != nil {
		t.Fatalf("decoded %+v", j)
	}
}

func TestNucleiJobWithoutFieldsDoesNotMarshal(t *testing.T) {
	t.Parallel()
	if _, err := json.Marshal(Job{ID: "x", Kind: KindNuclei}); err == nil {
		t.Fatal("marshalled a nuclei job with nothing in it")
	}
}

func TestNucleiResultCaps(t *testing.T) {
	t.Parallel()
	body := func(jsonl string) []byte {
		return []byte(`{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"","jsonl_b64":"` + jsonl + `"}`)
	}
	r, err := decodeJobResult(body(base64.StdEncoding.EncodeToString([]byte("{}\n"))))
	if err != nil || string(r.JSONL()) != "{}\n" || r.XML() != nil {
		t.Fatalf("a small result: %v %+v", err, r)
	}
	atCap := base64.StdEncoding.EncodeToString(make([]byte, MaxResultJSONL))
	if r, err := decodeJobResult(body(atCap)); err != nil || len(r.JSONL()) != MaxResultJSONL {
		t.Fatalf("a result at the cap: %v", err)
	}
	over := base64.StdEncoding.EncodeToString(make([]byte, MaxResultJSONL+1))
	if _, err := decodeJobResult(body(over)); !errors.Is(err, errTooLarge) {
		t.Fatalf("a result over the cap: %v, want errTooLarge", err)
	}
	if _, err := decodeJobResult(body("!!!!")); !errors.Is(err, errInvalid) {
		t.Fatalf("not base64: %v", err)
	}
	both := []byte(`{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"PHhtbC8+","jsonl_b64":"e30K"}`)
	if _, err := decodeJobResult(both); !errors.Is(err, errInvalid) {
		t.Fatalf("both outputs: %v", err)
	}
	failed := []byte(`{"status":"failed","reason":"","exit_code":1,"truncated":false,"xml_b64":"","jsonl_b64":"e30K"}`)
	if _, err := decodeJobResult(failed); !errors.Is(err, errInvalid) {
		t.Fatalf("output on a failed result: %v", err)
	}
	for _, reason := range []string{"nuclei_missing", "pack_mismatch", "pack_invalid"} {
		if _, err := decodeJobResult([]byte(`{"status":"refused","reason":"` + reason + `","exit_code":-1,"truncated":false,"xml_b64":""}`)); err != nil {
			t.Errorf("reason %s: %v", reason, err)
		}
	}
}

func TestNucleiHeartbeat(t *testing.T) {
	t.Parallel()
	sha := strings.Repeat("b", 64)
	hb := func(n string) []byte {
		return []byte(`{"version":"1.0.0","nmap":{"present":true,"version":"7.94SVN"},"nuclei":` + n + `}`)
	}
	ok, err := decodeActiveHeartbeat(hb(`{"present":true,"version":"v3.3.7","pack":{"version":"2026.11.10","sha256":"` + sha + `"}}`))
	if err != nil || !ok.Nuclei.Present || ok.Nuclei.Pack.SHA256 != sha {
		t.Fatalf("a good heartbeat: %v %+v", err, ok)
	}
	if _, err := decodeActiveHeartbeat(hb(`{"present":false,"version":"","pack":{"version":"","sha256":""}}`)); err != nil {
		t.Fatalf("nuclei missing: %v", err)
	}
	for name, n := range map[string]string{
		"a pack with a version and no hash": `{"present":true,"version":"v3","pack":{"version":"2026.11.10","sha256":""}}`,
		"a bad hash":                        `{"present":true,"version":"v3","pack":{"version":"2026.11.10","sha256":"XYZ"}}`,
		"a bad version":                     `{"present":true,"version":"v3 ; rm","pack":{"version":"","sha256":""}}`,
		"an unknown field":                  `{"present":true,"version":"v3","pack":{"version":"","sha256":""},"templates":3}`,
	} {
		if _, err := decodeActiveHeartbeat(hb(n)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunningQuery(t *testing.T) {
	t.Parallel()
	a, b, c, d := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32), strings.Repeat("d", 32)
	for raw, want := range map[string]int{"": 0, "wait=0": 0, "running=" + a: 1, "running=" + a + "," + b: 2, "running=" + a + "," + b + "," + c: 3} {
		q, err := queryOf(newReq2(raw), rJobs)
		if err != nil || len(q.running) != want {
			t.Errorf("%q: %v %v", raw, err, q.running)
		}
	}
	for _, raw := range []string{"running=" + a + "," + b + "," + a, "running=" + a + "," + b + "," + c + "," + d, "running=" + a + "," + a, "running=" + a + ",", "running=,", "running=" + a + ";" + b, "running=" + a[:31]} {
		if _, err := queryOf(newReq2(raw), rJobs); err == nil {
			t.Errorf("%q accepted", raw)
		}
	}
}

func FuzzJobUnmarshal(f *testing.F) {
	f.Add([]byte(nucleiJobJSON))
	f.Add([]byte(snmpJobJSON))
	f.Add([]byte(`{"id":"c0ffee00c0ffee00c0ffee00c0ffee00","shape":"normal","rate":1,"targets":["192.168.10.1"],"timeout_s":5}`))
	f.Add([]byte(`{"id":"x","kind":"shell"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var rep JobsReply
		if err := jsonstrict.Decode([]byte(`{"instance":"x","jobs":[`+string(b)+`],"cancel":[]}`), &rep); err != nil {
			return
		}
		for _, j := range rep.Jobs {
			if (j.Kind == KindNuclei) != (j.Nuclei != nil) || (j.Kind == KindSNMP) != (j.SNMP != nil) {
				t.Fatalf("kind and fields disagree: %+v", j)
			}
			if _, err := json.Marshal(j); err != nil {
				t.Fatalf("a decoded job does not marshal: %v", err)
			}
		}
	})
}

// D-165 (protocol 3): host_errors on a nuclei result is bounded and shaped; a result without it still decodes.
func TestNucleiResultHostErrors(t *testing.T) {
	t.Parallel()
	head := `{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":""`
	if r, err := decodeJobResult([]byte(head + `}`)); err != nil || len(r.HostErrors) != 0 {
		t.Fatalf("without host_errors: %v %+v", err, r)
	}
	ok := head + `,"host_errors":[{"target":"192.168.10.20:8080","errors":3,"unreachable":true},{"target":"10.0.0.7:22","errors":1,"unreachable":false}]}`
	if r, err := decodeJobResult([]byte(ok)); err != nil || len(r.HostErrors) != 2 || !r.HostErrors[0].Unreachable || r.HostErrors[1].Errors != 1 {
		t.Fatalf("a good one: %v %+v", err, r)
	}
	var many []string
	for i := range MaxHostErrors + 1 {
		many = append(many, fmt.Sprintf(`{"target":"10.0.0.%d:22","errors":1,"unreachable":false}`, i+1))
	}
	bad := map[string]string{
		"over the entry cap":    head + `,"host_errors":[` + strings.Join(many, ",") + `]}`,
		"zero errors":           head + `,"host_errors":[{"target":"10.0.0.7:22","errors":0,"unreachable":false}]}`,
		"errors over the cap":   head + `,"host_errors":[{"target":"10.0.0.7:22","errors":1048577,"unreachable":false}]}`,
		"a name, not host:port": head + `,"host_errors":[{"target":"evil.example:22","errors":1,"unreachable":false}]}`,
		"a path in the target":  head + `,"host_errors":[{"target":"10.0.0.7:22/x","errors":1,"unreachable":false}]}`,
		"a target twice":        head + `,"host_errors":[{"target":"10.0.0.7:22","errors":1,"unreachable":false},{"target":"10.0.0.7:22","errors":2,"unreachable":false}]}`,
		"an unknown field":      head + `,"host_errors":[{"target":"10.0.0.7:22","errors":1,"unreachable":false,"x":1}]}`,
		"on a failed result":    `{"status":"failed","reason":"","exit_code":1,"truncated":false,"xml_b64":"","host_errors":[{"target":"10.0.0.7:22","errors":1,"unreachable":false}]}`,
	}
	for name, body := range bad {
		if _, err := decodeJobResult([]byte(body)); !errors.Is(err, errInvalid) {
			t.Errorf("%s: %v, want errInvalid", name, err)
		}
	}
}

// D-520 (protocol 5, before its first release): the scope of a nuclei job and own_ip in the nuclei heartbeat. A LAN job keeps the
// shape it had (no scope), so an older worker still reads it; an own_ip job carries its scope; an older decoder, which knows no
// scope, refuses the own_ip job (strict decoding: fail closed, nothing runs).
func TestNucleiScopeOnTheWire(t *testing.T) {
	t.Parallel()
	lan, err := json.Marshal(Job{ID: strings.Repeat("c", 32), Kind: KindNuclei, TimeoutS: 60, Nuclei: &NucleiJob{Templates: []string{"CVE-2024-1"}}})
	if err != nil || strings.Contains(string(lan), "scope") {
		t.Fatalf("a LAN job: %s %v", lan, err)
	}
	own := strings.Replace(nucleiJobJSON, `"rate":5`, `"rate":5,"scope":"own_ip"`, 1)
	rep, err := decodeReply(t, own)
	if err != nil || rep.Jobs[0].Nuclei.Scope != "own_ip" {
		t.Fatalf("decoded %v %+v", err, rep)
	}
	out, err := json.Marshal(rep.Jobs[0])
	var back Job
	if err != nil || json.Unmarshal(out, &back) != nil || back.Nuclei.Scope != "own_ip" {
		t.Fatalf("round trip %s %v %+v", out, err, back)
	}
	type nucleiJobOld struct { // the nuclei job before D-520
		ID            string         `json:"id"`
		Kind          string         `json:"kind"`
		TimeoutS      int            `json:"timeout_s"`
		Pack          JobPack        `json:"pack"`
		Templates     []string       `json:"templates"`
		Targets       []NucleiTarget `json:"targets"`
		Rate          int            `json:"rate"`
		MaxHostErrors int            `json:"max_host_errors"`
	}
	var old nucleiJobOld
	if err := jsonstrict.Decode([]byte(own), &old); err == nil {
		t.Error("an older decoder accepted an own_ip job")
	}
	if err := jsonstrict.Decode([]byte(nucleiJobJSON), &old); err != nil {
		t.Errorf("an older decoder refused a LAN job: %v", err)
	}
	hb, err := decodeActiveHeartbeat([]byte(`{"version":"1.0.0","nmap":{"present":true,"version":"7.94"},"nuclei":{"present":true,"version":"v3.11.1","pack":{"version":"","sha256":""},"own_ip":true}}`))
	if err != nil || !hb.Nuclei.OwnIP {
		t.Fatalf("heartbeat %v %+v", err, hb)
	}
	if hb, err := decodeActiveHeartbeat([]byte(`{"version":"1.0.0","nmap":{"present":true,"version":"7.94"},"nuclei":{"present":true,"version":"v3.11.1","pack":{"version":"","sha256":""}}}`)); err != nil || hb.Nuclei.OwnIP {
		t.Fatalf("an older heartbeat: %v %+v", err, hb)
	}
}
