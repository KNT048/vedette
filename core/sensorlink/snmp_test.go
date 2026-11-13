package sensorlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/knt048/vedette/internal/jsonstrict"
)

const snmpJobJSON = `{"id":"c0ffee00c0ffee00c0ffee00c0ffee00","kind":"snmp","timeout_s":600,"rate":10,` +
	`"credentials":[{"version":"v2c","community":"s3cret-community"},{"version":"v3","user":"vedette","auth":"sha","auth_pass":"authpass1","priv":"aes128","priv_pass":"privpass1"}],` +
	`"targets":[{"ip":"192.168.10.20","credentials":[1,0]},{"ip":"10.0.0.7","credentials":[0]}]}`

// D-512 (protocol 5): an snmp job travels with its credentials and targets, and decodes back to the same job.
func TestSNMPJobRoundTrip(t *testing.T) {
	t.Parallel()
	var rep JobsReply
	if err := jsonstrict.Decode([]byte(`{"instance":"x","jobs":[`+snmpJobJSON+`],"cancel":[]}`), &rep); err != nil {
		t.Fatal(err)
	}
	j := rep.Jobs[0]
	if j.Kind != KindSNMP || j.SNMP == nil || j.TimeoutS != 600 || j.SNMP.Rate != 10 || len(j.SNMP.Credentials) != 2 || j.SNMP.Credentials[1].PrivPass != "privpass1" ||
		len(j.SNMP.Targets) != 2 || j.SNMP.Targets[0].Credentials[0] != 1 {
		t.Fatalf("decoded %+v", j)
	}
	if err := CheckSNMPJob(j.SNMP); err != nil {
		t.Fatalf("a good job: %v", err)
	}
	b, err := json.Marshal(j)
	if err != nil || string(b) != snmpJobJSON {
		t.Fatalf("marshal: %v\n%s\n%s", err, b, snmpJobJSON)
	}
	var unknown Job
	if err := json.Unmarshal([]byte(strings.Replace(snmpJobJSON, `"rate":10,`, `"rate":10,"oids":["1.3.6.1"],`, 1)), &unknown); err == nil {
		t.Fatal("an snmp job with a field it does not have decoded")
	}
}

// A credential never reaches a log line or a formatted error through fmt or slog.
func TestSNMPCredentialIsRedacted(t *testing.T) {
	t.Parallel()
	c := SNMPCredential{Version: SNMPv2c, Community: "s3cret-community"}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "cred", c, "job", SNMPJob{Credentials: []SNMPCredential{c}})
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v %#v %s %q", c, c, c, c), fmt.Sprintf("%+v", SNMPJob{Credentials: []SNMPCredential{c}}), logged.String()} {
		if strings.Contains(s, "s3cret") {
			t.Errorf("the community shows: %s", s)
		}
	}
}

func TestCheckSNMPJob(t *testing.T) {
	t.Parallel()
	good := func() *SNMPJob {
		return &SNMPJob{Rate: 5, Credentials: []SNMPCredential{{Version: SNMPv2c, Community: "public"}, {Version: SNMPv3, User: "u", Auth: SNMPAuthSHA256, AuthPass: "12345678"}},
			Targets: []SNMPTarget{{IP: "192.168.1.1", Credentials: []int{0, 1}}}}
	}
	if err := CheckSNMPJob(good()); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(j *SNMPJob){
		"rate 0":                      func(j *SNMPJob) { j.Rate = 0 },
		"rate 1001":                   func(j *SNMPJob) { j.Rate = 1001 },
		"no credential":               func(j *SNMPJob) { j.Credentials = nil },
		"v1":                          func(j *SNMPJob) { j.Credentials[0].Version = "v1" },
		"an empty community":          func(j *SNMPJob) { j.Credentials[0].Community = "" },
		"a control byte in it":        func(j *SNMPJob) { j.Credentials[0].Community = "pub\nlic" },
		"a v2c with a user":           func(j *SNMPJob) { j.Credentials[0].User = "x" },
		"md5":                         func(j *SNMPJob) { j.Credentials[1].Auth = "md5" },
		"a short auth password":       func(j *SNMPJob) { j.Credentials[1].AuthPass = "1234567" },
		"des":                         func(j *SNMPJob) { j.Credentials[1].Priv, j.Credentials[1].PrivPass = "des", "12345678" },
		"a privacy password, no priv": func(j *SNMPJob) { j.Credentials[1].PrivPass = "12345678" },
		"aes, no password":            func(j *SNMPJob) { j.Credentials[1].Priv = SNMPPrivAES128 },
		"a v3 with a community":       func(j *SNMPJob) { j.Credentials[1].Community = "x" },
		"no target":                   func(j *SNMPJob) { j.Targets = nil },
		"a name":                      func(j *SNMPJob) { j.Targets[0].IP = "printer.local" },
		"IPv6":                        func(j *SNMPJob) { j.Targets[0].IP = "fe80::1" },
		"not canonical":               func(j *SNMPJob) { j.Targets[0].IP = "192.168.001.1" },
		"a target twice": func(j *SNMPJob) {
			j.Targets = append(j.Targets, SNMPTarget{IP: "192.168.1.1", Credentials: []int{0}})
		},
		"a credential out of range": func(j *SNMPJob) { j.Targets[0].Credentials = []int{2} },
		"a credential twice":        func(j *SNMPJob) { j.Targets[0].Credentials = []int{0, 0} },
		"no credential to try":      func(j *SNMPJob) { j.Targets[0].Credentials = nil },
		"five to try":               func(j *SNMPJob) { j.Targets[0].Credentials = []int{0, 1, 0, 1, 0} },
	}
	for name, mut := range bad {
		j := good()
		mut(j)
		if err := CheckSNMPJob(j); !errors.Is(err, errInvalid) {
			t.Errorf("%s: %v, want errInvalid", name, err)
		}
	}
	many := good()
	for i := range MaxSNMPTargets {
		many.Targets = append(many.Targets, SNMPTarget{IP: fmt.Sprintf("10.0.%d.%d", i/200, i%200+1), Credentials: []int{0}})
	}
	if err := CheckSNMPJob(many); !errors.Is(err, errInvalid) {
		t.Errorf("65 targets: %v", err)
	}
}

// D-512: snmp on a result is bounded and shaped; the value of a device is untrusted and only its size is checked here.
func TestSNMPResult(t *testing.T) {
	t.Parallel()
	head := `{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":""`
	ok := head + `,"snmp":[{"target":"192.168.10.20","status":"ok","credential":1,"values":{"sys_descr":"Juniper Networks, Inc. ex4200-48t","sys_object_id":".1.3.6.1.4.1.2636.1.1.1.2.31","sys_name":"sw1","ent_class":"3","ent_model":"","ent_software":"","ent_serial":""}},` +
		`{"target":"10.0.0.7","status":"no_answer","credential":0,"values":{"sys_descr":"","sys_object_id":"","sys_name":"","ent_class":"","ent_model":"","ent_software":"","ent_serial":""}}]}`
	r, err := decodeJobResult([]byte(ok))
	if err != nil || len(r.SNMP) != 2 || r.SNMP[0].Values.SysName != "sw1" || r.SNMP[1].Status != SNMPStatusNoAnswer {
		t.Fatalf("a good one: %v %+v", err, r)
	}
	one := func(s string) string { return head + `,"snmp":[` + s + `]}` }
	empty := `"values":{"sys_descr":"","sys_object_id":"","sys_name":"","ent_class":"","ent_model":"","ent_software":"","ent_serial":""}`
	bad := map[string]string{
		"an unknown status":    one(`{"target":"10.0.0.7","status":"maybe","credential":0,` + empty + `}`),
		"a credential over 7":  one(`{"target":"10.0.0.7","status":"ok","credential":8,` + empty + `}`),
		"a name as target":     one(`{"target":"evil.example","status":"ok","credential":0,` + empty + `}`),
		"a value too long":     one(`{"target":"10.0.0.7","status":"ok","credential":0,"values":{"sys_descr":"` + strings.Repeat("x", MaxSNMPValue+1) + `","sys_object_id":"","sys_name":"","ent_class":"","ent_model":"","ent_software":"","ent_serial":""}}`),
		"a value on no answer": one(`{"target":"10.0.0.7","status":"no_answer","credential":0,"values":{"sys_descr":"x","sys_object_id":"","sys_name":"","ent_class":"","ent_model":"","ent_software":"","ent_serial":""}}`),
		"an unknown value":     one(`{"target":"10.0.0.7","status":"ok","credential":0,"values":{"sys_contact":"x","sys_descr":"","sys_object_id":"","sys_name":"","ent_class":"","ent_model":"","ent_software":"","ent_serial":""}}`),
		"a target twice":       head + `,"snmp":[{"target":"10.0.0.7","status":"ok","credential":0,` + empty + `},{"target":"10.0.0.7","status":"ok","credential":0,` + empty + `}]}`,
		"with nmap output":     `{"status":"done","reason":"","exit_code":0,"truncated":false,"xml_b64":"PHg+","snmp":[{"target":"10.0.0.7","status":"ok","credential":0,` + empty + `}]}`,
		"on a result not done": `{"status":"failed","reason":"","exit_code":-1,"truncated":false,"xml_b64":"","snmp":[{"target":"10.0.0.7","status":"ok","credential":0,` + empty + `}]}`,
		"over the targets of a job": func() string {
			var many []string
			for i := range MaxSNMPTargets + 1 {
				many = append(many, fmt.Sprintf(`{"target":"10.0.0.%d","status":"no_answer","credential":0,%s}`, i+1, empty))
			}
			return head + `,"snmp":[` + strings.Join(many, ",") + `]}`
		}(),
	}
	for name, body := range bad {
		if _, err := decodeJobResult([]byte(body)); !errors.Is(err, errInvalid) {
			t.Errorf("%s: %v, want errInvalid", name, err)
		}
	}
}

// D-512: the heartbeat of a worker of protocol 5 says snmp; one of protocol 4 leaves it out and still decodes.
func TestActiveHeartbeatSNMP(t *testing.T) {
	t.Parallel()
	base := `{"version":"1.2.3","nmap":{"present":true,"version":"7.94"},"nuclei":{"present":false,"version":"","pack":{"version":"","sha256":""}}`
	if h, err := decodeActiveHeartbeat([]byte(base + `}`)); err != nil || h.SNMP {
		t.Fatalf("protocol 4: %v %+v", err, h)
	}
	if h, err := decodeActiveHeartbeat([]byte(base + `,"snmp":true}`)); err != nil || !h.SNMP {
		t.Fatalf("protocol 5: %v %+v", err, h)
	}
	if _, err := decodeActiveHeartbeat([]byte(base + `,"snmp":"yes"}`)); err == nil {
		t.Fatal("snmp as a string decoded")
	}
}
