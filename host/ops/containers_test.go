package ops

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

func TestSystemctlGrammarForTheContainerCommands(t *testing.T) {
	t.Parallel()
	v := validateSystemctl("vedette-core.service")
	var ok [][]string
	ok = append(ok, []string{"daemon-reload"})
	for _, s := range api.Services {
		u := "vedette-" + s + ".service"
		ok = append(ok, []string{"restart", u}, []string{"stop", u}, []string{"is-active", u})
	}
	for _, a := range ok {
		if err := v(a); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	for _, a := range [][]string{
		{}, {"daemon-reload", "--now"}, {"daemon-reexec"}, {"restart"}, {"restart", "vedette-core.service", "vedette-sensor.service"},
		{"restart", "vedette-nope.service"}, {"restart", "sshd.service"}, {"restart", "vedette-host.service"}, {"stop", "vedette-host.service"},
		{"restart", "vedette-core"}, {"restart", "vedette-core.service\n"}, {"restart", " vedette-core.service"}, {"restart", "-vedette-core.service"},
		{"restart", "../vedette-core.service"}, {"restart", "vedette-core.socket"}, {"start", "vedette-sensor.service"},
		{"enable", "vedette-core.service"}, {"disable", "vedette-core.service"}, {"enable", "--now", "vedette-core.service"},
		{"mask", "vedette-core.service"}, {"is-active", "vedette-core.service", "x"}, {"kill", "vedette-core.service"},
		{"--user", "restart", "vedette-core.service"}, {"-H", "x", "restart", "vedette-core.service"}, {"daemon-reload", "vedette-core.service"},
		{"RESTART", "vedette-core.service"}, {"restart", "vedette-core.service;id"}, {"restart", "vedette-core.service\x00"},
	} {
		if err := v(a); err == nil {
			t.Errorf("%q was accepted", a)
		}
	}
}

func TestPodmanGrammarIsInspectOfTheFiveContainersOnly(t *testing.T) {
	t.Parallel()
	for _, s := range api.Services {
		if err := validatePodman([]string{"container", "inspect", "vedette-" + s}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, a := range [][]string{
		{}, {"container", "inspect"}, {"container", "inspect", "vedette-nope"}, {"container", "inspect", "vedette-core", "x"},
		{"container", "inspect", "--format", "json", "vedette-core"}, {"inspect", "vedette-core"}, {"container", "rm", "vedette-core"},
		{"container", "exec", "vedette-core"}, {"container", "inspect", "vedette-core\n"}, {"container", "inspect", "-vedette-core"},
		{"container", "inspect", "vedette-core.service"}, {"container", "inspect", "VEDETTE-CORE"}, {"run", "--privileged", "x"},
		{"pull", "x"}, {"image", "inspect", "vedette-core"}, {"--root", "/x", "container", "inspect", "vedette-core"},
	} {
		if err := validatePodman(a); err == nil {
			t.Errorf("%q was accepted", a)
		}
	}
}

func FuzzValidateSystemctlContainers(f *testing.F) {
	v := validateSystemctl("vedette-core.service")
	f.Add("restart", "vedette-core.service", "")
	f.Add("daemon-reload", "", "")
	f.Add("stop", "vedette-honeypot.service", "x")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		args := []string{a, b, c}
		if err := v(args); err != nil {
			return
		}
		// Whatever got through is one of the fixed shapes, with a unit from the closed list.
		for _, x := range args {
			if strings.ContainsAny(x, " \t\r\n\x00;|&$`'\"") {
				t.Fatalf("accepted %q", args)
			}
		}
	})
}

func FuzzValidatePodman(f *testing.F) {
	f.Add("container", "inspect", "vedette-core")
	f.Add("run", "--privileged", "x")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		args := []string{a, b, c}
		if validatePodman(args) != nil {
			return
		}
		if a != "container" || b != "inspect" || !strings.HasPrefix(c, "vedette-") || strings.ContainsAny(c, " \n\x00/.") {
			t.Fatalf("accepted %q", args)
		}
	})
}

func TestClassifyActiveReadsTheWord(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"active\n": api.UnitActive, "inactive\n": api.UnitInactive, "failed\n": api.UnitFailed, "activating\n": api.UnitOther,
		"deactivating": api.UnitOther, " active ": api.UnitActive, "": api.UnitUnknown, "Active": api.UnitUnknown, "unknown\n": api.UnitUnknown,
		"active\ninactive": api.UnitUnknown, "active inactive": api.UnitUnknown, "inactive\x00": api.UnitUnknown, "ACTIVE": api.UnitUnknown,
		strings.Repeat("a", 33): api.UnitUnknown, "active" + strings.Repeat(" ", 40): api.UnitUnknown,
	} {
		if got := ClassifyActive([]byte(in)); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}

func FuzzClassifyActive(f *testing.F) {
	f.Add([]byte("active\n"))
	f.Add([]byte("inactive"))
	f.Fuzz(func(t *testing.T, b []byte) {
		switch ClassifyActive(b) {
		case api.UnitActive, api.UnitInactive, api.UnitFailed, api.UnitOther, api.UnitUnknown:
		default:
			t.Fatal("not one of the known states")
		}
	})
}

func inspectJSON(name, digest, extra string) string {
	return fmt.Sprintf(`[{"Name":%q,"ImageDigest":%q,"State":{"Running":true%s}}]`, name, digest, extra)
}

func TestParseInspect(t *testing.T) {
	t.Parallel()
	d := "sha256:" + strings.Repeat("c", 64)
	ok := map[string]struct {
		text   string
		health string
	}{
		"healthy":     {inspectJSON("vedette-core", d, `,"Health":{"Status":"healthy"}`), api.HealthHealthy},
		"unhealthy":   {inspectJSON("vedette-core", d, `,"Health":{"Status":"unhealthy"}`), api.HealthUnhealthy},
		"starting":    {inspectJSON("vedette-core", d, `,"Health":{"Status":"starting"}`), api.HealthStarting},
		"healthcheck": {inspectJSON("vedette-core", d, `,"Healthcheck":{"Status":"healthy"}`), api.HealthHealthy},
		"no check":    {inspectJSON("vedette-core", d, ``), api.HealthNone},
		"odd word":    {inspectJSON("vedette-core", d, `,"Health":{"Status":"great"}`), api.HealthUnknown},
		"extra field": {`[{"Name":"vedette-core","ImageDigest":"` + d + `","Env":["A=1"],"State":{"Running":true,"Health":{"Status":"healthy","Log":[]}}}]`, api.HealthHealthy},
	}
	for name, c := range ok {
		i, err := parseInspect([]byte(c.text), "core")
		if err != nil || i.Digest != d || !i.Running || i.Health != c.health {
			t.Errorf("%s: %+v %v", name, i, err)
		}
	}
	for name, text := range map[string]string{
		"empty":             "",
		"not json":          "garbage",
		"object":            `{"Name":"vedette-core"}`,
		"empty array":       `[]`,
		"two":               strings.TrimSuffix(inspectJSON("vedette-core", d, ""), "]") + "," + strings.TrimPrefix(inspectJSON("vedette-core", d, ""), "["),
		"other container":   inspectJSON("vedette-sensor", d, ""),
		"slash name":        inspectJSON("/vedette-core", d, ""),
		"no digest":         `[{"Name":"vedette-core","State":{"Running":true}}]`,
		"short digest":      inspectJSON("vedette-core", "sha256:abc", ""),
		"upper digest":      inspectJSON("vedette-core", "sha256:"+strings.Repeat("C", 64), ""),
		"tag as digest":     inspectJSON("vedette-core", "latest", ""),
		"digest with space": inspectJSON("vedette-core", d+" ", ""),
		"trailing data":     inspectJSON("vedette-core", d, "") + " x",
		"two documents":     inspectJSON("vedette-core", d, "") + inspectJSON("vedette-core", d, ""),
		"wrong type":        `[{"Name":5,"ImageDigest":"` + d + `"}]`,
		"state not object":  `[{"Name":"vedette-core","ImageDigest":"` + d + `","State":5}]`,
		"too large":         inspectJSON("vedette-core", d, "") + strings.Repeat(" ", maxInspectOutput),
		"deep":              strings.Repeat("[", 100000),
	} {
		if i, err := parseInspect([]byte(text), "core"); err == nil {
			t.Errorf("%s was accepted: %+v", name, i)
		}
	}
}

func FuzzParseInspect(f *testing.F) {
	d := "sha256:" + strings.Repeat("c", 64)
	f.Add([]byte(inspectJSON("vedette-core", d, `,"Health":{"Status":"healthy"}`)), "core")
	f.Add([]byte(`[{"Name":"vedette-sensor"}]`), "sensor")
	f.Add([]byte(strings.Repeat("[", 5000)), "scan")
	f.Fuzz(func(t *testing.T, b []byte, svc string) {
		i, err := parseInspect(b, svc)
		if err != nil {
			return
		}
		if !digestRE.MatchString(i.Digest) {
			t.Fatalf("digest %q", i.Digest)
		}
		switch i.Health {
		case api.HealthHealthy, api.HealthUnhealthy, api.HealthStarting, api.HealthNone, api.HealthUnknown:
		default:
			t.Fatalf("health %q", i.Health)
		}
	})
}
