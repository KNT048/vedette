package ops

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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

func TestPodmanGrammarOfTheContainerInspect(t *testing.T) {
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

// FuzzValidateSystemctlContainers builds argv from the accepted pieces (so the fuzzer reaches the accepted
// shapes) and corrupts them: an argv with a piece changed must be refused, and a clean one accepted.
func FuzzValidateSystemctlContainers(f *testing.F) {
	v := validateSystemctl("vedette-core.service")
	f.Add(uint8(0), uint8(0), "", uint8(0))
	f.Add(uint8(1), uint8(2), "", uint8(0))
	f.Add(uint8(2), uint8(4), ".x", uint8(1))
	f.Add(uint8(3), uint8(1), "\n", uint8(2))
	f.Add(uint8(1), uint8(3), "-", uint8(3))
	verbs := []string{"daemon-reload", "restart", "stop", "is-active"}
	f.Fuzz(func(t *testing.T, vi, si uint8, junk string, mode uint8) {
		verb := verbs[int(vi)%len(verbs)]
		unit := "vedette-" + api.Services[int(si)%len(api.Services)] + ".service"
		args := []string{verb}
		if verb != "daemon-reload" {
			args = append(args, unit)
		}
		clean := true
		switch mode % 4 {
		case 1: // junk glued to the unit or the verb
			if junk != "" {
				args[len(args)-1] += junk
				clean = false
			}
		case 2: // an extra argument
			if junk != "" {
				args = append(args, junk)
				clean = false
			}
		case 3: // an option in front
			if junk != "" {
				args = append([]string{junk}, args...)
				clean = false
			}
		}
		err := v(args)
		if clean && err != nil {
			t.Fatalf("a fixed shape was refused: %q: %v", args, err)
		}
		if !clean && err == nil {
			// Whatever got through must still be one of the fixed shapes.
			ok := slices.Equal(args, []string{"daemon-reload"}) || (len(args) == 2 && slices.Contains(verbs[1:], args[0]) && isServiceUnit(args[1]))
			if !ok {
				t.Fatalf("accepted %q", args)
			}
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

// The time limits agree with each other (D-123 L6): the host never gives up on a restart before systemd
// does, and a step that is made of several has a limit at least their sum.
func TestTimeLimitsAreConsistent(t *testing.T) {
	t.Parallel()
	for _, svc := range unitServices {
		text, err := renderUnit(svc, goldFill(true))
		if err != nil {
			t.Fatal(err)
		}
		declared := 90 * time.Second // systemd's default when the unit has no TimeoutStartSec
		for l := range strings.SplitSeq(string(text), "\n") {
			if v, ok := strings.CutPrefix(l, "TimeoutStartSec="); ok {
				n, err := strconv.Atoi(v)
				if err != nil {
					t.Fatal(err)
				}
				declared = time.Duration(n) * time.Second
			}
		}
		if startTimeoutOf(svc) < declared || restartLimitFor(svc) < declared {
			t.Errorf("%s: restart limit %v, start timeout %v, the unit's own %v", svc, restartLimitFor(svc), startTimeoutOf(svc), declared)
		}
		if revertLimitFor(svc) < fileSlack+reloadLimit+restartLimitFor(svc) {
			t.Errorf("%s: the revert limit %v is under write + reload + restart", svc, revertLimitFor(svc))
		}
	}
	if recoverLimit < reloadLimit+fileSlack {
		t.Errorf("recoverLimit %v is under one reload plus the file work", recoverLimit)
	}
	// The whole of a start that waits for the health and then reverts fits in the command's timeout (15 minutes).
	worst := reloadLimit + restartLimitFor(api.ServiceCore) + 2*time.Minute + revertLimitFor(api.ServiceCore)
	if worst > 15*time.Minute {
		t.Errorf("a core start can take %v, over the 15 minutes of the command", worst)
	}
}
