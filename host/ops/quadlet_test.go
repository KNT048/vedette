package ops

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
)

const (
	goldA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	goldB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func goldFill(install bool) unitFill {
	return unitFill{Digest: goldA, Install: install, CoreUID: 10001, CoreGID: 10002, SensorUID: 10003, SensorGID: 10004, DataDir: "/var/lib/vedette"}
}

// core_data goes into one Volume= line (D-142 H1): anything that is not a plain absolute path is refused, so
// no value can add a line, an option or a second mount to the unit.
func TestCoreDataInTheUnitIsAStrictPath(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"/var/lib/vedette", "/srv/vedette-data", "/data/a.b_c/d", "/a"} {
		f := goldFill(true)
		f.DataDir = ok
		b, err := renderUnit(api.ServiceCore, f)
		if err != nil || !strings.Contains(string(b), "\nVolume="+ok+":/var/lib/vedette\n") {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/", "var/lib", "/var/lib/", "/var//lib", "/var/../etc", "/var/./lib", "/a b", "/a:b", "/a\nVolume=/:/x", "/a\r", "/a,b", "/a:ro", "/é", "/a%h", "/a$x", "/" + strings.Repeat("a", 220), "-v", "/a\x00"} {
		f := goldFill(true)
		f.DataDir = bad
		if b, err := renderUnit(api.ServiceCore, f); err == nil {
			t.Errorf("%q accepted: %s", bad, b)
		}
	}
	// Only core uses it.
	f := goldFill(true)
	f.DataDir = ""
	for _, s := range []string{api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		if _, err := renderUnit(s, f); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	b, _ := renderUnit(api.ServiceCore, goldFill(true))
	if strings.Contains(string(b), "master.key") || strings.Contains(string(b), "-key") {
		t.Errorf("core's unit still names a key file:\n%s", b)
	}
}

// D-146 (L5 of the sensor protocol): nmap can leave a child that setsid()ed away from the group the worker kills, and without an init
// that child becomes a zombie of PID 1, which is the worker. The scan unit therefore runs under podman's init (Quadlet RunInit=, which
// the generator turns into --init; checked with the quadlet generator of podman 5.7), and vedette-sensor is not made a subreaper.
// The sensor starts no child process, so its unit has none.
func TestScanUnitRunsUnderAnInit(t *testing.T) {
	t.Parallel()
	for svc, want := range map[string]bool{api.ServiceScan: true, api.ServiceSensor: false, api.ServiceCore: false, api.ServiceHoneypot: false} {
		b, err := renderUnit(svc, goldFill(true))
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(strings.Split(string(b), "\n"), "RunInit=true"); got != want {
			t.Errorf("%s: RunInit=true present = %t, want %t", svc, got, want)
		}
	}
}

// The golden files are the unit texts of DEPLOYMENT.md 6.1: any change to a template shows here and
// must be made on purpose (UPDATE_GOLDEN=1 rewrites them).
func TestUnitTemplatesMatchTheGoldenFiles(t *testing.T) {
	t.Parallel()
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		for _, install := range []bool{true, false} {
			got, err := renderUnit(svc, goldFill(install))
			if err != nil {
				t.Fatalf("%s: %v", svc, err)
			}
			name := svc + ".container"
			if !install {
				name = svc + ".noinstall.container"
			}
			path := filepath.Join("testdata", "units", name)
			if os.Getenv("UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) //nolint:gosec // a golden file under testdata
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from its golden file:\n%s", name, got)
			}
			if install != strings.HasSuffix(string(got), installSection) {
				t.Errorf("%s: [Install] present = %t, want %t", name, !install, install)
			}
		}
	}
}

func TestOnlyTheFourServicesWithAUnitInTheSpecHaveATemplate(t *testing.T) {
	t.Parallel()
	for _, svc := range api.Services {
		_, err := renderUnit(svc, goldFill(true))
		if (svc == api.ServiceGreenbone) != (err != nil) {
			t.Errorf("%s: err %v", svc, err)
		}
	}
	if _, err := renderUnit("nope", goldFill(true)); err == nil {
		t.Error("an unknown service has a template")
	}
}

func TestRenderRefusesEveryBadFillIn(t *testing.T) {
	t.Parallel()
	badDigests := []string{
		"", "sha256:", goldA + "\nExec=/bin/sh", goldA + " ", " " + goldA, strings.ToUpper(goldA), "sha512:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("a", 65), "sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 63) + "\n", "latest", "x@" + goldA, goldA + "\r", "sha256:" + strings.Repeat("a", 64) + "\x00",
	}
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		for _, d := range badDigests {
			f := goldFill(true)
			f.Digest = d
			if b, err := renderUnit(svc, f); err == nil {
				t.Errorf("%s accepted digest %q: %s", svc, d, b)
			}
		}
	}
	for _, id := range []int{0, -1, 1 << 31, 1<<31 + 5} {
		for _, c := range []struct {
			svc string
			mut func(*unitFill)
		}{
			{api.ServiceCore, func(f *unitFill) { f.CoreUID = id }},
			{api.ServiceCore, func(f *unitFill) { f.CoreGID = id }},
			{api.ServiceCore, func(f *unitFill) { f.SensorGID = id }},
			{api.ServiceSensor, func(f *unitFill) { f.SensorUID = id }},
			{api.ServiceSensor, func(f *unitFill) { f.SensorGID = id }},
			{api.ServiceScan, func(f *unitFill) { f.SensorUID = id }},
			{api.ServiceScan, func(f *unitFill) { f.SensorGID = id }},
		} {
			f := goldFill(true)
			c.mut(&f)
			if b, err := renderUnit(c.svc, f); err == nil {
				t.Errorf("%s accepted id %d: %s", c.svc, id, b)
			}
		}
	}
	// The honeypot uses no host.conf id, so it renders without any.
	if _, err := renderUnit(api.ServiceHoneypot, unitFill{Digest: goldA, Install: true}); err != nil {
		t.Errorf("honeypot needs no ids: %v", err)
	}
	// The edges are accepted.
	f := goldFill(true)
	f.CoreUID, f.SensorGID = 1, 1<<31-1
	if _, err := renderUnit(api.ServiceCore, f); err != nil {
		t.Errorf("edges: %v", err)
	}
}

// Only the digest and the ids vary between two renders of a service, and each lands in its own place.
func TestRenderPutsFillInsOnlyWhereTheyBelong(t *testing.T) {
	t.Parallel()
	a, _ := renderUnit(api.ServiceCore, goldFill(true))
	f := goldFill(true)
	f.Digest = goldB
	b, _ := renderUnit(api.ServiceCore, f)
	if strings.ReplaceAll(string(a), goldA, goldB) != string(b) {
		t.Error("the digest changed more than the Image= line")
	}
	f = goldFill(true)
	f.CoreUID, f.CoreGID, f.SensorGID = 20001, 20002, 20004
	c, _ := renderUnit(api.ServiceCore, f)
	want := strings.NewReplacer("User=10001:10002", "User=20001:20002", "--group-add=10004", "--group-add=20004").Replace(string(a))
	if want != string(c) {
		t.Errorf("the ids changed more than User= and --group-add:\n%s", c)
	}
}

func TestParseUnitReadsBackWhatRenderMade(t *testing.T) {
	t.Parallel()
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		for _, install := range []bool{true, false} {
			text, _ := renderUnit(svc, goldFill(install))
			d, ins, err := parseUnit(svc, text)
			if err != nil || d != goldA || ins != install {
				t.Errorf("%s install=%t: %q %t %v", svc, install, d, ins, err)
			}
		}
	}
	core, _ := renderUnit(api.ServiceCore, goldFill(true))
	for name, text := range map[string]string{
		"empty":          "",
		"other service":  strings.ReplaceAll(string(core), repoCore, repoSensor),
		"two images":     string(core) + "Image=" + repoCore + "@" + goldB + "\n",
		"no image":       strings.ReplaceAll(string(core), "Image=", "Imagx="),
		"short digest":   strings.ReplaceAll(string(core), goldA, "sha256:abc"),
		"carriage":       strings.ReplaceAll(string(core), "\n", "\r\n"),
		"tag not digest": strings.ReplaceAll(string(core), "@"+goldA, ":latest"),
		"other repo":     strings.ReplaceAll(string(core), repoCore, "docker.io/evil/core"),
		"nul":            string(core) + "\x00",
		"huge":           string(core) + strings.Repeat("#", maxUnitSize),
	} {
		if _, _, err := parseUnit(api.ServiceCore, []byte(text)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, _, err := parseUnit(api.ServiceGreenbone, core); err == nil {
		t.Error("greenbone has no unit")
	}
}

func FuzzRenderUnit(f *testing.F) {
	f.Add("core", goldA, true, 10001, 10002, 10003, 10004)
	f.Add("sensor", goldA+"\nExec=x", false, 0, 0, -1, 7)
	f.Add("scan", "", true, 1, 1, 1<<31, 1)
	f.Add("honeypot", goldB, true, 0, 0, 0, 0)
	f.Fuzz(func(t *testing.T, svc, digest string, install bool, cu, cg, su, sg int) {
		out, err := renderUnit(svc, unitFill{Digest: digest, Install: install, CoreUID: cu, CoreGID: cg, SensorUID: su, SensorGID: sg})
		if err != nil {
			return
		}
		// What comes out is the template with the fill-ins in their places: it parses back, carries the
		// digest on one Image= line, and has no line the template does not have.
		d, ins, perr := parseUnit(svc, out)
		if perr != nil || d != digest || ins != install {
			t.Fatalf("round trip: %q %t %v for %q", d, ins, perr, out)
		}
		base, err := renderUnit(svc, goldFill(install))
		if err != nil {
			t.Fatal(err)
		}
		baseLines := strings.Split(string(base), "\n")
		for _, l := range strings.Split(string(out), "\n") {
			if slices.Contains(baseLines, l) || strings.HasPrefix(l, "Image=") || strings.HasPrefix(l, "User=") || strings.HasPrefix(l, "PodmanArgs=") {
				continue
			}
			t.Fatalf("a line the template does not have: %q", l)
		}
	})
}

func FuzzParseUnit(f *testing.F) {
	core, _ := renderUnit(api.ServiceCore, goldFill(true))
	f.Add("core", core)
	f.Add("honeypot", []byte("Image="+repoHoneypot+"@"+goldA+"\n"))
	f.Add("scan", []byte("Image=\n\r"))
	f.Fuzz(func(t *testing.T, svc string, text []byte) {
		d, _, err := parseUnit(svc, text)
		if err == nil && !digestRE.MatchString(d) {
			t.Fatalf("accepted digest %q", d)
		}
	})
}
