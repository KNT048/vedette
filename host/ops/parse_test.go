package ops_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(opstest.Fixture(name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSimulationUbuntu(t *testing.T) {
	t.Parallel()
	sim := ops.ParseSimulation(fixture(t, "sim_ubuntu.txt"))
	if sim.NewDeps != 1 || sim.Removals != 0 || sim.Truncated || len(sim.Upgrades) != 2 {
		t.Fatalf("%+v", sim)
	}
	libc, ssl := sim.Upgrades[0], sim.Upgrades[1]
	if libc.Name != "libc6" || libc.From != "2.39-0ubuntu8.2" || libc.To != "2.39-0ubuntu8.3" || libc.Security || libc.Origin != "Ubuntu:24.04/noble-updates" {
		t.Errorf("libc6: %+v", libc)
	}
	if ssl.Name != "openssl" || !ssl.Security || ssl.Origin != "Ubuntu:24.04/noble-security" || ssl.To != "3.0.13-0ubuntu3.4" {
		t.Errorf("openssl: %+v", ssl)
	}
}

func TestParseSimulationDebian(t *testing.T) {
	t.Parallel()
	sim := ops.ParseSimulation(fixture(t, "sim_debian.txt"))
	if len(sim.Upgrades) != 2 || sim.Removals != 1 {
		t.Fatalf("%+v", sim)
	}
	if u := sim.Upgrades[0]; u.Name != "openssl" || !u.Security || u.Origin != "Debian-Security:13/stable-security" {
		t.Errorf("%+v", u)
	}
	if u := sim.Upgrades[1]; u.Name != "tzdata" || u.Security || u.To != "2025c-0+deb13u1" {
		t.Errorf("%+v", u)
	}
}

func TestParseSimulationHostileLinesAreSkipped(t *testing.T) {
	t.Parallel()
	sim := ops.ParseSimulation(fixture(t, "sim_hostile.txt"))
	// Only good-pkg parses (once: duplicates collapse); the rest fail the name, version or shape rules.
	var names []string
	for _, u := range sim.Upgrades {
		names = append(names, u.Name)
		if !ops.PkgNameRE.MatchString(u.Name) {
			t.Errorf("a name that fails the package-name rule got through: %q", u.Name)
		}
	}
	if !slices.Equal(names, []string{"good-pkg", "weird"}) {
		t.Fatalf("names = %v", names)
	}
	if sim.Upgrades[1].Origin != "" || sim.Upgrades[1].Security {
		t.Errorf("an origin with a space must be ignored: %+v", sim.Upgrades[1])
	}
	if sim.NewDeps != 1 { // "nofrom" has no installed version, so it is a new dependency
		t.Errorf("NewDeps = %d", sim.NewDeps)
	}
}

func TestParseSimulationBounds(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := 0; i < 6000; i++ {
		b.WriteString("Inst pkg" + strings.Repeat("a", 1) + itoa(i) + " [1.0] (2.0 Ubuntu:24.04/noble-updates [amd64])\n")
	}
	sim := ops.ParseSimulation([]byte(b.String()))
	if len(sim.Upgrades) != 5000 || !sim.Truncated {
		t.Fatalf("got %d upgrades, truncated %v", len(sim.Upgrades), sim.Truncated)
	}
	long := "Inst x [1.0] (2.0 " + strings.Repeat("a", 10000) + ")\nInst after-long [1.0] (2.0 Ubuntu:24.04/noble-security [amd64])\n"
	if sim = ops.ParseSimulation([]byte(long)); !sim.Truncated {
		t.Errorf("a line over the limit must be reported as truncated: %+v", sim)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func FuzzParseSimulation(f *testing.F) {
	for _, n := range []string{"sim_ubuntu.txt", "sim_debian.txt", "sim_hostile.txt", "sim_after.txt"} {
		f.Add(fixture(f, n))
	}
	f.Add([]byte("Inst a [1] (2 O:1/x-security [a], [b]) []\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		sim := ops.ParseSimulation(in)
		if len(sim.Upgrades) > 5000 {
			t.Fatal("more upgrades than the bound")
		}
		for _, u := range sim.Upgrades {
			// Whatever the input, what comes out is safe to put in an argv: it passes the validator.
			args := append(append([]string{}, "-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "--no-remove", "install", "--only-upgrade"), u.Name)
			if err := ops.ValidateApt(args); err != nil {
				t.Fatalf("parsed name %q is not valid argv: %v", u.Name, err)
			}
			if strings.ContainsAny(u.From+u.To+u.Origin, " \n\t;|&$`\"'\\") {
				t.Fatalf("a field carries a dangerous character: %+v", u)
			}
		}
	})
}

func TestParseUpdateHosts(t *testing.T) {
	t.Parallel()
	got := ops.ParseUpdateHosts(fixture(t, "apt_update.txt"))
	want := []string{"archive.ubuntu.com", "evil", "ppa.example.net", "security.ubuntu.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if h := ops.ParseUpdateHosts([]byte("Get:1 ftp://x.example/ y\nGet:2 http://[::1]/ y\nGet:3 http://a_b.example/ y\nGet:x http://c.example/\n")); len(h) != 0 {
		t.Errorf("non-http schemes and odd hosts must be ignored: %v", h)
	}
}

func FuzzParseUpdateHosts(f *testing.F) {
	f.Add(fixture(f, "apt_update.txt"))
	f.Fuzz(func(t *testing.T, in []byte) {
		h := ops.ParseUpdateHosts(in)
		if len(h) > 20 || !slices.IsSorted(h) {
			t.Fatalf("bad result %v", h)
		}
		for _, x := range h {
			if strings.ContainsAny(x, " /:@\\\n") {
				t.Fatalf("host %q", x)
			}
		}
	})
}

func TestParseAptConfig(t *testing.T) {
	t.Parallel()
	on := ops.ParseAptConfig(fixture(t, "aptconfig_on.txt"))
	if !on.Enabled() || !on.SecurityOnly() || len(on.AllowedOrigins) != 2 {
		t.Errorf("on: %+v", on)
	}
	off := ops.ParseAptConfig(fixture(t, "aptconfig_off.txt"))
	if off.Enabled() || off.SecurityOnly() {
		t.Errorf("off: %+v", off)
	}
	leaky := ops.ParseAptConfig(fixture(t, "aptconfig_leaky.txt"))
	if !leaky.Enabled() || leaky.SecurityOnly() {
		t.Errorf("an allowed origin that is not security must fail SecurityOnly: %+v", leaky)
	}
	if c := ops.ParseAptConfig(nil); c.Enabled() || c.SecurityOnly() {
		t.Errorf("empty config: %+v", c)
	}
}

func FuzzParseAptConfig(f *testing.F) {
	f.Add(fixture(f, "aptconfig_on.txt"))
	f.Add([]byte("APT::Periodic::Unattended-Upgrade \"1\";\nUnattended-Upgrade::Allowed-Origins:: \"x\";"))
	f.Fuzz(func(_ *testing.T, in []byte) {
		c := ops.ParseAptConfig(in)
		_ = c.Enabled()
		_ = c.SecurityOnly()
	})
}

func TestParseRebootPkgs(t *testing.T) {
	t.Parallel()
	got := ops.ParseRebootPkgs([]byte("linux-image-6.8.0-45-generic\nlibc6\nlibc6\n../etc\nBad Name\n\n-x\n"))
	if !slices.Equal(got, []string{"libc6", "linux-image-6.8.0-45-generic"}) {
		t.Fatalf("%v", got)
	}
}

func TestRedactJournalLine(t *testing.T) {
	t.Parallel()
	secrets := []string{
		"vdt_osquery_aB3dE5gH7jK9mN1pQ3sU5wY", "Zk3Jh8Pq9Rt2Vw5Xy7", "abcdef0123456789abcdef", "hunter2",
		"xoxb-1234567890-abcdefghijk", "xapp-1-A0123-4567-abcdef", "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"sk-abcdefghijklmnopqrstuvwxyz", "AKIAABCDEFGHIJKLMNOP", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef-ghij",
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
	}
	for _, line := range strings.Split(strings.TrimSpace(string(fixture(t, "journal_core.jsonl"))), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		out := string(ops.RedactJournalLine([]byte(line)))
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("secret %q survived in %s", s, out)
			}
		}
		if !json.Valid([]byte(out)) {
			t.Errorf("redaction broke the JSON: %s", out)
		}
	}
	pem := `{"MESSAGE":"key -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabc\n-----END PRIVATE KEY----- done"}`
	out := string(ops.RedactJournalLine([]byte(pem)))
	if strings.Contains(out, "MIIEvQ") || !json.Valid([]byte(out)) || !strings.Contains(out, "done") {
		t.Errorf("pem: %s", out)
	}
	plain := `{"MESSAGE":"listening on :8443"}`
	if got := string(ops.RedactJournalLine([]byte(plain))); got != plain {
		t.Errorf("a clean line must be unchanged: %s", got)
	}
}

func FuzzRedactJournalLine(f *testing.F) {
	for _, line := range strings.Split(string(fixture(f, "journal_core.jsonl")), "\n") {
		f.Add(line)
	}
	f.Add(`{"MESSAGE":"-----BEGIN X-----\n-----END X-----"}`)
	f.Fuzz(func(t *testing.T, line string) {
		out := ops.RedactJournalLine([]byte(line))
		if json.Valid([]byte(line)) && !json.Valid(out) {
			t.Fatalf("redaction turned valid JSON into invalid JSON:\n in: %q\nout: %q", line, out)
		}
		if again := ops.RedactJournalLine(out); !bytes.Equal(again, out) {
			t.Fatalf("redaction is not idempotent:\n once: %q\ntwice: %q", out, again)
		}
	})
}

func TestFilterJournal(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	n, w, err := ops.FilterJournal(bytes.NewReader(fixture(t, "journal_core.jsonl")), &out, 1<<20)
	if err != nil || n != 8 || int64(out.Len()) != w {
		t.Fatalf("n=%d w=%d len=%d err=%v", n, w, out.Len(), err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, l := range lines {
		if !json.Valid([]byte(l)) || !strings.HasPrefix(l, "{") {
			t.Errorf("an output line is not a JSON object: %q", l)
		}
	}
	if !strings.Contains(out.String(), "a journal line that is not a JSON object was dropped") {
		t.Errorf("the dropped line must leave a note")
	}
	// Over budget: stop, never cut.
	out.Reset()
	if _, _, err := ops.FilterJournal(bytes.NewReader(fixture(t, "journal_core.jsonl")), &out, 100); err == nil {
		t.Errorf("a budget of 100 bytes must fail")
	}
	// A line over 1 MiB becomes a note.
	out.Reset()
	huge := `{"MESSAGE":"` + strings.Repeat("a", 1<<20+10) + `"}` + "\n" + `{"MESSAGE":"after"}` + "\n"
	n, _, err = ops.FilterJournal(strings.NewReader(huge), &out, 1<<22)
	if err != nil || n != 2 || !strings.Contains(out.String(), "longer than 1 MiB") || !strings.Contains(out.String(), `"after"`) {
		t.Errorf("n=%d err=%v out=%.200s", n, err, out.String())
	}
}

func FuzzFilterJournal(f *testing.F) {
	f.Add(fixture(f, "journal_core.jsonl"))
	f.Add([]byte("{\"a\":1}\r\n\r\n{"))
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		_, _, err := ops.FilterJournal(bytes.NewReader(in), &out, 1<<22)
		if err != nil {
			return
		}
		for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
			if l == "" {
				continue
			}
			if !json.Valid([]byte(l)) || !strings.HasPrefix(l, "{") {
				t.Fatalf("output line is not a JSON object: %q", l)
			}
		}
	})
}

func TestParseManifest(t *testing.T) {
	t.Parallel()
	good := `{"version":1,"db_schema":"core=3,findings=2","created_at":"2026-11-09T12:00:00Z","includes_secrets":true}`
	m, err := ops.ParseManifest([]byte(good))
	if err != nil || m.DBSchema != "core=3,findings=2" || !m.IncludesSecrets {
		t.Fatalf("%+v %v", m, err)
	}
	bad := map[string]string{
		"empty": ``, "not json": `x`, "unknown field": strings.Replace(good, `"version":1`, `"version":1,"x":1`, 1),
		"version 2": strings.Replace(good, `:1,`, `:2,`, 1), "version 0": strings.Replace(good, `"version":1`, `"version":0`, 1),
		"bad schema": strings.Replace(good, "core=3", "Core=3", 1), "schema injection": strings.Replace(good, "core=3", "core=3;drop", 1),
		"bad time": strings.Replace(good, "2026-11-09T12:00:00Z", "yesterday", 1), "trailing": good + `{}`,
		"huge": `{"version":1,"db_schema":"` + strings.Repeat("a=1,", 70000) + `"}`,
	}
	for name, in := range bad {
		if _, err := ops.ParseManifest([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ops.ParseManifest([]byte(strings.Replace(good, "core=3,findings=2", "", 1))); err != nil {
		t.Errorf("an empty schema is valid: %v", err)
	}
}

func FuzzParseManifest(f *testing.F) {
	f.Add(`{"version":1,"db_schema":"core=3","created_at":"2026-11-09T12:00:00Z","includes_secrets":false}`)
	f.Fuzz(func(t *testing.T, in string) {
		m, err := ops.ParseManifest([]byte(in))
		if err != nil {
			return
		}
		if m.Version != 1 || strings.ContainsAny(m.DBSchema, " \n\"';") {
			t.Fatalf("accepted a bad manifest: %+v", m)
		}
	})
}

func TestSchemaNewer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		backup, live string
		want         bool
	}{
		{"core=3,findings=2", "core=3,findings=2", false},
		{"core=2", "core=3,findings=2", false},
		{"core=4", "core=3", true},
		{"core=3,newmod=1", "core=3", true},
		{"", "core=3", false},
		{"core=3", "", true},
	}
	for _, tc := range tests {
		if got := ops.SchemaNewer(tc.backup, tc.live); got != tc.want {
			t.Errorf("SchemaNewer(%q, %q) = %v", tc.backup, tc.live, got)
		}
	}
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

func TestFcntlLockHeldWithoutAHolder(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if held, err := ops.FcntlLockHeld(dir + "/missing"); err != nil || held {
		t.Errorf("missing file: %v %v", held, err)
	}
	f := dir + "/lock"
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if held, err := ops.FcntlLockHeld(f); err != nil || held {
		t.Errorf("unlocked file: %v %v", held, err)
	}
	// A symlink is not followed.
	if err := os.Symlink(f, dir+"/link"); err != nil {
		t.Fatal(err)
	}
	if _, err := ops.FcntlLockHeld(dir + "/link"); err == nil {
		t.Error("a symlink lock file was followed")
	}
}

func TestFreeBytes(t *testing.T) {
	t.Parallel()
	n, err := ops.FreeBytes(t.TempDir())
	if err != nil || n == 0 {
		t.Fatalf("free = %d, err %v", n, err)
	}
	if _, err := ops.FreeBytes("/definitely/not/here"); err == nil {
		t.Error("a missing path was accepted")
	}
}
