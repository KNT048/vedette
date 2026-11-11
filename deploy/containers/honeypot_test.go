package containers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec" //nolint:depguard // the tests run go and python3 with fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/modules/honeypot"
)

// The honeypot image (WP-08e, D-162). Its text, its locks and its unit are checked here; what a connection does to the running container is
// checked by effect by scripts/dev/honeypot-check.sh (make honeypot-check), which builds it.

func honeypotUnit(t *testing.T) map[string][]string {
	t.Helper()
	b, err := ops.RenderUnit("honeypot", "sha256:"+strings.Repeat("a", 64), true, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	kv := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			kv[k] = append(kv[k], v)
		}
	}
	return kv
}

var (
	reqLine   = regexp.MustCompile(`^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+) \\$`)
	hashLine  = regexp.MustCompile(`^    --hash=sha256:[0-9a-f]{64}( \\)?$`)
	initConst = func(text, name string) string {
		m := regexp.MustCompile(`(?m)^` + name + ` = ("[^"]*"|[0-9]+)`).FindStringSubmatch(text)
		if m == nil {
			return ""
		}
		return strings.Trim(m[1], `"`)
	}
)

// Every Python package of the image is an exact version with the hash of every file it may be installed from; pip is told to refuse anything
// else (--require-hashes). OpenCanary's version is the one in pins.env and requirements.in, and a requirements file cannot carry an index or a URL.
func TestHoneypotPipLockIsHashed(t *testing.T) {
	t.Parallel()
	p := pins(t)
	if got := strings.TrimSpace(read(t, "honeypot/requirements.in")); got != "opencanary=="+p["OPENCANARY_VERSION"] {
		t.Errorf("requirements.in is %q, want opencanary==%s (pins.env OPENCANARY_VERSION)", got, p["OPENCANARY_VERSION"])
	}
	seen := map[string]bool{}
	for _, f := range []string{"honeypot/requirements.txt", "honeypot/requirements-sdist.txt"} {
		cur, hashes := "", 0
		flush := func() {
			if cur != "" && hashes == 0 {
				t.Errorf("%s: %s has no hash", f, cur)
			}
		}
		for _, l := range strings.Split(read(t, f), "\n") {
			switch {
			case l == "" || strings.HasPrefix(l, "#"):
			case reqLine.MatchString(l):
				flush()
				m := reqLine.FindStringSubmatch(l)
				cur, hashes = m[1], 0
				if k := strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(m[1])); seen[k] {
					t.Errorf("%s: %s is pinned twice", f, m[1])
				} else {
					seen[k] = true
				}
				if f == "honeypot/requirements.txt" && m[1] == "opencanary" && m[2] != p["OPENCANARY_VERSION"] {
					t.Errorf("requirements.txt pins opencanary %s, pins.env says %s", m[2], p["OPENCANARY_VERSION"])
				}
			case hashLine.MatchString(l):
				hashes++
			default:
				t.Errorf("%s: unexpected line %q (only name==version and --hash=sha256 lines: no index, URL, editable or option)", f, l)
			}
		}
		flush()
	}
	if !seen["opencanary"] {
		t.Error("requirements.txt does not pin opencanary")
	}
	cf := read(t, "honeypot/Containerfile")
	for _, want := range []string{"--require-hashes", "--only-binary=:all:", "--no-deps", "-none-any", "--no-build-isolation"} {
		if !strings.Contains(cf, want) {
			t.Errorf("honeypot/Containerfile: missing %q", want)
		}
	}
	for _, l := range strings.Split(cf, "\n") {
		if strings.Contains(l, "pip install") && !strings.Contains(l, "--require-hashes") && !strings.Contains(l, "--no-index") {
			t.Errorf("honeypot/Containerfile: a pip install that is neither hash-checked nor from local wheels: %q", l)
		}
	}
}

// The image fits the unit host/ops writes: the path of the health command, the mounts, the capability, the user the unit's UserNS=auto can map,
// the audit path core writes into opencanary.conf, and the read-only root (everything writable is under /tmp or in the two volumes).
func TestHoneypotImageFitsItsUnit(t *testing.T) {
	t.Parallel()
	u := honeypotUnit(t)
	cf := read(t, "honeypot/Containerfile")
	ini := read(t, "honeypot/init.py")
	var health []string
	if err := json.Unmarshal([]byte(u["HealthCmd"][0]), &health); err != nil || len(health) != 3 {
		t.Fatalf("HealthCmd=%v: %v", u["HealthCmd"], err)
	}
	if !strings.Contains(cf, "COPY --from=build /out/vedette "+health[0]+"\n") {
		t.Errorf("the image must hold the core binary at %q, the path of the unit's HealthCmd", health[0])
	}
	if !strings.Contains(cf, "./cmd/vedette\n") || !strings.Contains(cf, "CGO_ENABLED=0") {
		t.Error("the health binary is the static (no cgo) build of ./cmd/vedette: nothing of it can link a GPL library")
	}
	if !slices.Equal(u["DropCapability"], []string{"ALL"}) || !slices.Equal(u["AddCapability"], []string{"SETUID"}) {
		t.Errorf("capabilities Drop=%v Add=%v: ALL dropped and SETUID alone added (init.py needs it once, to drop root)", u["DropCapability"], u["AddCapability"])
	}
	if u["NoNewPrivileges"][0] != "true" || u["ReadOnly"][0] != "true" || u["Tmpfs"][0] != "/tmp" || u["UserNS"][0] != "auto" {
		t.Errorf("hardening lines of the unit changed: %v", u)
	}
	// the mounts: init.py and the image use the paths the unit mounts to
	var conf, log string
	for _, v := range u["Volume"] {
		parts := strings.Split(v, ":")
		switch {
		case strings.HasSuffix(parts[0], "/config"):
			conf = parts[1]
		case strings.HasSuffix(parts[0], "/log"):
			log = parts[1]
			if len(parts) != 3 || parts[2] != "U" {
				t.Errorf("the log volume %q needs :U so the container's user owns it under UserNS=auto", v)
			}
		}
	}
	if initConst(ini, "CONF_DIR") != conf || initConst(ini, "LOG_DIR") != log || conf == "" || log == "" {
		t.Errorf("init.py CONF_DIR=%q LOG_DIR=%q, the unit mounts %q and %q", initConst(ini, "CONF_DIR"), initConst(ini, "LOG_DIR"), conf, log)
	}
	if !strings.Contains(cf, "ln -s "+conf+" /rootfs/etc/opencanaryd") {
		t.Errorf("OpenCanary finds opencanary.conf at /etc/opencanaryd: the image must link it to %s", conf)
	}
	// core writes the Samba audit path into opencanary.conf (modules/honeypot/opencanary.go); /var/log is read-only, so it is a link into /tmp
	conf2, err := honeypot.RenderConfig(honeypot.ConfigInput{LogPath: log + "/opencanary.jsonl", Enabled: []honeypot.ServiceName{honeypot.SMB, honeypot.SSH}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(conf2, &cfg); err != nil {
		t.Fatal(err)
	}
	audit, _ := cfg["smb.auditfile"].(string)
	if audit == "" || !strings.Contains(cf, "ln -s "+initConst(ini, "AUDIT")+" /rootfs"+audit) {
		t.Errorf("smb.auditfile %q must be a link to init.py's AUDIT %q", audit, initConst(ini, "AUDIT"))
	}
	if !strings.HasPrefix(initConst(ini, "AUDIT"), "/tmp/") || !strings.HasPrefix(initConst(ini, "SHARE"), "/tmp/") || !strings.Contains(read(t, "honeypot/smb.conf"), "path = "+initConst(ini, "SHARE")+"\n") {
		t.Error("the audit file and the share are on the tmpfs, and smb.conf serves init.py's SHARE")
	}
	for _, line := range strings.Split(read(t, "honeypot/smb.conf"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && strings.HasSuffix(strings.TrimSpace(k), "directory") || strings.Contains(line, "private dir") {
			if !strings.Contains(v, "/tmp/samba") {
				t.Errorf("smb.conf: %q is not under /tmp (the root is read-only)", line)
			}
		}
	}
	// UserNS=auto maps a range that starts at 0: the unprivileged uid must be inside the smallest range podman picks (1024)
	uid, err := strconv.Atoi(initConst(ini, "UID"))
	if err != nil || uid < 1 || uid > 1023 {
		t.Errorf("init.py UID=%q must be a non-root uid below 1024 (the least UserNS=auto maps)", initConst(ini, "UID"))
	}
	if !strings.Contains(cf, "hp:x:"+strconv.Itoa(uid)+":0:") {
		t.Errorf("the image's passwd has no user hp with uid %d, gid 0 (Samba's guest account)", uid)
	}
	if !strings.Contains(read(t, "honeypot/smb.conf"), "guest account = hp") {
		t.Error("smb.conf: the guest account is hp, the user Samba runs as (it cannot switch user)")
	}
	// exec form, no shell, the init that the image copies
	if !strings.Contains(cf, `ENTRYPOINT ["/usr/bin/python3", "-I", "/usr/local/lib/vedette-hp/init.py"]`) || !strings.Contains(cf, "deploy/containers/honeypot/init.py /usr/local/lib/vedette-hp/init.py\n") {
		t.Error("ENTRYPOINT must be the exec form of init.py at the path the image copies it to")
	}
	// the drop is checked in code: root must not be regainable, and nothing starts before it
	for _, want := range []string{"os.setuid(UID)", "os.setuid(0)", "except PermissionError", "root can be regained"} {
		if !strings.Contains(ini, want) {
			t.Errorf("init.py: missing %q", want)
		}
	}
	if i, j := strings.Index(ini, "drop_privileges()\n"), strings.Index(ini, "spawn(["); i < 0 || j < 0 || i > j {
		t.Error("init.py must drop privileges before it starts any child")
	}
	// OpenCanary's traps the module may enable have ports; the health check reads them from the same file, so the image holds no port list
	if strings.Contains(cf, "EXPOSE") {
		t.Error("the unit decides what is reachable (a namespace of macvlan addresses): no EXPOSE")
	}
}

// The honeypot's audit prefix is the shape init.py accepts, and every field of it is one the server decides (never the client's user, domain,
// machine name or path), the rule the sink's sanitising rests on.
func TestHoneypotAuditPrefixHoldsOnlyServerValues(t *testing.T) {
	t.Parallel()
	smb := read(t, "honeypot/smb.conf")
	m := regexp.MustCompile(`(?m)^\s*full_audit:prefix = (\S+)$`).FindStringSubmatch(smb)
	if m == nil {
		t.Fatal("no full_audit:prefix in smb.conf")
	}
	fields := strings.Split(m[1], "|")
	if len(fields) != 6 {
		t.Fatalf("prefix %q has %d fields, init.py expects 6 before op|status|path", m[1], len(fields))
	}
	for _, f := range fields {
		switch f { // %I client address, %i server address, %L server name, %R protocol, %a client OS class, %S share
		case "%I", "%i", "%L", "%R", "%a", "%S":
		default:
			t.Errorf("prefix field %s is not decided by the server: the client controls %%U, %%u, %%m, %%D, %%h and the path", f)
		}
	}
	for _, want := range []string{"map to guest = Bad User", "read only = yes", "guest ok = yes", "disable netbios = yes", "full_audit:success = connect openat", "load printers = no"} {
		if !strings.Contains(smb, want) {
			t.Errorf("smb.conf: missing %q", want)
		}
	}
	if strings.Contains(smb, "read only = no") || strings.Contains(smb, "writable") || strings.Contains(smb, "writeable") || strings.Contains(smb, "server string = Samba") {
		t.Error("smb.conf: the share is read-only and the banner is generic")
	}
}

func python(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	return p
}

// The sink that turns Samba's syslog audit into the line OpenCanary's smb module parses (init.py audit_line) is driven with hostile inputs, and
// each result is parsed the way the module does (opencanary/modules/samba.py: the text after the LAST ": " of the line, split on "|"): the
// fields the module reads must be the server's, and a client's bytes must never add a field, a line or a source address.
func TestHoneypotSinkRefusesForgedAuditLines(t *testing.T) {
	t.Parallel()
	py := python(t)
	prefix := "<190>Nov 11 05:25:06 smbd_audit[42]: "
	good := "192.168.1.5|192.168.1.240|FILESERVER|SMB3_11|Win10|Shared|openat|ok|"
	cases := []string{
		prefix + good + "passwords.txt",                                                // 0: normal
		prefix + strings.Replace(good, "192.168.1.5", "::ffff:192.168.1.5", 1) + "a.txt", // 1: IPv4 as IPv6-mapped
		prefix + good + "a|6.6.6.6|7.7.7.7|x|y|z|openat|ok|b",                          // 2: '|' in the path
		prefix + good + "x\nsmbd_audit: |6.6.6.6|1.1.1.1|a|b|c|d|e||openat|ok|forged",    // 3: a forged second line
		prefix + good + "x: |6.6.6.6|1.1.1.1|a|b|c|d|e||openat|ok|forged",              // 4: ": " would move the module's cut
		prefix + good + strings.Repeat("A", 5000),                                      // 5: long
		prefix + good + "café\x00\x1b[31m\r.txt",                                  // 6: non-ASCII and control characters
		prefix + "evil|192.168.1.240|FILESERVER|SMB3_11|Win10|Shared|openat|ok|a",      // 7: source is not an address
		prefix + "192.168.1.5|192.168.1.240|FILESERVER|SMB3_11|Win10|Shared|unlink|ok|a", // 8: an operation we do not audit
		prefix + "192.168.1.5|192.168.1.240|FILESERVER|SMB3_11|Win10|Shared|openat|maybe|a", // 9: a status Samba never writes
		prefix + "192.168.1.5|192.168.1.240|FILESERVER|SMB3_11|Win10|openat|ok|a",       // 10: a field short (a '|' moved by the client)
		"<190>Nov 11 05:25:06 sshd: 192.168.1.5|1|2|3|4|5|openat|ok|a",                  // 11: not ours
		prefix + "192.168.1.5|192.168.1.240|FILE SERVER|SMB3_11|Win10|Shared|openat|ok|a", // 12: a space where the server decides a word
		prefix + good,                                                                  // 13: an empty path (a share root)
		prefix + "256.1.1.1|192.168.1.240|FILESERVER|SMB3_11|Win10|Shared|openat|ok|a", // 14: not an IPv4 address
		prefix + good + "r|/tmp/share/Q4 payroll.xlsx",                                  // 15: what Samba writes for an open: mode|absolute path
	}
	in, _ := json.Marshal(cases)
	code := "import importlib.util, json, sys\n" +
		"s = importlib.util.spec_from_file_location('hpinit', sys.argv[1]); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n" +
		"print(json.dumps([m.audit_line(c.encode('utf-8')) for c in json.load(sys.stdin)]))\n"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, py, "-I", "-c", code, "honeypot/init.py") //nolint:gosec // test: fixed argv, python3 from PATH
	cmd.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3: %v\n%s", err, stderr.String())
	}
	var got []*string
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(cases) {
		t.Fatalf("output %q: %v", out, err)
	}
	// what the module's regexp `^.*smbd_audit.*: (.*$)` takes, then split("|")
	moduleRE := regexp.MustCompile(`^.*smbd_audit.*: (.*)$`)
	fieldsOf := func(line string) []string {
		m := moduleRE.FindStringSubmatch(strings.TrimSuffix(line, "\n"))
		if m == nil {
			return nil
		}
		return strings.Split(m[1], "|")
	}
	refused := map[int]bool{7: true, 8: true, 9: true, 10: true, 11: true, 12: true, 14: true}
	for i, g := range got {
		if refused[i] {
			if g != nil {
				t.Errorf("case %d must be refused, got %q", i, *g)
			}
			continue
		}
		if g == nil {
			t.Errorf("case %d must be accepted", i)
			continue
		}
		line := *g
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || strings.ContainsAny(strings.TrimSuffix(line, "\n"), "\r\x00\x1b") {
			t.Errorf("case %d: not exactly one clean line: %q", i, line)
		}
		f := fieldsOf(line)
		if len(f) != 13 {
			t.Errorf("case %d: the module would see %d fields, want 13: %q", i, len(f), line)
			continue
		}
		if f[1] != "192.168.1.5" || f[2] != "192.168.1.240" || f[4] != "Shared" || f[5] != "FILESERVER" || f[10] != "openat" || f[11] != "ok" {
			t.Errorf("case %d: the module's fields are not the server's: %q", i, f)
		}
		if len(f[12]) > 200 || strings.Contains(f[12], "|") {
			t.Errorf("case %d: path %q", i, f[12])
		}
	}
	if want := "smbd_audit: |192.168.1.5|192.168.1.240|192.168.1.5|Shared|FILESERVER|SMB3_11|Win10|||openat|ok|passwords.txt\n"; got[0] == nil || *got[0] != want {
		t.Errorf("case 0 = %v, want %q", got[0], want)
	}
	if got[15] == nil || !strings.HasSuffix(*got[15], "|openat|ok|/Q4 payroll.xlsx\n") {
		t.Errorf("case 15 = %v: the mode and the share's folder are dropped, the name is kept", got[15])
	}
	if got[3] != nil &&!strings.HasPrefix(fieldsOf(*got[3])[12], "x?") {
		t.Errorf("a forged line in the path survived: %q", *got[3])
	}
}

// make honeypot-check runs the image with the files core's own code writes (honeypot.RenderConfig, RenderTokens, the log path of the unit's
// mount): this writes them into VEDETTE_HP_OUT. Without the variable it does nothing.
func TestHoneypotWriteFixture(t *testing.T) {
	out := os.Getenv("VEDETTE_HP_OUT")
	if out == "" {
		t.Skip("VEDETTE_HP_OUT is not set (make honeypot-check sets it)")
	}
	conf, err := honeypot.RenderConfig(honeypot.ConfigInput{
		Enabled: honeypot.Services, LogPath: "/var/lib/vedette/honeypot/log/opencanary.jsonl", FileNames: []string{"passwords.txt", "Q4 payroll.xlsx"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := honeypot.RenderTokens([]string{"passwords.txt", "Q4 payroll.xlsx"})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{honeypot.ConfFile: conf, honeypot.TokensFile: tokens} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil { //nolint:gosec // a fixture the container reads
			t.Fatal(err)
		}
	}
}

// By effect (make honeypot-check sets VEDETTE_HP_LOGFILE to the log the running container wrote): every line is one honeypot.ParseLine accepts,
// and the log types named in VEDETTE_HP_WANT are all present. Without the variable the test has nothing to read and is skipped.
func TestHoneypotLogFileParses(t *testing.T) {
	path := os.Getenv("VEDETTE_HP_LOGFILE")
	if path == "" {
		t.Skip("VEDETTE_HP_LOGFILE is not set (make honeypot-check sets it)")
	}
	b, err := os.ReadFile(path) //nolint:gosec // test: the path comes from the check script
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]int{}
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var raw struct {
			LogType int `json:"logtype"`
		}
		if json.Unmarshal(l, &raw) != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if raw.LogType < 2000 { // OpenCanary's own boot/ping lines (1000-1006) are not hits: core skips them by log type
			continue
		}
		rec, err := honeypot.ParseLine(l)
		if err != nil {
			t.Errorf("honeypot.ParseLine refused %q: %v", l, err)
			continue
		}
		seen[rec.LogType]++
		t.Logf("parsed: logtype=%d src=%s dst=%s dport=%d file=%q user=%q", rec.LogType, rec.Src, rec.Dst, rec.DstPort, rec.Filename, rec.User)
	}
	for _, w := range strings.Split(os.Getenv("VEDETTE_HP_WANT"), ",") {
		if w == "" {
			continue
		}
		n, _ := strconv.Atoi(w)
		if seen[n] == 0 {
			t.Errorf("no line of log type %d in %s (saw %v)", n, path, seen)
		}
	}
}

// No GPL or AGPL code is linked into a Vedette binary. The binaries are static (CGO_ENABLED=0 in every Containerfile and in make host-deb), so no
// C library can be linked in; this reads the licence file of every Go module that each binary links (`go list -deps`, from the module cache) and
// fails on a GPL, LGPL or AGPL text. Samba (GPL-3) is in the honeypot image as a separate process of the Debian package, started by init.py with
// exec: no Vedette binary imports or links it.
func TestNoGPLIsLinkedIntoVedetteBinaries(t *testing.T) {
	t.Parallel()
	gpl := regexp.MustCompile(`(?i)GNU\s+(AFFERO\s+|LESSER\s+|LIBRARY\s+)?GENERAL\s+PUBLIC\s+LICENSE`)
	licenseName := regexp.MustCompile(`(?i)^(licen[sc]e|copying|unlicense|notice)([-._].*)?$`)
	for _, bin := range []string{"vedette", "vedette-host", "vedette-sensor"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		cmd := exec.CommandContext(ctx, "go", "list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Dir}}{{end}}", "./cmd/"+bin) //nolint:gosec // test: fixed argv
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly", "CGO_ENABLED=0", "GOOS=linux")
		out, err := cmd.Output()
		cancel()
		if err != nil {
			t.Fatalf("go list %s: %v", bin, err)
		}
		mods := map[string]string{}
		for _, l := range strings.Split(string(out), "\n") {
			if path, dir, ok := strings.Cut(l, " "); ok && dir != "" {
				mods[path] = dir
			}
		}
		if len(mods) < 2 { // the main module and golang.org/x/sys at least: an empty list would make the check pass for nothing
			t.Fatalf("%s: only %d modules found: %v", bin, len(mods), mods)
		}
		for path, dir := range mods {
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			for _, e := range ents {
				if e.IsDir() || !licenseName.MatchString(e.Name()) {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // a licence file of a module in the module cache
				if err != nil {
					t.Fatal(err)
				}
				if len(b) > 4096 {
					b = b[:4096] // the title is at the top; later mentions (an MPL "Secondary License" clause) are not the licence itself
				}
				if gpl.Match(b) {
					t.Errorf("%s links module %s whose %s is a GPL-family licence", bin, path, e.Name())
				}
			}
		}
	}
}
