package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/chain"
	"github.com/knt048/vedette/host/api"
)

func TestRedactArgs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain values stay", `{"name":"eth0","count":3,"on":true,"x":null}`, `{"count":3,"name":"eth0","on":true,"x":null}`},
		{"sensitive key", `{"password":"hunter2","api_key":"abc","Authorization":"x","token":"t","private_key":"k"}`, `{"Authorization":"[redacted]","api_key":"[redacted]","password":"[redacted]","private_key":"[redacted]","token":"[redacted]"}`},
		{"empty sensitive value is not a secret", `{"token":""}`, `{"token":""}`},
		{"vedette token", `{"v":"vdt_osquery_0123456789abcdef"}`, `{"v":"[redacted]"}`},
		{"slack", `{"a":"xapp-1-A0123-456","b":"xoxb-123-456-abc"}`, `{"a":"[redacted]","b":"[redacted]"}`},
		{"bearer", `{"h":"Bearer abc.def"}`, `{"h":"[redacted]"}`},
		{"password=", `{"u":"https://x/?password=abc"}`, `{"u":"[redacted]"}`},
		{"jwt", `{"j":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}`, `{"j":"[redacted]"}`},
		{"pem", `{"k":"-----BEGIN PRIVATE KEY-----\nabc"}`, `{"k":"[redacted]"}`},
		{"github pat", `{"p":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}`, `{"p":"[redacted]"}`},
		{"long mixed token", `{"t":"aB3dE5gH7jK9mN1pQ3sT5vW7yZ"}`, `{"t":"[redacted]"}`},
		{"hex id is not a token", `{"backup_id":"0123456789abcdef0123456789abcdef"}`, `{"backup_id":"0123456789abcdef0123456789abcdef"}`},
		{"uuid is not a token", `{"id":"11111111-1111-4111-8111-111111111111"}`, `{"id":"11111111-1111-4111-8111-111111111111"}`},
		{"version and cidr", `{"v":"1.2.3","c":"192.168.1.0/24","t":"2026-11-09T10:00:00Z"}`, `{"c":"192.168.1.0/24","t":"2026-11-09T10:00:00Z","v":"1.2.3"}`},
		{"nested", `{"mgmt":{"dns":["1.1.1.1"],"secret":"s"}}`, `{"mgmt":{"dns":["1.1.1.1"],"secret":"[redacted]"}}`},
		{"float and huge numbers", `{"f":1.5,"b":123456789012345678901234567890}`, `{"b":"[number]","f":"[number]"}`},
		{"long string", `{"s":"` + strings.Repeat("a b ", 100) + `"}`, `{"s":"[truncated]"}`},
		{"not json", `{nope`, `null`},
		{"empty", ``, `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := json.Marshal(redactArgs([]byte(tt.in)))
			if err != nil || string(b) != tt.want {
				t.Fatalf("redactArgs(%s)\n got %s (%v)\nwant %s", tt.in, b, err, tt.want)
			}
		})
	}
}

func TestRedactBounds(t *testing.T) {
	t.Parallel()
	var items []string
	for i := range 100 {
		items = append(items, fmt.Sprintf(`"item number %d"`, i))
	}
	big := redactArgs([]byte(`{"a":[` + strings.Join(items, ",") + `]}`))
	c, err := chain.Canon(big)
	if err != nil || len(c) > redactMaxCanon {
		t.Fatalf("canon len %d err %v", len(c), err)
	}
	deep := strings.Repeat(`{"a":`, 50) + `1` + strings.Repeat(`}`, 50)
	if c, err := chain.Canon(redactArgs([]byte(deep))); err != nil || !strings.Contains(string(c), truncatedMarker) {
		t.Fatalf("deep: %s %v", c, err)
	}
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf(`"k%02d":%d`, i, i))
	}
	got := redactArgs([]byte(`{` + strings.Join(many, ",") + `}`)).(map[string]any)
	if len(got) != redactMaxItems+1 || got["_truncated"] != true {
		t.Fatalf("object keys: %d", len(got))
	}
}

func FuzzRedactArgs(f *testing.F) {
	f.Add(`{"a":["b",{"c":1.5}],"token":"x"}`)
	f.Add(`[[[[[[[[[[1]]]]]]]]]]`)
	f.Add(`"just a string"`)
	f.Fuzz(func(t *testing.T, s string) {
		out := redactArgs([]byte(s))
		c, err := chain.Canon(out)
		if err != nil {
			t.Fatalf("not canonicalisable: %v", err)
		}
		if len(c) > redactMaxCanon {
			t.Fatalf("too large: %d", len(c))
		}
		if strings.Contains(string(c), "vdt_osquery_0123456789abcdef") {
			t.Fatal("secret survived")
		}
	})
}

func TestEventLogBounds(t *testing.T) {
	t.Parallel()
	l := newEventLog(time.Now)
	for i := range maxEvents + 25 {
		l.add(api.Event{Kind: api.KindLog, Line: fmt.Sprint("line ", i)})
	}
	evs, _, done := l.since(0)
	if done || len(evs) != maxEvents {
		t.Fatalf("kept %d events (done=%v)", len(evs), done)
	}
	if evs[0].Seq != 26 || evs[len(evs)-1].Seq != uint64(maxEvents+25) {
		t.Fatalf("seq range %d..%d", evs[0].Seq, evs[len(evs)-1].Seq)
	}
	for _, e := range evs {
		if !e.Truncated {
			t.Fatal("event without truncated=true after drops")
		}
	}
	// Resume after a dropped range starts at the oldest kept event.
	evs, _, _ = l.since(3)
	if len(evs) != maxEvents || evs[0].Seq != 26 {
		t.Fatalf("resume: %d events from %d", len(evs), evs[0].Seq)
	}
	l.finish()
	if _, _, done := l.since(0); !done {
		t.Fatal("not done after finish")
	}
	l.add(api.Event{Kind: api.KindLog, Line: "late"}) // a leaked handler writing after the run: ignored
	if evs, _, _ := l.since(uint64(maxEvents + 25)); len(evs) != 0 {
		t.Fatal("event accepted after finish")
	}
}

func TestEventLogByteCap(t *testing.T) {
	t.Parallel()
	l := newEventLog(time.Now)
	line := strings.Repeat("x", maxEventLine)
	for range 6000 { // 6000 x 2 KiB = 12 MiB > the 8 MiB cap
		l.add(api.Event{Kind: api.KindLog, Line: line})
	}
	evs, _, _ := l.since(0)
	if len(evs)*maxEventLine > maxEventBytes+64*len(evs) || len(evs) >= 6000 {
		t.Fatalf("kept %d events of 2 KiB", len(evs))
	}
}

func TestCleanLine(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"tab\there", "tab here"},
		{"line1\nline2\r\n", "line1 line2  "},
		{"nul\x00and bell\a", "nul and bell "},
		{"bad \xff utf8", "bad ? utf8"},
		{"esc\x1b[31mred", "esc [31mred"},
	}
	for _, tt := range tests {
		if got := cleanLine(tt.in); got != tt.want {
			t.Errorf("cleanLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	long := cleanLine(strings.Repeat("é", 3000)) // 2-byte runes: must not cut one in half
	if len(long) > maxEventLine || strings.ContainsRune(long, '�') {
		t.Fatalf("len %d", len(long))
	}
	if got := cleanLine(strings.Repeat("a", 5000)); len(got) != maxEventLine {
		t.Fatalf("len %d", len(got))
	}
}

func TestPruneRetention(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := openRunStore(filepath.Join(dir, "state"), os.Getuid(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	put := func(i int, age time.Duration, st api.Status) string {
		id := fmt.Sprintf("rn_%016x", i)
		fin := now.Add(-age)
		r := api.Run{RunID: id, Command: "test.echo", Status: st, StartedAt: now.Add(-age), FinishedAt: &fin}
		if err := s.put(storedRun{Run: r}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.eventsPath(id), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		return id
	}
	old := put(1, 91*24*time.Hour, api.StatusSucceeded)
	running := put(2, 200*24*time.Hour, api.StatusRunning) // never pruned, however old
	var newest string
	for i := range 520 {
		newest = put(100+i, time.Duration(520-i)*time.Minute, api.StatusSucceeded)
	}
	oldest := fmt.Sprintf("rn_%016x", 100)
	rec := idemRecord{RequestID: "11111111-1111-4111-8111-111111111111", Command: "c", RunID: newest, At: now.Add(-31 * 24 * time.Hour)}
	if err := s.idemPut(rec); err != nil {
		t.Fatal(err)
	}
	fresh := idemRecord{RequestID: "22222222-2222-4222-8222-222222222222", Command: "c", RunID: newest, At: now.Add(-time.Hour)}
	if err := s.idemPut(fresh); err != nil {
		t.Fatal(err)
	}
	gone := idemRecord{RequestID: "33333333-3333-4333-8333-333333333333", Command: "c", RunID: old, At: now}
	if err := s.idemPut(gone); err != nil {
		t.Fatal(err)
	}

	s.prune(now)

	if _, ok := s.get(old); ok {
		t.Error("a 91-day-old run survived")
	}
	if _, ok := s.get(oldest); ok {
		t.Error("the 521st newest run survived the 500 cap")
	}
	if _, ok := s.get(running); !ok {
		t.Error("a non-terminal run was pruned")
	}
	if _, ok := s.get(newest); !ok {
		t.Error("the newest run was pruned")
	}
	if n := len(s.list(1000)); n != 501 { // 500 terminal + the running one
		t.Errorf("%d runs kept", n)
	}
	if _, err := os.Stat(s.eventsPath(old)); !os.IsNotExist(err) {
		t.Error("events file of a pruned run survived")
	}
	if _, ok := s.idemGet(rec.RequestID); ok {
		t.Error("a 31-day-old idempotency record survived")
	}
	if _, ok := s.idemGet(fresh.RequestID); !ok {
		t.Error("a fresh idempotency record was pruned")
	}
	if _, ok := s.idemGet(gone.RequestID); ok {
		t.Error("an idempotency record of a pruned run survived")
	}
	// Files and memory agree after a reload.
	s2, err := openRunStore(filepath.Join(dir, "state"), os.Getuid(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s2.list(1000)); n != 501 {
		t.Errorf("%d runs after reload", n)
	}
}

func TestRunFilesAre0600(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	s, err := openRunStore(filepath.Join(dir, "state"), os.Getuid(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.put(storedRun{Run: api.Run{RunID: "rn_0123456789abcdef", Status: api.StatusSucceeded, StartedAt: now, FinishedAt: &now}}); err != nil {
		t.Fatal(err)
	}
	if err := s.idemPut(idemRecord{RequestID: "11111111-1111-4111-8111-111111111111", At: now}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(dir, "state", "runs", "rn_0123456789abcdef.json"),
		filepath.Join(dir, "state", "idem", "11111111-1111-4111-8111-111111111111.json"),
	} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	for _, d := range []string{"runs", "idem"} {
		st, err := os.Stat(filepath.Join(dir, "state", d))
		if err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s dir: %v %v", d, st, err)
		}
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "state", "runs"))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, distro, release string
	}{
		{"ubuntu", "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n", "ubuntu", "24.04"},
		{"debian unquoted", "ID=debian\nVERSION_ID=13\n", "debian", "13"},
		{"single quotes", "ID='debian'\nVERSION_ID='13'", "debian", "13"},
		{"missing", "NAME=x\n", "unknown", "unknown"},
		{"empty", "", "unknown", "unknown"},
		{"injection attempt", "ID=ubuntu; rm -rf /\nVERSION_ID=$(id)\n", "unknown", "unknown"},
		{"spaces around", " ID = ubuntu \n VERSION_ID = \"22.04\" \n", "ubuntu", "22.04"},
		{"too long", "ID=" + strings.Repeat("a", 40) + "\n", "unknown", "unknown"},
		{"last wins", "ID=a\nID=b\n", "b", "unknown"},
		{"id_like ignored", "ID_LIKE=debian\n", "unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, r := ParseOSRelease([]byte(tt.in))
			if d != tt.distro || r != tt.release {
				t.Fatalf("got %q %q, want %q %q", d, r, tt.distro, tt.release)
			}
		})
	}
}

func FuzzParseOSRelease(f *testing.F) {
	f.Add([]byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"))
	f.Add([]byte("ID=\"\nVERSION_ID='\n=\n=="))
	f.Fuzz(func(t *testing.T, data []byte) {
		d, r := ParseOSRelease(data)
		for _, v := range []string{d, r} {
			if v != "unknown" && !osTokenRE.MatchString(v) {
				t.Fatalf("unsafe token %q", v)
			}
		}
	})
}

func shortTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "vi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// Review M3: the socket directory must be owned by the host user and the socket group, not just have a safe mode.
func TestListenChecksDirectoryOwnerAndGroup(t *testing.T) {
	t.Parallel()
	dir := shortTemp(t)
	sockDir := filepath.Join(dir, "run")
	if err := os.Mkdir(sockDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sockDir, 0o750); err != nil { //nolint:gosec // the directory must have the exact mode 0750 under test
		t.Fatal(err)
	}
	if err := os.Lchown(sockDir, -1, os.Getgid()); err != nil {
		t.Fatal(err)
	}
	listen := func(owner, gid int, path string) error {
		s := &Server{o: Options{SocketPath: path, OwnerUID: owner, SocketGID: gid}}
		ln, err := s.Listen(t.Context())
		if err == nil {
			_ = ln.Close()
		}
		return err
	}
	if err := listen(os.Getuid()+1, os.Getgid(), filepath.Join(sockDir, "a.sock")); err == nil {
		t.Error("a directory owned by another uid was accepted")
	}
	if err := listen(os.Getuid(), os.Getgid()+1, filepath.Join(sockDir, "a.sock")); err == nil {
		t.Error("a directory of another group was accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(sockDir, link); err != nil {
		t.Fatal(err)
	}
	if err := listen(os.Getuid(), os.Getgid(), filepath.Join(link, "a.sock")); err == nil {
		t.Error("a symlinked socket directory was accepted")
	}
	if err := listen(os.Getuid(), os.Getgid(), filepath.Join(sockDir, "ok.sock")); err != nil {
		t.Errorf("the right owner and group: %v", err)
	}
}

// Review M3: if the socket path was swapped for a symlink between bind and chown/chmod, nothing behind it is touched.
func TestSecureSocketNeverFollowsASymlink(t *testing.T) {
	t.Parallel()
	dir := shortTemp(t)
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "h.sock")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := secureSocket(path, os.Getgid()); err == nil {
		t.Fatal("a symlink was accepted as the socket")
	}
	if st, err := os.Stat(victim); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("the symlink target was modified: %v %v", st, err)
	}
}

// The server must not set ReadTimeout: it would cut live event streams (found in review).
func TestHTTPServerHasNoReadTimeout(t *testing.T) {
	t.Parallel()
	s := &Server{log: slog.New(slog.DiscardHandler)}
	if hs := s.newHTTPServer(); hs.ReadTimeout != 0 || hs.WriteTimeout != 0 || hs.ReadHeaderTimeout == 0 {
		t.Fatalf("ReadTimeout %v WriteTimeout %v ReadHeaderTimeout %v", hs.ReadTimeout, hs.WriteTimeout, hs.ReadHeaderTimeout)
	}
}

func TestRedactKeys(t *testing.T) {
	t.Parallel()
	got, _ := json.Marshal(redactArgs([]byte(`{"vdt_live_9fQ2xLm7Rt8Kp3Zw":1,"name":"x","ghp_abcdefghijklmnopqrstuvwxyz0123456789":2}`)))
	if strings.Contains(string(got), "vdt_live") || strings.Contains(string(got), "ghp_") || !strings.Contains(string(got), `"name":"x"`) {
		t.Fatalf("%s", got)
	}
}

func TestAmbiguousKeys(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]bool{
		`{"a":1,"A":2}`:             true,
		`{"a":1,"a":2}`:             true,
		`{"a":{"b":1,"B":2}}`:       true,
		`{"a":[{"b":1},{"B":2}]}`:   false, // different objects
		`{"a":{"b":1},"b":2}`:       false, // different levels
		`{"a":1,"b":{"a":2}}`:       false,
		`{"a":[1,2,{"x":1,"X":1}]}`: true,
		`{"a":1}`:                   false,
		`[]`:                        false,
		`{`:                         false,
		`{"a":"A","b":"B"}`:         false, // values are not keys
		`{"a":{"x":1},"A":{"y":2}}`: true,
		`{"k":[],"K":[]}`:           true,
		`{"a":{"x":1},"b":{"x":1}}`: false,
	} {
		if got := ambiguousKeys([]byte(in)) != ""; got != want {
			t.Errorf("ambiguousKeys(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestThrottleBoundedKeys(t *testing.T) {
	t.Parallel()
	th := newAuditThrottle(time.Minute)
	now := time.Now()
	for i := range 5000 {
		th.allow(fmt.Sprint("uid:", i), now, i)
	}
	if len(th.state) > throttleMaxKeys+1 {
		t.Fatalf("%d keys", len(th.state))
	}
	ok, _, _ := th.allow("brand-new", now, 1)
	_ = ok // lands in the shared overflow key, still throttled, never unbounded
}
