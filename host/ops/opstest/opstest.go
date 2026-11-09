// Package opstest builds a fake machine for tests of host/ops, host/client and the host contract:
// a temporary root directory with the files the commands read (os-release, dpkg lock files, boot
// id, apt.conf.d, core's data directory with a real SQLite database and key), and fake binaries,
// small shell scripts that record their argv and environment and print fixture files. Nothing here
// touches the real /etc, /var or /run, and nothing starts apt, dpkg or systemctl. It is test
// support: the binary never imports it (a contract test asserts that).
package opstest

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops"

	_ "modernc.org/sqlite" // the driver of core's database
)

// Bins are the binary names of the command runner.
var Bins = []string{"apt-get", "apt-config", "dpkg", "systemctl", "journalctl"}

// BootID is the boot id a fresh machine has.
const BootID = "11111111-2222-4333-8444-555555555555"

// Machine is the fake machine.
type Machine struct {
	Root     string // the Deps.Root
	State    string // the state directory of host and ops
	CoreData string // core's data directory (vedette.db, vedette.key)
	Bin      string // fake binaries
	Rec      string // recorded calls and markers
	Rules    string // behaviour rules of the fakes

	t testing.TB
}

// Fixture returns the path of a file of host/ops/testdata.
func Fixture(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "testdata", name)
}

// NewMachine creates the machine: Ubuntu 24.04, no lock held, apt.conf.d present, core's database
// (WAL mode, a migration table and a core_secret table) and key file, and fake binaries that
// succeed with empty output until a rule says otherwise.
func NewMachine(t testing.TB) *Machine {
	t.Helper()
	base, err := os.MkdirTemp("", "om")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	m := &Machine{
		Root: filepath.Join(base, "root"), State: filepath.Join(base, "state"), CoreData: filepath.Join(base, "core"),
		Bin: filepath.Join(base, "bin"), Rec: filepath.Join(base, "rec"), Rules: filepath.Join(base, "rules"), t: t,
	}
	for _, d := range []string{m.Root, m.Bin, m.Rec, m.Rules, filepath.Join(m.Root, "etc/apt/apt.conf.d"),
		filepath.Join(m.Root, "var/lib/dpkg"), filepath.Join(m.Root, "var/lib/apt/lists"), filepath.Join(m.Root, "var/cache/apt/archives"),
		filepath.Join(m.Root, "var/run"), filepath.Join(m.Root, "proc/sys/kernel/random")} {
		m.must(os.MkdirAll(d, 0o750))
	}
	m.must(os.MkdirAll(m.State, 0o700))
	m.must(os.MkdirAll(m.CoreData, 0o700))
	m.OSRelease("ubuntu", "24.04", "Ubuntu 24.04.3 LTS")
	m.WriteRoot("proc/sys/kernel/random/boot_id", BootID+"\n")
	m.WriteRoot("proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	m.WriteRoot("proc/uptime", "3600.55 12000.10\n")
	for _, f := range []string{"var/lib/dpkg/lock-frontend", "var/lib/dpkg/lock", "var/lib/apt/lists/lock", "var/cache/apt/archives/lock"} {
		m.WriteRoot(f, "")
	}
	for _, name := range Bins {
		m.writeFake(name)
	}
	m.NewCoreDB(map[string]int{"core": 3, "findings": 2}, 2)
	m.must(os.WriteFile(filepath.Join(m.CoreData, "vedette.key"), []byte("0123456789abcdef0123456789abcdef"), 0o600))
	return m
}

func (m *Machine) must(err error) {
	m.t.Helper()
	if err != nil {
		m.t.Fatal(err)
	}
}

// WriteRoot writes a file under the root.
func (m *Machine) WriteRoot(rel, content string) {
	m.t.Helper()
	p := filepath.Join(m.Root, rel)
	m.must(os.MkdirAll(filepath.Dir(p), 0o750))
	m.must(os.WriteFile(p, []byte(content), 0o600))
}

// RemoveRoot deletes a file under the root.
func (m *Machine) RemoveRoot(rel string) { _ = os.Remove(filepath.Join(m.Root, rel)) }

// ReadRoot reads a file under the root.
func (m *Machine) ReadRoot(rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join(m.Root, rel)) //nolint:gosec // test support: a path under the fake root
	return string(b), err
}

// OSRelease sets /etc/os-release.
func (m *Machine) OSRelease(id, version, pretty string) {
	m.WriteRoot("etc/os-release", fmt.Sprintf("ID=%s\nVERSION_ID=\"%s\"\nPRETTY_NAME=\"%s\"\n", id, version, pretty))
}

// SetBootID changes the boot id (a reboot happened).
func (m *Machine) SetBootID(id string) { m.WriteRoot("proc/sys/kernel/random/boot_id", id+"\n") }

// CoreDBPath is core's database file.
func (m *Machine) CoreDBPath() string { return filepath.Join(m.CoreData, "vedette.db") }

// NewCoreDB creates core's database in WAL mode with goose-style version tables (module -> highest
// version) and a core_secret table with the given number of rows, plus one data table. It leaves
// the connection closed (no -wal file stays behind unless a test opens it).
func (m *Machine) NewCoreDB(versions map[string]int, secrets int) {
	m.t.Helper()
	_ = os.Remove(m.CoreDBPath())
	db := m.OpenCoreDB()
	defer func() { _ = db.Close() }()
	stmts := []string{
		`CREATE TABLE core_secret (id TEXT PRIMARY KEY, purpose TEXT NOT NULL, ciphertext BLOB NOT NULL)`,
		`CREATE TABLE note (id INTEGER PRIMARY KEY, body TEXT NOT NULL)`,
		`INSERT INTO note(body) VALUES ('first')`,
	}
	for mod, v := range versions {
		stmts = append(stmts,
			fmt.Sprintf(`CREATE TABLE core_migration_%s (id INTEGER PRIMARY KEY, version_id INTEGER NOT NULL, is_applied INTEGER NOT NULL, tstamp TEXT)`, mod),
			fmt.Sprintf(`INSERT INTO core_migration_%s(version_id, is_applied) VALUES (0, 1)`, mod))
		for i := 1; i <= v; i++ {
			stmts = append(stmts, fmt.Sprintf(`INSERT INTO core_migration_%s(version_id, is_applied) VALUES (%d, 1)`, mod, i))
		}
	}
	for i := 0; i < secrets; i++ {
		stmts = append(stmts, fmt.Sprintf(`INSERT INTO core_secret VALUES ('sec-%d', 'test', x'00ff')`, i))
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(context.Background(), s); err != nil {
			m.t.Fatal(err)
		}
	}
	m.must(os.Chmod(m.CoreDBPath(), 0o600))
}

// OpenCoreDB opens core's database the way core does (WAL, one connection); the caller closes it.
func (m *Machine) OpenCoreDB() *sql.DB {
	m.t.Helper()
	db, err := sql.Open("sqlite", "file:"+m.CoreDBPath()+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		m.t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	return db
}

// Notes reads the body of every row of the note table of the database at path (core's by default).
func (m *Machine) Notes(path string) []string {
	m.t.Helper()
	if path == "" {
		path = m.CoreDBPath()
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		m.t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.QueryContext(context.Background(), `SELECT body FROM note ORDER BY id`)
	if err != nil {
		m.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var b string
		m.must(rows.Scan(&b))
		out = append(out, b)
	}
	return out
}

// Rule makes a fake binary answer: when the joined argv contains pattern (first matching rule
// wins, in the order the rules were added), print the fixture file (empty for no output) and exit
// with code. requires is a marker that must exist ("!name": must not exist); sets is a marker the
// rule creates when it fires. Markers let a fake change its answers after a call (a package list
// that shrinks once the install ran). A rule with the empty pattern matches every call.
func (m *Machine) Rule(bin, pattern, fixture string, code int, requires, sets string) {
	m.t.Helper()
	out := ""
	if fixture != "" {
		out = Fixture(fixture)
	}
	m.rule(bin, pattern, out, code, requires, sets)
}

// RuleText is Rule with the output given as text.
func (m *Machine) RuleText(bin, pattern, text string, code int, requires, sets string) {
	m.t.Helper()
	f, err := os.CreateTemp(m.Rec, "out-")
	m.must(err)
	_, err = f.WriteString(text)
	m.must(err)
	m.must(f.Close())
	m.rule(bin, pattern, f.Name(), code, requires, sets)
}

func (m *Machine) rule(bin, pattern, out string, code int, requires, sets string) {
	m.t.Helper()
	f, err := os.OpenFile(filepath.Join(m.Rules, bin), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // test support: a path under the fake rules dir
	m.must(err)
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintf(f, "%s|%s|%d|%s|%s\n", pattern, out, code, requires, sets)
	m.must(err)
}

// ClearRules removes the rules of a fake binary.
func (m *Machine) ClearRules(bin string) { _ = os.Remove(filepath.Join(m.Rules, bin)) }

// Mark creates (or, with on false, removes) a marker.
func (m *Machine) Mark(name string, on bool) {
	p := filepath.Join(m.Rec, "mark."+name)
	if on {
		m.must(os.WriteFile(p, nil, 0o600))
		return
	}
	_ = os.Remove(p)
}

// Marked reports whether a marker exists.
func (m *Machine) Marked(name string) bool {
	_, err := os.Stat(filepath.Join(m.Rec, "mark."+name))
	return err == nil
}

func (m *Machine) writeFake(name string) {
	script := `#!/bin/sh
REC='` + m.Rec + `'
RULES='` + m.Rules + `/` + name + `'
NAME='` + name + `'
if [ "$NAME" = systemctl ] && [ "$1" = reboot ]; then
  cat '` + m.State + `'/runs/rn_*.json > "$REC/runs-at-reboot.tmp" 2>/dev/null
  mv "$REC/runs-at-reboot.tmp" "$REC/runs-at-reboot.json"
fi
{
  echo "=== env"
  env | grep -v '^\(PWD\|SHLVL\|_\|OLDPWD\)=' | sort
} >> "$REC/$NAME.env"
{
  echo "=== call"
  printf 'arg:%s\n' "$@"
} >> "$REC/$NAME.calls"
[ -f "$RULES" ] || exit 0
args="$*"
while IFS='|' read -r pat out code req set; do
  case "$args" in *"$pat"*) ;; *) continue ;; esac
  if [ -n "$req" ]; then
    case "$req" in
      '!'*) [ -e "$REC/mark.${req#!}" ] && continue ;;
      *) [ -e "$REC/mark.$req" ] || continue ;;
    esac
  fi
  [ -n "$set" ] && : > "$REC/mark.$set"
  [ -n "$out" ] && cat "$out"
  exit "${code:-0}"
done < "$RULES"
exit 0
`
	m.must(os.WriteFile(filepath.Join(m.Bin, name), []byte(script), 0o755)) //nolint:gosec // a test fake must be executable
}

// BinPaths is the Deps.BinPaths of the fakes.
func (m *Machine) BinPaths() map[string]string {
	p := map[string]string{}
	for _, n := range Bins {
		p[n] = filepath.Join(m.Bin, n)
	}
	return p
}

// Calls returns the argv of each call a fake binary received, oldest first.
func (m *Machine) Calls(bin string) [][]string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, bin+".calls")) //nolint:gosec // test support: a path under the fake rec dir
	var out [][]string
	var cur []string
	flush := func() {
		// A call with no argument lines is a process the runner killed (a timed-out poll) between
		// writing its header and its arguments; every real call has at least one argument.
		if len(cur) > 0 {
			out = append(out, cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case line == "=== call":
			flush()
		case strings.HasPrefix(line, "arg:"):
			cur = append(cur, strings.TrimPrefix(line, "arg:"))
		}
	}
	flush()
	return out
}

// Envs returns, for each call of a fake binary, the environment it saw (KEY=value lines, sorted,
// without the variables the shell adds itself).
func (m *Machine) Envs(bin string) [][]string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, bin+".env")) //nolint:gosec // test support: a path under the fake rec dir
	var out [][]string
	var cur []string
	started := false
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case line == "=== env":
			if started {
				out = append(out, cur)
			}
			cur, started = []string{}, true
		case line != "":
			cur = append(cur, line)
		}
	}
	if started {
		out = append(out, cur)
	}
	return out
}

// AllCalls returns every call of every fake, as "binary arg arg ...".
func (m *Machine) AllCalls() []string {
	var out []string
	for _, n := range Bins {
		for _, c := range m.Calls(n) {
			out = append(out, n+" "+strings.Join(c, " "))
		}
	}
	return out
}

// RunsAtReboot is the content of the run files at the moment the fake systemctl got "reboot".
func (m *Machine) RunsAtReboot() string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "runs-at-reboot.json"))
	return string(b)
}

// Config is the ops.Config of this machine.
func (m *Machine) Config() ops.Config {
	return ops.Config{StateDir: m.State, CoreData: m.CoreData, CoreUnit: "vedette-core.service", Version: "test", OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler)}
}

// Deps is the ops.Deps of this machine: the temp root, the fake binaries, and quick polling. now may be nil.
func (m *Machine) Deps(now func() time.Time) ops.Deps {
	return ops.Deps{
		Root: m.Root, BinPaths: m.BinPaths(), Now: now,
		CoreWait: 3 * time.Second, CorePoll: 5 * time.Millisecond, HealthSettle: 10 * time.Millisecond,
		LockHeld: func(string) (bool, error) { return false, nil },
	}
}

// Ops builds ops.Ops on this machine; mutate may adjust the Deps and Config.
func (m *Machine) Ops(now func() time.Time, mutate ...func(*ops.Config, *ops.Deps)) *ops.Ops {
	m.t.Helper()
	cfg, d := m.Config(), m.Deps(now)
	for _, f := range mutate {
		f(&cfg, &d)
	}
	o, err := ops.NewWithDeps(cfg, d)
	if err != nil {
		m.t.Fatal(err)
	}
	return o
}
