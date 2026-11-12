// Package opstest builds a fake machine for tests of host/ops, host/client and the host contract:
// a temporary root directory with the files the commands read (os-release, dpkg lock files, boot
// id, apt.conf.d, core's data directory with a database file and a key), and fake binaries,
// small shell scripts that record their argv and environment and print fixture files. Nothing here
// touches the real /etc, /var or /run, and nothing starts apt, dpkg or systemctl. It is test
// support: the binary never imports it (a contract test asserts that).
//
// Core's database here is plain bytes, and so is a snapshot: the host never opens, parses or runs
// SQL on core's data (D-87), and no package under host/ imports a SQL driver (a contract test
// asserts that too), so the fake machine does not either.
package opstest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec/exectest"
	"github.com/knt048/vedette/host/ops"
)

// Bins are the binary names of the command runner.
var Bins = []string{"apt-get", "apt-config", "dpkg", "systemctl", "journalctl", "netplan", "chronyc", ops.BinIP, "podman", ops.BinIptables, ops.BinConntrack,
	"systemd-run", "dpkg-deb", "dpkg-query"}

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
// file (bytes) and key file, and fake binaries that succeed with empty output until a rule says
// otherwise.
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
	m.WriteRoot("usr/sbin/netplan", "") // CheckBackend wants the file (the fake binary lives in Bin)
	m.WriteRoot("proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	m.WriteRoot("proc/uptime", "3600.55 12000.10\n")
	for _, f := range []string{"var/lib/dpkg/lock-frontend", "var/lib/dpkg/lock", "var/lib/apt/lists/lock", "var/cache/apt/archives/lock"} {
		m.WriteRoot(f, "")
	}
	for _, name := range Bins {
		if name != ops.BinIptables {
			m.writeFake(name)
		}
	}
	m.StatefulIptables()
	m.StatefulIP() // Start makes the honeypot namespace, so every machine has an ip that remembers it
	m.WriteDB("db: first")
	m.must(os.WriteFile(filepath.Join(m.CoreData, "vedette.key"), []byte(Key), 0o600))
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

// Key is the content of the key file of a fresh machine.
const Key = "0123456789abcdef0123456789abcdef"

// Schema is the db_schema a snapshot reports unless a test says otherwise.
const Schema = "core=3,findings=2"

// WriteDB replaces core's database file by content (mode 0600, like core's own).
func (m *Machine) WriteDB(content string) {
	m.t.Helper()
	m.must(os.WriteFile(m.CoreDBPath(), []byte(content), 0o600))
}

// DB is the content of core's live database file.
func (m *Machine) DB() string {
	b, _ := os.ReadFile(m.CoreDBPath())
	return string(b)
}

// SnapOpts shapes a snapshot core writes.
type SnapOpts struct {
	At     time.Time // created_at (default: now of the machine's clock, see Snapshot)
	Schema string    // db_schema (default Schema)
	NoKey  bool      // includes_key false and no key file
	DB     *string   // database bytes (default: a copy of the live database)
}

// Snapshot writes what core writes before it calls the host (spec 6.11): snapshots/<id>/ in core's
// data directory with vedette.db (a copy of the live database), snapshot.json and, unless NoKey,
// vedette.key (a copy of the live key). at is the created_at. It returns the id.
func (m *Machine) Snapshot(at time.Time, mutate ...func(*SnapOpts)) string {
	m.t.Helper()
	o := SnapOpts{At: at, Schema: Schema}
	for _, f := range mutate {
		f(&o)
	}
	id, err := ops.RandomID()
	m.must(err)
	dir := filepath.Join(m.CoreData, "snapshots", id)
	m.must(os.MkdirAll(dir, 0o700))
	db := m.DB()
	if o.DB != nil {
		db = *o.DB
	}
	m.must(os.WriteFile(filepath.Join(dir, "vedette.db"), []byte(db), 0o600))
	if !o.NoKey {
		key, err := os.ReadFile(filepath.Join(m.CoreData, "vedette.key"))
		m.must(err)
		m.must(os.WriteFile(filepath.Join(dir, "vedette.key"), key, 0o600)) //nolint:gosec // test support: a path under the fake core directory
	}
	meta, err := json.Marshal(map[string]any{"created_at": o.At.UTC().Format(time.RFC3339), "db_schema": o.Schema, "includes_key": !o.NoKey})
	m.must(err)
	m.must(os.WriteFile(filepath.Join(dir, "snapshot.json"), meta, 0o600))
	return id
}

// SnapshotPath is the path of a file of a snapshot.
func (m *Machine) SnapshotPath(id, name string) string {
	return filepath.Join(m.CoreData, "snapshots", id, name)
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

func (m *Machine) writeFake(name string) { m.writeFakeWith(name, "") }

// writeFakeWith writes a fake binary: record the call, answer by the rules, then run tail (shell text) and succeed.
func (m *Machine) writeFakeWith(name, tail string) {
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
  export -p
} >> "$REC/$NAME.env"
{
  echo "=== call"
  printf 'arg:%s\n' "$@"
} >> "$REC/$NAME.calls"
[ -f "$RULES" ] || RULES=/dev/null
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
` + tail + `
exit 0
`
	exectest.WriteScript(m.t, filepath.Join(m.Bin, name), script) // under syscall.ForkLock: no ETXTBSY when parallel tests fork
}

// StatefulIptables makes (NewMachine does it) the fake iptables one that has no DOCKER-USER chain until the
// marker "docker-user" is set (every call then fails, like on a box without Docker); with the marker, "-S
// DOCKER-USER" prints the rules as "-A DOCKER-USER <rule>" lines, "-I DOCKER-USER <n> <rule>" puts the rule at
// position n and "-C DOCKER-USER <rule>" succeeds only for a remembered one (the same words; the real
// iptables compares the rule, not the words). DockerFlush forgets the rules (Docker restarted). Rules added with Rule fire first.
func (m *Machine) StatefulIptables() {
	m.writeFakeWith(ops.BinIptables, `R="$REC/ipt.rules"
[ -e "$REC/mark.docker-user" ] || exit 1
touch "$R"
case "$args" in
  "-w 5 -S DOCKER-USER") while IFS= read -r l; do echo "-A DOCKER-USER $l"; done < "$R"; exit 0 ;;
  "-w 5 -C DOCKER-USER "*) grep -qxF -- "${args#-w 5 -C DOCKER-USER }" "$R" 2>/dev/null; exit $? ;;
  "-w 5 -I DOCKER-USER "*)
    rest="${args#-w 5 -I DOCKER-USER }"; pos="${rest%% *}"; rule="${rest#* }"
    n=$(wc -l < "$R")
    [ "$pos" -le $((n + 1)) ] || { echo "index of insertion too big" >&2; exit 1; }
    { head -n $((pos - 1)) "$R"; echo "$rule"; tail -n +"$pos" "$R"; } > "$R.new"; mv "$R.new" "$R"; exit 0 ;;
esac
exit 2
`)
}

// DockerAdminRule appends a rule of the administrator's own (the words after the chain name) at the end of the fake DOCKER-USER chain.
func (m *Machine) DockerAdminRule(rule string) {
	f, err := os.OpenFile(filepath.Join(m.Rec, "ipt.rules"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	m.must(err)
	_, err = f.WriteString(rule + "\n")
	m.must(err)
	m.must(f.Close())
}

// DockerDelete removes one rule (the words after the chain name) from the fake DOCKER-USER chain.
func (m *Machine) DockerDelete(rule string) {
	var keep []string
	for _, l := range m.DockerRules() {
		if l != rule {
			keep = append(keep, l)
		}
	}
	text := ""
	if len(keep) > 0 {
		text = strings.Join(keep, "\n") + "\n"
	}
	m.must(os.WriteFile(filepath.Join(m.Rec, "ipt.rules"), []byte(text), 0o600))
}

// DockerAdminRuleFirst puts a rule of the administrator's own at the top of the fake DOCKER-USER chain.
func (m *Machine) DockerAdminRuleFirst(rule string) {
	p := filepath.Join(m.Rec, "ipt.rules")
	old, _ := os.ReadFile(p)                                          //nolint:gosec // test support: a path under the fake rec dir
	m.must(os.WriteFile(p, append([]byte(rule+"\n"), old...), 0o600)) //nolint:gosec // test support: a path under the fake rec dir
}

// DockerChain says whether the fake box has a DOCKER-USER chain.
func (m *Machine) DockerChain(on bool) { m.Mark("docker-user", on) }

// DockerFlush empties the fake DOCKER-USER chain (Docker restarted and made it again).
func (m *Machine) DockerFlush() { _ = os.Remove(filepath.Join(m.Rec, "ipt.rules")) }

// DockerRules are the rules the fake DOCKER-USER chain holds, as the words after the chain, one per line.
func (m *Machine) DockerRules() []string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, "ipt.rules"))
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
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
// without the variables the shell adds itself). The fake records it with the builtin `export -p` and the
// parsing, filtering and sorting happen here: `env | grep | sort` in the fake cost three more processes on
// every call of every fake, most of the run time of the host tests under -race.
func (m *Machine) Envs(bin string) [][]string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, bin+".env")) //nolint:gosec // test support: a path under the fake rec dir
	var out [][]string
	var cur []string
	started := false
	done := func() {
		if started {
			slices.Sort(cur)
			out = append(out, cur)
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch line {
		case "=== env":
			done()
			cur, started = []string{}, true
		case "":
		default:
			if kv, ok := exportLine(line); ok {
				if k, _, _ := strings.Cut(kv, "="); !slices.Contains([]string{"PWD", "SHLVL", "_", "OLDPWD"}, k) {
					cur = append(cur, kv)
				}
			}
		}
	}
	done()
	return out
}

// exportLine turns one line of `export -p` into KEY=value: dash quotes the value 'like this' ('"'"' for a quote),
// bash in POSIX mode (macOS /bin/sh) "like this" (backslash before $ ` " \). A variable without a value (bash:
// `export OLDPWD`) is skipped; a line that is not `export ...` is kept as it is, so an assertion on it fails.
// ponytail: one line per variable; a value with a newline is not parsed (no fake is given one).
func exportLine(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "export ")
	if !ok {
		return line, true
	}
	name, word, ok := strings.Cut(rest, "=")
	if !ok {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(word); i++ {
		switch c := word[i]; c {
		case '\'':
			j := strings.IndexByte(word[i+1:], '\'')
			if j < 0 {
				return line, true
			}
			b.WriteString(word[i+1 : i+1+j])
			i += j + 1
		case '"':
			for i++; i < len(word) && word[i] != '"'; i++ {
				if word[i] == '\\' && i+1 < len(word) && strings.IndexByte("$`\"\\", word[i+1]) >= 0 {
					i++
				}
				b.WriteByte(word[i])
			}
		case '\\':
			if i+1 < len(word) {
				i++
				b.WriteByte(word[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return name + "=" + b.String(), true
}

// AllCalls returns every call of every fake but ip, as "binary arg arg ...".
func (m *Machine) AllCalls() []string {
	var out []string
	for _, n := range Bins {
		if n == ops.BinIptables {
			continue // every start looks at DOCKER-USER; the Docker forward tests read Calls(ops.BinIptables) themselves
		}
		if n == ops.BinIP {
			continue // every start makes the honeypot namespace; the decoy tests read Calls(ops.BinIP) themselves
		}
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
	return ops.Config{
		StateDir: m.State, CoreData: m.CoreData, CoreUnit: "vedette-core.service", Version: "test",
		CoreUID: os.Getuid(), CoreGID: os.Getgid(), SensorUID: SensorUID, SensorGID: SensorGID,
		OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler),
	}
}

// Deps is the ops.Deps of this machine: the temp root, the fake binaries, and quick polling. now may be nil.
func (m *Machine) Deps(now func() time.Time) ops.Deps {
	return ops.Deps{
		Root: m.Root, BinPaths: m.BinPaths(), Now: now, ChainTop: filepath.Dir(m.CoreData), Arch: "amd64",
		CoreWait: 3 * time.Second, CorePoll: 5 * time.Millisecond, HealthSettle: 10 * time.Millisecond,
		LockHeld: func(string) (bool, error) { return false, nil },
		// The machine has no network cards unless a test says so: never the real ones of the developer's computer.
		Interfaces: func() ([]ops.HostIface, error) { return nil, nil },
		NeighDump:  func() ([]byte, error) { return nil, nil }, // nor its neighbour table
		// The fake namespace file is a plain file; there is no nsfs in a test.
		IsNetNS: func(*os.File) (bool, error) { return true, nil },
		// The waits between two looks at a container take no time; they are still counted, so the
		// 120 s of the health wait are 60 looks.
		Sleep: func(ctx context.Context, _ time.Duration) bool { return ctx.Err() == nil },
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

// StatefulIP makes (NewMachine does it) the fake ip one that remembers what the decoy commands do: links made in the
// host namespace, links moved into vedette-hp with their MAC, address and up flag, the rules, the
// sysctls, the routing tables and the nft ruleset. "ip netns add" creates /run/netns/vedette-hp under the root (with no
// table), a table exists once a route went into it, and "route flush table N" of a table that does not exist answers as
// iproute2 6.19 does (exit 2, "Error: ipv4: FIB table does not exist." and "Flush terminated" on stderr; #475),
// "ip -n vedette-hp -j addr show" prints the links as JSON, and "nft list ruleset" prints the
// egress ruleset once "nft -f -" loaded it, "sysctl -n" reads back what "sysctl -w" set (the marker "sysctl-wrong" makes it read 9) (unless the marker "nft-noload" is set: the load then
// silently does nothing). Rules added with Rule fire before this and can make a call fail.
func (m *Machine) StatefulIP() {
	m.writeFakeWith(ops.BinIP, `S="$REC/ip"; ROOT='`+m.Root+`'
{ [ -d "$S/host" ] && [ -d "$S/ns" ]; } || mkdir -p "$S/host" "$S/ns"
mode=host
if [ "$1" = "-n" ]; then shift 2; mode=ns; fi
args="$*"
setfield() { # file key value
  grep -v "^$2=" "$1" > "$1.tmp" 2>/dev/null; echo "$2=$3" >> "$1.tmp"; mv "$1.tmp" "$1"
}
case "$mode:$args" in
  "host:netns add vedette-hp")
    mkdir -p "$ROOT/run/netns"; : > "$ROOT/run/netns/vedette-hp"; rm -f "$S/tables"; exit 0 ;;
  "host:netns exec vedette-hp /usr/sbin/sysctl -n "*)
    set -- $args; shift 5
    for k in "$@"; do
      v="" # the last value "sysctl -w" set for k (builtins only: this runs on every look of the decoy)
      if [ -r "$S/sysctl" ]; then
        while IFS= read -r l; do
          for w in $l; do case $w in "$k="*) v=${w##*=} ;; esac; done
        done < "$S/sysctl"
      fi
      [ -e "$REC/mark.sysctl-wrong" ] && v=9
      echo "$v"
    done
    exit 0 ;;
  "host:netns exec vedette-hp /usr/sbin/sysctl -w "*)
    echo "$args" >> "$S/sysctl"; exit 0 ;;
  "host:netns exec vedette-hp /usr/sbin/nft -f -")
    cat > "$S/ruleset.in"
    [ -e "$REC/mark.nft-noload" ] || cp "$S/ruleset.in" "$S/ruleset"
    exit 0 ;;
  "host:netns exec vedette-hp /usr/sbin/nft list ruleset")
    if [ -e "$S/ruleset" ]; then
      printf 'table inet vedette_hp {\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tct state established,related accept\n\t\toif "lo" accept\n\t\tct state new drop\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n'
    fi
    exit 0 ;;
  "host:link add link "*)
    set -- $args
    [ -e "$S/host/$6" ] && exit 2
    echo "$8" > "$S/host/$6"; echo "$4" > "$S/host/$6.parent"; exit 0 ;;
  "host:link set "*" netns vedette-hp")
    set -- $args
    [ -e "$S/host/$3" ] || exit 1
    [ -e "$S/ns/$3" ] && exit 2
    { echo "mac=$(cat "$S/host/$3")"; echo "up=0"; } > "$S/ns/$3"
    rm -f "$S/host/$3" "$S/host/$3.parent"; exit 0 ;;
  "host:link del "*)
    set -- $args; rm -f "$S/host/$3" "$S/host/$3.parent"; exit 0 ;;
  "ns:addr add "*)
    set -- $args; [ -e "$S/ns/$5" ] || exit 1; echo "addr=$3" >> "$S/ns/$5"; exit 0 ;;
  "ns:link set lo up") exit 0 ;;
  "ns:link set "*" up")
    set -- $args; [ -e "$S/ns/$3" ] || exit 1; setfield "$S/ns/$3" up 1; exit 0 ;;
  "ns:link del "*)
    set -- $args; [ -e "$S/ns/$3" ] || exit 1; rm -f "$S/ns/$3"; exit 0 ;;
  "ns:rule add "*)
    grep -qxF "$args" "$S/rules" 2>/dev/null && exit 2
    echo "$args" >> "$S/rules"; exit 0 ;;
  "ns:rule del "*)
    d="rule add ${args#rule del }"
    grep -qxF "$d" "$S/rules" 2>/dev/null || exit 2
    grep -vxF "$d" "$S/rules" > "$S/rules.tmp"; mv "$S/rules.tmp" "$S/rules"; exit 0 ;;
  "ns:route flush table "*)
    set -- $args
    grep -qxF "$4" "$S/tables" 2>/dev/null || { printf 'Error: ipv4: FIB table does not exist.\nFlush terminated\n' >&2; exit 2; }
    echo "$args" >> "$S/routes"; exit 0 ;;
  "ns:route "*)
    for t in $args; do :; done # the last word: the table
    grep -qxF "$t" "$S/tables" 2>/dev/null || echo "$t" >> "$S/tables"
    echo "$args" >> "$S/routes"; exit 0 ;;
  "ns:-j addr show")
    printf '[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"link_type":"loopback","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}'
    for f in "$S"/ns/*; do
      [ -e "$f" ] || continue
      n=${f##*/}; mac=""; up=""; addrs=""
      while IFS= read -r l; do
        case $l in mac=*) mac=${l#mac=} ;; up=*) up=${l#up=} ;; addr=*) addrs="$addrs ${l#addr=}" ;; esac
      done < "$f"
      fl='"BROADCAST","MULTICAST"'; [ "$up" = 1 ] && fl="$fl"',"UP","LOWER_UP"'
      printf ',{"ifindex":2,"ifname":"%s","flags":[%s],"link_type":"ether","address":"%s","addr_info":[' "$n" "$fl" "$mac"
      first=1
      for a in $addrs; do
        [ $first = 1 ] || printf ','
        first=0
        printf '{"family":"inet","local":"%s","prefixlen":%s}' "${a%/*}" "${a#*/}"
      done
      printf ']}'
    done
    printf ']\n'; exit 0 ;;
esac`)
}

// IPState reads a file of the stateful fake ip: "ruleset", "rules", "routes", "sysctl", or
// "ns/<link>" and "host/<link>"; "" when absent.
func (m *Machine) IPState(rel string) string {
	b, _ := os.ReadFile(filepath.Join(m.Rec, ops.BinIP, rel)) //nolint:gosec // test support: a path under the fake rec dir
	return string(b)
}

// IPLinks lists the links of the namespace ("ns") or of the host ("host") in the stateful fake ip.
func (m *Machine) IPLinks(where string) []string {
	es, _ := os.ReadDir(filepath.Join(m.Rec, ops.BinIP, where))
	var out []string
	for _, e := range es {
		if n := e.Name(); !strings.Contains(n, ".") {
			out = append(out, n)
		}
	}
	return out
}
